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

import os
import queue
import shutil
import signal
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

    def __init__(self, base_dir: Path, malware_dir: Path, peekaboo_py: Path,
                 artifacts_dir: Path | None = None, timeout: int = 180):
        self._base        = base_dir.resolve()
        self._malware_dir = malware_dir.resolve()
        self._peekaboo    = peekaboo_py.resolve()
        self._artifacts   = (artifacts_dir or (base_dir / "builds")).resolve()
        if self._artifacts == self._base or self._artifacts.parent == self._artifacts:
            raise ValueError("build artifact directory must be a dedicated subdirectory")
        self._timeout     = timeout
        self._builds:     dict[str, _Live] = {}
        self._lock        = threading.Lock()
        # peekaboo.py writes to module-local filenames, so concurrent builds
        # must not share that workspace.
        self._run_lock    = threading.Lock()

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
                    yield {"type": EV_STATE, "status": live.status, "heartbeat": True}
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
            resolved = p.resolve()
            allowed = (resolved.is_relative_to(self._base)
                       or resolved.is_relative_to(self._artifacts))
            if allowed and resolved.is_file():
                return resolved
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

    def clear_artifacts(self) -> int:
        """Delete immutable Builder outputs without touching pipeline samples."""
        if not self._artifacts.exists():
            return 0
        files = sum(1 for path in self._artifacts.rglob("*") if path.is_file())
        shutil.rmtree(self._artifacts)
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
        # The generator writes into shared module directories. Keep that
        # mutable phase serialized, then snapshot outputs per build.
        with self._run_lock:
            self._run_serial(build_id)

    def _run_serial(self, build_id: str) -> None:
        with self._lock:
            live = self._builds.get(build_id)
        if not live:
            return

        live.status     = "running"
        live.start_time = datetime.now().isoformat()
        self._publish(live, {"type": EV_STATE, "status": "running"})

        p = live.params
        cmd = [
            sys.executable, str(self._peekaboo),
            "-p", p.get("payload",     "meow"),
            "-e", p.get("encryption",  "speck"),
            "-m", p.get("malware",     "injection"),
            "-i", p.get("injection",   "virtualallocex"),
            "-s", p.get("stealer",     "telegram"),
            "-r", p.get("persistence", "none"),
        ]

        if p.get("malware") == "stealer":
            source_dir = self._malware_dir / "stealer" / p.get("stealer", "telegram")
        else:
            source_dir = self._malware_dir / "injection" / p.get("injection", "virtualallocex")
        expected_main = source_dir / "peekaboo.exe"
        expected_persistence = source_dir / "persistence.exe"

        # A successful subprocess return is not enough: peekaboo.py handles
        # compiler failures internally. Remove stale outputs so only files
        # produced by this invocation can satisfy the postcondition.
        for stale in (expected_main, expected_persistence):
            try:
                stale.unlink(missing_ok=True)
            except OSError as exc:
                self._finalize(live, status="error", returncode=-1,
                               output=f"could not clear stale output {stale}: {exc}")
                return

        # peekaboo.py runs from the project root so its relative paths resolve.
        try:
            proc = subprocess.Popen(
                cmd, cwd=str(self._base),
                stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                text=True, bufsize=1,
                start_new_session=True,
            )
        except Exception as exc:
            self._finalize(live, status="error", returncode=-1,
                           output=f"failed to spawn: {exc}")
            return

        out_lines: list[str] = []
        read_error: list[Exception] = []

        def pump_output() -> None:
            try:
                assert proc.stdout is not None
                for raw in proc.stdout:
                    line = raw.rstrip("\n")
                    out_lines.append(line)
                    live.output = "\n".join(out_lines)
                    self._publish(live, {"type": EV_LINE, "text": line})
            except Exception as exc:
                read_error.append(exc)

        reader = threading.Thread(target=pump_output, daemon=True)
        reader.start()

        def close_output() -> None:
            try:
                if proc.stdout is not None:
                    proc.stdout.close()
            except OSError:
                pass

        try:
            proc.wait(timeout=self._timeout)
        except subprocess.TimeoutExpired:
            try:
                os.killpg(proc.pid, signal.SIGKILL)
            except (OSError, ProcessLookupError):
                proc.kill()
            proc.wait()
            reader.join(timeout=5)
            close_output()
            output = "\n".join([*out_lines, f"Build timed out after {self._timeout}s."])
            self._finalize(live, status="timeout", returncode=-1,
                           output=output)
            return
        except Exception as exc:
            try:
                os.killpg(proc.pid, signal.SIGKILL)
            except (OSError, ProcessLookupError):
                proc.kill()
            proc.wait()
            reader.join(timeout=5)
            close_output()
            self._finalize(live, status="error", returncode=-1, output=str(exc))
            return

        reader.join(timeout=5)
        if reader.is_alive():
            close_output()
            reader.join(timeout=1)
        else:
            close_output()
        if read_error:
            self._finalize(live, status="error", returncode=-1,
                           output=f"output reader failed: {read_error[0]}")
            return

        rc = proc.returncode
        status = "success" if rc == 0 else "failed"

        if status == "success":
            if not expected_main.is_file() or expected_main.stat().st_size == 0:
                status = "failed"
                out_lines.append("Builder exited successfully but produced no peekaboo.exe.")
            else:
                try:
                    build_dir = self._artifacts / build_id
                    build_dir.mkdir(parents=True, exist_ok=False)
                    bin_path = build_dir / "peekaboo.exe"
                    shutil.copy2(expected_main, bin_path)
                    if (p.get("persistence") != "none"
                            and expected_persistence.is_file()
                            and expected_persistence.stat().st_size > 0):
                        shutil.copy2(expected_persistence, build_dir / "persistence.exe")
                    with self._lock:
                        try:
                            stored_path = str(bin_path.relative_to(self._base))
                        except ValueError:
                            stored_path = str(bin_path)
                        live.params = dict(p, out_path=stored_path)
                except Exception as exc:
                    status = "error"
                    rc = -1
                    out_lines.append(f"Could not preserve build artifacts: {exc}")

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
