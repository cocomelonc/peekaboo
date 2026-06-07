"""
peekaboo SQLite store - builds, samples (and future tables)
single file: dashboard/peekaboo.db
"""
from __future__ import annotations
import json
import sqlite3
from datetime import datetime
from pathlib import Path

DB_PATH = Path(__file__).parent / "peekaboo.db"

# --------------------------------------------------------------------------- #
#  Connection                                                                   #
# --------------------------------------------------------------------------- #

def _conn() -> sqlite3.Connection:
    c = sqlite3.connect(DB_PATH, check_same_thread=False)
    c.row_factory = sqlite3.Row
    c.execute("PRAGMA journal_mode=WAL")   # safe for concurrent Flask threads
    c.execute("PRAGMA foreign_keys=ON")
    return c


# --------------------------------------------------------------------------- #
#  Schema                                                                       #
# --------------------------------------------------------------------------- #

def init() -> None:
    with _conn() as db:
        db.execute("""
            CREATE TABLE IF NOT EXISTS builds (
                id          TEXT PRIMARY KEY,
                params      TEXT NOT NULL DEFAULT '{}',
                status      TEXT NOT NULL DEFAULT 'queued',
                output      TEXT          DEFAULT '',
                returncode  INTEGER,
                created     TEXT,
                start_time  TEXT,
                end_time    TEXT
            )
        """)
        db.execute("CREATE INDEX IF NOT EXISTS idx_builds_created ON builds(created DESC)")

        db.execute("""
            CREATE TABLE IF NOT EXISTS samples (
                session_id  TEXT PRIMARY KEY,
                files       TEXT NOT NULL DEFAULT '[]',
                total_size  INTEGER NOT NULL DEFAULT 0,
                created     TEXT,
                actor       TEXT NOT NULL DEFAULT '',
                ttps        INTEGER NOT NULL DEFAULT 0,
                status      TEXT NOT NULL DEFAULT 'built'
            )
        """)
        db.execute("CREATE INDEX IF NOT EXISTS idx_samples_created ON samples(created DESC)")

        db.execute("""
            CREATE TABLE IF NOT EXISTS reports (
                session_id  TEXT NOT NULL,
                idx         INTEGER NOT NULL,
                url         TEXT NOT NULL DEFAULT '',
                content     TEXT NOT NULL DEFAULT '',
                created     TEXT,
                PRIMARY KEY (session_id, idx)
            )
        """)
        db.execute("CREATE INDEX IF NOT EXISTS idx_reports_session ON reports(session_id)")

        db.execute("""
            CREATE TABLE IF NOT EXISTS pipeline_sessions (
                session_id  TEXT PRIMARY KEY,
                actor_id    TEXT NOT NULL DEFAULT '',
                started     TEXT,
                finished    TEXT,
                status      TEXT NOT NULL DEFAULT 'running',
                ttps        TEXT NOT NULL DEFAULT '[]',
                params      TEXT NOT NULL DEFAULT '{}'
            )
        """)
        db.execute("CREATE INDEX IF NOT EXISTS idx_psessions_started ON pipeline_sessions(started DESC)")

        db.execute("""
            CREATE TABLE IF NOT EXISTS mitre_library (
                slug        TEXT PRIMARY KEY,
                date        TEXT NOT NULL DEFAULT '',
                title       TEXT NOT NULL DEFAULT '',
                category    TEXT NOT NULL DEFAULT 'other',
                attack_ids  TEXT NOT NULL DEFAULT '[]',
                blog_url    TEXT NOT NULL DEFAULT '',
                src_path    TEXT NOT NULL DEFAULT '',
                snippet     TEXT NOT NULL DEFAULT '',
                mod_ref     TEXT NOT NULL DEFAULT '',
                implemented INTEGER NOT NULL DEFAULT 0
            )
        """)
        db.execute("CREATE INDEX IF NOT EXISTS idx_mitre_cat ON mitre_library(category)")
        db.execute("CREATE INDEX IF NOT EXISTS idx_mitre_date ON mitre_library(date DESC)")


# --------------------------------------------------------------------------- #
#  Helpers                                                                      #
# --------------------------------------------------------------------------- #

def _row(row: sqlite3.Row) -> dict:
    d = dict(row)
    try:
        d["params"] = json.loads(d["params"] or "{}")
    except Exception:
        d["params"] = {}
    return d


def _sample_row(row: sqlite3.Row) -> dict:
    d = dict(row)
    try:
        d["files"] = json.loads(d["files"] or "[]")
    except Exception:
        d["files"] = []
    return d


# --------------------------------------------------------------------------- #
#  Builds - writes                                                              #
# --------------------------------------------------------------------------- #

def save_build(build: dict) -> None:
    with _conn() as db:
        db.execute(
            """
            INSERT OR REPLACE INTO builds
              (id, params, status, output, returncode, created, start_time, end_time)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                build["id"],
                json.dumps(build.get("params", {})),
                build.get("status", "queued"),
                build.get("output", ""),
                build.get("returncode"),
                build.get("created"),
                build.get("start_time"),
                build.get("end_time"),
            ),
        )


def clear_builds() -> None:
    with _conn() as db:
        db.execute("DELETE FROM builds")


# --------------------------------------------------------------------------- #
#  Builds - reads                                                               #
# --------------------------------------------------------------------------- #

def get_build(build_id: str) -> dict | None:
    with _conn() as db:
        row = db.execute("SELECT * FROM builds WHERE id = ?", (build_id,)).fetchone()
    return _row(row) if row else None


def get_builds(limit: int = 200) -> list[dict]:
    with _conn() as db:
        rows = db.execute(
            "SELECT * FROM builds ORDER BY created DESC LIMIT ?", (limit,)
        ).fetchall()
    return [_row(r) for r in rows]


# --------------------------------------------------------------------------- #
#  Samples - writes                                                             #
# --------------------------------------------------------------------------- #

def save_sample(sample: dict) -> None:
    with _conn() as db:
        db.execute(
            """
            INSERT OR REPLACE INTO samples
              (session_id, files, total_size, created, actor, ttps, status)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                sample["session_id"],
                json.dumps(sample.get("files", [])),
                sample.get("total_size", 0),
                sample.get("created", datetime.now().isoformat()),
                sample.get("actor", ""),
                sample.get("ttps", 0),
                sample.get("status", "built"),
            ),
        )


def clear_samples() -> None:
    with _conn() as db:
        db.execute("DELETE FROM samples")


# --------------------------------------------------------------------------- #
#  Samples - reads                                                              #
# --------------------------------------------------------------------------- #

def get_samples(limit: int = 200) -> list[dict]:
    with _conn() as db:
        rows = db.execute(
            "SELECT * FROM samples ORDER BY created DESC LIMIT ?", (limit,)
        ).fetchall()
    return [_sample_row(r) for r in rows]


# --------------------------------------------------------------------------- #
#  Reports - writes                                                             #
# --------------------------------------------------------------------------- #

def save_report(session_id: str, idx: int, url: str, content: str) -> None:
    with _conn() as db:
        db.execute(
            """
            INSERT OR REPLACE INTO reports (session_id, idx, url, content, created)
            VALUES (?, ?, ?, ?, ?)
            """,
            (session_id, idx, url, content, datetime.now().isoformat()),
        )


def clear_reports() -> None:
    with _conn() as db:
        db.execute("DELETE FROM reports")


def clear_reports_for_session(session_id: str) -> None:
    with _conn() as db:
        db.execute("DELETE FROM reports WHERE session_id = ?", (session_id,))


# --------------------------------------------------------------------------- #
#  Reports - reads                                                              #
# --------------------------------------------------------------------------- #

def get_reports(session_id: str) -> list[dict]:
    with _conn() as db:
        rows = db.execute(
            "SELECT idx, url, content FROM reports WHERE session_id = ? ORDER BY idx",
            (session_id,),
        ).fetchall()
    return [dict(r) for r in rows]


# --------------------------------------------------------------------------- #
#  Pipeline sessions — writes                                                   #
# --------------------------------------------------------------------------- #

def save_pipeline_session(session: dict) -> None:
    with _conn() as db:
        db.execute(
            """
            INSERT OR REPLACE INTO pipeline_sessions
              (session_id, actor_id, started, finished, status, ttps, params)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                session["session_id"],
                session.get("actor_id", ""),
                session.get("started"),
                session.get("finished"),
                session.get("status", "running"),
                json.dumps(session.get("ttps", [])),
                json.dumps(session.get("params", {})),
            ),
        )


def update_pipeline_session(session_id: str, **kwargs) -> None:
    if not kwargs:
        return
    sets, vals = [], []
    for k, v in kwargs.items():
        if k in ("ttps", "params"):
            v = json.dumps(v)
        sets.append(f"{k} = ?")
        vals.append(v)
    vals.append(session_id)
    with _conn() as db:
        db.execute(
            f"UPDATE pipeline_sessions SET {', '.join(sets)} WHERE session_id = ?",
            vals,
        )


def clear_pipeline_sessions() -> None:
    with _conn() as db:
        db.execute("DELETE FROM pipeline_sessions")


# --------------------------------------------------------------------------- #
#  Pipeline sessions — reads                                                    #
# --------------------------------------------------------------------------- #

def _psession_row(row: sqlite3.Row) -> dict:
    d = dict(row)
    for k in ("ttps", "params"):
        try:
            d[k] = json.loads(d[k] or "[]" if k == "ttps" else "{}")
        except Exception:
            d[k] = [] if k == "ttps" else {}
    return d


def get_pipeline_sessions(limit: int = 100) -> list[dict]:
    with _conn() as db:
        rows = db.execute(
            "SELECT * FROM pipeline_sessions ORDER BY started DESC LIMIT ?", (limit,)
        ).fetchall()
    return [_psession_row(r) for r in rows]


def get_pipeline_session(session_id: str) -> dict | None:
    with _conn() as db:
        row = db.execute(
            "SELECT * FROM pipeline_sessions WHERE session_id = ?", (session_id,)
        ).fetchone()
    return _psession_row(row) if row else None


# --------------------------------------------------------------------------- #
#  Migration: import legacy builds.json → DB (runs once, idempotent)           #
# --------------------------------------------------------------------------- #

def migrate_json(json_path: Path) -> int:
    if not json_path.exists():
        return 0
    try:
        entries = json.loads(json_path.read_text())
    except Exception:
        return 0
    imported = 0
    with _conn() as db:
        for e in entries:
            if not e.get("id"):
                continue
            db.execute(
                """
                INSERT OR IGNORE INTO builds
                  (id, params, status, output, returncode, created, start_time, end_time)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    e["id"],
                    json.dumps(e.get("params", {})),
                    e.get("status", "unknown"),
                    e.get("output", ""),
                    e.get("returncode"),
                    e.get("created"),
                    e.get("start_time"),
                    e.get("end_time"),
                ),
            )
            imported += 1
    return imported


# --------------------------------------------------------------------------- #
#  Migration: scan samples directory → DB (runs once on startup, idempotent)   #
# --------------------------------------------------------------------------- #

def migrate_samples(samples_dir: Path, pipeline_dir: Path | None = None) -> int:
    if not samples_dir.exists():
        return 0
    imported = 0
    with _conn() as db:
        for d in samples_dir.iterdir():
            if not d.is_dir():
                continue
            files = [
                {"name": f.name, "size": f.stat().st_size}
                for f in d.iterdir()
                if f.is_file() and not f.name.startswith(".")
            ]
            if not files:
                continue
            meta: dict = {}
            if pipeline_dir:
                meta_path = pipeline_dir / d.name / "meta.json"
                if meta_path.exists():
                    try:
                        meta = json.loads(meta_path.read_text())
                    except Exception:
                        pass
            created = datetime.fromtimestamp(d.stat().st_mtime).isoformat()
            db.execute(
                """
                INSERT OR IGNORE INTO samples
                  (session_id, files, total_size, created, actor, ttps, status)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    d.name,
                    json.dumps(files),
                    sum(f["size"] for f in files),
                    created,
                    meta.get("actor_id", ""),
                    meta.get("ttps", 0),
                    meta.get("status", "built"),
                ),
            )
            imported += 1
    return imported


# --------------------------------------------------------------------------- #
#  MITRE library cache                                                          #
# --------------------------------------------------------------------------- #

def save_mitre_entries(entries: list[dict]) -> None:
    with _conn() as db:
        db.execute("DELETE FROM mitre_library")
        for e in entries:
            db.execute(
                """
                INSERT OR REPLACE INTO mitre_library
                  (slug, date, title, category, attack_ids, blog_url, src_path, snippet, mod_ref, implemented)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    e.get("slug", ""),
                    e.get("date", ""),
                    e.get("title", ""),
                    e.get("category", "other"),
                    json.dumps(e.get("attack_ids", [])),
                    e.get("blog_url", ""),
                    e.get("src_path") or "",
                    e.get("snippet", ""),
                    e.get("module") or "",
                    1 if e.get("implemented") else 0,
                ),
            )


def _mitre_row(row: sqlite3.Row) -> dict:
    d = dict(row)
    try:
        d["attack_ids"] = json.loads(d["attack_ids"] or "[]")
    except Exception:
        d["attack_ids"] = []
    d["implemented"] = bool(d["implemented"])
    d["module"] = d.pop("mod_ref", "")
    return d


def get_mitre_entries(category: str = "all") -> list[dict]:
    with _conn() as db:
        if category == "all":
            rows = db.execute(
                "SELECT * FROM mitre_library ORDER BY date DESC"
            ).fetchall()
        else:
            rows = db.execute(
                "SELECT * FROM mitre_library WHERE category = ? ORDER BY date DESC",
                (category,),
            ).fetchall()
    return [_mitre_row(r) for r in rows]


def get_mitre_entry(slug: str) -> dict | None:
    with _conn() as db:
        row = db.execute(
            "SELECT * FROM mitre_library WHERE slug = ?", (slug,)
        ).fetchone()
    return _mitre_row(row) if row else None


def count_mitre_entries() -> int:
    with _conn() as db:
        return db.execute("SELECT COUNT(*) FROM mitre_library").fetchone()[0]


def clear_mitre_entries() -> None:
    with _conn() as db:
        db.execute("DELETE FROM mitre_library")
