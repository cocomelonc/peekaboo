"""
peekaboo SQLite store — builds (and future tables)
single file: dashboard/peekaboo.db
"""
from __future__ import annotations
import json
import sqlite3
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


# --------------------------------------------------------------------------- #
#  Writes                                                                       #
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


# --------------------------------------------------------------------------- #
#  Reads                                                                        #
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
#  Migration: import legacy builds.json → DB (runs once, idempotent)           #
# --------------------------------------------------------------------------- #

def clear_builds() -> None:
    with _conn() as db:
        db.execute("DELETE FROM builds")


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
