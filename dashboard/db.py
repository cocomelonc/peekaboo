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

        db.execute("""
            CREATE TABLE IF NOT EXISTS artifact_map (
                tid          TEXT PRIMARY KEY,
                name         TEXT NOT NULL DEFAULT '',
                tactic       TEXT NOT NULL DEFAULT '',
                rule_count   INTEGER NOT NULL DEFAULT 0,
                event_ids    TEXT NOT NULL DEFAULT '[]',
                categories   TEXT NOT NULL DEFAULT '[]',
                reg_keys     TEXT NOT NULL DEFAULT '[]',
                processes    TEXT NOT NULL DEFAULT '[]',
                cmdlines     TEXT NOT NULL DEFAULT '[]',
                rules        TEXT NOT NULL DEFAULT '[]',
                built_at     TEXT
            )
        """)
        db.execute("CREATE INDEX IF NOT EXISTS idx_artifact_tactic ON artifact_map(tactic)")

        db.execute("""
            CREATE TABLE IF NOT EXISTS artifact_summaries (
                tid           TEXT NOT NULL,
                model         TEXT NOT NULL DEFAULT '',
                summary       TEXT NOT NULL DEFAULT '',
                raw_output    TEXT NOT NULL DEFAULT '',
                summarized_at TEXT NOT NULL DEFAULT (datetime('now')),
                PRIMARY KEY (tid, model)
            )
        """)

        db.execute("""
            CREATE TABLE IF NOT EXISTS session_summaries (
                session_id    TEXT NOT NULL,
                model         TEXT NOT NULL DEFAULT '',
                summary       TEXT NOT NULL DEFAULT '',
                raw_output    TEXT NOT NULL DEFAULT '',
                summarized_at TEXT NOT NULL DEFAULT (datetime('now')),
                PRIMARY KEY (session_id, model)
            )
        """)

        db.execute("""
            CREATE TABLE IF NOT EXISTS actor_summaries (
                actor_id      TEXT NOT NULL,
                model         TEXT NOT NULL DEFAULT '',
                summary       TEXT NOT NULL DEFAULT '',
                raw_output    TEXT NOT NULL DEFAULT '',
                summarized_at TEXT NOT NULL DEFAULT (datetime('now')),
                PRIMARY KEY (actor_id, model)
            )
        """)

        db.execute("""
            CREATE TABLE IF NOT EXISTS family_summaries (
                family_id     TEXT NOT NULL,
                model         TEXT NOT NULL DEFAULT '',
                summary       TEXT NOT NULL DEFAULT '',
                raw_output    TEXT NOT NULL DEFAULT '',
                summarized_at TEXT NOT NULL DEFAULT (datetime('now')),
                PRIMARY KEY (family_id, model)
            )
        """)

        db.execute("""
            CREATE TABLE IF NOT EXISTS ttp_implementations (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                attack_id   TEXT NOT NULL,
                tactic      TEXT NOT NULL DEFAULT '',
                tech_name   TEXT NOT NULL DEFAULT '',
                blog_slug   TEXT NOT NULL,
                blog_url    TEXT NOT NULL DEFAULT '',
                meow_slug   TEXT NOT NULL DEFAULT '',
                platform    TEXT NOT NULL DEFAULT 'windows',
                notes       TEXT NOT NULL DEFAULT '',
                added_at    TEXT DEFAULT (datetime('now')),
                UNIQUE(attack_id, blog_slug)
            )
        """)
        db.execute("CREATE INDEX IF NOT EXISTS idx_ttp_impl_attack_id ON ttp_implementations(attack_id)")
        db.execute("CREATE INDEX IF NOT EXISTS idx_ttp_impl_blog_slug  ON ttp_implementations(blog_slug)")
        db.execute("CREATE INDEX IF NOT EXISTS idx_ttp_impl_platform   ON ttp_implementations(platform)")

        # ------------------------------------------------------------------ #
        # KB enrichment tables (written by worker.py, read by chatbot RAG)  #
        # ------------------------------------------------------------------ #
        db.execute("""
            CREATE TABLE IF NOT EXISTS kb_docs (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                slug        TEXT NOT NULL UNIQUE,
                title       TEXT NOT NULL DEFAULT '',
                date        TEXT NOT NULL DEFAULT '',
                blog_url    TEXT NOT NULL DEFAULT '',
                category    TEXT NOT NULL DEFAULT '',
                attack_ids  TEXT NOT NULL DEFAULT '[]',
                src_path    TEXT NOT NULL DEFAULT '',
                implemented INTEGER NOT NULL DEFAULT 0,
                source_type TEXT NOT NULL DEFAULT 'blog',
                indexed_at  TEXT NOT NULL DEFAULT (datetime('now'))
            )
        """)
        db.execute("CREATE INDEX IF NOT EXISTS idx_kb_docs_slug     ON kb_docs(slug)")
        db.execute("CREATE INDEX IF NOT EXISTS idx_kb_docs_category ON kb_docs(category)")
        # migration: add source_type to existing installs
        try:
            db.execute("ALTER TABLE kb_docs ADD COLUMN source_type TEXT NOT NULL DEFAULT 'blog'")
        except Exception:
            pass  # column already exists

        db.execute("""
            CREATE TABLE IF NOT EXISTS kb_embeddings (
                doc_id      INTEGER NOT NULL REFERENCES kb_docs(id) ON DELETE CASCADE,
                model       TEXT    NOT NULL DEFAULT 'nomic-embed-text',
                vector      TEXT    NOT NULL DEFAULT '[]',
                dims        INTEGER NOT NULL DEFAULT 768,
                embedded_at TEXT    NOT NULL DEFAULT (datetime('now')),
                PRIMARY KEY (doc_id, model)
            )
        """)

        db.execute("""
            CREATE TABLE IF NOT EXISTS kb_tags (
                doc_id      INTEGER NOT NULL REFERENCES kb_docs(id) ON DELETE CASCADE,
                model       TEXT    NOT NULL DEFAULT '',
                tags        TEXT    NOT NULL DEFAULT '[]',
                raw_output  TEXT    NOT NULL DEFAULT '',
                tagged_at   TEXT    NOT NULL DEFAULT (datetime('now')),
                PRIMARY KEY (doc_id, model)
            )
        """)

        db.execute("""
            CREATE TABLE IF NOT EXISTS kb_summaries (
                doc_id        INTEGER NOT NULL REFERENCES kb_docs(id) ON DELETE CASCADE,
                model         TEXT    NOT NULL DEFAULT '',
                summary       TEXT    NOT NULL DEFAULT '',
                raw_output    TEXT    NOT NULL DEFAULT '',
                summarized_at TEXT    NOT NULL DEFAULT (datetime('now')),
                PRIMARY KEY (doc_id, model)
            )
        """)

        db.execute("""
            CREATE TABLE IF NOT EXISTS ttp_extracted (
                doc_id       INTEGER NOT NULL REFERENCES kb_docs(id) ON DELETE CASCADE,
                model        TEXT    NOT NULL DEFAULT '',
                attack_ids   TEXT    NOT NULL DEFAULT '[]',
                tactics      TEXT    NOT NULL DEFAULT '[]',
                confidence   TEXT    NOT NULL DEFAULT 'low',
                rationale    TEXT    NOT NULL DEFAULT '',
                raw_output   TEXT    NOT NULL DEFAULT '',
                extracted_at TEXT    NOT NULL DEFAULT (datetime('now')),
                PRIMARY KEY (doc_id, model)
            )
        """)
        db.execute("CREATE INDEX IF NOT EXISTS idx_ttp_extracted_model ON ttp_extracted(model)")

        db.execute("""
            CREATE TABLE IF NOT EXISTS patch_history (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                filename    TEXT NOT NULL DEFAULT '',
                orig_size   INTEGER NOT NULL DEFAULT 0,
                patch_size  INTEGER NOT NULL DEFAULT 0,
                patches     TEXT NOT NULL DEFAULT '[]',
                applied     TEXT NOT NULL DEFAULT '[]',
                score       INTEGER NOT NULL DEFAULT 0,
                created     TEXT
            )
        """)
        db.execute("CREATE INDEX IF NOT EXISTS idx_patch_history_created ON patch_history(created DESC)")


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
#  Pipeline sessions - writes                                                   #
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
#  Pipeline sessions - reads                                                    #
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
#  Migration: import legacy builds.json -> DB (runs once, idempotent)           #
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
#  Migration: scan samples directory -> DB (runs once on startup, idempotent)   #
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


def get_mitre_entries_paged(
    q: str = "",
    category: str = "",
    offset: int = 0,
    limit: int = 10,
) -> list[dict]:
    with _conn() as db:
        conds: list[str] = []
        args:  list      = []
        if category:
            conds.append("category = ?")
            args.append(category)
        if q:
            pat = f"%{q}%"
            conds.append(
                "(title LIKE ? OR attack_ids LIKE ? OR category LIKE ? OR slug LIKE ?)"
            )
            args += [pat, pat, pat, pat]
        sql = "SELECT * FROM mitre_library"
        if conds:
            sql += " WHERE " + " AND ".join(conds)
        sql += " ORDER BY date DESC LIMIT ? OFFSET ?"
        args += [limit, offset]
        rows = db.execute(sql, args).fetchall()
    return [_mitre_row(r) for r in rows]


def count_mitre_entries_filtered(q: str = "", category: str = "") -> int:
    with _conn() as db:
        conds: list[str] = []
        args:  list      = []
        if category:
            conds.append("category = ?")
            args.append(category)
        if q:
            pat = f"%{q}%"
            conds.append(
                "(title LIKE ? OR attack_ids LIKE ? OR category LIKE ? OR slug LIKE ?)"
            )
            args += [pat, pat, pat, pat]
        sql = "SELECT COUNT(*) FROM mitre_library"
        if conds:
            sql += " WHERE " + " AND ".join(conds)
        return db.execute(sql, args).fetchone()[0]


def get_mitre_categories() -> list[tuple[str, int]]:
    with _conn() as db:
        rows = db.execute(
            "SELECT category, COUNT(*) n FROM mitre_library GROUP BY category ORDER BY n DESC"
        ).fetchall()
    return [(r[0], r[1]) for r in rows]


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


# --------------------------------------------------------------------------- #
#  Artifact Map                                                                 #
# --------------------------------------------------------------------------- #

def save_artifact_entries(entries: list[dict]) -> None:
    with _conn() as db:
        db.execute("DELETE FROM artifact_map")
        now = datetime.now().isoformat()
        for e in entries:
            db.execute(
                """
                INSERT OR REPLACE INTO artifact_map
                  (tid, name, tactic, rule_count, event_ids, categories,
                   reg_keys, processes, cmdlines, rules, built_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    e["tid"],
                    e.get("name", ""),
                    e.get("tactic", ""),
                    e.get("rule_count", 0),
                    json.dumps(e.get("event_ids", [])),
                    json.dumps(e.get("categories", [])),
                    json.dumps(e.get("reg_keys", [])),
                    json.dumps(e.get("processes", [])),
                    json.dumps(e.get("cmdlines", [])),
                    json.dumps(e.get("rules", [])),
                    now,
                ),
            )


def _artifact_row(row: sqlite3.Row) -> dict:
    d = dict(row)
    for k in ("event_ids", "categories", "reg_keys", "processes", "cmdlines", "rules"):
        try:
            d[k] = json.loads(d[k] or "[]")
        except Exception:
            d[k] = []
    return d


def get_artifact_entries(tactic: str = "all", q: str = "") -> list[dict]:
    with _conn() as db:
        if tactic == "all":
            rows = db.execute(
                "SELECT * FROM artifact_map ORDER BY rule_count DESC"
            ).fetchall()
        else:
            rows = db.execute(
                "SELECT * FROM artifact_map WHERE tactic LIKE ? ORDER BY rule_count DESC",
                (f"%{tactic}%",),
            ).fetchall()
    results = [_artifact_row(r) for r in rows]
    if q:
        q = q.lower()
        results = [
            r for r in results
            if q in r["tid"].lower() or q in r["name"].lower() or q in r["tactic"].lower()
        ]
    return results


def get_artifact_entry(tid: str) -> dict | None:
    with _conn() as db:
        row = db.execute(
            "SELECT * FROM artifact_map WHERE tid = ?", (tid.upper(),)
        ).fetchone()
    return _artifact_row(row) if row else None


def count_artifact_entries() -> int:
    with _conn() as db:
        return db.execute("SELECT COUNT(*) FROM artifact_map").fetchone()[0]


def get_artifact_stats() -> dict:
    with _conn() as db:
        total_techniques = db.execute("SELECT COUNT(*) FROM artifact_map").fetchone()[0]
        total_rules = db.execute(
            "SELECT SUM(rule_count) FROM artifact_map"
        ).fetchone()[0] or 0
        rows = db.execute("SELECT tactic, event_ids FROM artifact_map").fetchall()
    tactic_set: set[str] = set()
    event_set: set[int] = set()
    for row in rows:
        for t in (row["tactic"] or "").split(","):
            t = t.strip()
            if t:
                tactic_set.add(t)
        try:
            for eid in json.loads(row["event_ids"] or "[]"):
                event_set.add(int(eid))
        except Exception:
            pass
    return {
        "total_techniques": total_techniques,
        "total_rules":      total_rules,
        "unique_tactics":   len(tactic_set),
        "unique_event_ids": len(event_set),
        "tactics":          sorted(tactic_set),
    }


def clear_artifact_entries() -> None:
    with _conn() as db:
        db.execute("DELETE FROM artifact_map")


# --------------------------------------------------------------------------- #
#  Artifact Summaries (LLM-precomputed, written by worker.py sigma)            #
# --------------------------------------------------------------------------- #

def get_artifact_tids_without_summary(model: str) -> list[str]:
    with _conn() as db:
        rows = db.execute(
            """
            SELECT tid FROM artifact_map
            WHERE tid NOT IN (
                SELECT tid FROM artifact_summaries WHERE model = ?
            )
            ORDER BY rule_count DESC
            """,
            (model,),
        ).fetchall()
    return [r["tid"] for r in rows]


def upsert_artifact_summary(tid: str, model: str, summary: str, raw_output: str = "") -> None:
    with _conn() as db:
        db.execute(
            """
            INSERT INTO artifact_summaries (tid, model, summary, raw_output, summarized_at)
            VALUES (?, ?, ?, ?, datetime('now'))
            ON CONFLICT(tid, model) DO UPDATE SET
                summary=excluded.summary,
                raw_output=excluded.raw_output,
                summarized_at=excluded.summarized_at
            """,
            (tid, model, summary, raw_output),
        )


def get_artifact_summary(tid: str, model: str | None = None) -> str:
    with _conn() as db:
        if model:
            row = db.execute(
                "SELECT summary FROM artifact_summaries WHERE tid=? AND model=? LIMIT 1",
                (tid.upper(), model),
            ).fetchone()
        else:
            row = db.execute(
                "SELECT summary FROM artifact_summaries WHERE tid=? ORDER BY summarized_at DESC LIMIT 1",
                (tid.upper(),),
            ).fetchone()
    return (row["summary"] or "") if row else ""


def count_artifact_summaries(model: str | None = None) -> int:
    with _conn() as db:
        if model:
            return db.execute(
                "SELECT COUNT(*) FROM artifact_summaries WHERE model=?", (model,)
            ).fetchone()[0]
        return db.execute("SELECT COUNT(*) FROM artifact_summaries").fetchone()[0]


def get_artifact_summarized_tids(model: str) -> list[str]:
    with _conn() as db:
        rows = db.execute(
            "SELECT tid FROM artifact_summaries WHERE model=?", (model,)
        ).fetchall()
    return [r["tid"] for r in rows]


# --------------------------------------------------------------------------- #
#  Patch History                                                                #
# --------------------------------------------------------------------------- #

def save_patch_run(filename: str, orig_size: int, patch_size: int,
                   patches: list, applied: list, score: int) -> None:
    with _conn() as db:
        db.execute(
            """
            INSERT INTO patch_history (filename, orig_size, patch_size, patches, applied, score, created)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (filename, orig_size, patch_size,
             json.dumps(patches), json.dumps(applied), score,
             datetime.now().isoformat()),
        )


def get_patch_history(limit: int = 10) -> list[dict]:
    with _conn() as db:
        rows = db.execute(
            "SELECT * FROM patch_history ORDER BY created DESC LIMIT ?", (limit,)
        ).fetchall()
    result = []
    for row in rows:
        d = dict(row)
        for k in ("patches", "applied"):
            try:
                d[k] = json.loads(d[k] or "[]")
            except Exception:
                d[k] = []
        result.append(d)
    return result


def clear_patch_history() -> None:
    with _conn() as db:
        db.execute("DELETE FROM patch_history")


# --------------------------------------------------------------------------- #
#  TTP Implementations                                                         #
# --------------------------------------------------------------------------- #

def upsert_ttp_implementations(entries: list[dict]) -> int:
    now = datetime.now().isoformat()
    inserted = 0
    with _conn() as db:
        for e in entries:
            db.execute(
                """
                INSERT INTO ttp_implementations
                  (attack_id, tactic, tech_name, blog_slug, blog_url,
                   meow_slug, platform, notes, added_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(attack_id, blog_slug) DO UPDATE SET
                  tactic    = excluded.tactic,
                  tech_name = excluded.tech_name,
                  blog_url  = excluded.blog_url,
                  meow_slug = excluded.meow_slug,
                  platform  = excluded.platform,
                  notes     = excluded.notes
                """,
                (
                    e["attack_id"],
                    e.get("tactic", ""),
                    e.get("tech_name", ""),
                    e["blog_slug"],
                    e.get("blog_url", ""),
                    e.get("meow_slug", ""),
                    e.get("platform", "windows"),
                    e.get("notes", ""),
                    now,
                ),
            )
            inserted += 1
    return inserted


def _ttp_impl_row(row: sqlite3.Row) -> dict:
    return dict(row)


def get_ttp_implementations(
    attack_id: str | None = None,
    platform:  str | None = None,
    q:         str | None = None,
) -> list[dict]:
    with _conn() as db:
        sql  = "SELECT * FROM ttp_implementations"
        args: list = []
        conds: list[str] = []
        if attack_id:
            conds.append("(attack_id = ? OR attack_id LIKE ?)")
            args += [attack_id, attack_id + ".%"]
        if platform:
            conds.append("platform = ?")
            args.append(platform)
        if conds:
            sql += " WHERE " + " AND ".join(conds)
        sql += " ORDER BY attack_id, blog_slug"
        rows = db.execute(sql, args).fetchall()

    results = [_ttp_impl_row(r) for r in rows]

    if q:
        ql = q.lower()
        results = [
            r for r in results
            if ql in r["attack_id"].lower()
            or ql in r["tech_name"].lower()
            or ql in r["tactic"].lower()
            or ql in r["blog_slug"].lower()
            or ql in r["notes"].lower()
        ]
    return results


def get_ttp_by_attack_id(attack_id: str) -> list[dict]:
    with _conn() as db:
        rows = db.execute(
            "SELECT * FROM ttp_implementations WHERE attack_id = ? ORDER BY blog_slug",
            (attack_id,),
        ).fetchall()
    return [_ttp_impl_row(r) for r in rows]


def get_ttp_attack_ids() -> list[str]:
    """Distinct attack_ids with at least one implementation, sorted."""
    with _conn() as db:
        rows = db.execute(
            "SELECT DISTINCT attack_id FROM ttp_implementations ORDER BY attack_id"
        ).fetchall()
    return [r[0] for r in rows]


def count_ttp_implementations() -> int:
    with _conn() as db:
        return db.execute("SELECT COUNT(*) FROM ttp_implementations").fetchone()[0]


def count_ttp_techniques() -> int:
    with _conn() as db:
        return db.execute(
            "SELECT COUNT(DISTINCT attack_id) FROM ttp_implementations"
        ).fetchone()[0]


def clear_ttp_implementations() -> None:
    with _conn() as db:
        db.execute("DELETE FROM ttp_implementations")


# --------------------------------------------------------------------------- #
#  KB docs                                                                      #
# --------------------------------------------------------------------------- #

def upsert_kb_doc(doc: dict) -> int:
    """Insert or replace a KB doc. Returns the row id."""
    with _conn() as db:
        db.execute(
            """
            INSERT INTO kb_docs
              (slug, title, date, blog_url, category, attack_ids, src_path, implemented, source_type)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(slug) DO UPDATE SET
              title       = excluded.title,
              date        = excluded.date,
              blog_url    = excluded.blog_url,
              category    = excluded.category,
              attack_ids  = excluded.attack_ids,
              src_path    = excluded.src_path,
              implemented = excluded.implemented,
              source_type = excluded.source_type
            """,
            (
                doc["slug"],
                doc.get("title") or "",
                doc.get("date") or "",
                doc.get("blog_url") or "",
                doc.get("category") or "",
                json.dumps(doc.get("attack_ids") or []),
                doc.get("src_path") or "",
                1 if doc.get("implemented") else 0,
                doc.get("source_type") or "blog",
            ),
        )
        row = db.execute("SELECT id FROM kb_docs WHERE slug = ?", (doc["slug"],)).fetchone()
        return row[0] if row else -1


def get_kb_docs_without_embedding(model: str = "nomic-embed-text") -> list[dict]:
    """Return all kb_docs that have no entry in kb_embeddings for the given model."""
    with _conn() as db:
        rows = db.execute(
            """
            SELECT id, slug, title, date, category, attack_ids
            FROM kb_docs
            WHERE id NOT IN (SELECT doc_id FROM kb_embeddings WHERE model = ?)
            ORDER BY id
            """,
            (model,),
        ).fetchall()
    result = []
    for r in rows:
        d = dict(r)
        try:
            d["attack_ids"] = json.loads(d["attack_ids"] or "[]")
        except Exception:
            d["attack_ids"] = []
        result.append(d)
    return result


def delete_kb_embeddings(model: str, doc_ids: list[int] | None = None) -> int:
    """Delete embedding rows. If doc_ids is None, deletes all for the model."""
    with _conn() as db:
        if doc_ids is None:
            cur = db.execute("DELETE FROM kb_embeddings WHERE model = ?", (model,))
        else:
            cur = db.executemany(
                "DELETE FROM kb_embeddings WHERE model = ? AND doc_id = ?",
                [(model, i) for i in doc_ids],
            )
        return cur.rowcount or 0


def delete_kb_tags(model: str, doc_ids: list[int] | None = None) -> int:
    """Delete tag rows. If doc_ids is None, deletes all for the model."""
    with _conn() as db:
        if doc_ids is None:
            cur = db.execute("DELETE FROM kb_tags WHERE model = ?", (model,))
        else:
            cur = db.executemany(
                "DELETE FROM kb_tags WHERE model = ? AND doc_id = ?",
                [(model, i) for i in doc_ids],
            )
        return cur.rowcount or 0


def get_kb_tagged_docs(model: str) -> list[dict]:
    """Return (id, slug, src_path, tagged_at, title, category, attack_ids) for docs
    that have a tag entry under this model - used to detect stale sources."""
    with _conn() as db:
        rows = db.execute(
            """
            SELECT d.id, d.slug, d.src_path, d.title, d.category, d.attack_ids,
                   t.tagged_at
            FROM kb_docs d
            JOIN kb_tags t ON t.doc_id = d.id
            WHERE t.model = ?
            """,
            (model,),
        ).fetchall()
    result = []
    for r in rows:
        d = dict(r)
        try:
            d["attack_ids"] = json.loads(d["attack_ids"] or "[]")
        except Exception:
            d["attack_ids"] = []
        result.append(d)
    return result


def upsert_kb_embedding(doc_id: int, model: str, vector: list[float]) -> None:
    with _conn() as db:
        db.execute(
            """
            INSERT INTO kb_embeddings (doc_id, model, vector, dims)
            VALUES (?, ?, ?, ?)
            ON CONFLICT(doc_id, model) DO UPDATE SET
              vector      = excluded.vector,
              dims        = excluded.dims,
              embedded_at = datetime('now')
            """,
            (doc_id, model, json.dumps(vector), len(vector)),
        )


def kb_stats() -> dict:
    with _conn() as db:
        docs          = db.execute("SELECT COUNT(*) FROM kb_docs").fetchone()[0]
        embeddings    = db.execute("SELECT COUNT(*) FROM kb_embeddings").fetchone()[0]
        tags          = db.execute("SELECT COUNT(*) FROM kb_tags").fetchone()[0]
        ttp_extracted = db.execute("SELECT COUNT(*) FROM ttp_extracted").fetchone()[0]
        summaries     = db.execute("SELECT COUNT(*) FROM kb_summaries").fetchone()[0]
    return {"docs": docs, "embeddings": embeddings, "tags": tags,
            "ttp_extracted": ttp_extracted, "summaries": summaries}


def get_kb_doc_by_id(doc_id: int) -> dict | None:
    with _conn() as db:
        row = db.execute("SELECT * FROM kb_docs WHERE id = ?", (doc_id,)).fetchone()
    if not row:
        return None
    d = dict(row)
    try:
        d["attack_ids"] = json.loads(d["attack_ids"] or "[]")
    except Exception:
        d["attack_ids"] = []
    return d


def get_kb_docs_without_tags(model: str) -> list[dict]:
    """Return all kb_docs that have no entry in kb_tags for the given model."""
    with _conn() as db:
        rows = db.execute(
            """
            SELECT id, slug, title, date, category, attack_ids, src_path
            FROM kb_docs
            WHERE id NOT IN (SELECT doc_id FROM kb_tags WHERE model = ?)
            ORDER BY id
            """,
            (model,),
        ).fetchall()
    result = []
    for r in rows:
        d = dict(r)
        try:
            d["attack_ids"] = json.loads(d["attack_ids"] or "[]")
        except Exception:
            d["attack_ids"] = []
        result.append(d)
    return result


def upsert_kb_tag(doc_id: int, model: str, tags: list[str], raw_output: str = "") -> None:
    with _conn() as db:
        db.execute(
            """
            INSERT INTO kb_tags (doc_id, model, tags, raw_output)
            VALUES (?, ?, ?, ?)
            ON CONFLICT(doc_id, model) DO UPDATE SET
              tags       = excluded.tags,
              raw_output = excluded.raw_output,
              tagged_at  = datetime('now')
            """,
            (doc_id, model, json.dumps(tags), raw_output),
        )


def get_kb_tags_all(model: str | None = None) -> dict[str, list[str]]:
    """Return {slug: [tags]} for the given model - used by chatbot RAG.
    If model is None, returns tags from any model (union if multiple)."""
    with _conn() as db:
        if model:
            rows = db.execute(
                """
                SELECT d.slug, t.tags
                FROM kb_tags t
                JOIN kb_docs d ON d.id = t.doc_id
                WHERE t.model = ?
                """,
                (model,),
            ).fetchall()
        else:
            rows = db.execute(
                """
                SELECT d.slug, t.tags
                FROM kb_tags t
                JOIN kb_docs d ON d.id = t.doc_id
                """,
            ).fetchall()
    out: dict[str, list[str]] = {}
    for r in rows:
        try:
            tags = json.loads(r["tags"] or "[]")
        except Exception:
            tags = []
        if r["slug"] in out:
            # union if multiple models
            out[r["slug"]] = sorted(set(out[r["slug"]]) | set(tags))
        else:
            out[r["slug"]] = tags
    return out


# --------------------------------------------------------------------------- #
#  KB Summaries (LLM-precomputed, written by worker.py summarize)             #
# --------------------------------------------------------------------------- #

def get_kb_docs_without_summary(model: str) -> list[dict]:
    with _conn() as db:
        rows = db.execute(
            """
            SELECT id, slug, title, date, category, attack_ids, src_path
            FROM kb_docs
            WHERE id NOT IN (SELECT doc_id FROM kb_summaries WHERE model = ?)
            ORDER BY id
            """,
            (model,),
        ).fetchall()
    result = []
    for r in rows:
        d = dict(r)
        try:
            d["attack_ids"] = json.loads(d["attack_ids"] or "[]")
        except Exception:
            d["attack_ids"] = []
        result.append(d)
    return result


def upsert_kb_summary(doc_id: int, model: str, summary: str, raw_output: str = "") -> None:
    with _conn() as db:
        db.execute(
            """
            INSERT INTO kb_summaries (doc_id, model, summary, raw_output)
            VALUES (?, ?, ?, ?)
            ON CONFLICT(doc_id, model) DO UPDATE SET
              summary       = excluded.summary,
              raw_output    = excluded.raw_output,
              summarized_at = datetime('now')
            """,
            (doc_id, model, summary, raw_output),
        )


def delete_kb_summaries(model: str, doc_ids: list[int] | None = None) -> int:
    with _conn() as db:
        if doc_ids is None:
            cur = db.execute("DELETE FROM kb_summaries WHERE model = ?", (model,))
        else:
            cur = db.executemany(
                "DELETE FROM kb_summaries WHERE model = ? AND doc_id = ?",
                [(model, i) for i in doc_ids],
            )
        return cur.rowcount or 0


def get_kb_summarized_docs(model: str) -> list[dict]:
    """Docs with summaries under this model - used to detect stale sources."""
    with _conn() as db:
        rows = db.execute(
            """
            SELECT d.id, d.slug, d.src_path, s.summarized_at
            FROM kb_docs d
            JOIN kb_summaries s ON s.doc_id = d.id
            WHERE s.model = ?
            """,
            (model,),
        ).fetchall()
    return [dict(r) for r in rows]


def get_kb_summary_for_slug(slug: str, model: str | None = None) -> str:
    """Return one summary string for a slug. Latest model wins if model is None."""
    with _conn() as db:
        if model:
            row = db.execute(
                """
                SELECT s.summary FROM kb_summaries s
                JOIN kb_docs d ON d.id = s.doc_id
                WHERE d.slug = ? AND s.model = ? AND s.summary != ''
                """,
                (slug, model),
            ).fetchone()
        else:
            row = db.execute(
                """
                SELECT s.summary FROM kb_summaries s
                JOIN kb_docs d ON d.id = s.doc_id
                WHERE d.slug = ? AND s.summary != ''
                ORDER BY s.summarized_at DESC LIMIT 1
                """,
                (slug,),
            ).fetchone()
    return row["summary"] if row else ""


def get_kb_summaries_all(model: str | None = None) -> dict[str, str]:
    """Return {slug: summary} for chatbot template rendering. Latest model wins per slug."""
    with _conn() as db:
        if model:
            rows = db.execute(
                """
                SELECT d.slug, s.summary
                FROM kb_summaries s
                JOIN kb_docs d ON d.id = s.doc_id
                WHERE s.model = ? AND s.summary != ''
                """,
                (model,),
            ).fetchall()
        else:
            rows = db.execute(
                """
                SELECT d.slug, s.summary, s.summarized_at
                FROM kb_summaries s
                JOIN kb_docs d ON d.id = s.doc_id
                WHERE s.summary != ''
                ORDER BY s.summarized_at
                """,
            ).fetchall()
    out: dict[str, str] = {}
    for r in rows:
        if r["slug"]:
            out[r["slug"]] = r["summary"]
    return out


# --------------------------------------------------------------------------- #
#  TTP Extracted (LLM-inferred, written by worker.py ttp, read by chatbot)    #
# --------------------------------------------------------------------------- #

def _ttp_extracted_row(row: sqlite3.Row) -> dict:
    d = dict(row)
    for k in ("attack_ids", "tactics"):
        try:
            d[k] = json.loads(d[k] or "[]")
        except Exception:
            d[k] = []
    return d


def get_kb_docs_without_ttps(model: str) -> list[dict]:
    """Return kb_docs with src_path that have no ttp_extracted row for this model."""
    with _conn() as db:
        rows = db.execute(
            """
            SELECT id, slug, title, date, category, attack_ids, src_path
            FROM kb_docs
            WHERE src_path != ''
              AND id NOT IN (SELECT doc_id FROM ttp_extracted WHERE model = ?)
            ORDER BY id
            """,
            (model,),
        ).fetchall()
    result = []
    for r in rows:
        d = dict(r)
        try:
            d["attack_ids"] = json.loads(d["attack_ids"] or "[]")
        except Exception:
            d["attack_ids"] = []
        result.append(d)
    return result


def upsert_ttp_extracted(doc_id: int, model: str, attack_ids: list[str],
                          tactics: list[str], confidence: str,
                          rationale: str, raw_output: str = "") -> None:
    with _conn() as db:
        db.execute(
            """
            INSERT INTO ttp_extracted
              (doc_id, model, attack_ids, tactics, confidence, rationale, raw_output)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(doc_id, model) DO UPDATE SET
              attack_ids   = excluded.attack_ids,
              tactics      = excluded.tactics,
              confidence   = excluded.confidence,
              rationale    = excluded.rationale,
              raw_output   = excluded.raw_output,
              extracted_at = datetime('now')
            """,
            (doc_id, model, json.dumps(attack_ids), json.dumps(tactics),
             confidence, rationale, raw_output),
        )


def delete_ttp_extracted(model: str, doc_ids: list[int] | None = None) -> int:
    with _conn() as db:
        if doc_ids is None:
            cur = db.execute("DELETE FROM ttp_extracted WHERE model = ?", (model,))
        else:
            cur = db.executemany(
                "DELETE FROM ttp_extracted WHERE model = ? AND doc_id = ?",
                [(model, i) for i in doc_ids],
            )
        return cur.rowcount or 0


def get_ttp_extracted_all(model: str | None = None) -> list[dict]:
    """Return all rows joined with kb_docs metadata. If model is None, returns all models."""
    with _conn() as db:
        if model:
            rows = db.execute(
                """
                SELECT d.slug, d.title, d.blog_url, d.category,
                       d.attack_ids AS doc_attack_ids,
                       t.model, t.attack_ids, t.tactics, t.confidence,
                       t.rationale, t.extracted_at
                FROM ttp_extracted t
                JOIN kb_docs d ON d.id = t.doc_id
                WHERE t.model = ?
                ORDER BY d.id
                """,
                (model,),
            ).fetchall()
        else:
            rows = db.execute(
                """
                SELECT d.slug, d.title, d.blog_url, d.category,
                       d.attack_ids AS doc_attack_ids,
                       t.model, t.attack_ids, t.tactics, t.confidence,
                       t.rationale, t.extracted_at
                FROM ttp_extracted t
                JOIN kb_docs d ON d.id = t.doc_id
                ORDER BY d.id
                """,
            ).fetchall()
    result = []
    for r in rows:
        d = dict(r)
        for k in ("attack_ids", "tactics", "doc_attack_ids"):
            try:
                d[k] = json.loads(d[k] or "[]")
            except Exception:
                d[k] = []
        result.append(d)
    return result


def get_ttp_extracted_by_doc(doc_id: int, model: str) -> dict | None:
    with _conn() as db:
        row = db.execute(
            "SELECT * FROM ttp_extracted WHERE doc_id = ? AND model = ?",
            (doc_id, model),
        ).fetchone()
    return _ttp_extracted_row(row) if row else None


def get_ttp_extracted_by_attack_id(attack_id: str, model: str | None = None) -> list[dict]:
    """Return docs whose extracted attack_ids contain attack_id (exact match after JSON parse)."""
    with _conn() as db:
        if model:
            rows = db.execute(
                """
                SELECT d.slug, d.title, d.blog_url, d.category,
                       t.attack_ids, t.tactics, t.confidence, t.rationale, t.model
                FROM ttp_extracted t
                JOIN kb_docs d ON d.id = t.doc_id
                WHERE t.model = ? AND t.attack_ids LIKE ?
                ORDER BY t.confidence DESC, d.id
                """,
                (model, f"%{attack_id}%"),
            ).fetchall()
        else:
            rows = db.execute(
                """
                SELECT d.slug, d.title, d.blog_url, d.category,
                       t.attack_ids, t.tactics, t.confidence, t.rationale, t.model
                FROM ttp_extracted t
                JOIN kb_docs d ON d.id = t.doc_id
                WHERE t.attack_ids LIKE ?
                ORDER BY t.confidence DESC, d.id
                """,
                (f"%{attack_id}%",),
            ).fetchall()
    result = []
    for r in rows:
        d = dict(r)
        for k in ("attack_ids", "tactics"):
            try:
                d[k] = json.loads(d[k] or "[]")
            except Exception:
                d[k] = []
        if attack_id in d["attack_ids"]:  # exact membership check after JSON parse
            result.append(d)
    return result


def get_kb_ttp_extracted_docs(model: str) -> list[dict]:
    """Return (id, slug, src_path, extracted_at, title, category) for docs
    that have a ttp_extracted row under this model - used to detect stale sources."""
    with _conn() as db:
        rows = db.execute(
            """
            SELECT d.id, d.slug, d.src_path, d.title, d.category, d.attack_ids,
                   t.extracted_at
            FROM kb_docs d
            JOIN ttp_extracted t ON t.doc_id = d.id
            WHERE t.model = ?
            """,
            (model,),
        ).fetchall()
    result = []
    for r in rows:
        d = dict(r)
        try:
            d["attack_ids"] = json.loads(d["attack_ids"] or "[]")
        except Exception:
            d["attack_ids"] = []
        result.append(d)
    return result


def count_ttp_extracted(model: str | None = None) -> int:
    with _conn() as db:
        if model:
            return db.execute(
                "SELECT COUNT(*) FROM ttp_extracted WHERE model = ?", (model,)
            ).fetchone()[0]
        return db.execute("SELECT COUNT(*) FROM ttp_extracted").fetchone()[0]


def get_kb_embeddings_all(model: str = "nomic-embed-text") -> list[dict]:
    """Return all (slug, vector) pairs for the given model - used by chatbot RAG."""
    with _conn() as db:
        rows = db.execute(
            """
            SELECT d.slug, d.title, d.date, d.blog_url, d.category, d.attack_ids,
                   d.source_type, e.vector
            FROM kb_embeddings e
            JOIN kb_docs d ON d.id = e.doc_id
            WHERE e.model = ?
            ORDER BY d.id
            """,
            (model,),
        ).fetchall()
    result = []
    for r in rows:
        d = dict(r)
        try:
            d["attack_ids"] = json.loads(d["attack_ids"] or "[]")
        except Exception:
            d["attack_ids"] = []
        try:
            d["vector"] = json.loads(d["vector"] or "[]")
        except Exception:
            d["vector"] = []
        result.append(d)
    return result


# --------------------------------------------------------------------------- #
#  Session Summaries (written by worker.py apt, read by APT panel)             #
# --------------------------------------------------------------------------- #

def get_sessions_without_summary(model: str) -> list[dict]:
    with _conn() as db:
        rows = db.execute(
            """
            SELECT session_id, actor_id, ttps, params, started, finished, status
            FROM pipeline_sessions
            WHERE status = 'success'
              AND session_id NOT IN (
                  SELECT session_id FROM session_summaries WHERE model = ?
              )
            ORDER BY started DESC
            """,
            (model,),
        ).fetchall()
    result = []
    for r in rows:
        d = dict(r)
        try:
            d["ttps"] = json.loads(d["ttps"] or "[]")
        except Exception:
            d["ttps"] = []
        try:
            d["params"] = json.loads(d["params"] or "{}")
        except Exception:
            d["params"] = {}
        result.append(d)
    return result


def upsert_session_summary(session_id: str, model: str, summary: str, raw_output: str = "") -> None:
    with _conn() as db:
        db.execute(
            """
            INSERT INTO session_summaries (session_id, model, summary, raw_output, summarized_at)
            VALUES (?, ?, ?, ?, datetime('now'))
            ON CONFLICT(session_id, model) DO UPDATE SET
                summary=excluded.summary,
                raw_output=excluded.raw_output,
                summarized_at=excluded.summarized_at
            """,
            (session_id, model, summary, raw_output),
        )


def get_session_summary(session_id: str, model: str | None = None) -> str:
    with _conn() as db:
        if model:
            row = db.execute(
                "SELECT summary FROM session_summaries WHERE session_id=? AND model=? LIMIT 1",
                (session_id, model),
            ).fetchone()
        else:
            row = db.execute(
                "SELECT summary FROM session_summaries WHERE session_id=? ORDER BY summarized_at DESC LIMIT 1",
                (session_id,),
            ).fetchone()
    return (row["summary"] or "") if row else ""


def count_session_summaries(model: str | None = None) -> int:
    with _conn() as db:
        if model:
            return db.execute(
                "SELECT COUNT(*) FROM session_summaries WHERE model=?", (model,)
            ).fetchone()[0]
        return db.execute("SELECT COUNT(*) FROM session_summaries").fetchone()[0]


# --------------------------------------------------------------------------- #
#  Actor Summaries (written by worker.py actor, read by Malpedia panel)        #
# --------------------------------------------------------------------------- #

def get_actor_ids_without_summary(actor_ids: list[str], model: str) -> list[str]:
    if not actor_ids:
        return []
    with _conn() as db:
        done = {
            r[0] for r in db.execute(
                "SELECT actor_id FROM actor_summaries WHERE model=?", (model,)
            ).fetchall()
        }
    return [a for a in actor_ids if a not in done]


def upsert_actor_summary(actor_id: str, model: str, summary: str, raw_output: str = "") -> None:
    with _conn() as db:
        db.execute(
            """
            INSERT INTO actor_summaries (actor_id, model, summary, raw_output, summarized_at)
            VALUES (?, ?, ?, ?, datetime('now'))
            ON CONFLICT(actor_id, model) DO UPDATE SET
                summary=excluded.summary,
                raw_output=excluded.raw_output,
                summarized_at=excluded.summarized_at
            """,
            (actor_id, model, summary, raw_output),
        )


def get_actor_summary(actor_id: str, model: str | None = None) -> str:
    with _conn() as db:
        if model:
            row = db.execute(
                "SELECT summary FROM actor_summaries WHERE actor_id=? AND model=? LIMIT 1",
                (actor_id, model),
            ).fetchone()
        else:
            row = db.execute(
                "SELECT summary FROM actor_summaries WHERE actor_id=? ORDER BY summarized_at DESC LIMIT 1",
                (actor_id,),
            ).fetchone()
    return (row["summary"] or "") if row else ""


def count_actor_summaries(model: str | None = None) -> int:
    with _conn() as db:
        if model:
            return db.execute(
                "SELECT COUNT(*) FROM actor_summaries WHERE model=?", (model,)
            ).fetchone()[0]
        return db.execute("SELECT COUNT(*) FROM actor_summaries").fetchone()[0]


# --------------------------------------------------------------------------- #
#  Family Summaries (written by worker.py family, read by Malpedia panel)      #
# --------------------------------------------------------------------------- #

def get_family_ids_without_summary(family_ids: list[str], model: str) -> list[str]:
    if not family_ids:
        return []
    with _conn() as db:
        done = {
            r[0] for r in db.execute(
                "SELECT family_id FROM family_summaries WHERE model=?", (model,)
            ).fetchall()
        }
    return [f for f in family_ids if f not in done]


def upsert_family_summary(family_id: str, model: str, summary: str, raw_output: str = "") -> None:
    with _conn() as db:
        db.execute(
            """
            INSERT INTO family_summaries (family_id, model, summary, raw_output, summarized_at)
            VALUES (?, ?, ?, ?, datetime('now'))
            ON CONFLICT(family_id, model) DO UPDATE SET
                summary=excluded.summary,
                raw_output=excluded.raw_output,
                summarized_at=excluded.summarized_at
            """,
            (family_id, model, summary, raw_output),
        )


def get_family_summary(family_id: str, model: str | None = None) -> str:
    with _conn() as db:
        if model:
            row = db.execute(
                "SELECT summary FROM family_summaries WHERE family_id=? AND model=? LIMIT 1",
                (family_id, model),
            ).fetchone()
        else:
            row = db.execute(
                "SELECT summary FROM family_summaries WHERE family_id=? ORDER BY summarized_at DESC LIMIT 1",
                (family_id,),
            ).fetchone()
    return (row["summary"] or "") if row else ""


def count_family_summaries(model: str | None = None) -> int:
    with _conn() as db:
        if model:
            return db.execute(
                "SELECT COUNT(*) FROM family_summaries WHERE model=?", (model,)
            ).fetchone()[0]
        return db.execute("SELECT COUNT(*) FROM family_summaries").fetchone()[0]
