from __future__ import annotations

import json
import os
import sqlite3
import subprocess
import sys
import tempfile
import unittest
from contextlib import closing
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
CLI = ROOT / "peekaboo_cli.py"


def run_cli(*args: str, columns: int = 100,
            extra_env: dict[str, str] | None = None) -> subprocess.CompletedProcess[str]:
    env = os.environ.copy()
    for name in ("PEEKABOO_DB_PATH", "PEEKABOO_SAMPLES_DIR", "PEEKABOO_PIPELINE_DIR",
                 "PEEKABOO_BUILD_ARTIFACTS_DIR"):
        env.pop(name, None)
    env.update(COLUMNS=str(columns), NO_COLOR="1", PYTHONDONTWRITEBYTECODE="1")
    env.update(extra_env or {})
    return subprocess.run(
        [sys.executable, str(CLI), *args],
        cwd=ROOT,
        env=env,
        text=True,
        capture_output=True,
        timeout=20,
    )


class CliContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.runtime = tempfile.TemporaryDirectory()
        cls.runtime_path = Path(cls.runtime.name)
        cls.db_path = cls.runtime_path / "peekaboo.db"
        cls.samples_path = cls.runtime_path / "samples"
        cls.samples_path.mkdir()
        env = os.environ.copy()
        env.update(PEEKABOO_DB_PATH=str(cls.db_path), PYTHONDONTWRITEBYTECODE="1")
        initialized = subprocess.run(
            [sys.executable, "-c",
             "import sys; sys.path.insert(0, 'dashboard'); import db; db.init()"],
            cwd=ROOT, env=env, text=True, capture_output=True, timeout=10,
        )
        if initialized.returncode:
            raise RuntimeError(initialized.stderr)
        with closing(sqlite3.connect(cls.db_path)) as conn:
            conn.executemany("INSERT INTO artifact_map(tid) VALUES (?)", [("T1055",), ("T1027",)])
            conn.execute("INSERT INTO mitre_library(slug) VALUES ('test-module')")
            conn.execute(
                "INSERT INTO ttp_implementations(attack_id, blog_slug) VALUES ('T1055', 'test-module')"
            )
            conn.execute("INSERT INTO report_ttps(tid) VALUES ('T1055')")

            for sid, actor, tid, module, coverage in (
                ("aaaaaaaa", "apt-test-a", "T1055", "malware-injection-21", 100),
                ("bbbbbbbb", "apt-test-b", "T1027", "malware-cryptography-22", 0),
            ):
                stage = {
                    "stage_num": 1, "ttp_id": tid, "ttp_name": "Technique",
                    "tactic": "defense-evasion", "module_slug": module,
                    "blog_url": f"https://example.test/{module}",
                    "report_url": "https://example.test/report",
                    "evidence": "Report evidence.", "_out_bin": "sample.exe",
                    "detection": {"covered": bool(coverage), "sigma_count": int(bool(coverage))},
                }
                params = {
                    "stages": [stage],
                    "report_sources": [{"url": "https://example.test/report"}],
                    "detection": {"coverage_pct": coverage, "stages_total": 1,
                                  "gaps": [] if coverage else [tid]},
                }
                conn.execute(
                    "INSERT INTO pipeline_sessions VALUES (?, ?, ?, ?, ?, ?, ?)",
                    (sid, actor, "2026-01-01", "2026-01-01", "success", "[]", json.dumps(params)),
                )
                sample_dir = cls.samples_path / sid
                sample_dir.mkdir()
                (sample_dir / "sample.exe").write_bytes(b"MZtest")
            conn.commit()

    @classmethod
    def tearDownClass(cls) -> None:
        cls.runtime.cleanup()

    def test_json_is_raw_and_global_flag_works_in_both_positions(self) -> None:
        for args in (("--json", "--offline", "status"),
                     ("status", "--json", "--offline")):
            result = run_cli(*args, columns=40)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertNotIn("\x1b[", result.stdout)
            payload = json.loads(result.stdout)
            self.assertIn("docs", payload)

    def test_auto_color_is_disabled_for_captured_output(self) -> None:
        result = run_cli("pipeline", "list")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertNotIn("\x1b[", result.stdout)

        forced = run_cli("--color", "always", "pipeline", "list")
        self.assertEqual(forced.returncode, 0, forced.stderr)
        self.assertIn("\x1b[", forced.stdout)

    def test_compact_campaign_list_does_not_wrap(self) -> None:
        result = run_cli("--color", "never", "pipeline", "list", columns=60)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertLessEqual(max(map(len, result.stdout.splitlines())), 60)

    def test_rich_markup_from_data_is_escaped(self) -> None:
        code = (
            "import peekaboo_cli as c; "
            "c._configure_console('never'); "
            "c._row(c._cell('[/] [bold red]owned', 24, 'nav'))"
        )
        env = os.environ.copy()
        env["PYTHONDONTWRITEBYTECODE"] = "1"
        result = subprocess.run(
            [sys.executable, "-c", code], cwd=ROOT, env=env,
            text=True, capture_output=True, timeout=10,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("[/] [bold red]owned", result.stdout)

    def test_closed_pipe_is_successful(self) -> None:
        command = (
            "set -o pipefail; "
            f"{sys.executable} {CLI} pipeline list | head -n 1 >/dev/null"
        )
        env = os.environ.copy()
        for name in ("PEEKABOO_DB_PATH", "PEEKABOO_SAMPLES_DIR", "PEEKABOO_PIPELINE_DIR",
                     "PEEKABOO_BUILD_ARTIFACTS_DIR"):
            env.pop(name, None)
        env["PYTHONDONTWRITEBYTECODE"] = "1"
        result = subprocess.run(
            ["bash", "-c", command], cwd=ROOT, env=env, text=True,
            capture_output=True, timeout=10,
        )
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_bare_commands_do_not_raise_tracebacks(self) -> None:
        for command in ("library", "malpedia", "ttp", "artifacts", "builder",
                        "yara", "vtscan", "shellcode", "pipeline", "doctor"):
            result = run_cli("--offline", command)
            self.assertNotIn("Traceback", result.stderr)
            self.assertIn(result.returncode, (0, 1), (command, result.stderr))

    def test_doctor_verifies_seeded_demo_files_without_network(self) -> None:
        result = run_cli(
            "--db", str(self.db_path), "--offline", "doctor", "--demo", "--json",
            extra_env={"PEEKABOO_SAMPLES_DIR": str(self.samples_path)},
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        payload = json.loads(result.stdout)
        self.assertTrue(payload["ready"])
        self.assertFalse([check for check in payload["checks"] if check["level"] == "fail"])

    def test_campaign_views_diff_and_navigator_export(self) -> None:
        common = ("--db", str(self.db_path), "--offline")
        shown = run_cli(*common, "pipeline", "show", "aaaa", "--view", "evidence", "--json")
        self.assertEqual(shown.returncode, 0, shown.stderr)
        self.assertEqual(json.loads(shown.stdout)["session"], "aaaaaaaa")

        diff = run_cli(*common, "pipeline", "diff", "aaaa", "bbbb", "--json")
        self.assertEqual(diff.returncode, 0, diff.stderr)
        payload = json.loads(diff.stdout)
        self.assertEqual(payload["coverage"]["delta"], -100)
        self.assertEqual(payload["added"][0]["ttp_id"], "T1027")

        exported = run_cli(*common, "pipeline", "export", "aaaa", "--format", "navigator")
        self.assertEqual(exported.returncode, 0, exported.stderr)
        layer = json.loads(exported.stdout)
        self.assertEqual(layer["versions"]["layer"], "4.5")
        self.assertEqual(layer["domain"], "enterprise-attack")
        self.assertEqual(layer["techniques"][0]["techniqueID"], "T1055")

    def test_shellcode_analyse_and_convert_binary_or_stdin(self) -> None:
        payload_path = self.runtime_path / "payload.bin"
        payload_path.write_bytes(b"\xfc\x48\x83\xe4")
        analysed = run_cli("shellcode", "analyse", str(payload_path), "--json")
        self.assertEqual(analysed.returncode, 0, analysed.stderr)
        analysis = json.loads(analysed.stdout)
        self.assertEqual((analysis["size"], analysis["arch"]), (4, "x64"))

        env = os.environ.copy()
        env.update(NO_COLOR="1", PYTHONDONTWRITEBYTECODE="1")
        converted = subprocess.run(
            [sys.executable, str(CLI), "shellcode", "convert", "-", "--to", "python"],
            cwd=ROOT, env=env, input="fc4883e4", text=True,
            capture_output=True, timeout=10,
        )
        self.assertEqual(converted.returncode, 0, converted.stderr)
        self.assertIn('buf = b"\\xfc\\x48\\x83\\xe4"', converted.stdout)

        bad_output = run_cli(
            "shellcode", "convert", str(payload_path),
            "--output", str(self.runtime_path / "missing" / "payload.c"),
        )
        self.assertEqual(bad_output.returncode, 1)
        self.assertNotIn("Traceback", bad_output.stderr)

    def test_offline_blocks_network_commands(self) -> None:
        result = run_cli("--offline", "vtscan", "lookup", "deadbeef", "--json")
        self.assertEqual(result.returncode, 1)
        self.assertIn("offline mode blocks", json.loads(result.stdout)["error"])

    def test_non_interactive_vt_upload_requires_explicit_consent(self) -> None:
        payload_path = self.runtime_path / "upload.exe"
        payload_path.write_bytes(b"MZtest")
        result = run_cli("vtscan", "scan-file", str(payload_path), "--color", "never")
        self.assertEqual(result.returncode, 1)
        self.assertIn("requires --yes", result.stderr)

    def test_tui_requires_an_interactive_terminal(self) -> None:
        result = run_cli("tui")
        self.assertEqual(result.returncode, 1)
        self.assertIn("requires an interactive terminal", result.stderr)
        self.assertNotIn("Traceback", result.stderr)


if __name__ == "__main__":
    unittest.main()
