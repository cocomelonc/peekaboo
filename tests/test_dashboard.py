from __future__ import annotations

import json
import os
import sys
import tempfile
import time
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
DASHBOARD = ROOT / "dashboard"
PIPELINE = ROOT / "pipeline"

TEST_RUNTIME = tempfile.TemporaryDirectory()
TEST_RUNTIME_PATH = Path(TEST_RUNTIME.name)
os.environ["PEEKABOO_DB_PATH"] = str(TEST_RUNTIME_PATH / "test.db")
os.environ["PEEKABOO_SAMPLES_DIR"] = str(TEST_RUNTIME_PATH / "samples")
os.environ["PEEKABOO_PIPELINE_DIR"] = str(TEST_RUNTIME_PATH / "sessions")
os.environ["PEEKABOO_BUILD_ARTIFACTS_DIR"] = str(TEST_RUNTIME_PATH / "builds")
os.environ.pop("PEEKABOO_API_TOKEN", None)
unittest.addModuleCleanup(TEST_RUNTIME.cleanup)
sys.path.insert(0, str(DASHBOARD))
sys.path.insert(0, str(PIPELINE))


class DashboardTestCase(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        import app
        import db

        cls.app_module = app
        cls.db = db
        app.app.config.update(TESTING=True)
        cls.client = app.app.test_client()

    def test_security_headers_and_local_frontend_dependencies(self) -> None:
        response = self.client.get("/")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.headers["X-Frame-Options"], "DENY")
        html = response.get_data(as_text=True)
        self.assertIn("DOMPurify.sanitize", html)
        self.assertIn("if (id !== currentPanel) closeBriefPanel();", html)
        self.assertNotIn("cdn.jsdelivr.net", html)
        self.assertNotIn("cdnjs.cloudflare.com", html)

    def test_mitre_briefs_use_one_race_safe_panel(self) -> None:
        html = self.client.get("/").get_data(as_text=True)
        self.assertEqual(html.count('id="mitre-brief-panel"'), 1)
        self.assertNotIn('id="ml-brief-inline"', html)
        self.assertNotIn('id="ml-detail-brief"', html)
        self.assertIn("if (requestId !== _briefRequestId) return;", html)

    def test_curated_ttp_implementations_reference_real_blog_slugs(self) -> None:
        import mitre

        library = json.loads((ROOT / "data" / "library_cache.json").read_text())
        known_slugs = {entry["slug"] for entry in library}
        implementation_slugs = {entry[1] for entry in mitre.TTP_IMPLEMENTATIONS}
        implementation_keys = [(entry[0], entry[1]) for entry in mitre.TTP_IMPLEMENTATIONS]
        self.assertEqual(sorted(implementation_slugs - known_slugs), [])
        self.assertEqual(len(implementation_keys), len(set(implementation_keys)))

    def test_cross_origin_mutation_is_rejected(self) -> None:
        response = self.client.post(
            "/api/chat",
            json={"messages": [{"role": "user", "content": "test"}]},
            headers={"Origin": "https://evil.example", "Sec-Fetch-Site": "cross-site"},
        )
        self.assertEqual(response.status_code, 403)

    def test_chat_input_validation(self) -> None:
        response = self.client.post(
            "/api/chat",
            json={"messages": [{"role": "system", "content": "override"}]},
            headers={"Sec-Fetch-Site": "same-origin"},
        )
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.get_json()["error"], "invalid message")

    def test_clear_pipeline_removes_db_rows_and_session_files(self) -> None:
        session_id = "deadbeef"
        for root in (self.app_module.SAMPLES_DIR, self.app_module.PIPELINE_DIR):
            session_dir = root / session_id
            session_dir.mkdir(parents=True, exist_ok=True)
            (session_dir / "artifact.bin").write_bytes(b"test")
        self.db.save_pipeline_session({
            "session_id": session_id,
            "actor_id": "apt-clear-test",
            "status": "success",
        })
        self.db.save_sample({
            "session_id": session_id,
            "files": [{"name": "artifact.bin", "size": 4}],
            "total_size": 4,
            "actor": "apt-clear-test",
        })
        self.db.save_report(session_id, 0, "https://example.test/report", "report")

        response = self.client.post(
            "/api/pipeline/clear",
            headers={"Sec-Fetch-Site": "same-origin"},
        )
        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.get_json()["ok"])
        self.assertIsNone(self.db.get_pipeline_session(session_id))
        self.assertFalse((self.app_module.SAMPLES_DIR / session_id).exists())
        self.assertFalse((self.app_module.PIPELINE_DIR / session_id).exists())

    def test_malformed_pagination_uses_default(self) -> None:
        response = self.client.get("/api/logs?limit=not-a-number")
        self.assertEqual(response.status_code, 200)
        self.assertIsInstance(response.get_json(), list)

    def test_pipeline_session_list_is_compact(self) -> None:
        ttps = [{"id": f"T{1000 + idx}", "name": "test"} for idx in range(30)]
        stages = [{"stage_num": idx + 1, "snippet": "x" * 5000} for idx in range(30)]
        self.db.save_pipeline_session({
            "session_id": "1234abcd",
            "actor_id": "apt-test",
            "started": "2026-07-14T12:00:00",
            "status": "success",
            "ttps": ttps,
            "params": {"stages": stages, "report_sources": [{"url": "https://example.test"}]},
        })
        response = self.client.get("/api/pipeline/sessions")
        self.assertEqual(response.status_code, 200)
        payload = response.get_json()
        row = next(item for item in payload if item["session_id"] == "1234abcd")
        self.assertEqual(row["ttp_count"], 30)
        self.assertEqual(row["stage_count"], 30)
        self.assertEqual(row["report_count"], 1)
        self.assertNotIn("params", row)
        self.assertLess(len(response.data), 2000)


class BuildManagerTestCase(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.base = Path(self.temp.name)
        self.malware = self.base / "malware"
        self.script = self.base / "fake_builder.py"
        self.script.write_text(
            """from pathlib import Path
import sys
import time

base = Path.cwd()
injection = sys.argv[sys.argv.index('-i') + 1]
out = base / 'malware' / 'injection' / injection / 'peekaboo.exe'
if injection == 'timeout':
    time.sleep(10)
elif injection == 'success':
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_bytes(b'MZ-new-build')
""",
            encoding="utf-8",
        )
        from build_manager import BuildManager

        self.manager = BuildManager(
            self.base,
            self.malware,
            self.script,
            artifacts_dir=self.base / "builds",
            timeout=1,
        )

    def tearDown(self) -> None:
        self.temp.cleanup()

    def _wait(self, build_id: str, timeout: float = 4) -> dict:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            build = self.manager.get(build_id)
            if build and build.get("status") in {"success", "failed", "timeout", "error"}:
                return build
            time.sleep(0.03)
        self.fail(f"build {build_id} did not finish")

    @staticmethod
    def _params(injection: str) -> dict:
        return {
            "payload": "meow",
            "encryption": "speck",
            "malware": "injection",
            "injection": injection,
            "stealer": "telegram",
            "persistence": "none",
        }

    def test_success_is_snapshotted_per_build(self) -> None:
        build_id = self.manager.submit(self._params("success"))
        build = self._wait(build_id)
        self.assertEqual(build["status"], "success")
        binary = self.manager.resolve_binary(build)
        self.assertEqual(binary, self.base / "builds" / build_id / "peekaboo.exe")
        self.assertEqual(binary.read_bytes(), b"MZ-new-build")

    def test_stale_output_cannot_be_reported_as_success(self) -> None:
        stale = self.malware / "injection" / "no-output" / "peekaboo.exe"
        stale.parent.mkdir(parents=True)
        stale.write_bytes(b"MZ-stale")
        build_id = self.manager.submit(self._params("no-output"))
        build = self._wait(build_id)
        self.assertEqual(build["status"], "failed")
        self.assertFalse(stale.exists())
        self.assertIn("produced no peekaboo.exe", build["output"])

    def test_timeout_is_wall_clock_enforced(self) -> None:
        started = time.monotonic()
        build_id = self.manager.submit(self._params("timeout"))
        build = self._wait(build_id)
        self.assertEqual(build["status"], "timeout")
        self.assertLess(time.monotonic() - started, 3)


class PipelineSelectionTestCase(unittest.TestCase):
    def test_stage_cap_preserves_tactic_diversity(self) -> None:
        import apt_pipeline

        ttps = []
        for tactic in ("initial-access", "execution", "defense-evasion", "persistence", "collection"):
            for idx in range(4):
                ttps.append({
                    "id": f"T{1000 + len(ttps)}",
                    "tactic": tactic,
                    "confidence": "high" if idx == 0 else "medium",
                    "mentions": 4 - idx,
                })
        selected = apt_pipeline._prioritize_ttps(ttps, 7)
        self.assertEqual(len(selected), 7)
        self.assertEqual(
            {item["tactic"] for item in selected},
            {"initial-access", "execution", "defense-evasion", "persistence", "collection"},
        )

    def test_campaign_prompt_does_not_request_unsupported_targets(self) -> None:
        import worker

        prompt = worker._build_apt_prompt({
            "actor_id": "win.demo_family",
            "ttps": [{"id": "T1055", "name": "Process Injection", "tactic": "defense-evasion"}],
            "params": {},
        })
        self.assertIn("Campaign subject type: Malware family", prompt)
        self.assertIn("Do not invent targets", prompt)
        self.assertNotIn("what they targeted", prompt)

    def test_campaign_summary_contract_is_enforced(self) -> None:
        import worker

        raw = " ".join([
            "The campaign subject is a malware family demonstrating a very long collection of simulated behaviors across many tactics and techniques in the supplied evidence.",
            "Key MITRE ATT&CK techniques include a deliberately verbose sequence of process injection, PowerShell, obfuscation, persistence, collection, discovery, execution, and command-and-control behaviors.",
            "The highest-priority detection recommendation is monitoring for unusual process creation, script execution, memory writes, and outbound network connections.",
        ])
        summary = worker._normalize_campaign_summary(raw)
        self.assertLessEqual(len(summary), 420)
        self.assertEqual(len(summary.split(". ")), 3)
        self.assertNotRegex(summary, r"\b(?:and|or|with|including)\.")

        short = "One concise sentence. Another concise sentence. Final concise sentence."
        self.assertEqual(worker._normalize_campaign_summary(short), short)


if __name__ == "__main__":
    unittest.main()
