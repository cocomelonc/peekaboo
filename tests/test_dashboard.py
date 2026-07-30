from __future__ import annotations

import json
import os
import sys
import tempfile
import time
import unittest
from argparse import Namespace
from pathlib import Path
from unittest.mock import patch


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
sys.path.insert(0, str(DASHBOARD))
sys.path.insert(0, str(PIPELINE))


def tearDownModule() -> None:
    TEST_RUNTIME.cleanup()


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

    def test_campaign_graph_is_local_and_demo_ready(self) -> None:
        html = self.client.get("/").get_data(as_text=True)
        graph_runtime = ROOT / "dashboard" / "static" / "vendor" / "cytoscape-3.34.0"

        self.assertTrue((graph_runtime / "cytoscape.min.js").is_file())
        self.assertTrue((graph_runtime / "LICENSE").is_file())
        self.assertIn("vendor/cytoscape-3.34.0/cytoscape.min.js", html)
        self.assertLess(html.index('id="dtab-graph"'), html.index('id="dtab-reports"'))
        self.assertIn("function campaignGraphElements", html)
        self.assertIn("setCampaignGraphMode('campaign')", html)
        self.assertIn("setCampaignGraphMode('hunt')", html)
        self.assertIn("setCampaignGraphMode('evidence')", html)
        self.assertIn("prefers-reduced-motion: reduce", html)
        self.assertIn("requestFullscreen", html)
        self.assertNotIn("unpkg.com/cytoscape", html)

    def test_campaign_graph_metadata_round_trips_through_session_api(self) -> None:
        stage = {
            "stage_num": 1,
            "ttp_id": "T1055",
            "ttp_name": "Process Injection",
            "tactic": "defense-evasion",
            "evidence": "The report describes process injection.",
            "report_url": "https://example.test/report",
            "blog_url": "https://example.test/implementation",
            "module_slug": "malware-injection-21",
            "_out_src": "stage.c",
            "_out_bin": "stage.exe",
            "detection": {
                "covered": True,
                "sigma_count": 3,
                "event_ids": ["1", "10"],
            },
        }
        self.db.save_pipeline_session({
            "session_id": "feedcafe",
            "actor_id": "apt-graph-test",
            "started": "2026-07-15T12:00:00",
            "status": "success",
            "ttps": [{"id": "T1055", "name": "Process Injection"}],
            "params": {
                "stages": [stage],
                "detection": {"coverage_pct": 100, "stages_total": 1},
                "report_sources": [{"url": "https://example.test/report"}],
            },
        })

        response = self.client.get("/api/pipeline/session/feedcafe")
        self.assertEqual(response.status_code, 200)
        payload = response.get_json()
        stored = payload["session"]["params"]["stages"][0]
        self.assertEqual(stored["ttp_id"], "T1055")
        self.assertEqual(stored["detection"]["event_ids"], ["1", "10"])
        self.assertEqual(stored["module_slug"], "malware-injection-21")
        self.assertEqual(payload["report_sources"][0]["url"], "https://example.test/report")

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

        t1055 = self.db.get_ttp_implementations(attack_id="T1055")
        t1546 = self.db.get_ttp_implementations(attack_id="T1546")
        self.assertTrue(any(
            row["blog_slug"] == "malware-tricks-61"
            and row["tactic"] == "defense-evasion"
            and row["tech_name"] == "Process Injection"
            for row in t1055
        ))
        self.assertTrue(any(
            row["blog_slug"] == "mac-malware-persistence-12"
            and row["tactic"] == "persistence"
            and row["tech_name"] == "Event Triggered Execution"
            for row in t1546
        ))

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


class MitreSourceDiscoveryTestCase(unittest.TestCase):
    def test_python_source_is_discovered_after_native_sources(self) -> None:
        import mitre

        with tempfile.TemporaryDirectory() as temp:
            previous_root = mitre._MEOW
            try:
                mitre._MEOW = Path(temp)
                article = Path(temp) / "2026-07-25-malware-analysis-11"
                article.mkdir()
                python_source = article / "bin_gpt.py"
                python_source.write_text("print('test')\n", encoding="utf-8")
                self.assertEqual(mitre._find_meow_source("2026-07-25"), str(python_source))

                c_source = article / "hack.c"
                c_source.write_text("int main(void) { return 0; }\n", encoding="utf-8")
                self.assertEqual(mitre._find_meow_source("2026-07-25"), str(c_source))
            finally:
                mitre._MEOW = previous_root

    def test_external_blog_source_override_is_discovered(self) -> None:
        import mitre

        with tempfile.TemporaryDirectory() as temp:
            previous_root = mitre._RESEARCH_ROOT
            try:
                mitre._RESEARCH_ROOT = Path(temp)
                project = Path(temp) / "tiny-shamir"
                project.mkdir()
                source = project / "tiny_shamir.c"
                source.write_text("int main(void) { return 0; }\n", encoding="utf-8")
                self.assertEqual(
                    mitre._find_meow_source("2026-07-02", "malware-cryptography-45"),
                    str(source),
                )
            finally:
                mitre._RESEARCH_ROOT = previous_root

    def test_editorial_attack_overrides_replace_incidental_links(self) -> None:
        import mitre

        self.assertEqual(mitre.BLOG_ATTACK_OVERRIDES["malware-tricks-59"], ("T1055",))
        self.assertEqual(mitre.BLOG_ATTACK_OVERRIDES["malware-tricks-60"], ("T1055",))
        self.assertEqual(mitre.BLOG_ATTACK_OVERRIDES["malware-tricks-61"], ("T1055",))
        self.assertEqual(mitre.BLOG_ATTACK_OVERRIDES["mac-malware-persistence-12"], ("T1546",))
        self.assertEqual(mitre.BLOG_ATTACK_OVERRIDES["malware-cryptography-45"], ("T1027.013",))
        self.assertEqual(mitre.category_for_attack_ids(["T1055"], "tricks"), "injection")
        self.assertEqual(set(mitre.BLOG_SUMMARY_OVERRIDES), {
            "malware-analysis-9",
            "mac-malware-persistence-12",
            "ddos-wavelet-detection-1",
            "ddos-wavelet-detection-2",
            "malware-tricks-59",
            "malware-analysis-10",
            "ddos-syn-flood-detection-1",
            "malware-cryptography-45",
            "malware-tricks-60",
            "malware-analysis-11",
            "malware-tricks-61",
        })
        for summary in mitre.BLOG_SUMMARY_OVERRIDES.values():
            self.assertLessEqual(len(summary), 420)
            self.assertEqual(len(summary.split(". ")), 3)

    def test_portable_source_uses_declared_blog_platform(self) -> None:
        import discovery

        self.assertEqual(discovery._declared_platform(["malware", "linux", "c"]), "linux")
        self.assertEqual(discovery._declared_platform(["macos", "malware"]), "macos")
        self.assertFalse(discovery._has_windows_markers("#include <stdio.h>"))
        self.assertTrue(discovery._has_windows_markers("#include <windows.h>"))

    def test_ttp_seed_uses_artifact_fallback_without_stix_dependency(self) -> None:
        import db
        import mitre

        artifacts = [
            {"tid": "T1055", "name": "Process Injection", "tactic": "execution,defense-evasion"},
            {"tid": "T1546", "name": "Event Triggered Execution", "tactic": "privilege-escalation"},
        ]
        with (
            patch.object(mitre, "_build_tech_lookup", return_value={}),
            patch.object(db, "get_artifact_entries", return_value=artifacts),
            patch.object(db, "get_mitre_entries", return_value=[]),
            patch.object(db, "upsert_ttp_implementations", return_value=145) as upsert,
        ):
            self.assertEqual(mitre.seed_ttp_implementations(), 145)

        entries = upsert.call_args.args[0]
        process_injection = next(
            row for row in entries
            if row["attack_id"] == "T1055" and row["blog_slug"] == "malware-tricks-61"
        )
        folder_actions = next(
            row for row in entries
            if row["attack_id"] == "T1546"
            and row["blog_slug"] == "mac-malware-persistence-12"
        )
        self.assertEqual(process_injection["tech_name"], "Process Injection")
        self.assertEqual(process_injection["tactic"], "defense-evasion")
        self.assertEqual(folder_actions["tech_name"], "Event Triggered Execution")
        self.assertEqual(folder_actions["tactic"], "persistence")


class WorkerInitTestCase(unittest.TestCase):
    def test_init_updates_library_and_enrichment_docs_from_one_cache(self) -> None:
        import worker

        entries = [
            {
                "slug": "new-research",
                "title": "New research",
                "date": "2026-07-29",
                "category": "tricks",
                "attack_ids": [],
                "src_path": "/tmp/hack.c",
            }
        ]
        with tempfile.TemporaryDirectory() as temp:
            cache = Path(temp) / "library_cache.json"
            cache.write_text(json.dumps(entries), encoding="utf-8")
            with (
                patch.object(worker, "_LIB_CACHE", cache),
                patch.object(worker.db, "init"),
                patch.object(worker.db, "save_mitre_entries") as save_library,
                patch.object(worker.db, "upsert_kb_doc") as upsert_doc,
                patch.object(worker.db, "kb_stats", return_value={"docs": 1}),
            ):
                worker.cmd_init(Namespace())

        save_library.assert_called_once_with(entries)
        self.assertEqual(upsert_doc.call_count, 1)


class CompilerDependencyTestCase(unittest.TestCase):
    def test_math_library_is_inferred_for_portable_c(self) -> None:
        import compiler
        import discovery

        source = "#include <math.h>\ndouble score(double x) { return log1p(x); }\n"
        self.assertIn("-lm", compiler._extra_libs(source))
        self.assertIn("-lm", discovery._detect_extra_libs(source))


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

    def test_kb_summary_contract_strips_markdown_and_limits_length(self) -> None:
        import worker

        raw = (
            "### Purpose\n"
            "1. A defensive detector evaluates traffic anomalies without claiming attacker behavior. "
            "2. Haar wavelets and threshold scoring identify short bursts in time-series data. "
            "3. CSV scores and plotted peaks provide grounded evaluation output for review."
        )
        summary = worker._normalize_campaign_summary(raw)
        self.assertLessEqual(len(summary), 420)
        self.assertNotIn("#", summary)
        self.assertNotRegex(summary, r"\b[123]\.\s")

    def test_ttp_normalizer_drops_unknown_attack_ids(self) -> None:
        import worker

        ids, tactics, confidence, rationale = worker._normalize_ttps(
            {
                "attack_ids": ["T1055", "T1999", "T1055.999"],
                "tactics": ["defense-evasion"],
                "confidence": "high",
                "rationale": "test",
            },
            {"T1055"},
        )
        self.assertEqual(ids, ["T1055"])
        self.assertEqual(tactics, ["defense-evasion"])
        self.assertEqual(confidence, "high")
        self.assertEqual(rationale, "test")
        self.assertEqual(
            worker._curated_attack_ids("malware-cryptography-45"),
            ["T1027.013"],
        )

    def test_defensive_docs_do_not_request_offensive_mapping(self) -> None:
        import worker

        self.assertTrue(worker._is_defensive_doc({
            "slug": "ddos-wavelet-detection-1",
            "title": "Anti-DDoS research",
            "category": "analysis",
        }))
        self.assertIn("analysis/detection goal", worker._build_summary_prompt(
            {"slug": "malware-analysis-11", "title": "Binary analysis", "category": "analysis"},
            "Evaluate a model.",
            "print('benchmark')",
        ))

    def test_document_tag_constraints_remove_semantic_noise(self) -> None:
        import worker

        defensive = worker._normalize_tags_for_doc(
            {
                "slug": "ddos-wavelet-detection-1",
                "title": "Anti-DDoS detection",
                "category": "analysis",
            },
            ["crypto", "windows", "linux", "macos", "c"],
        )
        self.assertEqual(defensive, ["analysis", "detection", "cross-platform", "c"])

        curated = worker._normalize_tags_for_doc(
            {
                "slug": "malware-tricks-61",
                "title": "Module stomping",
                "category": "injection",
            },
            ["injection", "process-hollowing", "windows", "c"],
        )
        self.assertEqual(curated, ["injection", "windows", "c"])


if __name__ == "__main__":
    unittest.main()
