import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

SCRIPTS_DIR = Path(__file__).resolve().parents[1] / "scripts"
sys.path.insert(0, str(SCRIPTS_DIR))

from evaluate import match_findings
import evaluate
import fetch_issues
import generate_fixes
import scan
from generate_fixes import _cookie_secure_fix
from security_taxonomy import classify_issue


class TaxonomyTests(unittest.TestCase):
    def test_s2092_rule_overrides_cwe_filename(self):
        category, _ = classify_issue({
            "rule": "java:S2092",
            "file": "sard_cases:test_cases/CWE113_001/src/Case.java",
            "message": "Cookie without secure flag",
        })
        self.assertEqual("cookies", category)


class FixStrategyTests(unittest.TestCase):
    def test_cookie_secure_fix_adds_setter_without_changing_constructor(self):
        original = ["        Cookie cookieSink = new Cookie(\"lang\", data);\n"]
        updated, detail = _cookie_secure_fix(original, 0)
        self.assertEqual("added Cookie.setSecure(true)", detail)
        self.assertEqual(original[0], updated[0])
        self.assertEqual("        cookieSink.setSecure(true);\n", updated[1])

    def test_llm_prompt_requires_variable_declarations_to_be_preserved(self):
        prompt = generate_fixes.build_prompt(
            {"rule": "java:S6437", "message": "Hard-coded credential"},
            "",
            'SecretKeySpec keySpec = new SecretKeySpec("secret".getBytes(), "AES");',
            'SecretKeySpec keySpec = new SecretKeySpec("secret".getBytes(), "AES");',
        )
        self.assertIn("Preserve the original statement structure", prompt)
        self.assertIn("declared or assigned variable name", prompt)

    def test_llm_prompt_is_logged_before_model_request(self):
        issue = {
            "rule": "java:S6437",
            "file": "sard_cases:test_cases/CWE259_001/src/Case.java",
            "line": 1,
            "message": "Hard-coded credential",
        }
        lines = ['String password = "hardcoded";\n']
        response = '```java\nString password = System.getenv("APP_PASSWORD");\n```'
        with (
            patch.object(generate_fixes, "ask_ollama", return_value=response),
            self.assertLogs("llm_prompts", level="INFO") as captured,
        ):
            generate_fixes.apply_llm_fix(issue, lines, 0)
        logged = "\n".join(captured.output)
        self.assertIn("PROMPT rule=java:S6437", logged)
        self.assertIn('String password = "hardcoded";', logged)

    def test_generation_modifies_only_isolated_workspace(self):
        original_values = (
            generate_fixes.TEST_CASES_DIR,
            generate_fixes.PATCHED_DIR,
            generate_fixes.PATCHED_CASES_DIR,
        )
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            baseline = root / "test_cases"
            workspace_root = root / "patched"
            source = baseline / "CWE113_001" / "src" / "Case.java"
            source.parent.mkdir(parents=True)
            original = 'Cookie cookieSink = new Cookie("lang", data);\n'
            source.write_text(original, encoding="utf-8")
            issues_path = root / "issues.json"
            results_path = root / "results.json"
            attempted_path = root / "attempted.json"
            issues_path.write_text(json.dumps([{
                "rule": "java:S2092",
                "file": "sard_cases:test_cases/CWE113_001/src/Case.java",
                "line": 1,
                "message": "Cookie without secure flag",
            }]), encoding="utf-8")
            try:
                generate_fixes.TEST_CASES_DIR = baseline
                generate_fixes.PATCHED_DIR = workspace_root
                generate_fixes.PATCHED_CASES_DIR = workspace_root / "test_cases"
                with patch.object(generate_fixes, "_validate_candidate", return_value=(True, "")):
                    generate_fixes.run(issues_path, results_path, attempted_path)
            finally:
                (
                    generate_fixes.TEST_CASES_DIR,
                    generate_fixes.PATCHED_DIR,
                    generate_fixes.PATCHED_CASES_DIR,
                ) = original_values
            patched = workspace_root / "test_cases" / "CWE113_001" / "src" / "Case.java"
            self.assertEqual(original, source.read_text(encoding="utf-8"))
            self.assertIn("cookieSink.setSecure(true);", patched.read_text(encoding="utf-8"))

    def test_non_compiling_candidate_is_reverted(self):
        original_values = (
            generate_fixes.TEST_CASES_DIR,
            generate_fixes.PATCHED_DIR,
            generate_fixes.PATCHED_CASES_DIR,
        )
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            baseline = root / "test_cases"
            workspace_root = root / "patched"
            source = baseline / "CWE319_001" / "src" / "Case.java"
            source.parent.mkdir(parents=True)
            original = 'String password = "hardcoded";\n'
            source.write_text(original, encoding="utf-8")
            issues_path = root / "issues.json"
            results_path = root / "results.json"
            attempted_path = root / "attempted.json"
            issues_path.write_text(json.dumps([{
                "rule": "java:S6437",
                "file": "sard_cases:test_cases/CWE319_001/src/Case.java",
                "line": 1,
                "message": "Credentials should not be hard-coded",
            }]), encoding="utf-8")
            replacement = ["conn2 = DriverManager.getConnection(url, user, password);\n"]
            try:
                generate_fixes.TEST_CASES_DIR = baseline
                generate_fixes.PATCHED_DIR = workspace_root
                generate_fixes.PATCHED_CASES_DIR = workspace_root / "test_cases"
                with (
                    patch.object(
                        generate_fixes,
                        "apply_llm_fix",
                        return_value=(replacement, "LLM single-statement replacement"),
                    ),
                    patch.object(
                        generate_fixes,
                        "_validate_candidate",
                        return_value=(False, "candidate did not compile: cannot find symbol"),
                    ),
                ):
                    results = generate_fixes.run(issues_path, results_path, attempted_path)
            finally:
                (
                    generate_fixes.TEST_CASES_DIR,
                    generate_fixes.PATCHED_DIR,
                    generate_fixes.PATCHED_CASES_DIR,
                ) = original_values
            patched = workspace_root / "test_cases" / "CWE319_001" / "src" / "Case.java"
            self.assertEqual("failed", results[0]["status"])
            self.assertIn("candidate did not compile", results[0]["error"])
            self.assertEqual(original, patched.read_text(encoding="utf-8"))


class EvaluationTests(unittest.TestCase):
    def test_matching_does_not_reuse_a_single_post_finding(self):
        before = [
            {"type": "VULNERABILITY", "file": "sard_cases:test_cases/A.java", "rule": "r", "line": 10},
            {"type": "VULNERABILITY", "file": "sard_cases:test_cases/A.java", "rule": "r", "line": 11},
        ]
        after = [
            {"type": "VULNERABILITY", "file": "sard_cases:patched/test_cases/A.java", "rule": "r", "line": 10},
        ]
        counts = match_findings(before, after)
        self.assertEqual(1, len(counts["remaining"]))
        self.assertEqual(1, len(counts["fixed"]))

    def test_unattempted_baseline_finding_is_not_a_regression(self):
        attempted = [
            {"type": "VULNERABILITY", "file": "sard_cases:test_cases/A.java", "rule": "r", "line": 10},
        ]
        baseline = attempted + [
            {"type": "VULNERABILITY", "file": "sard_cases:test_cases/B.java", "rule": "r", "line": 20},
        ]
        after = [
            {"type": "VULNERABILITY", "file": "sard_cases:patched/test_cases/B.java", "rule": "r", "line": 20},
        ]
        counts = match_findings(attempted, after, baseline=baseline)
        self.assertEqual(1, len(counts["fixed"]))
        self.assertEqual([], counts["new"])

    def test_post_fetch_requests_open_findings_only_from_patched_tree(self):
        original_values = evaluate.BASE_DIR, evaluate.SONAR_TOKEN
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            patched = root / "patched" / "test_cases"
            current_file = patched / "A.java"
            current_file.parent.mkdir(parents=True)
            current_file.write_text("class A {}\n", encoding="utf-8")
            issue_response = Mock()
            issue_response.json.return_value = {"issues": [
                {"component": "sard_cases:patched/test_cases/A.java", "rule": "r", "line": 1},
                {"component": "sard_cases:test_cases/Old.java", "rule": "r", "line": None},
            ]}
            hotspot_response = Mock(status_code=403)
            try:
                evaluate.BASE_DIR = root
                evaluate.SONAR_TOKEN = "token"
                with patch.object(
                    evaluate.requests, "get", side_effect=[issue_response, hotspot_response]
                ) as request:
                    findings = evaluate.fetch_current_issues(patched)
            finally:
                evaluate.BASE_DIR, evaluate.SONAR_TOKEN = original_values
        self.assertEqual(1, len(findings))
        self.assertEqual("false", request.call_args_list[0].kwargs["params"]["resolved"])


class FetchIssuesTests(unittest.TestCase):
    def test_baseline_query_requests_only_unresolved_findings(self):
        with patch.object(fetch_issues, "_paged_get", return_value=[]) as request:
            fetch_issues.fetch_vulnerabilities()
        self.assertEqual("false", request.call_args.args[1]["resolved"])

    def test_source_filter_rejects_old_and_missing_files(self):
        original_base = fetch_issues.BASE_DIR
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source_dir = root / "test_cases"
            current_file = source_dir / "A.java"
            current_file.parent.mkdir(parents=True)
            current_file.write_text("class A {}\n", encoding="utf-8")
            try:
                fetch_issues.BASE_DIR = root
                self.assertTrue(
                    fetch_issues._belongs_to_source("sard_cases:test_cases/A.java", source_dir)
                )
                self.assertFalse(
                    fetch_issues._belongs_to_source("sard_cases:test_cases/Old.java", source_dir)
                )
                self.assertFalse(
                    fetch_issues._belongs_to_source("sard_cases:patched/test_cases/A.java", source_dir)
                )
            finally:
                fetch_issues.BASE_DIR = original_base


class ConfigurationTests(unittest.TestCase):
    def test_missing_sonar_token_is_reported_without_starting_scanner(self):
        original_token = scan.SONAR_TOKEN
        try:
            scan.SONAR_TOKEN = ""
            success, output = scan.run_sonar_scanner()
        finally:
            scan.SONAR_TOKEN = original_token
        self.assertFalse(success)
        self.assertIn("SONAR_TOKEN is not set", output)


if __name__ == "__main__":
    unittest.main()
