import json
import logging
import re
import shutil
import time
from collections import defaultdict
from pathlib import Path

import requests

from config import (
    MODEL,
    OLLAMA_TIMEOUT,
    OLLAMA_URL,
    PATCHED_CASES_DIR,
    PATCHED_DIR,
    REPORTS_DIR,
    TEST_CASES_DIR,
    CODE_CONTEXT_LINES,
)

from prompt_templates import build_prompt
from security_taxonomy import classify_issue

REPORTS_DIR.mkdir(exist_ok=True)
PATCHED_DIR.mkdir(exist_ok=True)
ATTEMPTED_FILE = REPORTS_DIR / "security_issues_attempted.json"

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s"
)

log = logging.getLogger(__name__)

ISSUES_FILE = REPORTS_DIR / "security_issues.json"
RESULTS_FILE = REPORTS_DIR / "fix_results.json"


def prepare_workspace():

    if PATCHED_CASES_DIR.exists():
        shutil.rmtree(PATCHED_CASES_DIR)

    shutil.copytree(TEST_CASES_DIR, PATCHED_CASES_DIR)


def resolve_path(component):

    relative = component.split(":", 1)[-1]
    relative = relative.replace("\\", "/")

    if "test_cases/" not in relative:
        return None

    relative = relative.split("test_cases/", 1)[-1]

    path = PATCHED_CASES_DIR / relative

    return path if path.exists() else None


def ask_ollama(prompt):

    for attempt in range(3):

        try:

            response = requests.post(
                OLLAMA_URL,
                json={
                    "model": MODEL,
                    "prompt": prompt,
                    "stream": False,
                    "options": {
                        "temperature": 0.1,
                        "num_ctx": 2048,
                        "num_predict": 200
                    }
                },
                timeout=OLLAMA_TIMEOUT
            )

            response.raise_for_status()

            data = response.json()

            return data.get("response", "").strip()

        except Exception as e:

            log.warning(f"Ollama error: {e}")

            time.sleep(3)

    return None


def clean_response(text):

    text = text.strip()

    if "</think>" in text:
        text = text.split("</think>")[-1]

    text = text.replace("```java", "")
    text = text.replace("```", "")

    return text.strip()


def looks_like_java(text):

    return ";" in text or "{" in text


def apply_indent(fixed_code, original_line):

    indent = original_line[:len(original_line) - len(original_line.lstrip())]

    return [
        indent + line.strip() + "\n"
        for line in fixed_code.splitlines()
        if line.strip()
    ]


def cookie_secure_fix(lines, index):

    line = lines[index]

    match = re.search(
        r"\b([A-Za-z_]\w*)\s*=\s*new\s+Cookie\s*\(",
        line
    )

    if not match:
        return None

    variable = match.group(1)

    secure_line = f"{variable}.setSecure(true);"

    for check in lines[index:index + 5]:

        if secure_line in check:
            return lines

    indent = line[:len(line) - len(line.lstrip())]

    updated = list(lines)

    updated.insert(
        index + 1,
        indent + secure_line + "\n"
    )

    return updated


def apply_rule_fix(issue, lines, index):

    rule = issue.get("rule")

    if rule == "java:S2092":
        return cookie_secure_fix(lines, index)

    return None


def apply_llm_fix(issue, lines, index, category):

    line_number = issue["line"]

    start = max(0, line_number - CODE_CONTEXT_LINES - 1)
    end = min(len(lines), line_number + CODE_CONTEXT_LINES)

    context = "".join(lines[start:end])

    vulnerable_line = lines[index]

    prompt = build_prompt(
        issue,
        category,
        context,
        vulnerable_line
    )

    raw = ask_ollama(prompt)

    if not raw:
        return None, "no model response"

    fixed = clean_response(raw)

    if not fixed:
        return None, "empty response"

    if not looks_like_java(fixed):
        return None, "not java code"

    fixed_lines = apply_indent(
        fixed,
        vulnerable_line
    )

    updated = list(lines)

    updated[index:index + 1] = fixed_lines

    return updated, "llm patch applied"


def validate_candidate(file_path):

    import compile as java_compile

    classes_dir = file_path.parent.parent / "classes"

    success, error = java_compile.compile_file(
        file_path,
        classes_dir
    )

    if success:
        return True

    return False


def run(max_issues=None):

    issues = json.loads(
        ISSUES_FILE.read_text(encoding="utf-8")
    )

    if max_issues:
        issues = issues[:max_issues]

    prepare_workspace()

    grouped = defaultdict(list)

    for issue in issues:

        if issue.get("file") and issue.get("line"):
            grouped[issue["file"]].append(issue)

    results = []

    for component, file_issues in grouped.items():

        file_path = resolve_path(component)

        if not file_path:

            log.warning(f"File not found: {component}")

            continue

        for issue in sorted(
            file_issues,
            key=lambda x: x["line"],
            reverse=True
        ):

            lines = file_path.read_text(
                encoding="utf-8"
            ).splitlines(keepends=True)

            index = issue["line"] - 1

            if index < 0 or index >= len(lines):

                results.append({
                    **issue,
                    "status": "failed",
                    "error": "line out of range"
                })

                continue

            category, _ = classify_issue(issue)

            updated = apply_rule_fix(
                issue,
                lines,
                index
            )

            strategy = "rule_based"

            detail = "rule fix"

            if updated is None:

                updated, detail = apply_llm_fix(
                    issue,
                    lines,
                    index,
                    category
                )

                strategy = "llm"

            if updated is None:

                results.append({
                    **issue,
                    "status": "failed",
                    "strategy": strategy,
                    "error": detail
                })

                continue

            original = list(lines)

            file_path.write_text(
                "".join(updated),
                encoding="utf-8"
            )

            valid = validate_candidate(file_path)

            if not valid:

                file_path.write_text(
                    "".join(original),
                    encoding="utf-8"
                )

                results.append({
                    **issue,
                    "status": "failed",
                    "strategy": strategy,
                    "error": "compile failed"
                })

                continue

            log.info(
                f"[PATCHED] {file_path.name}:{issue['line']}"
            )

            results.append({
                **issue,
                "status": "patched",
                "strategy": strategy,
                "error": ""
            })

    RESULTS_FILE.write_text(
        json.dumps(results, indent=2),
        encoding="utf-8"
    )

    patched = sum(
        r["status"] == "patched"
        for r in results
    )

    failed = sum(
        r["status"] == "failed"
        for r in results
    )

    log.info(
        f"Finished: {patched} patched, {failed} failed"
    )

    return results


if __name__ == "__main__":

    run()