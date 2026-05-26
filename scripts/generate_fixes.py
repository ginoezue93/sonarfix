import json
import logging
import shutil
from collections import defaultdict
from pathlib import Path

import requests

from config import (
    BASE_DIR, REPORTS_DIR, BACKUPS_DIR, PATCHED_DIR,
    KNOWLEDGE_DIR, OLLAMA_URL, MODEL, OLLAMA_TIMEOUT, CODE_CONTEXT_LINES,
)
from security_taxonomy import classify_issue

REPORTS_DIR.mkdir(exist_ok=True)
BACKUPS_DIR.mkdir(exist_ok=True)
PATCHED_DIR.mkdir(exist_ok=True)

log = logging.getLogger(__name__)

ISSUES_FILE  = REPORTS_DIR / "security_issues.json"
RESULTS_FILE = REPORTS_DIR / "fix_results.json"


def resolve_path(component: str) -> Path | None:
    relative = component.split(":", 1)[-1]
    path = BASE_DIR / Path(relative)
    return path if path.exists() else None


def load_knowledge(filename: str) -> str:
    path = KNOWLEDGE_DIR / filename
    try:
        return path.read_text(encoding="utf-8")
    except Exception as e:
        log.warning("Could not load knowledge file %s: %s", path, e)
        return ""


def extract_block(file_path: Path, line: int, context: int = CODE_CONTEXT_LINES):
    lines = file_path.read_text(encoding="utf-8").splitlines(keepends=True)
    start = max(0, line - context - 1)
    end   = min(len(lines), line + context)
    vulnerable_idx = line - 1 - start

    marked = list(lines[start:end])
    if 0 <= vulnerable_idx < len(marked):
        marked[vulnerable_idx] = marked[vulnerable_idx].rstrip() + "  // <-- VULNERABLE LINE\n"

    return "".join(marked), lines, start, end


def strip_markdown(code: str) -> str:
    import re
    # Remove DeepSeek R1 think blocks
    code = re.sub(r"<think>.*?</think>", "", code, flags=re.DOTALL).strip()
    # Extract content from the last ```...``` block (model puts final answer last)
    matches = re.findall(r"```(?:java)?\n(.*?)```", code, flags=re.DOTALL)
    if matches:
        return matches[-1].strip()
    # No code fences — strip any leading explanation line before Java code
    lines = code.splitlines()
    for i, line in enumerate(lines):
        stripped = line.strip()
        if stripped.startswith(("import ", "public ", "private ", "protected ",
                                 "class ", "//", "/*", "@", "if ", "for ",
                                 "try ", "return ", "String ", "int ", "void ")):
            return "\n".join(lines[i:]).strip()
    return code.strip()


def apply_block_fix(all_lines: list[str], start: int, end: int, fixed_code: str) -> list[str]:
    fixed_lines = fixed_code.splitlines(keepends=True)
    if fixed_lines and not fixed_lines[-1].endswith("\n"):
        fixed_lines[-1] += "\n"
    return all_lines[:start] + fixed_lines + all_lines[end:]


def backup(file_path: Path) -> Path:
    dest = BACKUPS_DIR / file_path.name
    counter = 0
    while dest.exists():
        counter += 1
        dest = BACKUPS_DIR / f"{file_path.stem}_{counter}{file_path.suffix}"
    shutil.copy2(file_path, dest)
    return dest


def build_prompt(issue: dict, category: str, owasp: str, knowledge: str, code_block: str) -> str:
    filename = Path(issue.get("file", "unknown")).name

    return f"""You are a senior application security engineer specializing in Java security and OWASP-compliant remediation.

VULNERABILITY
=============
File     : {filename}
Category : {category}
OWASP    : {owasp}
Severity : {issue.get("severity", "UNKNOWN")}
Rule     : {issue.get("rule", "")}
Line     : {issue.get("line", "?")}
Message  : {issue.get("message", "")}

OWASP SECURITY GUIDANCE
========================
{knowledge}

VULNERABLE JAVA CODE
====================
The line marked with "// <-- VULNERABLE LINE" contains the security issue.

{code_block}

TASK
====
Fix the security vulnerability in the marked line.

Reasoning process:
1. Identify the vulnerable pattern on the marked line
2. Understand why it is insecure
3. Determine the minimal OWASP-compliant fix
4. Preserve the original application functionality
5. Keep all other lines unchanged

OUTPUT RULES
============
- Return the corrected version of the entire shown code block
- Same indentation as original
- No markdown fences, no triple backticks
- No explanations, no comments
- The output will be written directly back to the source file
"""


def query_ollama(prompt: str, retries: int = 2) -> str | None:
    for attempt in range(1, retries + 2):
        try:
            r = requests.post(
                OLLAMA_URL,
                json={
                    "model": MODEL,
                    "prompt": prompt,
                    "stream": False,
                    "options": {"num_ctx": 8192, "num_predict": 2048, "num_gpu": 999},
                },
                timeout=OLLAMA_TIMEOUT,
            )
            r.raise_for_status()
            return r.json().get("response", "").strip()
        except Exception as e:
            log.warning("Ollama attempt %d/%d failed: %s", attempt, retries + 1, e)
            if attempt == retries + 1:
                log.error("All attempts failed")
                return None
    return None


def run(issues_file=ISSUES_FILE, results_file=RESULTS_FILE) -> list[dict]:
    with open(issues_file, "r", encoding="utf-8") as f:
        issues = json.load(f)

    log.info("Loaded %d findings from %s", len(issues), issues_file)

    # Group by file, process bottom-to-top to keep line numbers valid
    grouped: dict[str, list[dict]] = defaultdict(list)
    for issue in issues:
        if issue.get("file") and issue.get("line"):
            grouped[issue["file"]].append(issue)

    results = []

    for component, file_issues in grouped.items():
        file_path = resolve_path(component)
        if not file_path:
            log.warning("File not found: %s", component)
            for issue in file_issues:
                results.append(_result(issue, "skipped", "file not found"))
            continue

        # Bottom-to-top so earlier patches don't shift line numbers
        for issue in sorted(file_issues, key=lambda x: x["line"], reverse=True):
            line = issue["line"]
            log.info("[%s] line %d — %s", file_path.name, line, issue.get("message", "")[:80])

            category, tax_data = classify_issue(issue)
            knowledge = load_knowledge(tax_data["knowledge_file"])

            try:
                code_block, all_lines, start, end = extract_block(file_path, line)
            except Exception as e:
                log.error("Could not extract code from %s: %s", file_path, e)
                results.append(_result(issue, "failed", str(e)))
                continue

            prompt   = build_prompt(issue, category, tax_data["owasp"], knowledge, code_block)
            response = query_ollama(prompt)

            if not response:
                results.append(_result(issue, "failed", "no response from Ollama"))
                continue

            fixed_code = strip_markdown(response)

            backup_path = backup(file_path)
            log.debug("Backup → %s", backup_path)

            new_lines = apply_block_fix(all_lines, start, end, fixed_code)
            file_path.write_text("".join(new_lines), encoding="utf-8")

            # Mirror to patched/ preserving structure relative to BASE_DIR
            rel = file_path.relative_to(BASE_DIR)
            patched_copy = PATCHED_DIR / rel
            patched_copy.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(file_path, patched_copy)

            log.info("  [+] Fixed — category: %s", category)
            results.append(_result(issue, "patched", "", category=category, backup=str(backup_path)))

    with open(results_file, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2, ensure_ascii=False)

    patched_count = sum(1 for r in results if r["status"] == "patched")
    log.info("Fix run complete: %d patched, %d failed/skipped",
             patched_count, len(results) - patched_count)
    return results


def _result(issue: dict, status: str, error: str = "", **kwargs) -> dict:
    return {
        "file":     issue.get("file", ""),
        "line":     issue.get("line"),
        "rule":     issue.get("rule", ""),
        "severity": issue.get("severity", ""),
        "status":   status,
        "error":    error,
        **kwargs,
    }


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
    run()
