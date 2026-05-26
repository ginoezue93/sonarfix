import json
import logging
import subprocess
import sys
from pathlib import Path

from config import (
    BASE_DIR, TEST_CASES_DIR, REPORTS_DIR, LOGS_DIR,
    LIBS, SUPPORT_CLASSES, CP_SEP,
)

REPORTS_DIR.mkdir(exist_ok=True)
LOGS_DIR.mkdir(exist_ok=True)

log = logging.getLogger(__name__)

RESULTS_FILE = REPORTS_DIR / "compile_results.json"


def classpath(classes_dir: Path) -> str:
    return CP_SEP.join(str(p) for p in [*LIBS, SUPPORT_CLASSES, classes_dir])


def compile_file(java_file: Path, classes_dir: Path) -> tuple[bool, str]:
    classes_dir.mkdir(parents=True, exist_ok=True)
    result = subprocess.run(
        [
            "javac",
            "-cp", classpath(classes_dir),
            "-d", str(classes_dir),
            "-g",
            "-encoding", "UTF-8",
            str(java_file),
        ],
        capture_output=True,
        text=True,
    )
    return result.returncode == 0, result.stderr.strip()


def find_compilable_cases() -> list[tuple[Path, Path]]:
    pairs = []
    for case_dir in sorted(TEST_CASES_DIR.iterdir()):
        if not (case_dir.is_dir() and case_dir.name.upper().startswith("CWE")):
            continue
        src_dir     = case_dir / "src"
        classes_dir = case_dir / "classes"
        java_files  = list(src_dir.glob("*.java")) if src_dir.exists() else []
        for java_file in java_files:
            pairs.append((java_file, classes_dir))
    return pairs


def run(results_file=RESULTS_FILE) -> list[dict]:
    pairs = find_compilable_cases()
    log.info("Compiling %d Java files...", len(pairs))

    results = []
    ok = fail = 0

    for java_file, classes_dir in pairs:
        success, stderr = compile_file(java_file, classes_dir)
        status = "ok" if success else "failed"

        if success:
            ok += 1
            log.debug("[OK]   %s", java_file.name)
        else:
            fail += 1
            first_line = stderr.splitlines()[0] if stderr else "unknown error"
            log.warning("[FAIL] %s — %s", java_file.name, first_line)

        results.append({
            "file":   str(java_file.relative_to(BASE_DIR)),
            "status": status,
            "error":  stderr if not success else "",
        })

    with open(results_file, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2, ensure_ascii=False)

    log.info("Compilation done: %d ok, %d failed → %s", ok, fail, results_file)
    return results


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
    run()
