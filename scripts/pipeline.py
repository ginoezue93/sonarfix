import logging
import sys
import time
from datetime import datetime
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from config import (
    EVALUATION_DIR,
    LOGS_DIR,
    PATCHED_CASES_DIR,
    REPORTS_DIR,
    SONAR_TOKEN,
    TEST_CASES_DIR,
)

import compile as java_compile
import evaluate
import fetch_issues
import generate_fixes
import scan

LOGS_DIR.mkdir(exist_ok=True)
REPORTS_DIR.mkdir(exist_ok=True)
EVALUATION_DIR.mkdir(exist_ok=True)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler(
            LOGS_DIR / f"pipeline_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log",
            encoding="utf-8"
        )
    ]
)

log = logging.getLogger(__name__)


def run(max_issues=None):

    start = time.time()

    log.info("Pipeline started")

    if not SONAR_TOKEN:

        log.error("SONAR_TOKEN missing")

        return

    # -------------------------
    # 1. BASELINE SCAN
    # -------------------------

    log.info("Running baseline scan")

    baseline_ok = scan.run(TEST_CASES_DIR)

    if not baseline_ok:

        log.error("Baseline scan failed")

        return

    # -------------------------
    # 2. FETCH ISSUES
    # -------------------------

    issues = fetch_issues.run()

    if not issues:

        log.warning("No findings found")

        return

    log.info(f"Found {len(issues)} findings")

    # -------------------------
    # 3. GENERATE FIXES
    # -------------------------

    results = generate_fixes.run(
        max_issues=max_issues
    )

    patched = sum(
        r["status"] == "patched"
        for r in results
    )

    failed = sum(
        r["status"] == "failed"
        for r in results
    )

    log.info(f"Patched: {patched}")
    log.info(f"Failed: {failed}")

    # -------------------------
    # 4. COMPILE VALIDATION
    # -------------------------

    compile_results = java_compile.run(
        test_cases_dir=PATCHED_CASES_DIR
    )

    compile_failed = [
        result
        for result in compile_results
        if result["status"] != "ok"
    ]

    if compile_failed:

        log.error(
            f"Compilation failed: {len(compile_failed)} files"
        )

        return

    log.info("Compilation successful")

    # -------------------------
    # 5. PATCHED SCAN
    # -------------------------

    log.info("Running patched scan")

    patched_ok = scan.run(PATCHED_CASES_DIR)

    if not patched_ok:

        log.error("Patched scan failed")

        return

    # -------------------------
    # 6. EVALUATION
    # -------------------------

    report = evaluate.run()

    log.info(f"Fixed: {report['fixed']}")
    log.info(f"Remaining: {report['remaining']}")
    log.info(f"New: {report['new_regressions']}")
    log.info(f"Fix rate: {report['fix_rate_pct']}")

    duration = round(time.time() - start, 1)

    log.info(f"Pipeline finished in {duration}s")

    return report


if __name__ == "__main__":

    import argparse

    parser = argparse.ArgumentParser()

    parser.add_argument(
        "--max",
        type=int,
        default=None
    )

    args = parser.parse_args()

    run(max_issues=args.max)