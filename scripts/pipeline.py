import logging
import sys
import time
from datetime import datetime
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from config import LOGS_DIR, REPORTS_DIR, EVALUATION_DIR

LOGS_DIR.mkdir(exist_ok=True)
REPORTS_DIR.mkdir(exist_ok=True)
EVALUATION_DIR.mkdir(exist_ok=True)


def setup_logging():
    ts  = datetime.now().strftime("%Y%m%d_%H%M%S")
    fmt = logging.Formatter("%(asctime)s [%(levelname)s] %(name)s — %(message)s", "%H:%M:%S")

    root = logging.getLogger()
    root.setLevel(logging.DEBUG)

    sh = logging.StreamHandler(sys.stdout)
    sh.setLevel(logging.INFO)
    sh.setFormatter(fmt)

    fh = logging.FileHandler(LOGS_DIR / f"pipeline_{ts}.log", encoding="utf-8")
    fh.setLevel(logging.DEBUG)
    fh.setFormatter(fmt)

    root.addHandler(sh)
    root.addHandler(fh)


def step(name: str):
    log = logging.getLogger("pipeline")
    log.info("")
    log.info("=" * 50)
    log.info("  %s", name)
    log.info("=" * 50)


def run():
    setup_logging()
    log = logging.getLogger("pipeline")
    log.info("Pipeline started — %s", datetime.now().isoformat())
    total_start = time.time()

    import fetch_issues
    import generate_fixes
    import compile
    import scan
    import evaluate

    # ── Step 1: Fetch SonarQube findings ──────────────────────────────────────
    step("STEP 1 — FETCH SECURITY ISSUES")
    t = time.time()
    issues = fetch_issues.run()
    log.info("Step 1 done in %.1fs — %d findings", time.time() - t, len(issues))

    if not issues:
        log.warning("No findings — nothing to fix. Exiting.")
        return

    # ── Step 2: Generate and apply LLM fixes ──────────────────────────────────
    step("STEP 2 — GENERATE FIXES")
    t = time.time()
    results = generate_fixes.run()
    patched = sum(1 for r in results if r["status"] == "patched")
    log.info("Step 2 done in %.1fs — %d/%d patched", time.time() - t, patched, len(results))

    # ── Step 3: Recompile patched files ───────────────────────────────────────
    step("STEP 3 — COMPILE")
    t = time.time()
    compile_results = compile.run()
    ok   = sum(1 for r in compile_results if r["status"] == "ok")
    fail = sum(1 for r in compile_results if r["status"] == "failed")
    log.info("Step 3 done in %.1fs — %d ok, %d failed", time.time() - t, ok, fail)

    # ── Step 4: Re-scan with SonarQube ────────────────────────────────────────
    step("STEP 4 — SONARQUBE SCAN")
    t = time.time()
    scan_ok = scan.run()
    if scan_ok:
        log.info("Step 4 done in %.1fs", time.time() - t)
    else:
        log.error("SonarQube scan failed — evaluation may use stale data")

    # ── Step 5: Evaluate results ──────────────────────────────────────────────
    step("STEP 5 — EVALUATE")
    t = time.time()
    report = evaluate.run()
    log.info("Step 5 done in %.1fs", time.time() - t)

    # ── Summary ───────────────────────────────────────────────────────────────
    elapsed = time.time() - total_start
    log.info("")
    log.info("=" * 50)
    log.info("  PIPELINE COMPLETE  (%.0fs total)", elapsed)
    log.info("  Findings before : %d", report["pre_total"])
    log.info("  Findings after  : %d", report["post_total"])
    log.info("  Fixed           : %d", report["fixed"])
    log.info("  Fix rate        : %s", report["fix_rate_pct"])
    log.info("  Regressions     : %d", report["new_regressions"])
    log.info("=" * 50)


if __name__ == "__main__":
    run()
