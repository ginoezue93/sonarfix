import json
import logging
from datetime import datetime
from pathlib import Path

import requests

from config import (
    SONAR_URL, SONAR_TOKEN, PROJECT_KEY,
    REPORTS_DIR, EVALUATION_DIR,
)

REPORTS_DIR.mkdir(exist_ok=True)
EVALUATION_DIR.mkdir(exist_ok=True)

log = logging.getLogger(__name__)

PRE_FILE      = REPORTS_DIR / "security_issues.json"
POST_FILE     = REPORTS_DIR / "security_issues_post.json"
REPORT_FILE   = EVALUATION_DIR / "evaluation_report.json"
LINE_TOLERANCE = 5


# ── SonarQube helpers ──────────────────────────────────────────────────────────

def fetch_current_issues() -> list[dict]:
    findings = []

    r = requests.get(
        f"{SONAR_URL}/api/issues/search",
        params={"componentKeys": PROJECT_KEY, "types": "VULNERABILITY", "ps": 500},
        auth=(SONAR_TOKEN, ""),
        timeout=30,
    )
    r.raise_for_status()
    for v in r.json().get("issues", []):
        findings.append({
            "type":     "VULNERABILITY",
            "rule":     v.get("rule"),
            "file":     v.get("component"),
            "line":     v.get("line"),
            "message":  v.get("message"),
            "severity": v.get("severity"),
        })

    r2 = requests.get(
        f"{SONAR_URL}/api/hotspots/search",
        params={"projectKey": PROJECT_KEY, "ps": 500},
        auth=(SONAR_TOKEN, ""),
        timeout=30,
    )
    if r2.status_code == 200:
        for h in r2.json().get("hotspots", []):
            findings.append({
                "type":     "SECURITY_HOTSPOT",
                "rule":     h.get("rule"),
                "file":     h.get("component"),
                "line":     h.get("line"),
                "message":  h.get("message"),
                "severity": h.get("vulnerabilityProbability"),
            })

    return findings


# ── Matching ───────────────────────────────────────────────────────────────────

def _key(finding: dict) -> tuple:
    return (finding.get("file", ""), finding.get("rule", ""))


def _line(finding: dict) -> int:
    return finding.get("line") or 0


def match_findings(pre: list[dict], post: list[dict]) -> dict:
    post_by_key: dict[tuple, list[dict]] = {}
    for f in post:
        post_by_key.setdefault(_key(f), []).append(f)

    fixed    = []
    remaining = []
    matched_post_ids = set()

    for pf in pre:
        key       = _key(pf)
        candidates = post_by_key.get(key, [])
        matched = False
        for i, cf in enumerate(candidates):
            if i in matched_post_ids:
                continue
            if abs(_line(pf) - _line(cf)) <= LINE_TOLERANCE:
                remaining.append({**pf, "post_line": _line(cf)})
                matched_post_ids.add(id(cf))
                matched = True
                break
        if not matched:
            fixed.append(pf)

    # Post findings with no pre-match are regressions
    pre_ids = {id(f) for f in pre}
    new = [
        f for f in post
        if id(f) not in {id(r) for r in remaining}
        and not any(_key(f) == _key(p) and abs(_line(f) - _line(p)) <= LINE_TOLERANCE for p in pre)
    ]

    return {"fixed": fixed, "remaining": remaining, "new": new}


# ── Main ───────────────────────────────────────────────────────────────────────

def run(pre_file=PRE_FILE, post_file=POST_FILE, report_file=REPORT_FILE) -> dict:
    with open(pre_file, "r", encoding="utf-8") as f:
        pre = json.load(f)
    log.info("Pre-patch findings: %d", len(pre))

    log.info("Fetching post-patch findings from SonarQube...")
    post = fetch_current_issues()
    log.info("Post-patch findings: %d", len(post))

    with open(post_file, "w", encoding="utf-8") as f:
        json.dump(post, f, indent=2, ensure_ascii=False)

    counts = match_findings(pre, post)

    n_pre     = len(pre)
    n_fixed   = len(counts["fixed"])
    n_new     = len(counts["new"])
    n_remain  = len(counts["remaining"])
    fix_rate  = round(n_fixed / n_pre, 4) if n_pre else 0.0

    report = {
        "timestamp":        datetime.now().isoformat(),
        "pre_total":        n_pre,
        "post_total":       len(post),
        "fixed":            n_fixed,
        "remaining":        n_remain,
        "new_regressions":  n_new,
        "fix_rate":         fix_rate,
        "fix_rate_pct":     f"{fix_rate * 100:.1f}%",
        "fixed_issues":     counts["fixed"],
        "remaining_issues": counts["remaining"],
        "new_issues":       counts["new"],
    }

    with open(report_file, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2, ensure_ascii=False)

    log.info("Evaluation complete:")
    log.info("  Pre-patch  : %d findings", n_pre)
    log.info("  Post-patch : %d findings", len(post))
    log.info("  Fixed      : %d", n_fixed)
    log.info("  Remaining  : %d", n_remain)
    log.info("  New        : %d", n_new)
    log.info("  Fix rate   : %s", report["fix_rate_pct"])
    log.info("  Report     → %s", report_file)

    return report


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
    run()
