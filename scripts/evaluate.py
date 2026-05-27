import json
import logging
import re
from datetime import datetime

import requests

from config import (
    SONAR_URL,
    SONAR_TOKEN,
    PROJECT_KEY,
    REPORTS_DIR,
    EVALUATION_DIR,
)

REPORTS_DIR.mkdir(exist_ok=True)
EVALUATION_DIR.mkdir(exist_ok=True)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s"
)

log = logging.getLogger(__name__)

PRE_FILE = REPORTS_DIR / "security_issues.json"
POST_FILE = REPORTS_DIR / "security_issues_post.json"
REPORT_FILE = EVALUATION_DIR / "evaluation_report.json"


def fetch_current_issues():

    findings = []

    response = requests.get(
        f"{SONAR_URL}/api/issues/search",
        params={
            "componentKeys": PROJECT_KEY,
            "types": "VULNERABILITY",
            "resolved": "false",
            "ps": 500
        },
        auth=(SONAR_TOKEN, ""),
        timeout=30
    )

    response.raise_for_status()

    data = response.json()

    for issue in data.get("issues", []):

        findings.append({
            "type": "VULNERABILITY",
            "rule": issue.get("rule"),
            "file": issue.get("component"),
            "line": issue.get("line"),
            "message": issue.get("message"),
            "severity": issue.get("severity")
        })

    hotspot_response = requests.get(
        f"{SONAR_URL}/api/hotspots/search",
        params={
            "projectKey": PROJECT_KEY,
            "ps": 500
        },
        auth=(SONAR_TOKEN, ""),
        timeout=30
    )

    if hotspot_response.status_code == 200:

        hotspot_data = hotspot_response.json()

        for hotspot in hotspot_data.get("hotspots", []):

            findings.append({
                "type": "SECURITY_HOTSPOT",
                "rule": hotspot.get("rule"),
                "file": hotspot.get("component"),
                "line": hotspot.get("line"),
                "message": hotspot.get("message"),
                "severity": hotspot.get("vulnerabilityProbability")
            })

    return findings


def normalize_file(path):

    path = path or ""

    path = path.replace("\\", "/")

    path = re.sub(
        r":(?:patched/)?test_cases/",
        ":test_cases/",
        path
    )

    return path


def finding_key(finding):

    return (
        finding.get("type"),
        normalize_file(finding.get("file")),
        finding.get("rule")
    )


def finding_exists(finding, findings):

    target = finding_key(finding)

    for candidate in findings:

        current = finding_key(candidate)

        if current != target:
            continue

        line_a = finding.get("line")
        line_b = candidate.get("line")

        if line_a is None or line_b is None:
            return True

        if abs(line_a - line_b) <= 5:
            return True

    return False


def evaluate(pre_findings, post_findings):

    fixed = []
    remaining = []

    for finding in pre_findings:

        if finding_exists(finding, post_findings):
            remaining.append(finding)
        else:
            fixed.append(finding)

    new = []

    for finding in post_findings:

        if not finding_exists(finding, pre_findings):
            new.append(finding)

    return {
        "fixed": fixed,
        "remaining": remaining,
        "new": new
    }


def run():

    with open(PRE_FILE, "r", encoding="utf-8") as f:
        pre = json.load(f)

    log.info(f"Pre findings: {len(pre)}")

    post = fetch_current_issues()

    log.info(f"Post findings: {len(post)}")

    with open(POST_FILE, "w", encoding="utf-8") as f:
        json.dump(post, f, indent=2)

    result = evaluate(pre, post)

    fixed = len(result["fixed"])
    remaining = len(result["remaining"])
    new = len(result["new"])

    total = len(pre)

    fix_rate = round(fixed / total, 4) if total else 0

    report = {
        "timestamp": datetime.now().isoformat(),

        "pre_total": total,
        "post_total": len(post),

        "fixed": fixed,
        "remaining": remaining,
        "new_regressions": new,

        "fix_rate": fix_rate,
        "fix_rate_pct": f"{fix_rate * 100:.1f}%",

        "fixed_issues": result["fixed"],
        "remaining_issues": result["remaining"],
        "new_issues": result["new"]
    }

    with open(REPORT_FILE, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)

    log.info(f"Fixed: {fixed}")
    log.info(f"Remaining: {remaining}")
    log.info(f"New: {new}")
    log.info(f"Fix rate: {report['fix_rate_pct']}")

    return report


if __name__ == "__main__":

    run()