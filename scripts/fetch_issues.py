import json
import logging
import time

import requests

from config import (
    SONAR_URL, SONAR_TOKEN, PROJECT_KEY,
    REPORTS_DIR, LOGS_DIR,
)

REPORTS_DIR.mkdir(exist_ok=True)
LOGS_DIR.mkdir(exist_ok=True)

log = logging.getLogger(__name__)

OUTPUT_FILE = REPORTS_DIR / "security_issues.json"


def get_rule_metadata(rule_key: str) -> dict:
    try:
        r = requests.get(
            f"{SONAR_URL}/api/rules/show",
            params={"key": rule_key},
            auth=(SONAR_TOKEN, ""),
            timeout=15,
        )
        if r.status_code == 200:
            return r.json().get("rule", {})
    except Exception as e:
        log.debug("Rule metadata error for %s: %s", rule_key, e)
    return {}


def fetch_vulnerabilities() -> list[dict]:
    r = requests.get(
        f"{SONAR_URL}/api/issues/search",
        params={"componentKeys": PROJECT_KEY, "types": "VULNERABILITY", "ps": 500},
        auth=(SONAR_TOKEN, ""),
        timeout=30,
    )
    r.raise_for_status()
    return r.json().get("issues", [])


def fetch_hotspots() -> list[dict]:
    r = requests.get(
        f"{SONAR_URL}/api/hotspots/search",
        params={"projectKey": PROJECT_KEY, "ps": 500},
        auth=(SONAR_TOKEN, ""),
        timeout=30,
    )
    if r.status_code != 200:
        log.warning("Hotspot fetch returned %s", r.status_code)
        return []
    return r.json().get("hotspots", [])


def normalize(raw: dict, issue_type: str, metadata: dict) -> dict:
    standards = metadata.get("securityStandards", {})
    return {
        "type":        issue_type,
        "rule":        raw.get("rule"),
        "severity":    raw.get("severity") or raw.get("vulnerabilityProbability"),
        "message":     raw.get("message"),
        "file":        raw.get("component"),
        "line":        raw.get("line"),
        "owasp":       standards.get("owaspTop10", []),
        "cwe":         standards.get("cwe", []),
        "name":        metadata.get("name", ""),
        "description": metadata.get("htmlDesc", ""),
    }


def run(output_file=OUTPUT_FILE) -> list[dict]:
    log.info("Fetching vulnerabilities from SonarQube...")
    vulns = fetch_vulnerabilities()
    log.info("Found %d vulnerabilities", len(vulns))

    log.info("Fetching security hotspots...")
    hotspots = fetch_hotspots()
    log.info("Found %d hotspots", len(hotspots))

    combined = []

    for idx, v in enumerate(vulns):
        rule_key = v.get("rule", "")
        log.debug("[%d/%d] Enriching rule: %s", idx + 1, len(vulns), rule_key)
        meta = get_rule_metadata(rule_key)
        combined.append(normalize(v, "VULNERABILITY", meta))
        time.sleep(0.05)

    for idx, h in enumerate(hotspots):
        rule_key = h.get("rule", "")
        log.debug("[HS %d/%d] Enriching rule: %s", idx + 1, len(hotspots), rule_key)
        meta = get_rule_metadata(rule_key)
        combined.append(normalize(h, "SECURITY_HOTSPOT", meta))
        time.sleep(0.05)

    with open(output_file, "w", encoding="utf-8") as f:
        json.dump(combined, f, indent=2, ensure_ascii=False)

    log.info("Saved %d findings → %s", len(combined), output_file)
    return combined


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
    run()
