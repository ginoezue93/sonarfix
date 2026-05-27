import json
import logging

import requests

from config import (
    SONAR_URL,
    SONAR_TOKEN,
    PROJECT_KEY,
    REPORTS_DIR,
)

REPORTS_DIR.mkdir(exist_ok=True)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s"
)

log = logging.getLogger(__name__)

OUTPUT_FILE = REPORTS_DIR / "security_issues.json"


def get_rule_metadata(rule):

    try:

        response = requests.get(
            f"{SONAR_URL}/api/rules/show",
            params={"key": rule},
            auth=(SONAR_TOKEN, ""),
            timeout=15
        )

        if response.status_code == 200:
            return response.json().get("rule", {})

    except Exception as e:

        log.warning(f"Metadata error for {rule}: {e}")

    return {}


def fetch_vulnerabilities():

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

    return data.get("issues", [])


def fetch_hotspots():

    try:

        response = requests.get(
            f"{SONAR_URL}/api/hotspots/search",
            params={
                "projectKey": PROJECT_KEY,
                "ps": 500
            },
            auth=(SONAR_TOKEN, ""),
            timeout=30
        )

        response.raise_for_status()

        data = response.json()

        return data.get("hotspots", [])

    except Exception as e:

        log.warning(f"Hotspot fetch failed: {e}")

        return []


def normalize(issue, issue_type, metadata):

    standards = metadata.get("securityStandards", {})

    return {

        "type": issue_type,

        "rule": issue.get("rule"),

        "severity": issue.get("severity")
        or issue.get("vulnerabilityProbability"),

        "message": issue.get("message"),

        "file": issue.get("component"),

        "line": issue.get("line"),

        "owasp": standards.get("owaspTop10", []),

        "cwe": standards.get("cwe", []),

        "name": metadata.get("name", "")
    }


def run():

    if not SONAR_TOKEN:
        raise RuntimeError("SONAR_TOKEN missing")

    log.info("Fetching vulnerabilities...")

    vulnerabilities = fetch_vulnerabilities()

    log.info(f"Found {len(vulnerabilities)} vulnerabilities")

    log.info("Fetching hotspots...")

    hotspots = fetch_hotspots()

    log.info(f"Found {len(hotspots)} hotspots")

    findings = []

    metadata_cache = {}

    for issue in vulnerabilities:

        rule = issue.get("rule", "")

        if rule not in metadata_cache:
            metadata_cache[rule] = get_rule_metadata(rule)

        findings.append(
            normalize(
                issue,
                "VULNERABILITY",
                metadata_cache[rule]
            )
        )

    for hotspot in hotspots:

        rule = hotspot.get("rule", "")

        if rule not in metadata_cache:
            metadata_cache[rule] = get_rule_metadata(rule)

        findings.append(
            normalize(
                hotspot,
                "SECURITY_HOTSPOT",
                metadata_cache[rule]
            )
        )

    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:

        json.dump(
            findings,
            f,
            indent=2,
            ensure_ascii=False
        )

    log.info(f"Saved {len(findings)} findings")

    return findings


if __name__ == "__main__":

    run()