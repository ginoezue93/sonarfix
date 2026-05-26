import logging
import subprocess
import time

import requests

from config import BASE_DIR, SONAR_TOKEN

log = logging.getLogger(__name__)

REPORT_TASK_FILE = BASE_DIR / ".scannerwork" / "report-task.txt"
POLL_INTERVAL    = 5
POLL_TIMEOUT     = 300


def run_sonar_scanner() -> tuple[bool, str]:
    log.info("Running sonar-scanner from %s", BASE_DIR)
    result = subprocess.run(
        ["sonar-scanner"],
        cwd=str(BASE_DIR),
        capture_output=True,
        text=True,
    )
    return result.returncode == 0, result.stdout + result.stderr


def read_task_url() -> str | None:
    if not REPORT_TASK_FILE.exists():
        return None
    for line in REPORT_TASK_FILE.read_text(encoding="utf-8").splitlines():
        if line.startswith("ceTaskUrl="):
            return line.split("=", 1)[1].strip()
    return None


def wait_for_analysis(task_url: str, timeout: int = POLL_TIMEOUT) -> bool:
    log.info("Waiting for SonarQube analysis to finish...")
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            r = requests.get(task_url, auth=(SONAR_TOKEN, ""), timeout=10)
            status = r.json().get("task", {}).get("status", "")
            log.debug("Analysis status: %s", status)
            if status == "SUCCESS":
                log.info("Analysis completed successfully")
                return True
            if status in ("FAILED", "CANCELLED"):
                log.error("Analysis %s", status.lower())
                return False
        except Exception as e:
            log.warning("Poll error: %s", e)
        time.sleep(POLL_INTERVAL)
    log.error("Analysis timed out after %ds", timeout)
    return False


def run() -> bool:
    success, output = run_sonar_scanner()
    if not success:
        log.error("sonar-scanner exited with error:\n%s", output[-2000:])
        return False

    task_url = read_task_url()
    if not task_url:
        log.error("Could not read task URL from %s", REPORT_TASK_FILE)
        return False

    return wait_for_analysis(task_url)


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
    run()
