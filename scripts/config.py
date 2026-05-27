import os
from pathlib import Path

BASE_DIR = Path(__file__).parent.parent

SONAR_URL   = "http://localhost:9000"
SONAR_TOKEN = "sqp_3fdacd7596fb74d3f374798395330de6081af397"
PROJECT_KEY = "sard_cases"

OLLAMA_URL     = "http://localhost:11434/api/generate"
MODEL          = "deepseek-coder:6.7b"
OLLAMA_TIMEOUT = 300

CODE_CONTEXT_LINES = 8

TEST_CASES_DIR = BASE_DIR / "test_cases"
REPORTS_DIR    = BASE_DIR / "reports"
BACKUPS_DIR    = BASE_DIR / "backups"
PATCHED_DIR    = BASE_DIR / "patched"
PATCHED_CASES_DIR = PATCHED_DIR / "test_cases"
EVALUATION_DIR = BASE_DIR / "evaluation"
LOGS_DIR       = BASE_DIR / "logs"
KNOWLEDGE_DIR  = BASE_DIR / "knowledge"
LIBS_DIR       = BASE_DIR / "lib"

SUPPORT_CLASSES = LIBS_DIR / "support_classes"

LIBS = [
    LIBS_DIR / "servlet-api.jar",
    LIBS_DIR / "commons-lang-2.5.jar",
    LIBS_DIR / "commons-codec-1.5.jar",
    LIBS_DIR / "javamail-1.4.4.jar",
]

CP_SEP = ";"

SONAR_SCANNER = "sonar-scanner"
