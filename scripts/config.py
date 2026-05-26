import sys
from pathlib import Path

BASE_DIR = Path(__file__).parent.parent

SONAR_URL   = "http://localhost:9000"
SONAR_TOKEN = "DEIN_NEUER_TOKEN_HIER"
PROJECT_KEY = "sard_cases"

OLLAMA_URL     = "http://localhost:11434/api/generate"
MODEL          = "deepseek-r1:7b"
OLLAMA_TIMEOUT = 300

CODE_CONTEXT_LINES = 12

TEST_CASES_DIR = BASE_DIR / "test_cases"
REPORTS_DIR    = BASE_DIR / "reports"
BACKUPS_DIR    = BASE_DIR / "backups"
PATCHED_DIR    = BASE_DIR / "patched"
EVALUATION_DIR = BASE_DIR / "evaluation"
LOGS_DIR       = BASE_DIR / "logs"
KNOWLEDGE_DIR  = BASE_DIR / "knowledge"
LIBS_DIR       = BASE_DIR / "lib"

SUPPORT_CLASSES = Path("d:/bachekor/test_cases/bin/support_classes")

LIBS = [
    LIBS_DIR / "servlet-api.jar",
    LIBS_DIR / "commons-lang-2.5.jar",
    LIBS_DIR / "commons-codec-1.5.jar",
    LIBS_DIR / "javamail-1.4.4.jar",
]

CP_SEP = ";" if sys.platform == "win32" else ":"
