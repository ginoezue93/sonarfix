#!/usr/bin/env python3
"""
Selects 200 random *_01.java (bad+good baseline) files from the Juliet test
suite, compiles them and drops them into pipeline/test_cases/ so SonarQube
can scan for the bad() code paths.

Usage:
    python setup_bad_cases.py          # 200 random cases (default)
    python setup_bad_cases.py --n 100  # custom count
"""

import argparse
import json
import random
import shutil
import subprocess
import sys
from collections import defaultdict
from pathlib import Path

PIPELINE_DIR   = Path(__file__).parent
JULIET_SRC     = Path("d:/bachekor/test_cases/src/testcases")
SUPPORT_CLASSES = Path("d:/bachekor/test_cases/bin/support_classes")
LIBS_DIR       = PIPELINE_DIR / "lib"
TEST_CASES_DIR = PIPELINE_DIR / "test_cases"
DEFAULT_MANIFEST = PIPELINE_DIR / "reports" / "sample_manifest.json"

LIBS = [
    LIBS_DIR / "servlet-api.jar",
    LIBS_DIR / "commons-lang-2.5.jar",
    LIBS_DIR / "commons-codec-1.5.jar",
    LIBS_DIR / "javamail-1.4.4.jar",
]


def classpath(*extra):
    sep = ";" if sys.platform == "win32" else ":"
    return sep.join(str(p) for p in [*LIBS, SUPPORT_CLASSES, *extra])


def clear_test_cases():
    removed = 0
    for item in sorted(TEST_CASES_DIR.iterdir()):
        if item.is_dir() and item.name.upper().startswith("CWE"):
            shutil.rmtree(item)
            removed += 1
    print(f"Removed {removed} existing test case directories.")


def select_files(n: int, seed: int) -> list[Path]:
    all_files = sorted(JULIET_SRC.rglob("*_01.java"))
    all_files = [
        f for f in all_files
        if f.name not in ("Main.java", "ServletMain.java")
    ]
    chosen = random.Random(seed).sample(all_files, min(n, len(all_files)))
    print(f"Selected {len(chosen)} test files from {len(all_files)} available (seed={seed}).")
    return chosen


def cwe_tag(java_file: Path) -> str:
    for part in java_file.parts:
        if part.upper().startswith("CWE"):
            return part.split("_")[0].upper()
    return "CWE000"


def compile_test(java_file: Path, out_dir: Path) -> tuple[bool, str]:
    src_dir     = out_dir / "src"
    classes_dir = out_dir / "classes"
    src_dir.mkdir(parents=True, exist_ok=True)
    classes_dir.mkdir(parents=True, exist_ok=True)

    shutil.copy2(java_file, src_dir / java_file.name)

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
    return result.returncode == 0, result.stderr


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--n", type=int, default=200, help="Number of test cases")
    parser.add_argument("--seed", type=int, default=1337, help="Reproducible sampling seed")
    parser.add_argument(
        "--manifest",
        type=Path,
        default=DEFAULT_MANIFEST,
        help="Path for the selected input manifest",
    )
    args = parser.parse_args()

    if not SUPPORT_CLASSES.exists():
        print(f"ERROR: support classes not found at {SUPPORT_CLASSES}")
        print("Run 'python compile_per_test.py --n 1' once from d:/bachekor/test_cases/ to build them.")
        sys.exit(1)

    files = select_files(args.n, args.seed)
    clear_test_cases()

    counters: dict[str, int] = defaultdict(int)
    ok = fail = 0
    selected = []

    for java_file in files:
        tag = cwe_tag(java_file)
        counters[tag] += 1
        dir_name = f"{tag}_{counters[tag]:03d}"
        out_dir  = TEST_CASES_DIR / dir_name

        success, stderr = compile_test(java_file, out_dir)
        selected.append({
            "source": str(java_file),
            "case_dir": dir_name,
            "compiled": success,
        })
        if success:
            ok += 1
            print(f"  [OK]   {dir_name}  {java_file.name}")
        else:
            fail += 1
            shutil.rmtree(out_dir, ignore_errors=True)
            first_err = stderr.splitlines()[0] if stderr else "unknown error"
            print(f"  [FAIL] {dir_name}  {java_file.name}: {first_err}")

    print(f"\nDone — compiled: {ok}, failed: {fail}")
    args.manifest.parent.mkdir(parents=True, exist_ok=True)
    args.manifest.write_text(
        json.dumps({"seed": args.seed, "requested": args.n, "selected": selected}, indent=2),
        encoding="utf-8",
    )
    print(f"Output: {TEST_CASES_DIR}")
    print(f"Manifest: {args.manifest}")


if __name__ == "__main__":
    main()
