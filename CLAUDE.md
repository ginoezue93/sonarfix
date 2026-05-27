# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this project does

This is an automated security vulnerability remediation pipeline for Java code. It:
1. Compiles random samples from the NIST Juliet Java test suite into `test_cases/`
2. Scans them with SonarQube (static analysis)
3. Fetches detected vulnerabilities/hotspots from the SonarQube API and enriches them with rule metadata
4. Classifies findings by Sonar rule first, then uses rule-based or LLM-assisted fixes
5. Applies fixes in `patched/test_cases/`, recompiles, rescans, and evaluates the patch workspace

The baseline under `test_cases/` is not modified by `scripts/pipeline.py`.

## Prerequisites

- Docker (for SonarQube + PostgreSQL)
- `sonar-scanner` CLI in PATH
- `javac` (Java 11+) in PATH
- [Ollama](https://ollama.com/) running locally with `deepseek-coder:6.7b` pulled
- Juliet test suite source at `d:/bachekor/test_cases/` (compiled support classes at `d:/bachekor/test_cases/bin/support_classes`)
- `SONAR_TOKEN` set in the environment for scanner and API authentication

## Commands

### Start SonarQube
```bash
docker compose up -d
# SonarQube available at http://localhost:9000 (admin/admin on first run)
```

### Prepare test cases (run from repo root)
```bash
python setup_bad_cases.py                       # reproducible default sample
python setup_bad_cases.py --n 50 --seed 2026   # custom reproducible sample
```
This clears `test_cases/`, selects N `*_01.java` files from the Juliet suite, compiles each one, and writes `reports/sample_manifest.json` for reproducibility.

### Run SonarQube scan (run from repo root)
```bash
sonar-scanner
```
Uses `sonar-project.properties`. In PowerShell, set authentication with `$env:SONAR_TOKEN = "..."`.

### Run the pipeline (run from `scripts/` directory)
```bash
cd scripts
python pipeline.py        # baseline scan → patch copy → compile → post scan → evaluate
python fetch_issues.py    # Step 1 only: pull findings → reports/security_issues.json
python generate_fixes.py  # Step 2 only: apply fixes to patched/test_cases/
```

## Architecture

### Data flow
```
Juliet suite (d:/bachekor/test_cases/)
    └─► setup_bad_cases.py  ──► test_cases/CWEXX_NNN/{src,classes}/
                                       │
                                sonar-scanner
                                       │
                              SonarQube (localhost:9000)
                                       │
                              scripts/fetch_issues.py
                                       │
                              reports/security_issues.json
                                       │
                              scripts/generate_fixes.py
                               ├─ classify_issue()  → security_taxonomy.py
                               ├─ load_knowledge()  → knowledge/<category>.txt  (RAG)
                               ├─ rule fix / Ollama → isolated patch proposal
                               └─ compile + scan    → patched/test_cases/ evaluation
```

### Key files

| File | Role |
|------|------|
| `setup_bad_cases.py` | Selects & compiles Juliet test cases |
| `sonar-project.properties` | SonarQube project config (key: `sard_cases`) |
| `docker-compose.yaml` | SonarQube + PostgreSQL services |
| `scripts/fetch_issues.py` | Pulls vulnerabilities & hotspots, enriches with rule metadata |
| `scripts/generate_fixes.py` | Rule-based and LLM-assisted remediation in an isolated patch workspace |
| `scripts/security_taxonomy.py` | Sonar rule-first security categorization |
| `knowledge/*.txt` | Per-category RAG context (injection, cryptography, xss, ssrf, path_traversal, authentication, deserialization, generic) |
| `reports/security_issues.json` | Intermediate output: normalised list of findings with OWASP/CWE metadata |
| `lib/*.jar` | JARs needed to compile Juliet test cases (servlet-api, commons-lang, commons-codec, javamail) |

### Security taxonomy & RAG

`scripts/security_taxonomy.py` maps categories to guidance files. Known Sonar rules override benchmark filenames, so a cookie flag finding in a CWE-113 file is fixed as a cookie flag problem. Unmatched findings fall back to `"generic"`.

### LLM integration

- **Model**: configured in `scripts/config.py` and served via Ollama REST API (`http://localhost:11434/api/generate`)
- `generate_fixes.py` sends a single-turn, non-streaming request with `stream: false` and a 300 s timeout
- LLM output is accepted only as a single Java statement; compilation gates the patched workspace before evaluation

### SonarQube tokens

The scanner and API scripts read `SONAR_TOKEN` from the environment. Do not commit active tokens.
