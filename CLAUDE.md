# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this project does

This is an automated security vulnerability remediation pipeline for Java code. It:
1. Compiles random samples from the NIST Juliet Java test suite into `test_cases/`
2. Scans them with SonarQube (static analysis)
3. Fetches detected vulnerabilities/hotspots from the SonarQube API and enriches them with rule metadata
4. Classifies each finding into a security category, loads a matching RAG knowledge document, and sends a structured prompt to a local LLM (DeepSeek via Ollama) to generate a minimal fix
5. Patches the vulnerable source file in-place (original backed up to `backups/`)

`evaluate.py` is referenced in `scripts/pipeline.py` but **does not exist yet** — it is the missing Step 3.

## Prerequisites

- Docker (for SonarQube + PostgreSQL)
- `sonar-scanner` CLI in PATH
- `javac` (Java 11+) in PATH
- [Ollama](https://ollama.com/) running locally with `deepseek-coder:6.7b` pulled
- Juliet test suite source at `d:/bachekor/test_cases/` (compiled support classes at `d:/bachekor/test_cases/bin/support_classes`)

## Commands

### Start SonarQube
```bash
docker compose up -d
# SonarQube available at http://localhost:9000 (admin/admin on first run)
```

### Prepare test cases (run from repo root)
```bash
python setup_bad_cases.py          # 200 random Juliet cases (default)
python setup_bad_cases.py --n 50   # custom count
```
This clears `test_cases/`, selects N `*_01.java` files from the Juliet suite, compiles each one, and places the result in `test_cases/CWEXX_NNN/{src,classes}/`.

### Run SonarQube scan (run from repo root)
```bash
sonar-scanner
```
Uses `sonar-project.properties`. The scanner token and project key are `sard_cases`.

### Run the pipeline (run from `scripts/` directory)
```bash
cd scripts
python pipeline.py        # runs fetch → generate_fixes → evaluate (evaluate missing)
python fetch_issues.py    # Step 1 only: pull findings → reports/security_issues.json
python generate_fixes.py  # Step 2 only: apply LLM fixes to test_cases/
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
                               ├─ extract_code()    → source file ± 8 lines context
                               └─ POST Ollama API   → patch source, backup to backups/
```

### Key files

| File | Role |
|------|------|
| `setup_bad_cases.py` | Selects & compiles Juliet test cases |
| `sonar-project.properties` | SonarQube project config (key: `sard_cases`) |
| `docker-compose.yaml` | SonarQube + PostgreSQL services |
| `scripts/fetch_issues.py` | Pulls vulnerabilities & hotspots, enriches with rule metadata |
| `scripts/generate_fixes.py` | LLM-based auto-remediation, writes patched files |
| `scripts/secuirty_taxomomy.py` | **Filename has a typo** — the module is imported as `security_taxonomy` in `generate_fixes.py`, which will fail unless the file is renamed |
| `knowledge/*.txt` | Per-category RAG context (injection, cryptography, xss, ssrf, path_traversal, authentication, deserialization, generic) |
| `reports/security_issues.json` | Intermediate output: normalised list of findings with OWASP/CWE metadata |
| `lib/*.jar` | JARs needed to compile Juliet test cases (servlet-api, commons-lang, commons-codec, javamail) |

### Security taxonomy & RAG

`scripts/secuirty_taxomomy.py` maps category names → OWASP label + keyword list + knowledge file path. `generate_fixes.py` uses keyword matching on `message + rule` to classify each finding, then loads the matching `knowledge/` file as additional context in the LLM prompt. Unmatched findings fall back to the `"generic"` category.

### LLM integration

- **Model**: `deepseek-coder:6.7b` via Ollama REST API (`http://localhost:11434/api/generate`)
- `generate_fixes.py` sends a single-turn, non-streaming request with `stream: false` and a 300 s timeout
- The response is expected to be raw Java code only (no markdown). It replaces exactly the vulnerable line in the source file; the original line is preserved in `backups/<filename>.bak`

### SonarQube tokens

`fetch_issues.py` and `sonar-project.properties` each contain hardcoded SonarQube tokens. These are local-only tokens for a private Docker instance and are not secrets in the traditional sense, but should be replaced if the SonarQube instance is recreated.
