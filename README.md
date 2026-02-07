![image](https://github.com/mytechnotalent/tmt/blob/main/tmt.png?raw=true)

## FREE Reverse Engineering Self-Study Course [HERE](https://github.com/mytechnotalent/Reverse-Engineering-Tutorial)

<br>

# Today's Tutorial [February 7, 2026]
## Lesson 103: ARM-32 Course 2 (Part 38 – Pre-Increment Operator)
This tutorial will discuss the pre-increment operator.

-> Click [HERE](https://0xinfection.github.io/reversing) to read the FREE ebook. to read the FREE ebook.

<br>

# TMT — Lightweight Threat Modeling Toolkit

Author: [Kevin Thomas](mailto:ket189@pitt.edu)

An open-source production-ready, release-cycle threat modeling loop that detects logic bugs (replay attacks, race conditions, token/invite abuse) through pattern-based scanning and optional LLM-powered deep review.

Built for startup teams who need fast, repeatable security checks without heavyweight tools.

---

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    run_threat_model.py                      │
│                     (CLI Entry Point)                       │
├─────────────────────────────────────────────────────────────┤
│                    ThreatModelRunner                        │
│              (Orchestrates the full loop)                   │
├──────────────────────┬──────────────────────────────────────┤
│  Pattern Scanners    │  LLM Reviewer (optional)             │
│  ┌────────────────┐  │  ┌──────────────────────────────┐    │
│  │ ReplayScanner  │  │  │ HuggingFace (free, default)  │    │
│  │ RaceCondition  │  │  │ OpenAI (GPT-4 / GPT-4o)      │    │
│  │ TokenAbuse     │  │  │ Anthropic (Claude)           │    │
│  │ AuthSession    │  │  │ Ollama (local, via base_url) │    │
│  │ APIRoute       │  │  └──────────────────────────────┘    │
│  └────────────────┘  │  Structured prompts enforce JSON     │
├──────────────────────┴──────────────────────────────────────┤
│                    ReportGenerator                          │
│              Markdown + JSON output files                   │
└─────────────────────────────────────────────────────────────┘
```

---

## Quick Start

### 1. Install

```bash
cd TMT
pip install -e ".[dev]"
```

### 2. Scan Your Codebase (Pattern-based Only)

```bash
python run_threat_model.py --target /path/to/your/api --project-name "my-api"
```

### 3. Scan + LLM Review (Free with Hugging Face)

```bash
export HF_TOKEN="hf_..."   # Optional: get a free token at huggingface.co/settings/tokens
python run_threat_model.py \
  --target /path/to/your/api \
  --project-name "my-api" \
  --llm
```

### 4. Scan + LLM Review (OpenAI)

```bash
export TMT_LLM_API_KEY="sk-..."
python run_threat_model.py \
  --target /path/to/your/api \
  --project-name "my-api" \
  --llm \
  --llm-provider openai \
  --llm-model gpt-4
```

### 4. Use a Config File

```bash
python run_threat_model.py --target /path/to/your/api --config config.yaml
```

### 5. Run Tests

```bash
pytest tests/ -v --tb=short
```

---

## What It Detects

### Replay Attacks
| Finding                                    | Severity | CWE     |
| ------------------------------------------ | -------- | ------- |
| POST without idempotency key               | Medium   | CWE-294 |
| Missing request timestamp validation       | Low      | CWE-294 |
| Token used without single-use invalidation | High     | CWE-294 |

### Race Conditions
| Finding                           | Severity | CWE     |
| --------------------------------- | -------- | ------- |
| Non-atomic read-modify-write      | High     | CWE-362 |
| TOCTOU check-then-act pattern     | High     | CWE-367 |
| Unguarded concurrent redemption   | Critical | CWE-362 |
| Shared mutable state without sync | Medium   | CWE-362 |

### Token & Invite Abuse
| Finding                                         | Severity | CWE     |
| ----------------------------------------------- | -------- | ------- |
| Token generation without rate limiting          | High     | CWE-799 |
| Predictable token generation (UUID1, weak PRNG) | Critical | CWE-330 |
| Token created without expiration                | High     | CWE-613 |
| Invite token allows multiple redemptions        | High     | CWE-841 |
| No token revocation on logout                   | High     | CWE-613 |

### Auth & Session
| Finding                                    | Severity | CWE     |
| ------------------------------------------ | -------- | ------- |
| Route missing authentication               | High     | CWE-306 |
| Insecure session cookie configuration      | High     | CWE-614 |
| Missing CSRF protection                    | Medium   | CWE-352 |
| Weak password hashing (MD5/SHA1)           | Critical | CWE-916 |
| Session not regenerated after login        | High     | CWE-384 |
| Object access without authorization (IDOR) | Critical | CWE-639 |

### API Route Security
| Finding                           | Severity | CWE     |
| --------------------------------- | -------- | ------- |
| Missing input validation          | Medium   | CWE-20  |
| Missing rate limiting             | Medium   | CWE-770 |
| Verbose error details exposed     | Medium   | CWE-209 |
| Overly permissive CORS (wildcard) | High     | CWE-942 |
| Admin endpoint without role check | Critical | CWE-269 |
| Mass assignment vulnerability     | Critical | CWE-915 |

---

## LLM Review Prompts & Workflow

TMT includes four battle-tested prompt templates designed to maximize signal and minimize noise:

### Available Templates

| Template        | Focus                                                                 |
| --------------- | --------------------------------------------------------------------- |
| `api_route`     | Auth, input validation, rate limiting, CORS, IDOR, mass assignment    |
| `auth_session`  | Password storage, session fixation, JWT validation, MFA bypass, OAuth |
| `logic_bug`     | Replay attacks, race conditions, TOCTOU, double-spend, state machines |
| `comprehensive` | All categories in a single pass                                       |

### How Prompts Work

1. **Structured persona**: Security engineer context reduces hallucination
2. **Systematic checklist**: Forces the LLM to check each vulnerability class
3. **Evidence-based**: Only reports findings with concrete code references
4. **JSON output**: Enforced schema enables automated processing
5. **Confidence threshold**: Filters findings below 70% confidence

### Using LLM Review Independently

```python
from tmt.llm.prompts import PromptLibrary
from tmt.llm.reviewer import LLMReviewer
from tmt.config import LLMConfig

# Build prompts for manual use (e.g., paste into ChatGPT)
library = PromptLibrary()
prompts = library.build_prompt("logic_bug", open("my_api.py").read())
print(prompts["system"])
print(prompts["user"])

# Or use the automated reviewer (free with Hugging Face)
config = LLMConfig(enabled=True, provider="huggingface", model="Qwen/Qwen2.5-72B-Instruct")
reviewer = LLMReviewer(config)
review = reviewer.review_file("my_api.py", open("my_api.py").read(), "comprehensive")
for finding in review.findings:
    print(f"[{finding.severity.value}] {finding.title}")
```

---

## CI/CD Integration

### Exit Codes

| Code | Meaning                             |
| ---- | ----------------------------------- |
| 0    | No critical or high findings        |
| 1    | High severity findings detected     |
| 2    | Critical severity findings detected |

### GitHub Actions Example

```yaml
name: Threat Model
on: [pull_request]

jobs:
  threat-model:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: "3.11"
      - run: pip install -e ".[dev]"
      - run: |
          python run_threat_model.py \
            --target ./src \
            --project-name "${{ github.repository }}" \
            --output-dir ./security-reports
      - uses: actions/upload-artifact@v4
        if: always()
        with:
          name: threat-model-report
          path: ./security-reports/
```

### With LLM Review in CI

```yaml
      - run: |
          python run_threat_model.py \
            --target ./src \
            --project-name "${{ github.repository }}" \
            --llm
        env:
          HF_TOKEN: ${{ secrets.HF_TOKEN }}
```

---

## Recommended Release Workflow

Run this loop every release to catch logic bugs before they ship:

```
1. Pre-PR (developer):
   └─ python run_threat_model.py --target ./src

2. CI Pipeline (automated):
   └─ Pattern scan + LLM review on every PR
   └─ Block merge if exit code > 0

3. Pre-Release (security lead):
   └─ Full scan with comprehensive LLM review
   └─ Review Markdown report for new findings
   └─ Track findings in issue tracker

4. Post-Release:
   └─ Archive report in security/ directory
   └─ Compare finding counts to previous release
```

---

## Project Structure

```
TMT/
├── run_threat_model.py          # CLI entry point
├── config.yaml                  # Sample configuration
├── setup.py                     # Package setup
├── requirements.txt             # Dependencies
├── tmt/
│   ├── __init__.py
│   ├── config.py                # YAML config loader
│   ├── models.py                # Data models (Finding, ScanResult, etc.)
│   ├── runner.py                # Threat model loop orchestrator
│   ├── scanners/
│   │   ├── base_scanner.py      # Shared scanner framework
│   │   ├── replay_scanner.py    # Replay attack detection
│   │   ├── race_condition_scanner.py
│   │   ├── token_abuse_scanner.py
│   │   ├── auth_session_scanner.py
│   │   └── api_route_scanner.py
│   ├── llm/
│   │   ├── prompts.py           # Structured prompt templates
│   │   └── reviewer.py          # Multi-provider LLM integration
│   └── reports/
│       └── generator.py         # Markdown + JSON report generator
└── tests/
    ├── fixtures/
    │   ├── vulnerable_api.py    # Intentionally insecure (for testing)
    │   └── secure_api.py        # Properly secured (for false positive testing)
    ├── test_scanners.py
    ├── test_llm_reviewer.py
    └── test_runner.py
```

---

## Configuration Reference

| Setting                      | Default                      | Description                                 |
| ---------------------------- | ---------------------------- | ------------------------------------------- |
| `project_name`               | `unnamed-project`            | Project identifier for reports              |
| `target_dirs`                | `[src, app, api]`            | Directories to scan                         |
| `file_extensions`            | `[.py, .js, .ts]`            | File types to include                       |
| `exclude_dirs`               | `[node_modules, .venv, ...]` | Directories to skip                         |
| `scanner.enabled`            | `true`                       | Enable pattern scanning                     |
| `scanner.severity_threshold` | `low`                        | Minimum severity to report                  |
| `llm.enabled`                | `false`                      | Enable LLM review                           |
| `llm.provider`               | `huggingface`                | LLM provider (huggingface/openai/anthropic) |
| `llm.model`                  | `Qwen/Qwen2.5-72B-Instruct`  | Model identifier                            |
| `llm.temperature`            | `0.1`                        | Low for deterministic results               |
| `report.output_dir`          | `reports`                    | Report output directory                     |
| `report.formats`             | `[markdown, json]`           | Output formats                              |

---

## License

MIT
