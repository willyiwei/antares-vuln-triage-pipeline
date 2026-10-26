# AnTAres Vulnerability Triage Pipeline

A complete, deployable AI-powered vulnerability triage system that integrates Cisco AnTAres into a CI/CD workflow with governance controls, SARIF reporting, audit trails, and a web dashboard.

## What It Does

1. **Scans** — Submits repositories to Cisco AnTAres for AI-powered vulnerability detection
2. **Triages** — Applies governance policy (auto-accept, auto-reject, human review, escalate) based on severity, confidence, CVSS, and CVE status
3. **Reports** — Generates SARIF 2.1.0 reports, JSON summaries, and Markdown reports
4. **Dashboards** — Serves a web UI for reviewing, filtering, and updating findings

## Why This Project

This project demonstrates hands-on experience with:
- **AI security tooling** — Integrating commercial AI security APIs (Cisco AnTAres)
- **Governance & compliance** — Policy-based triage with audit trails
- **Industry standards** — SARIF output, NIST AI RMF alignment, OWASP LLM Top 10
- **Production patterns** — Async API clients, rate limiting, retry logic, config-driven pipelines
- **Full-stack delivery** — CLI, REST API, web dashboard, Docker, CI/CD

## Quick Start

```bash
# Install dependencies
uv sync

# Run a scan (mock mode — no API key needed)
antares-triage scan -r https://github.com/example/repo --mock

# Start the dashboard
antares-triage dashboard --host 127.0.0.1 --port 8181

# Or use the API directly
curl -X POST http://127.0.0.1:8181/api/scan \
  -H "Content-Type: application/json" \
  -d '{"repo_url": "https://github.com/example/repo"}'
```

## Project Structure

```
antares_vuln_triage_pipeline/
├── src/pipeline/
│   ├── cli.py              # CLI entry point (Click)
│   ├── config.py           # Configuration loading (YAML + env vars)
│   ├── models.py           # Pydantic data models
│   ├── antares_client.py   # AnTAres API client with retry/rate-limit
│   ├── governance.py       # Policy engine for triage decisions
│   ├── pipeline.py         # Main orchestrator (scan → triage → report)
│   ├── sarif.py            # SARIF 2.1.0 report generation
│   ├── reporting.py        # Markdown summary + dashboard data
│   └── dashboard_app.py    # FastAPI web dashboard
├── config/
│   └── pipeline.yaml       # Default configuration
├── dashboard/
│   └── index.html          # Dashboard HTML template
├── data/
│   └── sample_repos/       # Sample repo data for testing
├── tests/
│   ├── conftest.py         # Shared fixtures
│   ├── test_governance.py  # Governance policy tests
│   ├── test_pipeline.py    # Pipeline orchestration tests
│   └── test_sarif.py       # SARIF report tests
├── ci/
│   └── github/
│       └── workflows/
│           └── ci.yml      # GitHub Actions CI pipeline
├── docker/
│   └── Dockerfile          # Container image
├── pyproject.toml          # Project metadata & dependencies
└── README.md
```

## Governance Policy

The triage engine applies these rules in order:

1. **Escalation keywords** → `ESCALATE` (RCE, auth bypass, SQLi, etc.)
2. **Auto-reject severities** → `AUTO_REJECT` (configurable)
3. **Auto-accept** → low severity + high confidence + low CVSS
4. **CVE human review** → `HUMAN_REVIEW` (configurable)
5. **High confidence** → `AUTO_ACCEPT`
6. **Low confidence** → `AUTO_REJECT`
7. **Default** → `HUMAN_REVIEW`

## Configuration

Set your AnTAres API key via environment variable:

```bash
export ANTARES_API_KEY="your_key_here"
```

Or edit `config/pipeline.yaml` to adjust scan targets, output paths, and governance thresholds.

## Testing

```bash
uv run pytest tests/ -v
```

## Linting & Type Checking

```bash
uv run ruff check src/ tests/
uv run ruff format --check src/ tests/
uv run mypy src/
```

## Tech Stack

- **Python 3.11+** — Core language
- **FastAPI** — REST API & dashboard
- **Pydantic** — Data validation & models
- **httpx** — Async HTTP client for AnTAres API
- **SARIF 2.1.0** — Industry-standard vulnerability reporting
- **Docker** — Containerized deployment
- **GitHub Actions** — CI/CD pipeline

## License

MIT
