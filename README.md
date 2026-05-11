# MineCookieChecker

Safe, auditable HTTP cookie validation tool for minecraft.net.

> **Legal Notice:** This tool is intended **exclusively** for authorised security auditing by account owners or individuals with explicit written consent. Any use for credential stuffing, unauthorised access, or violation of Minecraft/Mojang Terms of Service is **strictly prohibited**. All runs are logged to a local audit database.

---

## Architecture

```
src/minecookiechecker/
├── __init__.py          # Package metadata
├── cli.py               # Click CLI entry-point
├── config.py            # Settings from env vars / CLI flags
├── consent.py           # Mandatory consent prompts and file-based consent
├── database.py          # SQLAlchemy audit log (SQLite)
├── models.py            # Domain models (CookieCandidate, ValidationResult)
├── output.py            # JSON / CSV / Rich table formatters
├── parser.py            # Cookie extraction from logs and cookies.txt
├── validator.py         # Async cookie validation via httpx
└── web/
    ├── app.py           # FastAPI web UI
    └── templates/
        └── index.html   # Single-page web interface
```

### Data flow

1. **Parse** cookies from logs directory or cookies.txt file
2. **Deduplicate** and normalise into `name=value` pairs
3. **Validate** each cookie with a safe HTTP GET to `minecraft.net/en-us/profile` (no login flows, no form submissions)
4. **Interpret** response (200 = valid, 302→login = invalid, 401 = invalid, 403 = expired)
5. **Output** results as JSON, CSV, or human-readable Rich table
6. **Audit** every run in local SQLite database

---

## Quick Start

### Prerequisites

- Python 3.10+
- pip

### Install

```bash
pip install -e ".[dev]"
```

### Run Tests

```bash
pytest tests/ -v --tb=short --cov=minecookiechecker
```

### Lint

```bash
ruff check src/ tests/
```

---

## CLI Usage

### Scan logs directory (dry run)

```bash
minecookiechecker scan --mode logs --path ./logs --dry-run --consent-file consent.txt
```

### Scan cookies.txt file

```bash
minecookiechecker scan --mode file --file ./cookies.txt --output results.json --format json --consent-file consent.txt
```

### CSV output

```bash
minecookiechecker scan --mode file --file ./cookies.txt --format csv --consent-file consent.txt
```

### Quick dry-run

```bash
minecookiechecker run --dry-run
```

### Start web UI

```bash
minecookiechecker serve --port 8080
```

### Consent file format

Create a file with `CONSENT_GRANTED` on the first line:

```
CONSENT_GRANTED
Operator: your-name
Date: 2024-06-15
Purpose: Authorised security audit
```

---

## Environment Variables

| Variable | Default | Description |
|---|---|---|
| `MC_CHECKER_CONCURRENCY` | `5` | Max concurrent validation requests |
| `MC_CHECKER_RATE_LIMIT` | `1` | Requests per second per domain |
| `MC_CHECKER_TIMEOUT_MS` | `5000` | HTTP request timeout in ms |
| `MC_CHECKER_DB_PATH` | `./data/audit.db` | Path to SQLite audit database |
| `MC_CHECKER_ENCRYPTION_PASSPHRASE` | *(none)* | Optional passphrase for DB encryption |

---

## Exit Codes

| Code | Meaning |
|---|---|
| `0` | Success (no actionable cookies found) |
| `1` | General error |
| `2` | Consent not provided |
| `3` | Validation failures found (valid cookies detected) |

---

## Docker

### One-line run

```bash
docker compose up --build checker-web
```

### CLI via Docker

```bash
docker compose run --rm checker-cli scan --mode logs --path /app/logs --dry-run --consent-file /app/consent.txt
```

### Build image only

```bash
docker build -t minecookiechecker .
```

---

## Web UI

Start with `minecookiechecker serve --port 8080` or `docker compose up checker-web`.

- Visit `http://localhost:8080`
- **Consent checkbox is mandatory** before any check runs
- Supports Cookie header string, cookies.txt path, and logs directory scanning
- Results displayed as JSON in the browser

### curl examples

```bash
# Check a cookie header string
curl -X POST http://localhost:8080/check \
  -F "consent=yes" \
  -F "mode=header" \
  -F "cookie_input=MC_SESSION=abc123; MUID=def456" \
  -F "dry_run=true"

# View audit history
curl http://localhost:8080/history
```

---

## Production Deployment

### Minimal cloud deploy

1. Build the Docker image and push to your registry
2. Set environment variables for concurrency, rate limits, and DB path
3. Mount a persistent volume for `/app/data` (audit database)
4. Expose port 8080 for the web UI (behind TLS termination)
5. Use `--consent-file` for automated pipelines

### Security checklist

- [ ] TLS termination in front of the web UI
- [ ] Restrict network access to the web UI (internal only)
- [ ] Mount audit DB on encrypted persistent volume
- [ ] Set `MC_CHECKER_ENCRYPTION_PASSPHRASE` for DB encryption
- [ ] Review audit logs regularly
- [ ] Run with least-privilege user (Dockerfile uses non-root `checker` user)
- [ ] Do not expose cookie values in production logs (default: redacted)
- [ ] Rate limiting configured to prevent abuse

---

## Security & Legal Checklist

- [x] Mandatory consent prompt before any network I/O
- [x] Audit log records operator identity, consent method, and run metadata
- [x] Cookie values redacted by default in all output
- [x] `--no-redact` flag required for debugging (explicit opt-in)
- [x] No credential stuffing, login flows, or form submissions
- [x] Rate limiting and concurrency controls (configurable)
- [x] No transmission of cookies to third parties
- [x] `--consent-file` option for automation pipelines
- [x] Web UI requires consent checkbox before any check
- [x] Non-root container user
- [x] Clear exit codes for automation

---

## Storm Review: Production Pitfalls & Mitigations

1. **Rate limiting bypass under high concurrency** – The aiolimiter token bucket is per-process. In multi-instance deployments, total request rate may exceed intended limits. *Mitigation:* Use a shared rate limiter (Redis-based) or deploy a reverse proxy with global rate limiting.

2. **False positives from CDN/WAF responses** – Cloudflare or Akamai may return 200 with a challenge page instead of actual profile content. *Mitigation:* Inspect response body for known challenge page markers (e.g. `cf-challenge`, `captcha`). Add response body heuristics to `_interpret_response`.

3. **Cookie scope mismatch** – Cookies extracted from logs may belong to subdomains (e.g., `api.minecraft.net` vs `www.minecraft.net`) and fail validation on the wrong host. *Mitigation:* Parse and respect domain attributes from Set-Cookie headers; validate against the correct subdomain.

4. **Audit DB corruption under concurrent writes** – SQLite has limited concurrency. Multiple simultaneous runs writing to the same DB can cause locks or corruption. *Mitigation:* Use WAL mode (`PRAGMA journal_mode=WAL`), or migrate to PostgreSQL for multi-user deployments.

5. **Legal liability from misconfigured automation** – A `--consent-file` without proper access controls could be used to bypass consent in unauthorised pipelines. *Mitigation:* Log the full consent file path and hash in the audit record. Require the consent file to be owned by the same user running the tool. Add file permission checks.

---

## License

MIT
