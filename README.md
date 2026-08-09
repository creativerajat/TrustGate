# TrustGate

Educational conference demo: **Same Model. Different Architecture.** — showing how system design around an LLM affects whether untrusted retrieved content can influence behavior safely.

**Milestone:** M2 (deterministic `POST /ask` — no LLM, no API key)

## Requirements

- Python 3.11+ (development uses Python 3.14)
- Dependencies in `requirements.txt`

## Installation

```bash
python -m pip install -r requirements.txt
```

## Run

Use the same Python interpreter that installed dependencies:

```bash
python -m uvicorn main:app --reload
```

Do not rely on a standalone `uvicorn` on `PATH` if it points at a different Python version.

- Application: [http://127.0.0.1:8000](http://127.0.0.1:8000)
- Health: [http://127.0.0.1:8000/health](http://127.0.0.1:8000/health)

## API

### `GET /health`

```json
{
  "status": "ok",
  "service": "TrustGate",
  "version": "0.2.0-m2"
}
```

### `POST /ask`

Request:

```json
{
  "query": "Can you summarize this patient's referral for me?",
  "use_malicious_doc": false
}
```

Response (benign): `guarded_blocked` is `false`, `audit_event` is `null`.

Response (malicious): guarded path returns a blocked message, `guarded_blocked` is `true`, and `audit_event` is populated.

#### Example (PowerShell)

```powershell
Invoke-RestMethod -Uri "http://127.0.0.1:8000/ask" -Method Post `
  -ContentType "application/json" `
  -Body '{"query":"Can you summarize this patient''s referral for me?","use_malicious_doc":false}'
```

```powershell
Invoke-RestMethod -Uri "http://127.0.0.1:8000/ask" -Method Post `
  -ContentType "application/json" `
  -Body '{"query":"Can you summarize this patient''s referral for me?","use_malicious_doc":true}'
```

## UI (M2)

The conference UI is unchanged visually. **RUN TRUSTGATE** calls `POST /ask` and renders the server response (unguarded panel, guarded panel, engineer's log, blocked badge).

Later milestones add real documents in the pipeline, Anthropic integration, and TrustGate security controls.

## Disclaimer

TrustGate is an educational conference demonstration. M2 uses deterministic mocks, not a live model.
