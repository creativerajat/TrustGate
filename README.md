# TrustGate

Educational conference demo: **Same Model. Different Architecture.** — showing how system design around an LLM affects whether untrusted retrieved content can influence behavior safely.

**Milestone:** M3 (retrieval + provenance + explicit untrusted-data boundary — **no LLM**, no API key)

## M3 architecture

```text
Retriever
   ↓
Provenance (document_id, source, trust_level, retrieved_at, …)
   ↓
UNTRUSTED DATA  (all retrieved content — benign or malicious)
   ↓
Trust boundary  (<untrusted_document> … DATA_ONLY …)
   ↓
┌─────────────────────┬──────────────────────┐
│ UNGUARDED path      │ GUARDED path         │
│ TRUSTED_BY_ERROR    │ policy inspect +     │
│ no boundary         │ deterministic block  │
└─────────────────────┴──────────────────────┘
```

**No LLM is used in M3.** Deterministic behavior validates the security architecture before introducing an actual model in later milestones.

Retrieved external content is **UNTRUSTED because it is retrieved data**, not because it looks malicious. RAG does not automatically make retrieved content trustworthy.

TrustGate demonstrates **Same Model. Different Architecture.** M0–M3 are fully deterministic and require no external LLM. M4 will introduce a real model (Anthropic) behind a small, swappable provider abstraction, configured via environment variables — never via committed credentials — and without weakening the M3 trust boundary.

Full specification, architecture, requirements, threat model, ADRs, and roadmap: [`SPEC.md`](SPEC.md).

## Requirements

- Python 3.11+ (development uses Python 3.14)
- Dependencies in `requirements.txt`

## Installation

```bash
python -m pip install -r requirements.txt
```

## Run

```bash
python -m uvicorn main:app --reload
```

- Application: [http://127.0.0.1:8000](http://127.0.0.1:8000)
- Health: [http://127.0.0.1:8000/health](http://127.0.0.1:8000/health)

## API

### `GET /health`

Returns `status`, `service`, and `version` (`0.3.0-m3`).

### `POST /ask`

Request:

```json
{
  "query": "Can you summarize this patient's referral for me?",
  "use_malicious_doc": false
}
```

Response includes:

- `query` — echoed user query
- `retrieval` — provenance metadata (`trust_level` is always `UNTRUSTED`)
- `retrieved_document_content` — for expandable UI only (not logged in engineer’s log)
- `unguarded_response`, `guarded_response`, `guarded_blocked`, `audit_event`
- `security_boundary` — `{ "present": true, "type": "UNTRUSTED_DATA", "policy": "DATA_ONLY" }`
- `engineer_log` — structured sections for the UI

#### Example (PowerShell)

```powershell
Invoke-RestMethod -Uri "http://127.0.0.1:8000/ask" -Method Post `
  -ContentType "application/json" `
  -Body '{"query":"Can you summarize this patient''s referral for me?","use_malicious_doc":false}'
```

## Disclaimer

TrustGate is an educational conference demonstration. M3 uses a deterministic retriever and pattern-based instruction detection — not production-grade prompt-injection defense.
