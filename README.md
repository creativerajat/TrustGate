# TrustGate

Educational conference demo: **Same Model. Different Architecture.** — showing how system design around an LLM affects whether untrusted retrieved content can influence behavior safely.

**Milestone:** M4A.1 (runtime LLM via swappable provider — **Ollama default** for local dev; guarded benign path only until M4B)

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

TrustGate demonstrates **Same Model. Different Architecture.** M0–M3 are fully deterministic. M4 adds a real runtime model behind a small provider abstraction (`LLMProvider`), configured via environment variables — never via committed credentials — without weakening the M3 trust boundary.

**Cursor vs TrustGate runtime:** The model you use inside Cursor to edit this repo is a *coding/agent* model. It is **not** automatically available to TrustGate at request time. TrustGate selects its own runtime provider and model via `TRUSTGATE_LLM_PROVIDER` and `TRUSTGATE_LLM_MODEL`.

Full specification, architecture, requirements, threat model, ADRs, and roadmap: [`SPEC.md`](SPEC.md).

## Runtime LLM providers

Local development defaults to **Ollama** (no Anthropic API key required).

### Ollama (default)

1. [Install Ollama](https://ollama.com/) and start the Ollama service.
2. Pull the model you configure, for example: `ollama pull llama3.2:3b`
3. Set environment variables (optional if defaults match):

```bash
TRUSTGATE_LLM_PROVIDER=ollama
TRUSTGATE_LLM_MODEL=llama3.2:3b
OLLAMA_BASE_URL=http://localhost:11434
```

4. Start TrustGate (see **Run** below).

### Anthropic (optional)

To use Anthropic instead of Ollama:

```bash
TRUSTGATE_LLM_PROVIDER=anthropic
TRUSTGATE_LLM_MODEL=claude-sonnet-5
ANTHROPIC_API_KEY=<set in your environment only>
```

Do not commit API keys. TrustGate does **not** fall back from Anthropic to Ollama when credentials are missing — the failure is reported explicitly in the Engineer's Log.

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

Returns `status`, `service`, `version` (`0.4.1-m4a1`), and non-sensitive runtime config (`provider`, `model`). No LLM call is made.

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
