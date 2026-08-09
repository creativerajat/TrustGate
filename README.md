# TrustGate

Educational conference demo: **Same Model. Different Architecture.** — showing how system design around an LLM affects whether untrusted retrieved content can influence behavior safely.

**Milestone:** M1 (static frontend — mock data only, no LLM)

## Requirements

- Python 3.11+ recommended
- Dependencies in `requirements.txt`

## Installation

```bash
pip install -r requirements.txt
```

## Run

```bash
uvicorn main:app --reload
```

Open [http://127.0.0.1:8000](http://127.0.0.1:8000).

### M1 UI checks

- Three panels (unguarded / guarded / engineer's log)
- Editable query, benign vs malicious document toggle, **RUN TRUSTGATE**
- Loading messages while mock run executes
- Malicious mock shows guarded **BLOCKED** badge and audit JSON in the log

Later milestones add `POST /ask`, `/health`, real documents, and Anthropic integration.
