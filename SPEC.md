# TrustGate — Specification & Architecture

This document is TrustGate's spec-driven development (SDD) source of truth: project
constitution, architecture, requirements, threat model, architecture decisions, and
the milestone roadmap. It is consolidated into a single file to match the project's
minimal-footprint convention (`main.py`, `index.html`, `requirements.txt`,
`README.md`, `SPEC.md`).

Runtime source of truth: `main.py` (server) and `index.html` (UI).
Operational instructions: `README.md`.

---

## 1. Constitution — Architectural Principles

These principles are invariant across milestones. Any milestone that would violate
one of them must be redesigned, not shipped.

**P1 — Untrusted data by default**
All externally retrieved content is UNTRUSTED by default — documents, web pages,
RAG chunks, tool results, API responses, uploaded files, third-party content, and
agent-generated external content. Retrieval does not confer authority.

**P2 — Data / instruction separation**
Retrieved content stays in the DATA plane. It must not automatically become
instructions in the CONTROL/INSTRUCTION plane. The architecture must explicitly
represent the boundary between DATA and INSTRUCTIONS.

**P3 — Provenance**
Retrieved content carries provenance metadata sufficient to establish source,
document identity, retrieval context, trust classification, and content type.

**P4 — Policy before authority**
A document does not influence agent behavior merely because it was retrieved.
Instruction-like content found inside retrieved data is treated as data and
evaluated against policy, not obeyed.

**P5 — Fail closed**
If untrusted content attempts an unauthorized action, the guarded architecture
fails closed (blocks) rather than silently executing the instruction.

**P6 — Observability**
Security decisions produce observable events suitable for audit and engineering
diagnosis (see Engineer's Log / `audit_event`).

**P7 — Model-agnostic security**
Security controls do not depend solely on the intelligence, obedience, or safety
behavior of the underlying LLM. The same model must remain safe because of
architecture and controls — not merely because the model follows instructions
correctly. ("Same Model. Different Architecture.")

---

## 2. Architecture (current: M3)

```text
USER
 ↓
QUERY
 ↓
RETRIEVER
 ↓
RETRIEVED DOCUMENT
 ↓
PROVENANCE + TRUST CLASSIFICATION      (always UNTRUSTED)
 ↓
UNTRUSTED DATA BOUNDARY
 ├──────────────────────────────┐
 │                              │
 ▼                              ▼
UNGUARDED PATH              GUARDED PATH
 │                              │
 │ TRUSTED-BY-ERROR             │ DATA-ONLY
 │ (build_unguarded_context)    │ (build_guarded_context)
 ▼                              ▼
LLM CONTEXT                 POLICY CONTROL
(no boundary)              (inspect_untrusted_document)
                                │
                                ▼
                            SIMULATED "LLM"   (M3: deterministic; M4: real model)
                                │
                                ▼
                         OUTPUT VALIDATION / BLOCK
                                │
                                ▼
                           AUDIT EVENT + ENGINEER LOG
```

**Unguarded path** — retrieved content is incorrectly allowed to enter instruction
space (`trust_level=TRUSTED_BY_ERROR`, `boundary=NONE`). This intentionally
demonstrates the architectural failure mode.

**Guarded path** — retrieved content remains explicitly classified as untrusted
data (`trust_level=UNTRUSTED`, `boundary=DATA_ONLY`) and is prevented from
acquiring authority merely by appearing in the retrieved document. A deterministic
policy check (`inspect_untrusted_document`) runs on the DATA before it can reach
model/instruction space; a detected instruction results in a fail-closed block and
an audit event.

**Important distinction:** the `<untrusted_document>…</untrusted_document>`
delimiter is a *representation* of the boundary, not the security mechanism by
itself. The actual security architecture is enforced through policy inspection,
context construction (`build_guarded_context` / `build_unguarded_context`),
output validation, and audit logging around that representation. This distinction
becomes load-bearing in M4: wrapping text in tags and sending it to a real LLM is
necessary but not sufficient — the surrounding controls are what make the
architecture safe.

Current implementation mapping (`main.py`):

| Architecture stage | Function |
|---|---|
| Retriever | `retrieve_document()` |
| Provenance + trust classification | `RetrievalResult` / `RetrievalMeta` (`trust_level` always `UNTRUSTED`) |
| Untrusted data boundary (guarded) | `build_guarded_context()` |
| Untrusted data boundary (unguarded, intentionally absent) | `build_unguarded_context()` |
| Policy control | `inspect_untrusted_document()` |
| Simulated LLM | `simulate_unguarded_response()` / `simulate_guarded_response()` |
| Audit event | `create_audit_event()` |
| Observability | `build_engineer_log()` → `engineer_log` in `POST /ask` |

---

## 3. Requirements

### M3 — Retrieval, provenance, untrusted-data boundary

- **REQ-M3-001**: The system SHALL retrieve a document through a server-side
  retrieval abstraction (`retrieve_document`).
- **REQ-M3-002**: Every retrieved document SHALL be classified as `UNTRUSTED` by
  default, regardless of content.
- **REQ-M3-003**: Retrieved content SHALL carry provenance metadata (document id,
  source, document type, retrieval method, trust level, retrieved-at timestamp).
- **REQ-M3-004**: The system SHALL maintain a distinct representation of retrieved
  content as untrusted data (`build_guarded_context`).
- **REQ-M3-005**: The guarded path SHALL explicitly separate retrieved data from
  instruction/control content (`<untrusted_document>` boundary, `policy=DATA_ONLY`).
- **REQ-M3-006**: The unguarded path SHALL intentionally demonstrate the
  architectural failure mode where retrieved instructions are treated as trusted
  (`build_unguarded_context`, `trust_level=TRUSTED_BY_ERROR`).
- **REQ-M3-007**: The guarded path SHALL detect unauthorized instruction attempts
  from retrieved content (`inspect_untrusted_document`) and fail closed
  (`guarded_blocked=true`, deterministic blocked message).
- **REQ-M3-008**: Security decisions SHALL be observable through an
  engineer/audit log (`engineer_log`, `audit_event`).
- **REQ-M3-009**: The M3 implementation SHALL remain deterministic and SHALL NOT
  require an external LLM.
- **REQ-M3-010**: The security architecture SHALL remain model-agnostic — the
  boundary, policy, and audit logic must not assume a specific model provider.

### Traceability (M0–M2, for context)

- M0: `GET /` serves `index.html` — satisfied.
- M1: three-panel conference UI, benign/malicious toggle — satisfied.
- M2: `POST /ask`, `GET /health`, request validation (empty query → 422) — satisfied.

---

## 4. Security / Threat Model

**Threat:** Indirect prompt injection through retrieved content.

**Attack path:**

```text
Attacker-controlled or compromised document
        ↓
Retriever
        ↓
Retrieved content
        ↓
Agent context
        ↓
Instruction interpretation
        ↓
Unauthorized action / data disclosure
```

**Trust assumption that MUST NOT be made:**
"Retrieved from the enterprise knowledge base" ≠ "trusted instructions."
Retrieval provenance (e.g. `source: Hospital A`) is not a trust signal by itself —
see Principle P1.

**Assets at risk:**

- System instructions
- Secrets / internal configuration (demo: `INTERNAL_KEY`)
- Privileged tools
- Downstream systems
- Sensitive information
- Agent authority (ability to act on the user's/system's behalf)

**M3 controls:**

- Trust classification (`trust_level=UNTRUSTED` for all retrieved content)
- Provenance metadata
- Explicit data/instruction boundary (`build_guarded_context` vs
  `build_unguarded_context`)
- Deterministic policy inspection (`inspect_untrusted_document`)
- Guarded response behavior (fail closed, `BLOCKED_MESSAGE`)
- Audit event (`create_audit_event`, surfaced in `engineer_log`)

**Explicit disclaimer:** M3 is a demonstration architecture. Its pattern-based
detector (`INJECTION_PATTERNS`) is intentionally simple and is **not** a
production-grade prompt-injection defense. Real production defenses (model/output
evaluation, stronger isolation, authorization, retrieval controls, testing, human
oversight) are introduced and evaluated in later milestones (M5–M9).

---

## 5. Architecture Decision Records

### ADR-001 — Explicit Untrusted-Data Boundary

**Status:** Accepted (M3)

**Context:** LLM applications increasingly consume external content through RAG,
tools, APIs, and agents. Retrieved content may contain adversarial instructions
(indirect prompt injection). Relying on the model alone to "know better" is not a
sufficient control.

**Decision:** Retrieved content is classified as `UNTRUSTED` by default and is
kept in a separate representation from instruction/control content
(`build_guarded_context`), independent of the underlying model.

**Rationale:** Security cannot depend solely on model instruction-following. The
architecture must establish an explicit trust boundary that exists before content
reaches model/instruction space, so the same model is safe or unsafe based on the
surrounding architecture (Principle P7).

**Consequences:**

- *Positive:* clearer security model; easier auditing; model-independent
  reasoning; safer RAG architecture; easier policy enforcement.
- *Trade-offs:* additional context construction; additional validation logic;
  possible latency (once a real model is introduced); possible false positives
  from pattern-based detection; additional observability requirements.

---

## 6. Implementation Roadmap

| Milestone | Scope | Status |
|---|---|---|
| M0 | Project skeleton (`main.py`, `index.html`, `GET /`) | **Complete** |
| M1 | Conference UI / deterministic demo (mock data, three panels) | **Complete** |
| M2 | API boundary (`POST /ask`, `GET /health`, request validation) | **Complete** |
| M3 | Retrieval + provenance + untrusted-data boundary | **Complete** |
| M4 | Real LLM integration | **Pending** |
| M5 | Adversarial prompt-injection scenarios | Pending |
| M6 | Policy enforcement and output security | Pending |
| M7 | Security observability / audit | Pending |
| M8 | Evaluation / attack benchmark | Pending |
| M9 | Production architecture hardening | Pending |

### M4 design guardrail (not yet implemented)

M4 introduces a real model (Anthropic). Before/while implementing M4:

- The model provider MUST be isolated behind a small provider abstraction
  (e.g. `LLM Provider → model.generate(...)`), not embedded provider-specific
  logic throughout the application.
- The model name MUST be configurable (single constant, not scattered).
- The API key MUST come from environment configuration — never hardcoded.
- No secrets may enter source code, HTML, README, git history, logs, or audit
  events.
- M4 MUST NOT weaken the M3 trust boundary: `build_guarded_context`,
  `inspect_untrusted_document`, fail-closed blocking, and audit logging must
  continue to gate what reaches the guarded model call.

---

## 7. Consistency Notes

This document is derived from, and must stay consistent with, `main.py` and
`index.html`. If a future milestone changes the shape of `POST /ask` or the
guarded/unguarded pipeline, update this file in the same change.
