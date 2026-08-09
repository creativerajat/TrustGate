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

**P8 — Resource-aware design (cost never overrides security)**
Priority order for every design decision, highest first: **security →
correctness → reliability → latency → cost.** Cost and latency optimizations
(e.g. avoiding unnecessary retries, extra model calls, or unnecessarily
capable models) are applied only *after* security, correctness, and
reliability requirements are satisfied — never as a substitute for them. Cost
considerations MUST NOT be used to justify skipping trust classification,
policy inspection, the guarded boundary, fail-closed blocking, or audit
logging. See §7.4 for the full cost-control policy.

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
itself. The actual security mechanism is the combination of trust classification
(`trust_level=UNTRUSTED`), provenance (`RetrievalMeta`), policy inspection
(`inspect_untrusted_document`), context construction (`build_guarded_context` /
`build_unguarded_context`), output validation/fail-closed blocking, and
audit/observability (`create_audit_event`, `engineer_log`) — not the delimiter
text alone. This distinction becomes load-bearing in M4: wrapping text in tags
and sending it to a real LLM is necessary but not sufficient — the surrounding
controls are what make the architecture safe.

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
| M4 | Real LLM integration | **In progress** (M4A + M4A.1 complete) |
| M5 | Adversarial prompt-injection scenarios | Pending |
| M6 | Policy enforcement and output security | Pending |
| M7 | Security observability / audit | Pending |
| M8 | Evaluation / attack benchmark | Pending |
| M9 | Production architecture hardening | Pending |

### M4 design guardrail (summary — full spec in §7)

M4 introduces a real runtime model behind a provider abstraction, configured
by environment variables, without weakening the M3 trust boundary. Local
development defaults to **Ollama**; **Anthropic** remains optional. See §7.

---

## 7. M4 — Runtime LLM Architecture

TrustGate M4 integrates a real runtime LLM on top of the M3 security pipeline
without replacing retrieval, provenance, trust classification, policy inspection,
fail-closed blocking, or audit observability.

> **Terminology note:** the models available inside Cursor (e.g. Sonnet 5 High,
> Opus 5 High, GPT-5.6 Sol Medium, Grok 4.5 High Fast, Composer 2.5 Fast) are
> **coding/agent models used to develop TrustGate.** They are **not** the runtime
> model TrustGate calls at request time. TrustGate's runtime provider and model
> are selected independently via environment configuration (`TRUSTGATE_LLM_PROVIDER`,
> `TRUSTGATE_LLM_MODEL`).

### 7.1 Runtime LLM Provider

```text
Application (main.py business logic)
  ↓
LLMProvider abstraction        (interface — no provider-specific code above this line)
  ↓
OllamaProvider  |  AnthropicProvider
  ↓                    ↓
local Ollama         Anthropic API
(localhost:11434)    (ANTHROPIC_API_KEY)
  ↓                    ↓
configured runtime model (TRUSTGATE_LLM_MODEL, see §7.2)
```

Interface (implemented in `llm_provider.py`):

```text
LLMProvider
  └── generate(system_prompt, user_prompt) -> GenerateResult

OllamaProvider(LLMProvider)
  └── HTTP chat API to OLLAMA_BASE_URL (default http://localhost:11434)

AnthropicProvider(LLMProvider)
  └── Anthropic Messages API using TRUSTGATE_LLM_MODEL
```

Business logic (`run_ask_pipeline`, guarded path) calls only `get_llm_provider()`
and `LLMProvider.generate()`. Provider-specific SDK/HTTP code stays inside
provider classes (Principle P7).

**Provider selection:** `TRUSTGATE_LLM_PROVIDER` — `ollama` (default) or
`anthropic`. Unknown values fail safely with a controlled provider-unavailable
result; **no silent fallback** between providers.

### 7.2 Runtime Model Configuration

- `TRUSTGATE_LLM_MODEL` is the single, application-level runtime model name
  (defined once in `llm_provider.py`, overridable via environment).
- Default model with default provider `ollama`: `llama3.2:3b` (small/local-friendly
  for conference-demo development).
- For Anthropic, set e.g. `TRUSTGATE_LLM_MODEL=claude-sonnet-5` in the environment.
- The **same** configured provider/model pair must be used for both guarded and
  unguarded paths when M4B lands — the architecture is the controlled variable,
  not model capability (§7.6).

### 7.3 Credential Security

- `ANTHROPIC_API_KEY` MUST come only from environment configuration.
- Never:
  - hardcode API keys in source
  - put API keys in `index.html`
  - put API keys in `README.md` / `SPEC.md`
  - return API keys through any API response
  - include API keys in `audit_event` or `engineer_log`
  - log API keys (stdout, error messages, tracebacks)
  - commit `.env` files containing real secrets (`.gitignore` already excludes
    `.env*` except `.env.example`)

### 7.4 Cost-Control Principle (Constitution P8)

*"Optimize API cost before optimizing model capability — but never before
security."* Priority order: **security → correctness → reliability → latency
→ cost.** None of the cost-control measures below may be used to skip or
weaken trust classification, the guarded boundary, policy inspection,
fail-closed blocking, or audit logging.

For the conference demo specifically:

- Do not call expensive/high-capability models unnecessarily.
- Use the **same** configured runtime model for both the guarded and unguarded
  comparison so the architecture/trust-boundary remains the only controlled
  experimental variable (see §7.6).
- Avoid unnecessary retries.
- Avoid unnecessary multi-agent or multi-call chains.
- Avoid re-sending the same large context repeatedly where it can be avoided.
- Keep prompts concise.
- Keep retrieved documents small and deterministic (as established in M3).
- Do not introduce embeddings, vector databases, additional agents, or extra LLM
  calls unless they materially improve the demo's ability to make its point.

### 7.5 M4 Incremental Implementation

M4 is split into sub-milestones, each independently testable:

| Sub-milestone | Scope | Status |
|---|---|---|
| **M4A** | Provider abstraction (`LLMProvider`, `AnthropicProvider`) + single guarded benign LLM path | **Complete** |
| **M4A.1** | Provider portability — `OllamaProvider`, env-driven provider selection, Ollama default for local dev | **Complete** |
| **M4B** | Guarded vs. unguarded comparison using the real model on both paths | Pending |
| **M4C** | Output validation and fail-closed behavior on real model output | Pending |
| **M4D** | Latency/cost/reliability hardening (timeouts, fallback behavior — see §7.7) | Pending |

**M4A.1 behavior (current):**

- **Benign guarded path:** exactly **one** runtime LLM call (`LLMProvider.generate`).
- **Malicious / threat detected:** **zero** LLM calls — block before provider.
- **Unguarded path:** still simulated (M4B pending).
- **Provider failure:** controlled `[PROVIDER UNAVAILABLE: …]` response; Engineer's
  Log records provider, model, and fail-safe; no credential leakage; no crash.
- **No cross-provider fallback** (e.g. Anthropic misconfiguration does not switch
  to Ollama).

**M4A MUST be completed before M4B begins.** Do not implement guarded/unguarded
LLM comparison in the same step as initial provider wiring.

### 7.6 Experimental Control

*"Same model, same user query, same retrieved document. The primary experimental
variable is the architecture/trust boundary."*

- The model MUST NOT change between the guarded and unguarded paths.
- The guarded path MUST NOT use a more capable (or otherwise different) model
  than the unguarded path, and vice versa — using a stronger model on the
  guarded side would confound the experiment and misattribute the model's
  capability, rather than the architecture, for any safety difference observed.
- **Unguarded:** query + retrieved document are treated as instruction/trusted
  context (per `build_unguarded_context`, `boundary=NONE`) when sent to the model.
- **Guarded:** query + retrieved document are explicitly treated as untrusted data
  (per `build_guarded_context`, `boundary=DATA_ONLY`) when sent to the model.
- Any observed difference in behavior between the two panels must be attributable
  to the architecture around the model, not to a different model, prompt
  unrelated to the boundary, or inconsistent input.

### 7.7 Demo Reliability (LLM failure fallback)

The conference demo MUST have a deterministic fallback for LLM failures. If the
external provider is unavailable, times out, rejects the request, or exceeds a
configured timeout:

- Do not crash the application.
- Do not expose provider credentials or raw provider error bodies.
- Return a controlled error/fallback state to the UI (consistent with the M2
  error-handling pattern already in `index.html` / `HTTPException` in `main.py`).
- Preserve the Engineer's Log.
- Preserve the security-boundary explanation (`security_boundary` fields must
  still describe the architecture even if the model call failed).
- The fallback response MUST NOT claim that a real LLM security decision occurred
  when it did not — it must be visibly distinguishable from a genuine guarded/
  unguarded model response (e.g. explicit "provider unavailable" state, not a
  silently substituted deterministic answer presented as if the model produced
  it).

### 7.8 Explicit M3 / M4 Boundary

- **M3** = deterministic security architecture simulation. No external LLM calls.
- **M4** = real LLM integration, built on top of the M3 boundary without
  replacing it.
- **M3 MUST remain runnable without an `ANTHROPIC_API_KEY`** — local development
  defaults to Ollama; Anthropic is optional and requires explicit configuration.

---

## 8. Consistency Notes

This document is derived from, and must stay consistent with, `main.py` and
`index.html`. If a future milestone changes the shape of `POST /ask` or the
guarded/unguarded pipeline, update this file in the same change.

As of M4A.1, `main.py` implements the M3 security pipeline plus a guarded benign
runtime LLM path via `LLMProvider` (`OllamaProvider` default, `AnthropicProvider`
optional). M4B–M4D are not implemented.
