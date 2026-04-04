# Helmet Six-Layer Defense Design

Status: Draft (implementation plan)
Owner Epic: `trx-v3rh`
Last updated: 2026-04-04

## 1. Goals

Helmet should provide a modular, reusable defense stack for untrusted AI input/output while staying runtime-agnostic.

Primary goals:
- Complete deterministic protection (Layer 1) with production-grade decode/sanitize semantics.
- Add pluggable Layer 2 scanner backends, including a fast local fine-tuned option.
- Add outbound leak controls (Layers 3/4) as first-class modules.
- Provide Layer 5 integration hooks (governor contracts) without coupling Helmet to host runtimes.
- Provide Layer 6 validators (path/url safety) as reusable pure functions.
- Keep Oqto bus compatibility in the runner adapter, not in Helmet core.

Non-goals:
- Helmet will not own Oqto-specific event transport or persistence.
- Helmet will not enforce global process-wide budgets itself (host runtime responsibility).

---

## 2. High-level architecture

```text
Inbound Untrusted Content
  -> L1 Deterministic Ingestion Gate
  -> L2 Scanner Orchestrator (optional per policy)
  -> Ingest Verdict + Structured Report

Outbound Candidate Content
  -> L3 Outbound Gate
  -> L4 Redaction Pipeline
  -> Outbound Verdict + Structured Report

Runtime-side (host, e.g. oqto-runner)
  -> L5 Governor (global limits + duplicate cache)
  -> Calls Helmet with caller/source metadata

Access APIs (tools/files/network)
  -> L6 Validators (path/url safety)
```

---

## 3. Module boundaries (crates/helmet-core)

Proposed new modules:

- `ingest` (L1 + L2 orchestration)
  - deterministic passes
  - optional scanner pass
  - source-aware fail behavior
- `scanner` (L2)
  - backend traits
  - remote and local backend implementations
  - score/verdict consistency logic
- `outbound_gate` (L3)
  - deterministic leak/exfil/artifact checks
- `redaction` (L4)
  - span-based redactors and pipeline
- `governor_contract` (L5 hook)
  - caller metadata + host callback interfaces
- `access_control` (L6)
  - path and URL validators
- `report` (shared schema)
  - stable structs for findings/verdict/evidence/stats

Keep existing modules and migrate incrementally:
- `preprocess` -> reused by `ingest`
- `heuristics` -> reused by `ingest` and `outbound_gate`
- `policy` -> generic decision/action layer

---

## 4. Layer-by-layer design

## Layer 1: Deterministic ingestion gate

### Required passes (ordered)
1. Unicode normalization + invisible/control stripping
2. Confusable normalization (with language-aware mode)
3. Recursive bounded decode pass:
   - HTML entities (numeric + hex)
   - URL encoding
   - base64/hex candidate decode
4. Decode-rescan pass (new): scan decoded buffers for attacks
5. Obfuscation scoring (entropy, combining marks, bidi, encoded density)
6. Pattern matching (existing heuristics + hardened regex set)
7. Token budget enforcement (model/profile aware)
8. Deterministic thresholding to allow/review/block

### Missing items to complete L1
- Token-aware truncation (not char-count fallback)
- Decode-and-rescan integration with bounded depth/size
- Explicit wallet-drain thresholds (token/char ratio, encoded blob limits)
- Combining-mark flood controls
- Structured deterministic reason codes

### L1 output contract

```rust
pub struct IngestDeterministicResult {
  pub clean_text: String,
  pub verdict: Decision,
  pub score: f32,
  pub reason_codes: Vec<String>,
  pub findings: Vec<Finding>,
  pub stats: DeterministicStats,
}
```

---

## Layer 2: Frontier scanner (pluggable)

### ScannerBackend trait

```rust
pub trait ScannerBackend {
  fn name(&self) -> &'static str;
  fn scan(&self, req: ScannerRequest) -> Result<ScannerResponse, ScannerError>;
}
```

### Backends
- `RemoteLlmBackend`: strongest model path for high-assurance scanning.
- `LocalFineTuneBackend`: low-latency local model path (quick option).

### Local model expectations
- Input: sanitized text + minimal metadata.
- Output: normalized JSON schema:
  - `score` (0-100)
  - `verdict` (allow/review/block)
  - `categories[]`
  - `evidence[]`
  - `rationale`
- Implementation should support a lightweight local runtime (onnx/gguf adapter)
  behind trait boundaries to avoid hard dependency lock-in.

### Orchestration rules
- Only run scanner when policy says required for source.
- Score/verdict consistency override:
  - if score >= block_threshold => block regardless of stated verdict.
- Source-aware fail semantics:
  - high-risk source: fail-closed
  - low-risk source: fail-open

---

## Layer 3: Outbound content gate

Deterministic checks before content leaves system boundaries.

Detection groups:
- Secrets/tokens
- Internal filesystem paths/hostnames
- Prompt-injection artifacts in generated output
- Exfil markers in URLs/markdown image links
- Financial leakage patterns (policy-configurable)

Output:
- verdict, score, findings, optional transformed output via policy

---

## Layer 4: Redaction pipeline

Span-based redactors chained in policy order.

Redactors:
- Secret redactor
- PII redactor (email/phone, personal-domain aware)
- Financial redactor

Pipeline result:
- redacted text
- redaction spans with reason/category
- metrics (count by category)

---

## Layer 5: Runtime governor integration hooks

Helmet does not enforce global limits, but provides host-integration contract.

```rust
pub struct GovernorContext {
  pub caller: String,
  pub source_type: String,
  pub estimated_cost_usd: Option<f64>,
  pub prompt_fingerprint: String,
}

pub enum GovernorDecision { Allow, Reject(String), Cached(String) }

pub trait GovernorHook {
  fn before_call(&self, ctx: &GovernorContext) -> GovernorDecision;
  fn after_call(&self, ctx: &GovernorContext, success: bool);
}
```

Oqto runner can implement:
- spend windows
- call volume limits
- lifetime process cap
- duplicate detection cache

---

## Layer 6: Access-control validators

Provide pure validation primitives:
- Path safety:
  - canonicalization
  - allowed roots
  - symlink escape prevention
  - sensitive filename/extension denylist
- URL safety:
  - scheme restriction (`http/https`)
  - DNS resolution checks
  - private/reserved range blocking
  - common rebinding/bypass denylist

These are library validators only; enforcement location is host runtime.

---

## 5. Shared report schema

Define stable cross-surface schema used by CLI/API/MCP and host runtimes:
- `decision`
- `score`
- `layer`
- `findings[]` (category, severity, span/evidence)
- `stats`
- `latency`
- `policy_action`

This schema is the adapter point for Oqto runner -> canonical bus events.

---

## 6. Oqto integration boundary

Compatibility is ensured in the host adapter (oqto-runner), not Helmet.

Runner responsibilities:
- call Helmet modules for ingress/egress/validators
- apply governor decisions globally
- translate results to Oqto canonical event/message model
- persist audit/security metadata via Oqto pathways

Helmet responsibilities:
- deterministic + scanner decisions
- normalized reports
- zero knowledge of Oqto bus protocol

---

## 7. Test strategy

1. Unit tests per pass/module
2. Regression corpus tests (known attacks + benign controls)
3. Property/fuzz tests:
   - decode parsers
   - regex performance guardrails
   - path/url validators
4. Performance benchmarks for hot-path deterministic checks
5. Cross-surface contract tests (CLI/API/MCP report consistency)

---

## 8. Rollout plan (mapped to trx-v3rh children)

- `trx-v3rh.1`: complete L1 deterministic gate
- `trx-v3rh.2`: L2 scanner framework + local backend
- `trx-v3rh.3`: outbound gate
- `trx-v3rh.4`: redaction pipeline
- `trx-v3rh.5`: access-control validators
- `trx-v3rh.6`: governor contracts
- `trx-v3rh.7`: corpus + fuzzing
- `trx-v3rh.8`: unified public report schema
- `trx-v3rh.9`: this design doc

---

## 9. Open decisions

1. Local scanner runtime: ONNX Runtime vs llama.cpp-style adapter.
2. Default source risk map for fail-open/fail-closed.
3. Which tokenizer(s) to use for budget estimation by default.
4. Redaction defaults: preserve format vs strict placeholder replacement.
5. Evidence retention policy for privacy-sensitive environments.
