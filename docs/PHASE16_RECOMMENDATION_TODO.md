# Phase 16.4–16.5 implementation TODO

This document turns the client-verification recommendation request into
implementation gates. Core deterministic recommendation and sealed payload
metadata landed in commit `dad99ef`; unchecked items remain release gates.

## Non-negotiable boundaries

- Recommendations consume persisted, same-session evidence only.
- Deterministic rules classify the result before optional explanation/reasoning.
- A recommendation has no execution authority. Accepting a recommendation only
  creates a new `ResearchAction`; the normal approval, scope, policy, and budget
  gates run again before a browser or HTTP operation.
- Cookies, credentials, CSRF values, bearer headers, browser storage, and raw
  secret-bearing console/network data never enter the recommendation, model
  context, API response, report, or manifest.
- Unsupported context, source/sink, framework, sanitizer, and exploitability
  are represented as `UNKNOWN`, never inferred as facts.

## 16.4-A: Domain and persistence

- [x] Add `VerificationRecommendation` entity and migration.
- [x] Add `RecommendationVerdict`: `CONFIRMED`, `REJECTED`, `INCONCLUSIVE`,
  `PARTIALLY_CONFIRMED`, `NEEDS_ADDITIONAL_VERIFICATION`.
- [x] Add bounded vulnerability class, injection context, confidence, reasoning,
  evidence references, remediation, and recommended-action enums.
- [x] Add a structured `SuggestedProbe`, not a free-form command or payload.
- [x] Enforce same-session references to ClientVerificationRun, ResearchAction,
  WebResource, Hypothesis/Finding, Evidence, and recommendation acceptance.
- [x] Preserve report-safe hashes and semantic references only; no DOM body,
  session secret, or raw token persistence.

## 16.4-B: Deterministic classification

- [x] Implement a rule table before LLM/heuristic explanation.
- [x] Candidate execution observed + control execution absent + valid lineage
  produces an execution differential.
- [x] Candidate reflection observed + execution absent produces reflection only,
  never a confirmed XSS verdict.
- [x] Equal candidate/control observations produce rejected or inconclusive
  results according to evidence completeness.
- [x] Missing candidate/control/lineage evidence produces `INCONCLUSIVE` or
  `NEEDS_ADDITIONAL_VERIFICATION`, never a fabricated context or sink.
- [ ] Classify reflected, stored, and DOM client-side behavior separately where
  evidence supports the distinction; otherwise retain `UNKNOWN`.

## 16.4-C: Recommendation policy

- [x] Map verdicts to minimal actions: `NO_ACTION`, `CLOSE_AS_REJECTED`,
  `COLLECT_MORE_EVIDENCE`, `RUN_ADDITIONAL_VERIFICATION`, `CREATE_FINDING`,
  `UPDATE_FINDING`, `REMEDIATE`, or `MANUAL_REVIEW`.
- [ ] Require a grounded reason for every suggested probe and remediation.
- [ ] Include remediation only where vulnerability class/context evidence
  supports it; otherwise recommend manual review or evidence collection.
- [x] Mark all new active verification recommendations as requiring approval.
- [ ] Do not propose repeated probes after a differential verification failed
  unless new grounded evidence changes the context or hypothesis.

## 16.4-D: API, report, and acceptance path

- [x] `GET /client-verifications/{run_id}/recommendation`.
- [x] `GET /sessions/{session_id}/recommendations` with bounded pagination.
- [x] `POST /recommendations/{id}/request-action` creates a new action only;
  it must not invoke Playwright, HTTP, or a tool adapter.
- [ ] Report and manifest sections separate Evidence, Interpretation, Verdict,
  Recommended Next Step, Suggested Verification, Remediation, and Confidence.
- [ ] Add UI cards only after API schemas and redaction tests are stable.

## 16.5: Generated payload/proof layer

- [x] Add `GeneratedPayload` persistence only for a confirmed, evidence-grounded
  vulnerability result.
- [x] Use a closed, versioned registry of inert-canary proof templates keyed by
  confirmed context; no free-form model payload is executable.
- [x] Store purpose, target parameter reference, context, expected candidate and
  control signals, safety class, template version/hash, and approval requirement.
- [ ] Return no generated proof when context, source/sink, encoding, or browser
  observations are not sufficiently evidenced.
- [ ] Acceptance creates a fresh action and repeats validation; generation and
  acceptance must never execute the proof directly.

## Required tests before declaring completion

- [x] Positive and negative candidate/control differential cases.
- [ ] Missing, malformed, tampered, and cross-session evidence lineage.
- [x] Reflection without execution; equal candidate/control; incomplete browser
  run; unknown context; CSP/sanitization evidence only.
- [ ] No automatic browser/HTTP/tool execution from generation or acceptance.
- [ ] Fresh approval, scope, policy, budget, cancellation, and action blocking.
- [ ] API schema/unknown-field, pagination, XSS escaping, and secret-redaction.
- [x] Migration upgrade/downgrade/preservation.
- [ ] Controlled supported-browser proof after the full offline gate passes.
