# Aegis upgrade roadmap

This roadmap is ordered by security dependency, not by tool popularity. A phase
is complete only after implementation, tests, migration checks where needed, and
documented evidence have passed. It does not authorize scans outside an
operator-approved immutable scope.

## Current baseline

Phases 0–15.3 are complete. Phase 16 has a committed security foundation and an
uncommitted Playwright executor vertical slice. The executor is disabled by
default and has not run against a real browser on this macOS 12 host because no
supported Chromium runtime is installed.

## Phase 16 — Controlled client-side verification

### 16.1: Execution contract and fail-closed browser lifecycle

Status: in progress.

- Preserve typed proposal, Evidence lineage, mandatory persisted approval, and
  the no-secret/no-arbitrary-command boundary in ADR-0008.
- Launch a new ephemeral browser context for each candidate and control run.
- Permit same-origin navigation only; block cross-origin requests and forbid
  user-profile, storage-state, cookie, token, or credential reuse.
- Resolve only repository-owned probe identifiers; an LLM provides no payload,
  selector, command, CSRF value, or browser script.
- Collect bounded, redacted browser evidence and deterministic hashes.

Exit criteria: unit tests cover refusal paths; a controlled Linux or
supported-browser runner proves an isolated candidate/control execution.

### 16.2: Persisted control-plane integration

Status: planned; depends on 16.1.

- Add revisioned storage and migrations for browser verification action, run,
  and redacted evidence metadata.
- Bind every run to a WebResource, Hypothesis, Evidence, ResearchAction,
  ActionApproval, budget entry, and report manifest.
- Add strict localhost API/CLI/UI lifecycle views. Approval and revalidation
  remain server-side; a client boolean is never authority.
- Rebuild derived state through existing builders and retain the rule that a
  browser executor cannot create a Finding.

Exit criteria: migration round-trip and same-session lineage tests; approval
revocation, cancellation, budget exhaustion, and secret-redaction regressions.

### 16.3: Deterministic verification and controlled proof

Status: planned; depends on 16.2.

- Add candidate/control comparison rules for safe browser observables.
- Run only the sealed, versioned probe inventory in isolated lab or staging.
- Require a deterministic Verification Engine decision before creating a
  Finding; inconclusive and rejected outcomes remain explicit.

Exit criteria: reproducible controlled-lab proof, no external browser egress,
no secret in exports, and a report manifest that verifies.

## Phase 17 — Passive and network intelligence connectors

Status: planned; starts only after Phase 16.2 is stable.

Priority connectors are HTTP/TLS/DNS enrichment and offline traffic analysis:

- `httpx`, technology fingerprinting, WAF detection, and TLS analysis;
- DNS/asset enrichment with fixed scope and no automatic domain expansion;
- PCAP imports from Zeek, Suricata, or tshark as offline artifacts;
- scanner-result imports before any new active scanner execution.

Each connector must use `tool-integration-v1`: closed profiles, deterministic
arguments, bounded output, immutable artifacts, parser/mapper provenance,
policy/approval checks, sanitized fixtures, and generic UI metadata. The model
selects semantic capabilities only.

Exit criteria: no connector can execute a shell string, expand scope, create a
Finding, or expose secrets through the API, LLM context, reports, or UI.

## Phase 18 — Production hardening

Status: planned; independent deployment work after the research loop is stable.

- PostgreSQL validation and operational migrations;
- authenticated multi-user operator control plane and audit identities;
- encrypted secret/evidence storage strategy and key lifecycle;
- DNS pinning/rebinding protections, distributed rate limits, observability,
  backups, and deployment runbooks.

Exit criteria: threat-model review, restore drill, authenticated authorization
tests, database migration validation, and deployment smoke proof.

## Explicitly deferred

Credential attacks, arbitrary exploitation frameworks, unrestricted Nmap/NSE,
wireless/RFID/SDR operations, password spraying, and arbitrary payloads are not
autonomous capabilities. They require a separately approved design with a new
risk class, explicit operator approval per action, bounded scope, and dedicated
controlled-environment evaluation.
