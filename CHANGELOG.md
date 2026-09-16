# Aegis implementation progress

This file records completed phases and commands that were actually executed. Planned work is not reported as completed.

## Unreleased — Phase 16 Client-Side Verification Foundation

- Added ADR-0008 and typed client-verification proposal/validator boundaries:
  evidence grounding, mandatory persisted approval, isolated lab/staging only,
  same-origin execution, no external egress, closed probe identifiers, and a
  candidate/control model.
- Added a disabled-by-default Playwright executor vertical slice with a fresh
  browser context per candidate/control run, same-origin request interception,
  in-memory CSRF observation, and bounded redacted DOM evidence. It neither
  accepts nor persists browser secrets or model-supplied commands.
- Added explicit browser runtime configuration. Python Playwright was installed
  locally for development, but Chromium could not be installed on the macOS 12
  host; no live browser execution is claimed.
- Updated evaluation tests to record the current Git SHA when a repository is
  present rather than assuming an unversioned checkout.

Actual verification so far: focused client-verification tests passed 4/4; Ruff,
compile checks, and `git diff --check` passed. Before Phase 16 can be declared
complete, its full persisted control plane and a real supported-browser
controlled-lab proof remain required.

## Phase 15.3 — Active Web Assessment Stabilization

- Registered bounded ffuf and Nuclei `tool-integration-v1` integrations with
  fixed executables, closed profiles (`web_content_small`,
  `web_content_standard`, `safe_templates`), controlled repository-owned
  wordlists/templates, deterministic argv, minimal child environments, bounded
  duration/output/results, scope filtering, and no shell execution.
- Added the typed Active Web Assessment plane for policy/budget previews,
  ToolRun and raw ToolArtifact persistence, artifact-backed Observations,
  Web Surface/System Model/Attack Graph rebuilds, multi-source Candidate
  provenance, Operator API/CLI flows, and the dashboard lifecycle panel.
- Removed client approval authority. Active requests now persist a
  `ResearchAction`; required execution stops at `ActionApproval=PENDING`, and
  only the existing approve/reject endpoints can change authority. Approval
  performs a fresh validator/ToolPolicy check. Rejection creates no ToolRun;
  policy revocation after approval invokes no process.
- Added migration `0015_active_web_assessment`, including constrained
  `web_candidate_provenance` lineage, and protected same-session
  Candidate/resource/ToolRun/ToolArtifact/Observation associations.
- Added dedicated offline ffuf/Nuclei/service/API/policy/security regressions,
  semantic registry/SDK tests, migration upgrade/downgrade/preservation tests,
  frontend lifecycle/XSS/approval tests, and explicit offline versus local
  socket-integration test gates. Tool results remain Observations/Candidates;
  the active plane and controller create no Findings.

Actual Phase 15.3-RC verification (2026-08-27): the complete Python gate passed
216 tests; the offline gate passed 200 with 16 explicitly selected local-network
integration tests, and that integration gate passed all 16 in a loopback-capable
environment. Fifteen migration tests, Ruff, compileall, cargo fmt, clippy
`-D warnings`, all 14 Rust tests, frontend typecheck, ESLint, 4 Vitest tests,
production build, and 3 Chromium Playwright flows passed. The controlled Docker
lab built, became healthy, and was shut down. The unchanged Phase 6 benchmark
remained TP=2, FP=0, TN=5, FN=0, correct inconclusive=1. `aegis tools doctor`
reported ffuf and Nuclei registered but unavailable on this host, so live binary
execution was not fabricated or installed; deterministic sanitized adapter
fixtures supplied the normal CI proof.

## Phase 15.2 — Persistent Web Surface + Operator Integration

- Added the rebuildable `web-surface-v1` projection backed by persistent
  WebResource, WebParameter, HTTPRequestTemplate, multi-source provenance,
  tool-reported template candidate, and WebSurfaceSnapshot records.
- Canonical resource identity includes normalized scheme, host, effective port,
  HTTP method, and concrete path; query values are excluded while parameter
  names are retained. GET and POST operations on one path remain distinct.
- Added bounded offline Burp import with mixed-scope filtering, safe form/link
  discovery, parse-failure artifact preservation, sensitive-header redaction,
  semantic request templates, deterministic hashes, idempotent incremental
  builds, and projection-only rebuilds.
- Added migration `0014_web_surface`, explicit WebResource-to-System Endpoint
  linkage, planner-safe semantic summaries, `aegis web` commands, stable
  Operator API endpoints, the first-class dashboard Web Surface page/import UI,
  resource detail, and `web-surface.json` report/manifest integration.
- Added ADR-0007. Imported template assertions remain `TOOL_REPORTED`
  Candidates and never create Findings. No ffuf or Nuclei execution was added;
  Phase 15 remains incomplete.

Actual Phase 15.2 verification (2026-08-26): 203 Python tests and 14 Rust
tests passed; Ruff, compileall, cargo fmt, and clippy `-D warnings` passed.
Frontend typecheck, ESLint, 3 Vitest tests, production build, and 3 sequential
Chromium Playwright flows passed. Fresh→head, 0013→head, and Alembic drift
checks passed. The Docker-backed Phase 6 benchmark remained TP=2, FP=0, TN=5,
FN=0, correct inconclusive=1, precision/recall/F1=1.0.

The controlled Phase 15.2 proof created Project
`cd0ee163-c323-43c9-b334-48e5eb6ea961` and Session
`387e3274-58d1-4888-b587-2c12c234c08a`. Burp artifact
`06f0dc44-28ae-472d-a215-68251900f925` had SHA-256
`a54c678d1e627273c44a12edfe8e3a0516f0e1488ca5994467eebe1d6e776e1d`;
4/5 entries were accepted and one external entry was ignored. The surface
contained three resources (GET=2, POST=1), five parameter names, three request
templates, one passive Candidate, and zero Findings. `/admin` accumulated
HTTP_EXECUTOR, TRAFFIC, HTML_LINK, and TEMPLATE_RESULT provenance while retaining
one WebResource and one System Endpoint. Repeated build hash
`bd9156da74465cf910345a333ef8f4a9c4a3e608be84f655582726f27f22d3ec`
was equal. Report manifest
`bc381a42ad70cd67662189c7d53dc02ae92e3419036b64f62573503329c8b122`
verified; projection, API, planner context, frontend build, and report credential
scans found zero fixture-secret matches. The lab was shut down after proof.

## Phase 14 — Web Dashboard + Tool Integration SDK

- Added `tool-integration-v1`, richer descriptors, bounded categories,
  backends/artifact types, parser/mapper protocols, static validation, UI
  metadata, golden fixtures, and reusable SDK tests.
- Wrapped existing HTTP, DNS, TLS, and Nmap registrations without changing
  controller/strategy authority or working adapters.
- Added generic tool/ToolRun, model/graph, controller plan/step/run, report, and
  sanitized runtime APIs. OpenAPI contains no credential response schemas.
- Added the React/TypeScript/Vite Operator Console: Project setup,
  scope/policy/approval/budget flow, controls, approvals, timeline, model,
  gaps/knowledge, actions, generic tools, graph, Candidate Signals, Findings,
  reports, and settings.
- Added `/ui` static serving, localhost defaults, polling, React escaping, unit
  tests, a production build, and a real Chromium Playwright smoke flow.
- Added ADR-0006 and the Tool Integration developer guide. No Phase 15 tools,
  dynamic plugins, shell surface, database migration, Rust, or C changes.

Actual Phase 14 verification (2026-08-25): 191 Python tests and 14 Rust tests
passed; Ruff, compile/import, cargo fmt and clippy passed. Frontend typecheck,
ESLint, 2 Vitest tests, production build, and 2 Chromium Playwright flows
passed. Production npm dependency audit reported zero vulnerabilities (the
macOS-12-compatible Playwright test dependency remains development-only).

The controlled browser proof created Project
`37b4c561-c6d4-4197-863d-76b54858d75d` and Session
`627d8992-ce73-468c-8d49-63ae8febd799` for `127.0.0.1:8001` in
`CONSERVATIVE` / `APPROVE_EVERY_ACTION` mode. It persisted a waiting
`SERVICE_DISCOVERY` action, executed zero ToolRuns before approval, then ran
Nmap as ToolRun `935bcdbd-591b-4484-8245-b72bf76414a5`, created one tool
Observation, rebuilt model/graph/knowledge, and displayed the timeline. Report
`a6dab3a4-86dd-4fa9-aceb-668023e69886` was generated; manifest
`85ae41105790a0adadcb51d863ed28f027381f7aa207f9e30e306328ac48c96c`
verified successfully. Credential scans of the bundle and reports returned no
key, bearer, Authorization, or Cookie values.

Phase 6 benchmark run `08912855-6602-4b42-89a3-d01382e48067` remained
TP=2, FP=0, TN=5, FN=0, correct inconclusive=1, precision/recall/F1=1.0.
NVIDIA live inference was not executed: no NVIDIA API key was present and the
actual runtime provider was `fake`; the configured model name remained
`nvidia/nemotron-3-nano-omni-30b-a3b-reasoning`.

## Phase 13 — Adaptive Research Policy + Operator Control Plane + Evidence-Backed Reporting

- Added persistent `ResearchProject` lifecycle and immutable per-session scope
  revisions, logical identity references, finite budget templates, controller
  mode, approval mode, sanitized provider/model configuration, and the built-in
  `research-policy-v1` profiles `CONSERVATIVE`, `BALANCED`, and `EXPERIMENTAL`.
- Added deterministic evidence novelty and policy-aware priority adjustment,
  bounded semantic repetition with closed repeat reasons, operator action-type
  blocking, and backward compatibility with
  `AEGIS_CONTROLLER_EXPERIMENTAL_MODE` without weakening ToolPolicy.
- Added `ActionApproval` with `AUTO`, `APPROVE_HIGHER_COST`, and
  `APPROVE_EVERY_ACTION`. Required approval follows strict action validation and
  a non-executing ToolPolicy/Rust-policy preview. Execution repeats policy
  authorization; approval cannot override a rejection. Operator rejection
  creates no ToolRun.
- Added idempotent ordered `research-event-v1` timeline projection and strict
  `operator-api-v1` local FastAPI endpoints for Projects, sessions, overview,
  events, actions, findings, gaps, assets, graph summary, pause/resume/stop,
  action-type blocking, approval, rejection, and cancellation. List endpoints
  use typed filters and bounded pagination.
- Added typed `SessionOverview`, per-session research/autonomy metrics, Project,
  policy, approval, and report CLI commands, plus expanded controller status and
  export metadata. The local control plane retains the existing safe
  `127.0.0.1` bind and does not claim production multi-user authentication.
- Added `aegis-report-v1` authoritative JSON and escaped static HTML reporting,
  deterministic executive summary, evidence-backed `FindingReport`, explicit
  fact/verification/inference separation, inconclusive/open-gap visibility,
  centralized recursive redaction, a raw-evidence index without bodies or
  headers, and per-file SHA-256/size manifest integrity.
- Added migration `0013_operator_reporting`, ADR-0005, a deterministic eight-case
  policy fixture, a Docker Phase 13 demonstration, and tests for fresh/Phase12
  migrations, project scope revisions, strict API schemas, approval/rejection,
  policy non-override, HTML escaping, prompt-like target data, report
  determinism, real supported-Finding lineage, manifest hashes, and credential
  exclusion.

Actual Phase 13 verification (2026-08-25): 185 Python tests and 14 Rust tests
passed; Ruff, compile/import, cargo fmt, and clippy `-D warnings` passed. Phase
10, 11, 12, and 13 focused evaluation assertions passed 4/4 with zero policy
bypasses and zero unsafe/out-of-scope controller execution. The Docker-backed
Phase 6 benchmark remained TP=2, FP=0, TN=5, FN=0, correct inconclusive=1,
precision=recall=F1=1.0.

The controlled Docker proof created fresh `CONSERVATIVE` and `EXPERIMENTAL`
sessions for only `127.0.0.1:8001`. Both naturally converged to one typed HTTP
action, one ToolRun, one request, one resolved owner-baseline gap, two Evidence
records total, zero repetitions, and zero Findings. In the conservative
`APPROVE_EVERY_ACTION` session, policy preview returned `WITHIN_SCOPE`, ToolRuns
before approval were 0, and approval executed exact `GET /api/orders/101` once.
Pause/resume preserved budget and did not repeat the action. Both report
manifests recalculated successfully; credential/report scans found zero secret
matches. The lab was shut down.

No live NVIDIA request ran because `NVIDIA_API_KEY`, `AEGIS_NVIDIA_API_KEY`,
`AEGIS_LLM_PROVIDER`, and `AEGIS_LLM_MODEL` were unset. The configured project
default remains `nvidia/nemotron-3-nano-omni-30b-a3b-reasoning` when
`nvidia_nim` is selected; no fake result was represented as live inference.

## Phase 12 — Typed Evidence Acquisition + Closed-Loop Research Controller

- Added strict `research-action-v1` discriminated actions, bounded expected-
  information selectors, purposes, semantic hashes, immutable
  `EvidenceAcquisitionContract`, deterministic satisfaction, and action/result
  lifecycle records.
- Added exact session-bound endpoint and authorized logical identity resolvers.
  Credentials remain inside the control plane and are added only after Tool
  Policy and Rust HTTP policy approval; actions, context, exports, logs, and
  provider requests contain no raw credential material.
- Added `closed-loop-controller-v1`, `controller-decision-v1`, and
  `closed-loop-controller-prompt-v1`: Phase 11 strategy input, strict provider
  output, Phase 10 ResearchIntent lineage, Phase 9 DiscoveryPlan/ToolRun reuse,
  exact Rust HTTP execution, model/graph/knowledge rebuilds, gap reevaluation,
  and deterministic stop conditions.
- Added persistent `ResearchBudget`, `ControllerStep`, `ResearchAction`, and
  `ResearchActionResult` storage via migration `0012_closed_loop_controller`,
  with a consumption ledger, pause/resume, completed-run reconciliation,
  semantic deduplication, and distinct reproduction numbers. Fresh→head and
  Phase 11→head migration tests preserve prior data.
- Added controlled `REPRODUCE_EXPERIMENT` handoff through the existing
  ExperimentRunner and VerificationEngine. Only the Verification Engine can
  create or update a Finding.
- Added `aegis controller plan|step|run|pause|resume|status|steps|actions|export`.
  Plan mode creates no ToolRun. JSON export contains audit metadata/IDs, no
  evidence body, credential, or private reasoning, and scans credential markers.
- Added 13 Phase 12 evaluation fixtures and coverage for schema escape,
  endpoint/identity relevance, out-of-scope references, prompt-like data,
  disabled-tool policy, duplicates, reproduction, budgets, pause/resume, crash
  reconciliation, plan-only execution, authority isolation, hashes, and exact
  owner-baseline acquisition.
- Changed the configured default NVIDIA core to
  `nvidia/nemotron-3-nano-omni-30b-a3b-reasoning`, with low-variance temperature
  `0.1`, and added ADR-0004. `reasoning_content` is ignored and not persisted;
  no key is hardcoded.
- Updated the project version to `0.12.0`, SPEC, README, Makefile, and ADRs.

Actual Phase 12 verification (2026-08-24): 175 Python tests and 14 Rust tests
passed; Ruff, compile/import, cargo fmt, and clippy `-D warnings` passed. The
Docker-backed Phase 6 benchmark remained TP=2, FP=0, TN=5, FN=0, correct
inconclusive=1, precision=recall=F1=1.0. Phase 10/11 evaluation tests remained
policy-bypass-free. The Phase 12 13-case fixture reported 3 valid actions, 5/5
invalid actions rejected, 1 duplicate prevented, 0 policy bypasses, 0
out-of-scope executions, 0 unnecessary ToolRuns, 1 gap resolved, and 1
verification handoff.

The controlled Docker proof used a fresh session scoped only to
`127.0.0.1:8001`. Given bob access to `order:101`, the controller selected alice
and exact `GET /api/orders/101`, received Rust policy `WITHIN_SCOPE`, persisted
one ToolRun/Evidence/Observation, changed model hash `a811c352...`→`20220d00...`,
graph hash `8d3efeca...`→`9b092748...`, and knowledge hash
`f2d209f6...`→`95c33b47...`, resolved `MISSING_BASELINE`, then returned
`STOP_SUFFICIENT_EVIDENCE`. Plan mode invoked zero target operations; injected
instruction-like/raw-command proposals produced zero ToolRuns; pause/resume did
not repeat the action; Finding count stayed 0; export was valid credential-clean
JSON with no reasoning content. The lab was shut down.

Live NVIDIA inference was not executed because neither `NVIDIA_API_KEY` nor
`AEGIS_NVIDIA_API_KEY` was configured in the runtime environment. No live proof
was silently replaced with a fake-provider result.

## Phase 11 — Research Strategy + Evidence-Gap Reasoning

- Added `knowledge-v1` with explicit `KNOWN`, `ASSUMED`, `UNKNOWN`,
  `CONFLICTING`, `UNTESTED`, and `INCONCLUSIVE` classifications. Observed known
  facts require Observation and Evidence/artifact lineage.
- Added persistent, typed EvidenceGaps, ResearchQuestions, KnowledgeSnapshots,
  and StrategyRuns with canonical hashes, semantic deduplication, deterministic
  resolution, blocked/stale history, and migration `0011_research_strategy`.
- Added deterministic gap detectors for missing service/protocol information,
  cross-identity owner baselines, structured Hypothesis missing information,
  conflicting observations, and insufficient reproduction history.
- Added a signal-driven access matrix, evidence-sufficiency states, competing
  hypothesis relationship vocabulary, multi-gap intent association, ordinal
  information gain/cost/priority, failed-attempt penalties, and redundant
  satisfied-intent prevention.
- Added `ResearchStrategyEngine`, which performs policy preview and hands closed
  ResearchIntents to Phase 10 but never executes tools, writes the System Model,
  writes the graph/signals, or creates Findings.
- Added `knowledge show`, `gaps list/show`, and `strategy plan/export` CLI. Plan
  mode records `tool_processes_invoked=0` and exports no raw credentials.
- Added nine deterministic Phase 11 evaluation fixtures, ADR-0003, README/SPEC
  documentation, and architecture tests for execution, authority, ground-truth,
  and prompt-injection isolation.

Actual Phase 11 verification (2026-08-23): 162 Python tests and 14 Rust tests
passed; Ruff, compile/import, cargo fmt, and clippy `-D warnings` passed. The 13
new regression assertions include 11 strategy unit/security tests, one complete
strategy-to-Discovery integration test, and Phase 10→11 migration preservation.
The Phase 10 planner evaluation remained 8 cases, 2 unsafe rejections, 1
duplicate, 0 policy bypasses, and 0 unnecessary ToolRuns. Phase 11's nine
deterministic fixtures produced 5 expected gaps, 9 correct case outcomes, 1
blocked gap, 1 redundant intent prevented, 0 unsafe actions, and 0 policy
bypasses.

The Docker demonstration used session
`7879b8de-b46b-4072-8b67-c5e53b0f8073`. A bob observation of order 101 built
model `3a88001613a51dd583fd06ceff026a8521ee8273981ba31f36cd55c451eec06c`
and graph `bade63f8fe0e9b47bf6c48f09f01bc4a749fd02c59a3db74109ef8909ec1d5e9`,
with one cross-identity CandidateSignal. Knowledge snapshot
`bd828523-6296-4d49-804b-ee80e2c57378` had hash
`49629a015be61f45f15a757e91a6419a38a7f766a2181c5fecf70ecc5073054b`,
18 KNOWN facts, 1 UNKNOWN, and an OPEN `MISSING_BASELINE` gap
`af26be0e-bb38-467b-b217-702f525a5ec4`.

Strategy run `e4dd0483-bcbf-4b19-9d65-28306f91f576` ranked that gap HIGH
(information gain 60, priority 80, one PASSIVE request) and proposed
`VERIFY_CANDIDATE_SIGNAL → HTTP_REQUEST → http/metadata`; policy allowed it and
plan-only invoked zero processes. Phase 10 step
`21b03018-c8eb-46d3-b452-8d6e07ccfb7d` executed ToolRun
`8bb31432-cb4f-4a94-9139-38879b62ba35` through the existing Rust HTTP and Tool
Policy path. An explicit existing controlled owner-baseline observation then
added the precise missing evidence. The model became
`352d7a1e20c9dcb5d7141784317ab6053e60f6a2a6bd7d6d83675ff47a156656`,
the two older graphs were STALE, and current graph
`a0610d1f-6ab6-4aa9-9b2c-8da31a230c00` had hash
`d0b84e626ecb8d7f95f29ac76eb40a7969f2da6372d49ca435d01e475bd63868`.
The gap became RESOLVED, repeated strategy created no new ToolRun, and repeated
knowledge builds produced identical hash
`5d318f6ee2ab2606e69db3d389726243f153a45d5eff5cea19a017b54275e60d`.

A deterministic conflicting/prompt-injected fixture produced one
`CONFLICTING_OBSERVATIONS` gap without creating `8.8.8.8`, expanding scope, or
executing a ToolRun. A separate Nmap-disabled session produced BLOCKED /
`TOOL_DISABLED` with zero ToolRuns. Finding count remained zero. Sanitized
strategy/research/model/graph exports had zero credential-pattern matches. Live
NVIDIA strategy assistance was not executed because no NVIDIA key was configured;
the deterministic strategy is authoritative in Phase 11.

The Docker Phase 6 benchmark run
`b9a9ecd1-f0de-4c4b-86e7-9bf8e1ab75d1` remained TP=2, FP=0, TN=5, FN=0,
correct inconclusive=1, precision=recall=F1=1.0. Docker health and controlled
operations passed; laboratory shutdown succeeded.

## Phase 10 — Research Planner + Capability-Based Tool Orchestration

- Added strict `planner-decision-v1` decisions, closed ResearchIntent vocabulary,
  persisted ResearchStep/ResearchIntent memory, semantic hashes, provenance, and
  deterministic lifecycle/satisfaction state.
- Added bounded trust-labelled ResearchContext construction for current session,
  scope, System Model, graph/signals, observations, plans/intents, Findings, and
  Hypotheses. Tool/target strings remain delimited untrusted data.
- Added deterministic intent→capability and capability→registered tool/profile
  resolution. The planner has no executable, argv, raw target, port, header,
  policy, Finding, graph, or System Model mutation surface.
- Reused Phase 9 DiscoveryPlan, ToolPolicy, ToolRun, artifact, Evidence, and
  Observation paths; HTTP continues through the Rust executor.
- Added bounded single-step/run/resume orchestration, plan-only execution
  separation, duplicate prevention, policy/no-tool failure handling, model/graph
  rebuilds, and CLI audit/export commands.
- Added migration `0010_research_planner`, planner security/integration tests,
  eight deterministic evaluation fixtures, and ADR-0002.

Actual Phase 10 verification (2026-08-22): 149 Python tests and 14 Rust tests
passed; Ruff, compile/import, cargo fmt, and clippy `-D warnings` passed. The
Phase 6 benchmark remained TP=2, FP=0, TN=5, FN=0, correct inconclusive=1,
precision/recall/F1=1.0.

The fresh Docker demonstration used session
`f178f830-f56d-4f54-8ed2-66a6f1321a1b`, initially built model
`135d41b4741838eaf6346f0211c1f97907193c55cd0627636c18cb21bb06c436`
and graph `6ea12f742cd1314d53c9451f0c07e5bb60077da301ebdddda9b11a499a8c4037`.
Plan-only proposed `DISCOVER_SERVICES → SERVICE_DISCOVERY →
nmap/service_discovery`, policy `ALLOWED`, with zero ToolRuns. The bounded run
reused that semantic intent, executed one Nmap 7.95 ToolRun against only
`127.0.0.1:8001`, persisted a 1,308-byte XML artifact with SHA-256
`14b98c969fdac9b44fd82c20c4223d7eff250018636c4edf59f53bfa209f747f`,
and satisfied the intent from its observation. HTTP and Nmap provenance merged
into one service. The resulting model hash was
`0ce1d1b3a7e1064acbb51f8aa09b04e34d5e8c9aaef29afe7aae45291cc14672`;
the old graph became STALE and the current graph hash became
`0e7363738a6e034590dc2fe016fe418069d348a4a90edf97e218673d724c45e0`.
The next planner step stopped with `STOP_SUFFICIENT_EVIDENCE`.

Out-of-scope, prompt-injection, duplicate-intent, step-limit, unavailable-tool,
policy rejection, and Finding-authority checks all failed closed with no policy
bypass. Sanitized research/discovery/model/graph exports contained no configured
credential markers. Live NVIDIA inference was not executed because
`NVIDIA_API_KEY` was unavailable. Docker laboratory shutdown succeeded.

## Phase 8 — Attack Graph + Path Analysis (completed 2026-08-22)

Implemented:

- deterministic `attack-graph-v1` projection linked to the exact semantic System Model
  SHA-256, with typed Asset/Service/Endpoint/Identity/Role/Permission/Capability/DataObject/
  TrustBoundary nodes;
- explicit traversable, informational, and blocking edge semantics; observed-only traversal;
  capability-derived edges that retain entity/Observation/Evidence provenance;
- deterministic BFS shortest paths and bounded, cycle-safe simple-path enumeration with
  configured depth/path/node limits and minimum-edge path confidence;
- persisted graph snapshot metadata and deduplicated `CROSS_IDENTITY_RESOURCE_ACCESS` and
  `ROLE_ACCESS_DIFFERENCE` candidate signals, explicitly separate from Hypotheses/Findings;
- canonical graph SHA-256 independent of UUIDs/timestamps, repeat-build determinism, dynamic
  stale detection against the current System Model hash, and fail-closed stale queries;
- graph neighbors/reachability/path/resource/signal query services and credential-free JSON
  export;
- `graph build/show/path/reachable/cross-identity/role-diff/export` CLI commands;
- Alembic `0008_phase8` migration preserving Phase 0–7 rows and strict graph/session/entity
  repository boundaries;
- architecture isolation tests proving that the graph layer imports no target network,
  executor, subprocess, laboratory, evaluation, or ground-truth components;
- no Rust changes, C, Nmap, DNS/TLS, crawler, Tool Registry, LLM integration, or graph database.

Fresh Docker demonstration:

```text
Research session: 6bcf9bc0-da1b-450b-a221-46733d5c41dc
System Model build: 21370273-6506-4453-8123-032c5df9f00f
System Model SHA-256: f1741b8d1ea743d7974a404da9f9fecd8b5aedeae06d2e14523f67629e9eca30
Graph A: 7f684195-79f7-4441-b48d-4da37a4f0e0a
Graph B: b48cbab6-b693-4d4d-84fe-6411b8b2882f
Graph SHA-256 (both): 26577ed1487991c7239cf3af66d38cfb6f8c043cf35f277b33d121a0fdbafa18
Projection: 30 nodes, 37 edges, 26 traversable, 1 blocking, 2 candidate signals
Alice -> /api/admin/stats: no traversable path; CANNOT_ACCESS carries observation/evidence
Admin -> /api/admin/stats: one-hop CAN_ACCESS path with observation/evidence provenance
Bob -> order:101: CAN_ACCESS -> RETURNS two-hop resource path
Cross-identity candidate: bob accesses order:101, observed owner alice; not labeled BOLA/Finding
Role difference: admin CAN_ACCESS, alice CANNOT_ACCESS; not privilege-escalation Finding
Incremental model SHA-256: 3e9f08486ef58ed9fd14e226160f77551bd0046115e5f1bc2ae540d1195f7d34
Old graph status: STALE; old query failed closed with MODEL_STALE
New graph: 1f87c97c-b3f6-4595-afd5-af205ac0fb68
New graph SHA-256: 43641b8f001f3a63827e45a59b7528fc62834e7052a040f60c88f26e28aa4363
JSON export: reports/graphs/phase8-demo.json; valid and credential scan empty
```

Phase 6 regression benchmark, eight controlled synthetic scenarios:

```text
Benchmark: 9e4c3b06-3310-403a-80de-7a3285f6d04c
TP/FP/TN/FN: 2/0/5/0
Correct inconclusive: 1
Precision/Recall/F1: 1.0/1.0/1.0
HTTP requests: 29
Runtime: 1733 ms
```

Validation results:

```text
Pre-change Python suite: 114 passed
Final Python suite: 120 passed
Phase 8-specific additions: 6 tests with unit, integration, migration, CLI, isolation,
  traversal, signal, stale-graph, export, and provenance assertions
Rust tests: 14 passed
cargo fmt/clippy -D warnings: passed
Ruff/compile: passed
Fresh database -> 0008 head and Phase 7 -> head preservation: passed
Docker build/start/health/demonstration/shutdown: passed
```

## Phase 7 — System Model + Asset/Identity/Capability Graph Foundation (completed 2026-08-22)

Implemented:

- typed, persistent System Asset, Service, Endpoint, Identity, Role, Permission, Capability,
  DataObject, TrustBoundary, and generic Relationship domain models;
- strict `OBSERVED`/`INFERRED` confidence and provenance invariants, with every observed graph
  fact linked to Observation and Evidence IDs;
- deterministic HTTP mapper and incremental `SystemModelBuilder` with explicit processed-ID
  checkpoints, idempotent upserts, accumulated provenance, first/last seen, and build metrics;
- conservative access facts (`CAN_ACCESS`/`CANNOT_ACCESS`), typed permission/capability facts,
  order resource extraction, ownership, reads, and endpoint-return relationships;
- cross-session and missing-endpoint relationship rejection at the repository boundary;
- semantic `system-model-v1` canonical export/hash, independent of generated UUIDs/timestamps;
- rebuild that deletes only the projection and replays immutable Evidence/Observations;
- model summary, assets, endpoints, identities, relationships, build/rebuild, and JSON export
  CLI commands;
- Alembic `0007_phase7` migration preserving Phase 0–6 records;
- architecture prepared for future observation mappers without adding Nmap, DNS, TLS,
  NetworkX pathfinding, a graph database, LLM enrichment, Rust, or C code.

Fresh Docker demonstration:

```text
Research session: 11849c9c-5afe-45c2-b1ab-3764ba03a60a
Current-code rebuild: 83f6a313-427a-44a9-bdd1-336f8ce051ce
Rebuild observations processed: 8
Model: 2 assets, 1 service, 7 endpoints, 4 identities, 3 roles,
  7 permissions, 6 capabilities, 3 data objects, 0 trust boundaries, 29 relationships
Model SHA-256: 115d988d8d036cb52e97cadeecb87a7598ea9db3f8e6920436fec3634530ab62
Idempotent build: 17cc2b7b-8fce-405e-9666-4506993a8557
Idempotent delta: 0 observations, 0 entities, 0 relationships; same hash
Incremental build: 8cf40cbe-1efb-4370-97bd-02066ff86429
Incremental delta: 1 observation, +1 endpoint, +1 permission, +1 capability,
  +2 relationships
Redirect semantics audit: 302 remains an Endpoint/Observation but creates no CAN_ACCESS edge;
  projection replayed after this conservative correction
admin CAN_ACCESS /api/admin/stats: observation dac8f11a-a517-4d47-abd1-1696dd699e99,
  evidence f77792af-f64e-4b48-aa59-71487e63f634
alice CANNOT_ACCESS /api/admin/stats: observation 9332768d-f55f-4ed3-a154-a6f2dc2c0c72,
  evidence 648cff8e-1e43-490d-b634-c2231613fdb4
bob CAN_ACCESS /api/orders/101 and alice OWNS order:101: observed with shared request lineage;
  no vulnerability label created
JSON export: valid; credential scan empty
```

Phase 6 regression benchmark, eight controlled synthetic scenarios:

```text
Benchmark: bf233772-80dc-4ebf-b7e0-4ddfe113761c
TP/FP/TN/FN: 2/0/5/0
Correct inconclusive: 1
Precision/Recall/F1: 1.0/1.0/1.0
HTTP requests: 29
Runtime: 1645 ms
```

Validation results:

```text
Pre-change Python suite: 107 passed in 15.68s
Final Python suite: 114 passed in 23.34s
Phase 7-specific additions: 7 tests
Rust tests: 14 passed
cargo fmt/clippy -D warnings: passed
Ruff/compile: passed
Fresh database -> 0007 head: passed
Docker build/start/health/shutdown: passed
```

## Phase 6 — Evaluation Framework + Ground-Truth Benchmarking (completed 2026-08-22)

Implemented:

- persisted `BenchmarkRun`, `ScenarioRun`, and `ScenarioEvaluation` records with evaluator,
  dataset, harness, configuration, provider/model, prompt, verifier, policy, executor, Git,
  lineage, failure-stage, and efficiency metadata;
- ground-truth and neutral harness canonical SHA-256 versioning, with ground truth loaded
  only after all selected scenario research runs complete;
- deterministic TP/FP/TN/FN and correct/unexpected-inconclusive classification, standard
  nullable Precision/Recall/F1/Accuracy/FPR/FNR metrics, and explicit undefined reasons;
- pipeline counters for observations, Evidence, hypotheses, experiments, policy decisions,
  executions, verification, Findings, HTTP requests, LLM runs/tokens/latency, and runtime;
- a neutral eight-scenario deterministic pipeline harness, clearly separated from live LLM
  model benchmarking;
- `eval run/list/show/scenario/compare/export` CLI commands and redacted JSON artifacts;
- Alembic `0006_phase6` migration preserving existing Phase 0–5 data;
- architecture tests enforcing `evals -> app` and preventing production/research access to
  ground truth.

Deterministic Docker benchmark (eight controlled synthetic scenarios; pipeline benchmark,
not real-world or LLM accuracy):

```text
Run A: 06e0dc50-ca79-4907-b5a0-b6dbcca05db2
Run B: b51d1aaf-1c84-4dab-bb05-cde94f69256c
Mode/status: DETERMINISTIC / COMPLETED
Scenarios: 8 completed, 0 failed
LAB-001 REJECTED -> TN
LAB-002 SUPPORTED -> TP
LAB-003 REJECTED -> TN
LAB-004 SUPPORTED -> TP
LAB-005 REJECTED -> TN
LAB-006 INCONCLUSIVE -> CORRECT_INCONCLUSIVE
LAB-007 REJECTED -> TN
LAB-008 REJECTED -> TN
TP/FP/TN/FN: 2/0/5/0
Correct/unexpected inconclusive: 1/0
Precision/Recall/F1/Accuracy: 1.0/1.0/1.0/1.0
FPR/FNR/Inconclusive rate: 0.0/0.0/0.125
Observations/Evidence/HTTP requests: 29/29/29
Hypotheses generated/accepted/rejected: 8/8/0
Experiments/executions/verifications/findings: 8/8/8/2
Policy approvals/rejections: 14/0
LLM runs: 16; token counts: null (fake provider does not report them)
Runtime A/B: 2281 ms / 2216 ms; comparison delta B-A: -65 ms
JSON export: summary.json, scenarios.json, sanitized config.json
```

Versioned hashes:

```text
Ground truth: 162c81146f8e0dc9c32d7715a3fdbc4f134dc0d2a745874237c753520d3b7ac3
Harness: 0e3461d8ae3a534d703af5e8d169704c20d4c61cbcafced9407289c1daf066e1
Run A configuration: e3bf305e040ea144c7cd780b2ce0ddd906b71f42bc0594e4ac319d2d6e3cbc99
```

Validation results:

```text
Pre-change Python suite: 95 passed
Final Python suite: 107 passed in 19.26s
Phase 6-specific additions: 12 tests
Rust tests: 14 passed
successive cargo fmt --check and cargo clippy -D warnings: passed
Ruff: passed
compile/import: passed
Docker build/start/health: passed
Two persisted benchmark runs and B-A comparison: passed
JSON export and credential scan: passed
```

## Phase 5 — Deterministic Verification Engine + Evidence-Backed Findings (completed 2026-08-22)

Implemented:

- closed, versioned typed verification specifications and `experiment-v2` prompt assets;
- eleven deterministic comparison primitives for HTTP metadata, body integrity, and JSON;
- per-execution `VerificationResult` with `verification-v1`, rule version, actual comparison values, reason, confidence tier, and complete lineage;
- independent canonical Evidence SHA-256 revalidation plus session, experiment, role, and Observation→Evidence consistency checks;
- explicit `SUPPORTED`, `REJECTED`, and `INCONCLUSIVE` semantics with fail-closed legacy, truncated, partial, and invalid-integrity behavior;
- repeat-run aggregation and configurable `AEGIS_MIN_VERIFICATION_RUNS` threshold;
- one evidence-backed Finding per experiment, created only for aggregate support and marked disputed if later evidence conflicts;
- `verify execution`, `verify experiment`, `findings list`, and `findings show` CLI commands;
- Alembic `0005_phase5` migration preserving Phase 0–4 records;
- localhost-only `scripts/phase5_demo.py` covering support, false-positive rejection, insufficient evidence, role boundary, repeatability, and independent hash checks.

Architecture decisions:

- LLM output can propose only a closed verification intent; ordinary code validates and evaluates it.
- Status equality alone is explicitly rejected as observable security impact.
- Every required relation must be complete and match, including a declared impact comparator, before support is possible.
- Legacy experiments without a typed specification yield `INCONCLUSIVE`; natural language is never parsed into an authoritative rule.
- Body-dependent comparisons reject truncated captures as inconclusive, while metadata-only rules can remain usable.
- Mixed repeated verdicts aggregate to `INCONCLUSIVE`; prior Finding history is retained and marked disputed rather than deleted.
- Phase 5 adds no Rust or C code and has no real-provider dependency.

Practical Docker demonstration:

```text
Research session: e60c8443-1609-43ae-9492-1712f3bae63f
SUPPORTED hypothesis/experiment: 90aa798b-a8dc-48db-9268-333108a0497c / 5a32c221-6c01-4fa8-ac8a-4650c2063eb3
Executions: d2c1fb3d-c554-4442-a5ee-00328b574e07, 37553bb3-575f-4c4d-995f-f6b4d65c51b2
Candidate/control evidence: 9d89e505-6992-4ab4-bc01-ce86114d533b / 5e5f6044-0cbe-430e-be67-de04fffb96db
VerificationResult: 2bd41f05-cbf6-4a11-871d-e7a535a791e4
Rule: http-candidate-control/v1
Comparisons: status 200 == 200; JSON id 101 == 101; owner alice == alice (observable impact)
Aggregate: SUPPORTED across 2 executions
Finding: b80c7b92-934f-4e17-ac00-c4645ae5ab97
Independent candidate/control hashes: valid
LAB-005-like: REJECTED, Finding false
LAB-006-like: INCONCLUSIVE, Finding false
LAB-007-like: REJECTED, Finding false
Persisted verification runs: 6 (2 supported, 3 rejected, 1 inconclusive)
Persisted findings: 1
Ground truth read by demo/verifier: no
```

Final executed results:

```text
Pre-change Python suite: 71 passed
Final Python suite: 95 passed in 11.28s
Phase 5-specific additions at final gate: 24 tests
Rust tests: 14 passed (1 core + 9 executor + 4 policy)
cargo fmt --check: passed
cargo clippy -D warnings: passed
Ruff: passed
compile/import: passed
fresh database -> 0005 head: passed
Phase 0/2/3/4 migration preservation: passed
Docker build/start/health: passed
Docker shutdown: passed
Ground-truth references in production verification path: 0
```

## Phase 4 — Experiment Engine + Deterministic Rust Policy Engine (completed 2026-08-22)

Implemented:

- versioned `experiment-v1` prompt and provider-independent typed candidate/control proposal;
- bounded experiment context derived only from the hypothesis, cited observations, missing information, immutable target scope, and logical identities;
- deterministic Experiment Validator rejecting invented/absolute paths, unknown identities, non-read-only methods, protected/model-unauthorized headers, excessive risk, and identical controls;
- control-plane identity resolution after policy approval, so LLM context and Experiment persistence contain no bearer token;
- `aegis-policy` Rust crate with protocol v1, parsed URL/scheme/host/port/method/bound/redirect/header checks, structured reason codes, and canonical policy SHA-256;
- fail-closed Python `RustPolicyClient`, paired policy audit, stateless Rust policy subprocess, and persisted Python per-session rate limiting;
- explicit `generate`, `show`, `check`, and `run` CLI boundaries; generation never executes and check performs no HTTP;
- repeatable `ExperimentExecution`, candidate/control policy decisions, and separate Evidence/Observation lineage;
- deterministic execution order `CONTROL → CANDIDATE`, with no execution unless both actions are approved;
- Alembic `0004_phase4` migration preserving Phase 0–3 rows and adding experiment/policy lineage;
- reproducible `scripts/phase4_demo.py` for the localhost laboratory only.

Architecture decisions:

- LLM output remains `INFERRED`; only executor runtime becomes Evidence/Observation.
- LLM proposes relative paths and logical identities. Python builds the scoped URL and resolves synthetic credentials only after policy approval.
- Rust policy is stateless and performs no network I/O. Policy failures, malformed output, protocol/hash mismatch, timeout, or missing binary deny execution.
- Candidate and control are all-or-nothing. A policy rejection prevents both executor calls.
- Rate limiting is persisted in the Python coordinator because subprocess-per-decision Rust policy has no shared state. It is deterministic for the current single-process coordinator.
- A successful run changes the hypothesis only from `NEW` to `TESTING`; no Phase 5 verdict, Finding, or severity is created.
- Host authorization uses a standards-based URL parser. Production-grade DNS address pinning/rebinding protection remains an explicit limitation.

Fresh deterministic demonstration:

```text
Research session: 1225488a-2b8f-4a7a-8066-70551f0d756a
Hypothesis: 2d789f08-617e-4358-ab88-3a358f220ba0
Experiment: 8c11b5be-c810-4c95-b2b2-72a8ce29b758
Experiment LLM run: d6de8a51-c2bb-4c27-8974-1256c820fe21
Prompt: experiment-v1
Candidate: bob GET /api/orders/101
Control: alice GET /api/orders/101
Policy-only check: candidate WITHIN_SCOPE, control WITHIN_SCOPE
Execution: ca6fd27f-50f2-476a-adeb-5af0d3c253cc / EXECUTED
Candidate evidence/observation: e07504b6-9d44-4290-9e83-d2f3608b5fb2 / b3a9b2ec-17c8-4665-a682-8ea4166589cf
Control evidence/observation: c7c9f0eb-e6e8-462d-b859-329b583c6172 / ccd88634-e19e-4a39-a805-86bf2f1f00f1
Persisted evidence/observations: 9 / 9
Independent Python evidence hashes: 9/9 verified
Hypothesis lifecycle after execution: TESTING
No security verdict produced: yes
```

Security rejection demonstrations:

```text
Absolute external experiment path: DRAFT/rejected by deterministic validator
Executor invoked for rejected path: false
Model-supplied Authorization header: DRAFT/rejected with HEADER_NOT_ALLOWED
Missing policy binary: typed failure; executor invoked false
Rate limit below pair size: POLICY_REJECTED; executor invoked false
Ground-truth references in app/reasoning, app/execution, app/llm: 0
```

Real-provider attempt:

```text
Provider/model: anthropic / claude-haiku-4-5-20251001
Operation: experiment generation only; no execution
Result: AUTHENTICATION_ERROR (HTTP 401)
Latest failed LLMRun: d5f94e50-4c53-4117-b0cc-1b8f72ce1073
Attempts/latency: 1 / 345 ms
Tokens: unavailable because authentication failed
Generated/accepted/rejected: 0 / 0 / 0
```

Final executed results:

```text
Pre-change Python suite: 59 passed
Final Python suite: 71 passed
Phase 4-specific additions: 12 tests
Rust tests: 14 passed (1 core + 9 executor + 4 policy)
cargo fmt --check: passed
cargo clippy -D warnings: passed
Ruff: passed
compile/import: passed
fresh database -> 0004 head: passed
Phase 0/Phase 2/Phase 3 database preservation tests: passed
Alembic ORM drift: none
Docker laboratory build/start/health: passed
Docker laboratory shutdown: passed
unsafe in Aegis Rust crates: none
```

Rust components:

- `aegis-core` canonical evidence protocol/hash library;
- `aegis-executor` bounded HTTP executor;
- `aegis-policy` deterministic authorization binary.

C components:

None — Rust covers the deterministic policy/execution boundary for Phase 4.

## Phase 3 — LLM Provider Abstraction + Evidence-Grounded Hypothesis Engine (completed 2026-08-22)

Implemented:

- provider-independent typed LLM messages, structured results, metadata, usage, and error codes;
- deterministic Fake provider with caller-supplied responses and no laboratory ground truth;
- one production Anthropic Messages API adapter using structured JSON schema output and bounded transient retries;
- versioned `hypothesis-v1` prompt assets with explicit target-data/prompt-instruction separation;
- bounded sanitized Context Builder with shared header redaction, trust annotation, identity metadata, and context SHA-256;
- deterministic Hypothesis Validator for session membership, Observation→Evidence linkage, hallucinated IDs/endpoints, per-run limits, and duplicates;
- Hypothesis Engine persisting only `NEW` / `INFERRED` accepted hypotheses plus completed or failed `LLMRun` metadata;
- typed missing-information objects that remain research requirements rather than executable actions;
- Alembic `0003_phase3` migration and hypothesis generate/list/show CLI commands.

Architecture decisions:

- The model receives a bounded structured context, never a raw database dump or raw Base64 body.
- Sensitive request headers are redacted before context construction; original Evidence is never modified.
- Target body content remains available only as bounded `UNTRUSTED TARGET DATA`.
- Provider parsing and deterministic domain validation are independent boundaries. Provider confidence cannot override invalid provenance.
- The reasoning packages do not import the Rust executor, laboratory ground truth, or scenario YAML.
- Phase 3 creates no Experiment, Finding, policy decision, or external action.

Fresh deterministic demonstration:

```text
Research session: 72998cf0-4e37-4172-afcc-a7f2cf4f3e1a
Stored observations/evidence: 7 / 7
Context observations: 7
Credentials in context: none
Context SHA-256 matched persisted LLMRun: yes
Fake LLM run: a721bb2f-cfb5-4f8c-b801-04ec7408eebf
Prompt: hypothesis-v1
Generated: 3
Accepted: 2
Rejected: 1 exact duplicate
Persisted hypotheses: 2
Statuses: NEW, NEW
Provenance classifications: INFERRED, INFERRED
Reference validation: 2/2 complete
```

Real-provider integration:

```text
Adapter invocation: executed against the same sanitized local session
Provider/model: anthropic / claude-haiku-4-5-20251001
Result: AUTHENTICATION_ERROR (HTTP 401)
Latest failed run: 1b50fcfc-5ec7-4ed8-9eba-40b4022b2d7d
LLMRun persisted as FAILED: yes
Attempts/latency: 1 / 363 ms
Tokens: unavailable because authentication failed
Generated/accepted/rejected: 0 / 0 / 0
```

This failed credential check is not reported as a successful model run and does not affect deterministic Phase 3 completion through the Fake provider.

Final executed results:

```text
Pre-change Python suite: 38 passed
Latest Python suite: 59 passed in 5.86s
Phase 3-specific additions: 21 tests
Rust regression: 10 passed
cargo fmt --check: passed
cargo clippy -D warnings: passed
Ruff: passed
compile/import: passed
fresh database -> 0003 head: passed
Phase 2 database -> 0003 preservation test: passed
Alembic ORM drift: none
editable install: aegis-research 0.3.0
wheel prompt assets: present
Docker laboratory build/start/health: passed
Docker laboratory shutdown: passed
```

## Phase 2 — Observation Pipeline + Rust Execution Plane (completed 2026-08-22)

Implemented:

- immutable, explicitly scoped `ResearchSession` domain model and persistence;
- Rust workspace with shared protocol crate and bounded HTTP executor;
- protocol version 1, structured error codes, redirect/timeout/method validation;
- streaming response capture with Base64 exact bytes and deterministic canonical SHA-256;
- subprocess-only Python `RustExecutorClient` with no shell and no silent fallback;
- exact Evidence, deterministic normalized Observation, trust classification, and complete lineage;
- Phase 2 Alembic migration preserving Phase 0 rows;
- CLI session creation, observation execution, redacted evidence display, and observation listing;
- real Python → Rust → local FastAPI → Evidence → Observation → SQLite integration test.

Architecture decisions:

- Python decides what to observe and enforces immutable scheme/hostname/port scope using parsed URLs.
- Rust performs one already-scoped HTTP operation and never reads ground truth or performs reasoning.
- `Evidence.experiment_id` is nullable because evidence collection precedes the Phase 4 Experiment Engine; legacy experiment-linked evidence remains valid.
- Body limits use streaming capture and `truncated=true`; they do not buffer the full response or fail over to another executor.
- Exact captured bytes are stored as Base64. Text is a UTF-8-lossy convenience representation.
- Sensitive request headers remain stored for reproducibility but CLI display redacts them.
- No Python executor fallback was added, avoiding silent masking of Rust failures.

Final executed results:

```text
Pre-change Python suite: 23 passed
Final Python suite: 38 passed in 4.63s
Rust tests: 10 passed (1 core + 9 executor)
cargo fmt --check: passed
cargo clippy -D warnings: passed
Ruff: passed
compile/import: passed
Alembic 0001 -> 0002 data-preservation test: passed
fresh database -> head: passed
Alembic ORM drift: none
Docker laboratory build/start/health: passed
Docker laboratory shutdown: passed
unsafe in Aegis Rust crates: none
```

Practical fresh-session demonstration:

```text
Research session: 2ee35127-5394-4217-a5dc-3c8ff09ce121
anonymous /health: 200
alice /api/profile: 200
bob /api/orders: 200
bob /api/orders/101: 200
alice /api/admin/stats: 403
admin /api/admin/stats: 200
anonymous /api/portal: 302, Location /login preserved
Persisted evidence: 7
Persisted observations: 7
Independent Python hash verification: 7/7
Complete observation/evidence/request/session provenance: 7/7
Authorization display redaction: verified
Ground-truth imports/reads in app research path: none
```

Rust components:

- `aegis-core` protocol and hashing library;
- `aegis-executor` HTTP binary.

C components:

None — no justified low-level use case in Phase 2.

## Phase 1 — Controlled Laboratory (completed 2026-08-22)

Implemented:

- deterministic FastAPI target isolated from the Python control plane;
- static synthetic bearer identities `alice`, `bob`, and `admin`;
- required profile, order, account, and admin endpoints plus two scenario-specific endpoints;
- eight controlled scenarios covering safe, vulnerable, false-positive, insufficient-evidence, role, and redirect behavior;
- eight validated YAML ground-truth definitions outside the target runtime;
- Docker image with localhost-only publication, non-root user, read-only root filesystem, dropped capabilities, and no host mounts;
- integration and ground-truth validation tests.

Architecture decisions:

- Phase 1 remains Python-only because the target environment does not justify a native execution boundary.
- The vulnerable application never imports `lab.ground_truth`.
- Docker build context is `lab/vulnerable_api`; `lab/scenarios` is not present in the image.
- Static tokens are deliberately synthetic and exist only inside the laboratory.
- The Compose network is a project-specific bridge. The service is published only as `127.0.0.1:8001`; an `internal: true` network was tested and rejected because Docker Desktop suppressed the required host port publication.

Commands executed:

```text
.venv/bin/python -m pytest tests/lab -vv
docker compose -f lab/docker-compose.yml config
docker compose -f lab/docker-compose.yml up --build --detach --wait
curl requests against /health, /api/profile, /api/orders, /api/orders/101,
  /api/admin/stats, and /api/portal on 127.0.0.1:8001
docker inspect lab-vulnerable-api-1
```

Actual final results:

```text
Full test suite: 23 passed in 1.36s
Phase 1 tests: 13 passed
Phase 0 regression tests: 10 passed
Ruff check: passed
Python imports/compile: passed
Ground-truth documents loaded: 8
Container: healthy
Health endpoint: HTTP 200
Alice profile: HTTP 200
Bob order list: HTTP 200, only orders 201 and 202
Bob -> Alice order 101: HTTP 200 with owner alice (controlled BOLA reproduced)
Alice -> admin stats: HTTP 403
Admin -> admin stats: HTTP 200
Anonymous -> portal: HTTP 302 to /login
Container UID/GID: 10001/10001
Read-only root filesystem: true
Privileged: false
Capabilities dropped: ALL
Ground truth present in target image: no
Compose shutdown after validation: successful
```

Rust components:

None — intentionally deferred to Phase 2.

C components:

None — no justified low-level use case in this phase.

## Phase 0 — Foundation (completed 2026-08-21)

Implemented:

- Pydantic domain models with explicit provenance;
- SQLAlchemy/SQLite persistence and repositories;
- initial Alembic migration;
- FastAPI health endpoint and Typer CLI;
- domain, storage, migration, API, and CLI tests.

Last Phase 0 baseline executed before Phase 1:

```text
10 passed
Imports: successful
CLI: successful
Database initialization: successful
Alembic drift check: no new upgrade operations
Control-plane /health: HTTP 200
```
# Phase 9 — Tool Registry + Controlled Discovery Plane

- Added `tool-registry-v1` with typed HTTP, DNS, TLS, and Nmap descriptors,
  capabilities, profiles, availability inspection, and fixed execution backends.
- Added persisted `DiscoveryPlan`, `ToolRun`, tool-policy decision, and immutable
  SHA-256-addressed `ToolArtifact` records via migration `0009`.
- Added deterministic scope/risk/profile policy checks and fail-closed handling
  for unavailable or disabled tools, out-of-scope targets and ports, and unsafe
  executable configuration.
- Added typed adapter validation, per-plan/per-tool rate bounds, explicit
  `VALIDATED` lifecycle transition, and per-tool failure isolation.
- Added closed Nmap profiles, safe argument-vector execution, sanitized process
  environments, bounded stdout/stderr, timeouts, XML artifacts, and the
  `nmap-parser-v1` deterministic parser.
- Corrected bounded subprocess capture to read both streams through EOF without
  unbounded buffering and allow only Nmap's exact `<!DOCTYPE nmaprun>` form.
- Added controlled DNS and TLS adapters and routed HTTP discovery through the
  existing Rust executor rather than introducing a second HTTP transport.
- Added discovery observations with untrusted tool-data classification and raw
  artifact lineage; malformed parser output retains its artifact without
  fabricating observations.
- Extended the System Model with Nmap, DNS, and TLS mappers, `DOMAIN` assets and
  `RESOLVES_TO` relations. HTTP and Nmap facts for the same service merge into a
  single canonical service with multi-source provenance.
- Extended Attack Graph provenance validation for tool-artifact-backed facts;
  graph snapshots remain immutable and become stale when discovery changes the
  System Model.
- Added CLI commands for tool inspection, plan/run separation, tool-run and
  artifact inspection, and sanitized JSON discovery export.
- Updated the project version to `0.9.0`.
- Approved `nvidia/nemotron-3-super-120b-a12b` as the primary future inference
  core and added a typed NVIDIA NIM provider without connecting it to discovery
  planning or tool execution. The fake provider remains the offline/test default.

Final Phase 9 verification: 136 Python tests and 14 Rust tests passed. The
deterministic benchmark remained TP=2, FP=0, TN=5, FN=0 with one correct
inconclusive result. A local Nmap 7.95 run observed `127.0.0.1:8001/tcp` open,
persisted and parsed its XML artifact, enriched one existing HTTP service, made
the old graph stale, and rebuilt a new deterministic graph.
### Experimental controller mode

- Added opt-in `AEGIS_CONTROLLER_EXPERIMENTAL_MODE` (disabled by default).
- The mode permits bounded in-scope exploration, resolved-gap revisits, and repeated typed
  observations while retaining scope, credentials, budgets, Tool Policy, strict action schemas,
  controlled execution, and deterministic Finding authority.
- Controller status and JSON export expose whether experimental mode was enabled.
- Corrected `.env.example` to use the configured Nano Omni NVIDIA model.
