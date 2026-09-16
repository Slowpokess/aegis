# Aegis

Aegis is an evidence-driven local platform for controlled AI-assisted security research. It is intended only for local laboratories, deliberately vulnerable applications, CTFs, owned systems, and systems for which the operator has explicit authorization.

The implementation is being delivered one verified phase at a time. Phases 0–15.3 are
complete. Aegis can collect scoped HTTP evidence through its Rust executor, generate
provenance-valid hypotheses and experiments, authorize actions through deterministic
Rust policy, and create Findings only after deterministic candidate/control verification.

## Core invariants

- Runtime observations, exact protocol records, source code, deterministic tool output, reproducible experiments, and laboratory ground truth are sources of truth.
- Model inference is never silently promoted to an observed fact.
- `OBSERVED`, `INFERRED`, and `UNKNOWN` are explicit provenance classifications.
- A hypothesis cannot become `SUPPORTED` without evidence references.
- A supported finding requires evidence, reproduction instructions, and control evidence.
- Future LLM components may propose actions; only deterministic policy may authorize execution.
- LLM output is always `INFERRED`; confidence is model confidence, not severity, verification, or proof.

## Phase 0 contents

```text
app/
├── cli/                 Typer entry point
├── domain/              Frozen Pydantic v2 domain models
├── storage/             SQLAlchemy mappings, database lifecycle, repositories
├── config.py            AEGIS_* configuration
└── main.py              FastAPI application factory and health endpoint
migrations/              Alembic initial schema migration
tests/                   Domain, repository, migration, API, and CLI tests
lab/                     Isolated controlled target and developer-only ground truth
native/rust/             Typed HTTP execution plane
app/llm/                 Provider-neutral LLM protocol and adapters
app/reasoning/           Sanitized context, prompts, validation, hypothesis orchestration
app/prompts/             Versioned reasoning prompt assets
```

The domain layer has no dependency on FastAPI, SQLAlchemy, a specific LLM vendor, or an external execution mechanism. Every persisted entity requires explicit provenance. SQLAlchemy records store validated domain payloads and selected indexed relationship/status fields. SQLite foreign keys are explicitly enabled. The same SQLAlchemy/Alembic boundary is suitable for a later PostgreSQL connection URL.

## Requirements

- Python 3.12+
- A virtual environment is strongly recommended

## Install

```bash
python3.12 -m venv .venv
source .venv/bin/activate
python -m pip install -e '.[dev]'
```

Copy `.env.example` to `.env` only when defaults need to be changed. Configuration uses the `AEGIS_` prefix.

## Database

Apply the versioned schema:

```bash
python -m alembic upgrade head
```

For local development, the idempotent CLI initializer creates the current schema directly:

```bash
aegis init-db
```

Alembic is the authoritative upgrade path. `AEGIS_DATABASE_URL` overrides the default `sqlite:///./aegis.db` for both the application and migrations.

## Run

```bash
python -m uvicorn app.main:app --host 127.0.0.1 --port 8000
curl --fail http://127.0.0.1:8000/health
```

The service binds to loopback in the documented command. Phase 0 exposes only `GET /health` and generated OpenAPI documentation.

## Controlled Laboratory

The Phase 1 laboratory is a deterministic synthetic FastAPI target. It is deliberately separate from the Aegis control-plane application.

Start and wait for its healthcheck:

```bash
docker compose -f lab/docker-compose.yml up --build --detach --wait
curl --fail http://127.0.0.1:8001/health
```

Stop it:

```bash
docker compose -f lab/docker-compose.yml down
```

The service is published only on `127.0.0.1:8001`. The container uses a non-root user, a read-only root filesystem, no host mounts, no privileged mode, and no additional Linux capabilities.

Synthetic bearer identities:

| Identity | Role | Authorization header |
| --- | --- | --- |
| Alice | `user` | `Authorization: Bearer alice-token` |
| Bob | `user` | `Authorization: Bearer bob-token` |
| Admin | `admin` | `Authorization: Bearer admin-token` |

Research-facing endpoints:

```text
GET /health
GET /api/profile
GET /api/orders
GET /api/orders/{order_id}
GET /api/orders/{order_id}/receipt
GET /api/account/settings
GET /api/account/settings/restricted
GET /api/admin/stats
GET /api/portal
```

Example:

```bash
curl --fail \
  -H 'Authorization: Bearer alice-token' \
  http://127.0.0.1:8001/api/profile
```

Ground truth is stored separately under `lab/scenarios` for tests and future evals. It is not exposed by the target API and is not copied into the target image. Developer rules for those files are documented in `lab/scenarios/README.md`.

CLI examples:

```bash
aegis --help
aegis info
aegis init-db --database-url sqlite:///./data/aegis.db
```

## Test

```bash
python -m pytest
```

Tests use isolated temporary SQLite databases, in-process ASGI clients, and a real loopback Python→Rust integration fixture. They check Phase 0 domain/storage invariants, all eight laboratory scenarios, Phase 2 protocol/storage lineage, Phase 3 context and referential-integrity boundaries, negative controls, ground-truth isolation, FastAPI startup, and CLI behavior.

## Observation Pipeline

Phase 2 separates responsibilities:

```text
Python control plane
  ResearchSession + immutable scope + storage + normalization
        ↓ versioned JSON over stdin/stdout
Rust execution plane
  validation + HTTP + timeout + redirect control + body bound + SHA-256
        ↓
Controlled target
```

Build the preferred/default executor and apply the latest schema:

```bash
make rust-build
python -m alembic upgrade head
```

The binary path defaults to `native/rust/target/debug/aegis-executor` and can be set explicitly with `AEGIS_EXECUTOR_PATH`. A broken or missing Rust executor is reported as an error; Aegis does not silently switch to a Python transport.

Start the laboratory, then create an immutable single-target session:

```bash
make lab-up

aegis research create \
  --name phase2-lab \
  --host 127.0.0.1 \
  --port 8001 \
  --scheme http
```

The command prints the session UUID. Execute and persist an observation:

```bash
aegis observe \
  --session <session-uuid> \
  --method GET \
  --path /api/profile \
  --identity alice
```

Inspect stored results:

```bash
aegis observations list --session <session-uuid>
aegis evidence show <evidence-uuid>
```

`evidence show` redacts `Authorization`, `Cookie`, `Set-Cookie`, and `Proxy-Authorization` headers. Exact request headers remain in evidence storage for reproducibility. Target response data is classified `UNTRUSTED`; deterministic normalized metadata is classified `TRUSTED`.

The executor retains at most `max_response_bytes` while streaming and marks captured evidence as truncated when more bytes exist. Redirect following defaults to false; when enabled, Rust still refuses cross-origin redirect expansion. Canonical hash and protocol details are documented in `native/rust/README.md`.

Run the complete Phase 2 gate:

```bash
make phase2-test
```

## LLM Reasoning / Hypothesis Engine

Phase 3 adds reasoning without granting an LLM any execution capability:

```text
Evidence + Observation
  → bounded sanitized context
  → versioned prompt
  → provider-independent structured generation
  → deterministic reference validation
  → NEW/INFERRED Hypothesis + LLMRun metadata
```

The context builder selects the latest bounded observations, excludes Base64 bodies, redacts sensitive HTTP headers, and limits both target body text and total serialized context. Target-controlled body text is explicitly enclosed as `UNTRUSTED TARGET DATA`; the system prompt says that it is data rather than instructions. The default limits are configurable with:

```text
AEGIS_LLM_CONTEXT_MAX_OBSERVATIONS=50
AEGIS_LLM_CONTEXT_MAX_BODY_CHARACTERS=2000
AEGIS_LLM_CONTEXT_MAX_TOTAL_CHARACTERS=50000
AEGIS_MAX_HYPOTHESES_PER_RUN=5
```

Prompts are versioned under `app/prompts/hypothesis`. The current version is `hypothesis-v1`, and every `LLMRun` stores that version plus a SHA-256 of the exact sanitized context.

The deterministic fake provider is the default and performs no network operation. Its output is explicitly supplied as a `HypothesisBatch` JSON file:

```bash
export AEGIS_LLM_PROVIDER=fake

aegis hypotheses generate \
  --session <session-uuid> \
  --fake-response ./local-hypothesis-response.json

aegis hypotheses list --session <session-uuid>
aegis hypotheses show <hypothesis-uuid>
```

Production providers remain behind the same typed `LLMProvider` boundary; no provider SDK is coupled to domain or reasoning code. The configured primary controller core is NVIDIA Nemotron 3 Nano Omni 30B A3B Reasoning through the NVIDIA NIM OpenAI-compatible endpoint. The deterministic fake provider remains the safe offline/test default:

```bash
export AEGIS_LLM_PROVIDER=nvidia_nim
export AEGIS_LLM_MODEL=nvidia/nemotron-3-nano-omni-30b-a3b-reasoning
export NVIDIA_API_KEY='configure-outside-version-control'

aegis hypotheses generate --session <session-uuid>
```

Anthropic remains an optional compatibility provider:

```bash
export AEGIS_LLM_PROVIDER=anthropic
export AEGIS_LLM_MODEL=claude-haiku-4-5-20251001
export ANTHROPIC_API_KEY='configure-outside-version-control'

aegis hypotheses generate --session <session-uuid>
```

The NVIDIA decision record is in `docs/architecture/ADR-0001-primary-llm-core.md`. It does not grant the model tool execution authority: Tool Registry selection and discovery remain deterministic.

### Experimental controller autonomy

An explicit experimental mode relaxes research-level relevance and repetition guards while
retaining the non-bypassable execution boundary:

```bash
export AEGIS_CONTROLLER_EXPERIMENTAL_MODE=true
```

When enabled, the controller may propose bounded in-scope exploration without an open evidence
gap, revisit a resolved gap, and repeat a previously satisfied typed observation. Every operation
still requires an existing session entity, authorized identity and method, immutable scope,
available budget, deterministic Tool Policy, and the existing controlled executor. Experimental
mode does not enable raw shell/argv, expose credentials, accept model-authored policy overrides,
or promote model proposals directly into authoritative facts, graph edges, signals, or Findings.
The mode is disabled by default and is reported by controller status and exports.

## Research Planner

Phase 10 introduces a bounded capability planner. The trust chain is deliberately
one-way: the LLM proposes a strict `ResearchIntent`; deterministic code resolves
its capability and registered tool/profile; Tool Policy authorizes against the
immutable session scope; Discovery executes; and Evidence/Observations determine
reality. The model never selects an executable, argv, URL, port, header, policy
exception, Finding, System Model entity, graph edge, or Candidate Signal.

The offline fake planner is the default and requires no inference network:

```bash
aegis research plan --session <session-uuid>
aegis research step --session <session-uuid>
aegis research run --session <session-uuid>
aegis research resume --session <session-uuid>
aegis research steps --session <session-uuid>
aegis research intents --session <session-uuid>
aegis research export --session <session-uuid> --format json
```

`research plan` persists the proposal, capability resolution, selected profile,
and policy preview but performs zero ToolRuns. `research run` is bounded by
`AEGIS_RESEARCH_MAX_STEPS`, `AEGIS_RESEARCH_MAX_TOOL_RUNS`, and
`AEGIS_RESEARCH_MAX_DURATION_SECONDS`; every actual target operation still passes
the Phase 9 Tool Policy. Context is independently bounded by the
`AEGIS_PLANNER_MAX_*` settings and labels all tool/target strings as untrusted
structured data. See `docs/architecture/ADR-0002-intent-not-commands.md`.

## Research Strategy and Evidence Gaps

Phase 11 adds a deterministic epistemic layer above the Phase 10 planner:

```text
Evidence → KnowledgeState → EvidenceGap → ResearchQuestion
         → ranked ResearchIntent → Phase 10 controlled orchestration
```

A fact is not an assumption, an unknown is not a negative result, a Candidate
Signal is not a Finding, and strategy is not authorization. `KNOWN` facts require
Observation plus Evidence/artifact lineage. `ASSUMED`, `UNKNOWN`, `CONFLICTING`,
`UNTESTED`, and `INCONCLUSIVE` remain distinct. Deterministic detectors identify
closed gap types from the current model, graph/signals, typed hypothesis missing
information, verification history, and research history; untrusted banners and
target strings are never parsed as strategy instructions.

Inspect and plan without executing a target process:

```bash
aegis knowledge show --session <session-uuid>
aegis gaps list --session <session-uuid>
aegis gaps show <gap-uuid>
aegis strategy plan --session <session-uuid>
aegis strategy export --session <session-uuid> --format json
```

`strategy plan` records ordinal information gain, bounded cost, policy preview,
and deterministic priority. It always reports `tool_processes_invoked: 0`.
Selected intents retain their gap associations and are handed to the existing
Research Planner/Discovery Plane; every execution still passes Tool Policy.
Gap resolution after a model rebuild is deterministic, history is retained as
`RESOLVED`, `BLOCKED`, or `STALE`, and only the Verification Engine can change
Finding state. LLM-assisted strategy is deliberately not enabled in Phase 11;
the configured NVIDIA provider remains available to the Phase 10 typed planner.
See `docs/architecture/ADR-0003-evidence-gaps-drive-research.md`.

Provider results normalize request ID, model, finish reason, latency, attempts, and reported token usage. Missing token values remain null. Provider errors use stable codes such as `AUTHENTICATION_ERROR`, `RATE_LIMIT`, `TIMEOUT`, and `STRUCTURED_OUTPUT_ERROR`; malformed output and invented references fail closed.

For every candidate, deterministic code checks:

- observation and evidence existence;
- membership in the same ResearchSession;
- exact Observation→Evidence linkage;
- missing-information references;
- explicit endpoint references against cited observations;
- the per-run maximum;
- normalized-title plus observation-ID duplicates.

No ID is silently repaired. Accepted hypotheses are persisted only as `NEW` with `INFERRED` provenance. The model cannot invoke the Rust executor, alter Evidence or Observation, read laboratory ground truth, create experiments, or create findings.

Run the complete Phase 3 gate:

```bash
make phase3-test
```

## Experiments and Policy

Phase 4 keeps generation and execution separate:

```text
Hypothesis → LLM experiment proposal → deterministic Python validation
           → Rust policy decision → explicit run → Rust HTTP executor
           → Evidence + normalized Observation
```

The model supplies only target-relative paths and logical identities. The Python control
plane resolves `alice`, `bob`, and `admin` to laboratory credentials after policy
approval; tokens are never included in the experiment prompt or persisted experiment.
Model-supplied protected headers, absolute or unobserved paths, unknown identities,
non-read-only methods, and risk above `LOW` fail closed.

Prompts live under `app/prompts/experiment`; Phase 4 records remain reproducible with
`experiment-v1`, while verification-aware generation uses `experiment-v2`.
Generate a proposal with the fake provider without executing it:

```bash
aegis experiments generate \
  --hypothesis <hypothesis-uuid> \
  --fake-response ./local-experiment-response.json

aegis experiments show <experiment-uuid>
aegis experiments check <experiment-uuid>
aegis experiments run <experiment-uuid>
```

`check` persists the candidate/control policy audit but performs no HTTP request. `run`
rechecks both actions under the current control-plane policy and executes neither unless
both are approved. Approved pairs run deterministically as control then candidate. Each
run creates a new `ExperimentExecution`, Evidence, and Observation lineage; previous
runs are not overwritten. Successful execution only moves the hypothesis to `TESTING`.
Phase 4 does not compare results, verify a vulnerability, create a Finding, or assign
severity.

The Rust policy accepts a versioned JSON operation over stdin/stdout and validates exact
scheme, parsed hostname, port, method, timeout, response bound, redirect behavior, and
model-controlled header allowlist. Python and Rust independently calculate the same
SHA-256 over canonical normalized policy JSON. `AEGIS_POLICY_PATH` selects the binary;
missing, timed-out, malformed, mismatched, or crashing policy processes deny execution.
The per-session request-rate limiter is deterministic and persisted in the Python
execution coordinator because Phase 4 uses a stateless subprocess per decision.

Run the Phase 4 gate:

```bash
make phase4-test
```

## Verification and Findings

Phase 5 adds a provider-independent, deterministic verification boundary:

```text
ExperimentExecution
  → candidate/control Evidence integrity and lineage checks
  → closed typed comparisons
  → SUPPORTED / REJECTED / INCONCLUSIVE
  → Finding only for aggregate SUPPORTED
```

`Hypothesis ≠ Finding`, `Experiment ≠ Finding`, and HTTP 200 alone is never proof of a
vulnerability. A verification-aware experiment persists a versioned `verification_spec`
containing only closed comparison types and operators—no `eval`, expressions, shell,
SQL, arbitrary regex, or provider-authored executable code. Supported primitives cover
status, headers, redirects, content type, body length/hash, JSON validity, selected JSON
field presence/value, and normalized JSON.

Every result stores `verification-v1`, a rule ID/version, the exact candidate/control
Evidence and Observation IDs, typed actual comparison values, integrity state, and a
reason. Body-dependent rules become `INCONCLUSIVE` for truncated evidence. Missing or
legacy specs, incomplete executions, broken cross-session/role lineage, and hash
mismatches also fail closed as `INCONCLUSIVE`.

Run and inspect deterministic verification:

```bash
aegis verify execution <execution-uuid>
aegis verify experiment <experiment-uuid>
aegis findings list --session <session-uuid>
aegis findings show <finding-uuid>
```

`AEGIS_MIN_VERIFICATION_RUNS` controls the minimum completed verification runs required
for aggregate support (default `1`). All supported runs aggregate to `SUPPORTED`, all
rejected runs to `REJECTED`, and mixed or incomplete results to `INCONCLUSIVE`. A later
contradiction does not delete history: the single experiment Finding is marked disputed.
Finding output contains logical identities and lineage but never displays bearer tokens.

Run the complete Phase 5 gate:

```bash
make phase5-test
```

## Evaluation and Benchmarking

Phase 6 compares completed research results with the isolated eight-scenario laboratory
ground truth only after the research workflow has finished. The dependency direction is
strict: `evals` may use `app` and `lab.ground_truth`; observation, reasoning, execution,
and verification code cannot import evaluation or ground-truth modules.

Two benchmark modes are distinct:

- `deterministic` is a pipeline benchmark driven by explicit, neutral harness fixtures.
  It verifies orchestration, lineage, classification, persistence, metrics, and reporting;
  it is not a measurement of LLM reasoning quality.
- `live` is reserved for a configured real-provider model benchmark. It does not accept
  credentials on the command line and is unavailable unless both provider credentials and
  a live model harness are configured.

Run, inspect, compare, and export benchmarks:

```bash
aegis eval run --mode deterministic --all
aegis eval run --mode deterministic --scenario LAB-002
aegis eval list
aegis eval show <benchmark-run-uuid>
aegis eval scenario <benchmark-run-uuid> LAB-002
aegis eval compare <run-a-uuid> <run-b-uuid>
aegis eval export <benchmark-run-uuid> --format json
```

The JSON export writes `summary.json`, `scenarios.json`, and a sanitized `config.json`
under `reports/evals/<run-id>/`. Each run persists the evaluator, harness, ground-truth,
and sanitized configuration hashes; provider/model, prompt, verifier, policy, executor,
and optional Git metadata; raw confusion-matrix components; nullable derived metrics;
per-scenario lineage; request/token/runtime counters; and failure stage.

Security verdicts (`SUPPORTED`, `REJECTED`, `INCONCLUSIVE`) remain separate from benchmark
classifications (`TP`, `FP`, `TN`, `FN`, correct/unexpected inconclusive, and not scored).
Precision, recall, and F1 use standard definitions. An undefined denominator produces
`null` with an explicit reason rather than an invented zero or one. Technical pipeline or
provider failures are not silently counted as security predictions.

Run the complete Phase 6 gate:

```bash
make phase6-test
```

## System Model

Phase 7 adds a persistent, deterministic projection of evidence-backed system facts:

```text
Evidence → Observation → SystemModelBuilder → typed entities and relationships
```

The System Model is not Evidence and does not replace immutable runtime records. Every
observed entity and relationship carries its source type, classification, confidence,
Observation IDs, Evidence IDs, and first/last-seen timestamps. Phase 7 creates only
`OBSERVED` facts; it performs no LLM enrichment and does not read evaluation ground truth.

The authoritative SQLite/PostgreSQL-ready projection contains typed assets, services,
endpoints, identities, roles, permissions, capabilities, data objects, trust boundaries,
and generic relationships. The HTTP mapper conservatively derives exact host/service/path,
logical identity access outcomes, and clear order resources/ownership. A `200` access fact
is not labeled as a vulnerability, and a `403` for one identity is not generalized to other
users or endpoints.

Build, query, rebuild, and export a session model:

```bash
aegis model build --session <session-uuid>
aegis model show --session <session-uuid>
aegis model assets --session <session-uuid>
aegis model endpoints --session <session-uuid>
aegis model identities --session <session-uuid>
aegis model relationships --session <session-uuid> --type CAN_ACCESS
aegis model relationships --session <session-uuid> --source alice
aegis model export --session <session-uuid> --format json
aegis model rebuild --session <session-uuid>
```

Incremental builds explicitly checkpoint processed Observation IDs. Reprocessing unchanged
input creates no duplicate entities or relationships. Rebuild deletes only the projection,
replays immutable observations, and reproduces the same semantic SHA-256. Export contains
logical identities and provenance, never request credentials or raw authorization headers.
Unsupported future sources are checkpointed as unsupported without crashing; a future
Nmap/DNS/TLS mapper can produce the same core entities without a separate database.

Run the complete Phase 7 gate:

```bash
make phase7-test
```

## Attack Graph and Path Analysis

Phase 8 projects the persistent System Model into a bounded, deterministic analytical
graph without contacting the target:

```text
Evidence → Observation → System Model → Attack Graph → Paths / Candidate Signals
```

The System Model remains the evidence-backed factual projection and database source of
truth. `attack-graph-v1` is a reproducible in-memory projection linked to the exact
`system-model-v1` SHA-256. Snapshot rows store only graph metadata and candidate signals;
nodes and edges are rebuilt rather than duplicated as a second topology database.

Edges are explicitly `TRAVERSABLE`, `INFORMATIONAL`, or `BLOCKING`. Exact observed
`CAN_ACCESS` transitions are traversable, `CANNOT_ACCESS` transitions are queryable but
never traversed, and ownership remains informational. Shortest paths use deterministic
BFS; bounded enumeration uses cycle-safe simple paths. Path confidence is the minimum
source-edge confidence—not an AI, severity, exploitability, or vulnerability score.

Build and query a graph:

```bash
aegis graph build --session <session-uuid>
aegis graph show <graph-uuid>
aegis graph path --graph <graph-uuid> --from identity:admin \
  --to endpoint:GET:http://127.0.0.1:8001/api/admin/stats
aegis graph reachable --graph <graph-uuid> --from identity:bob
aegis graph cross-identity --graph <graph-uuid>
aegis graph role-diff --graph <graph-uuid>
aegis graph export <graph-uuid> --format json
```

`CROSS_IDENTITY_RESOURCE_ACCESS` and `ROLE_ACCESS_DIFFERENCE` are deterministic candidate
signals with relationship, Observation, and Evidence lineage. A candidate signal is not a
Hypothesis or Finding. Findings still require the separate Experiment → Policy → Execution
→ Verification pipeline. Graph snapshots fail closed as stale when the System Model hash
changes. Limits are configured with `AEGIS_GRAPH_MAX_DEPTH` (default `6`),
`AEGIS_GRAPH_MAX_PATHS` (default `100`), and `AEGIS_GRAPH_MAX_NODES` (default `10000`).

Run the complete Phase 8 gate:

```bash
make phase8-test
```

## Data model boundaries

- `Observation` retains raw data, normalized data, provenance, trust, and timestamp separately.
- `Hypothesis` cites concrete observation/evidence IDs and keeps typed assumptions and missing information explicit. Its confidence remains self-reported model confidence.
- `Experiment` is an inferred candidate/control plan; `ExperimentExecution` records every explicit run and policy/evidence lineage.
- `Evidence` retains the exact captured HTTP request/response, executor metadata, protocol version, and Rust-generated canonical SHA-256.
- `VerificationResult` is immutable per execution and preserves rule, comparator, integrity, and evidence lineage.
- `Finding` is created only for aggregate deterministic `SUPPORTED`; rejected and inconclusive hypotheses remain stored without a new Finding.

## Known limitations

- The bundled deterministic benchmark uses eight controlled synthetic scenarios and
  explicit fixtures. Its metrics prove pipeline/evaluator behavior, not real-world or LLM
  accuracy.
- Live-model benchmark orchestration is architecture-ready but requires a configured real
  provider and live harness; deterministic fixtures do not estimate model quality.
- `create_all` is enabled by default for convenient local startup; deployments should set `AEGIS_AUTO_CREATE_SCHEMA=false` and apply Alembic migrations explicitly.
- PostgreSQL readiness is an architectural boundary, not a tested backend claim in Phase 0.
- The Phase 4 hostname authorization is parser-correct but not production-grade DNS pinning; DNS resolution/rebinding controls remain future hardening.
- The persisted Python rate limiter is deterministic for the current single-process coordinator but is not a distributed atomic limiter.
- Phase 3 uses deterministic exact deduplication rather than semantic similarity or embeddings.
- Exact synthetic request credentials remain in Evidence storage for reproducibility; they are excluded from LLM context and redacted from CLI display, but SQLite encryption-at-rest is not provided.
- Phase 7 maps only deterministic HTTP facts. Trust boundaries remain empty unless a future
  evidence source can support them; no inferred topology is fabricated.
- Phase 8 performs directed reachability over existing System Model relationships only. It
  does not discover endpoints, infer exploitability, score severity, or turn graph signals
  into Findings. Graph nodes are bounded in-memory and persisted paths are intentionally
  omitted to avoid combinatorial storage growth.
- The generic relationship table enforces entity existence and session isolation in the
  repository boundary because relational databases cannot express a foreign key spanning
  several typed target tables.

## Progress and next phase

Executed phase results are recorded in `CHANGELOG.md`.

Phases 0–15.3 are complete. Phase 16 is in progress: its typed client-side
verification boundary is implemented, and the Playwright executor vertical
slice is disabled by default pending persisted control-plane integration and a
supported Chromium runtime. See [the upgrade roadmap](docs/ROADMAP.md).

## Controlled client-side verification

Phase 16 extends the existing evidence lifecycle to browser-visible effects
without giving a model browser control. The model may propose an evidence-backed
context and a closed probe identifier. Deterministic code resolves the target,
rechecks scope and persisted approval, and owns every browser operation.

```text
Evidence-backed WebResource + Hypothesis
  → typed client-verification proposal
  → deterministic validation + persisted approval
  → ephemeral same-origin browser context
  → candidate / baseline control evidence
  → deterministic Verification Engine
  → Finding only when verification supports it
```

CSRF values, cookies, Authorization headers, credentials, and browser storage
are never accepted from model output and never appear in proposals, reports, or
LLM context. A future enabled executor can obtain an observed CSRF token only in
memory from a same-origin page in its new browser context. It may run only on
`ISOLATED_LAB` or `STAGING`, blocks external browser egress, and fails closed
when approval, a scoped evidence reference, or a configured Chromium binary is
missing.

## Operator Control Plane and Evidence-Backed Reports

Phase 13 formalizes the operator workflow around persistent Projects. A Project
owns revisioned scope configuration, logical identity references, a finite
budget, an approval mode, and one of three research policies. Each start creates
a new immutable ResearchSession scope snapshot; changing Project scope never
rewrites a historical session.

```bash
aegis projects create --name local-lab --policy CONSERVATIVE
aegis projects configure <project-id> --host 127.0.0.1 --port 8001 \
  --policy BALANCED --approval-mode APPROVE_EVERY_ACTION --max-actions 5
aegis projects start <project-id>
aegis controller status --session <session-id>
aegis controller approvals --session <session-id>
aegis controller approve <action-id>
aegis report generate --session <session-id>
```

`CONSERVATIVE`, `BALANCED`, and `EXPERIMENTAL` control research prioritization,
novelty, repetition, and exploration. They never replace ToolPolicy: immutable
scope, authorized identities, capability bounds, Rust HTTP policy, and Finding
authority remain deterministic. The legacy
`AEGIS_CONTROLLER_EXPERIMENTAL_MODE=true` setting maps to the experimental
controller behavior for backward compatibility.

Approval modes are `AUTO`, `APPROVE_HIGHER_COST`, and
`APPROVE_EVERY_ACTION`. Required approvals are created only after validation and
a non-executing policy preview. Approval triggers a fresh policy check; rejection
creates no ToolRun. The local FastAPI operator API is intended for development,
defaults to `127.0.0.1`, uses strict versioned schemas, bounded pagination, and
does not claim production multi-user authentication.

Reports are exported beneath
`reports/projects/<project-id>/<session-id>/` as deterministic JSON projections
plus escaped static HTML. Findings retain verification, Evidence, and
Observation references; rejected and inconclusive hypotheses remain separate.
Raw evidence bodies and credential material are excluded. `manifest.json`
records the SHA-256 and size of every exported artifact. Target-controlled HTML
and instruction-like text are escaped data, never report instructions.

## Typed Evidence Acquisition and Closed-Loop Controller

Phase 12 lets the configured reasoning model control research decisions without
controlling authority. It emits only a strict `TypedResearchAction`; deterministic
code resolves model entities, validates relevance and provenance, resolves a
logical authorized identity without exposing its credential, and applies Tool
Policy plus the existing Rust HTTP policy/executor boundary.

```text
LLM/deterministic decision -> TypedResearchAction -> validation -> policy
                           -> controlled execution -> Evidence/Observation
                           -> Model/Graph/Knowledge/Gaps -> next decision
```

For `HTTP_OBSERVE`, the model chooses existing endpoint and identity entity IDs,
not a raw URL or Authorization header. A missing owner baseline for `order:101`
therefore resolves to the exact owner and exact `/api/orders/101` endpoint; an
unrelated `/health` action or wrong identity is rejected and cannot resolve the
gap. `EvidenceAcquisitionContract` freezes the authorized semantic target and
bounds before execution.

The controller is persistent and budgeted:

```bash
aegis controller plan --session <session-id>
aegis controller step --session <session-id>
aegis controller run --session <session-id>
aegis controller pause --session <session-id>
aegis controller resume --session <session-id>
aegis controller status --session <session-id>
aegis controller steps --session <session-id>
aegis controller actions --session <session-id>
aegis controller export --session <session-id> --format json
```

`plan` may produce and validate a proposal but performs zero target operations.
Every executed target operation has persisted action, contract, policy,
DiscoveryPlan/ToolRun or ExperimentExecution, Evidence/Observation, and derived
state lineage. Pause takes effect at the next safe boundary; resume preserves
the ledger and semantic deduplication.

Default limits are configured with `AEGIS_CONTROLLER_MAX_STEPS`,
`AEGIS_CONTROLLER_MAX_ACTIONS`, `AEGIS_CONTROLLER_MAX_TOOL_RUNS`,
`AEGIS_CONTROLLER_MAX_REQUESTS`, `AEGIS_CONTROLLER_MAX_DURATION_SECONDS`,
`AEGIS_CONTROLLER_MAX_LLM_CALLS`, and
`AEGIS_CONTROLLER_MAX_ACTIONS_PER_STEP`. The controller cannot increase them.

The configured primary model is
`nvidia/nemotron-3-nano-omni-30b-a3b-reasoning` through NVIDIA NIM. Tests and
offline runs use the deterministic/Fake path. API keys remain environment-only;
provider `reasoning_content` is ignored and not persisted. The model never
creates Findings: only the deterministic Verification Engine can do that.
# Tool Registry and Controlled Discovery Plane

Phase 9 adds a deterministic discovery boundary. Tools are selected by a typed
capability and a closed, versioned profile; neither users nor model output can
supply a shell command or arbitrary Nmap arguments. The registry describes what
is available, while policy independently decides whether a request is allowed
for the immutable `ResearchSession` scope.

The built-in `tool-registry-v1` catalog exposes:

- `http`, routed through the existing Rust HTTP executor;
- `dns`, limited to scoped A/AAAA resolution facts;
- `tls`, limited to handshake and certificate facts;
- `nmap`, limited to the closed `common_tcp_ports` and
  `service_discovery` profiles.

Discovery is deliberately split into planning and execution:

```bash
aegis tools list
aegis tools doctor
aegis discover plan --session <session-id> --profile standard
aegis discover run <plan-id>
aegis discover export <plan-id> --format json
```

Every external run is scope-checked before execution. Nmap uses a resolved,
known executable and an internally generated argument vector with `shell=False`,
a sanitized environment, bounded output, and a timeout. Raw output is retained
as an immutable `ToolArtifact` with SHA-256 before deterministic parsing. Parser
failure preserves the artifact and creates no fabricated observations.

Tool and target output is always untrusted data. Service banners, DNS names, TLS
certificate text, Nmap product strings, and HTTP content are never instructions.
Discovery creates evidence-backed facts, not vulnerability conclusions:

```text
DiscoveryPlan -> ToolRun -> ToolArtifact -> Observation
              -> System Model -> Attack Graph
```

For an IP-based HTTP laboratory target, `standard` schedules HTTP metadata and
optional Nmap service discovery. DNS is scheduled only for a hostname, and TLS
only when TLS is applicable. Nmap is never installed automatically; `tools
doctor` reports it unavailable and execution fails closed when the binary is
missing.

Configuration limits:

```text
AEGIS_TOOL_MAX_CONCURRENCY=2
AEGIS_TOOL_MAX_RUNS_PER_PLAN=8
AEGIS_TOOL_ARTIFACT_MAX_BYTES=1000000
AEGIS_NMAP_ENABLED=true
```

Known Phase 9 limitations: discovery is restricted to one exact scoped host and
explicit scoped ports; there is no CIDR expansion, NSE, brute force, content
fuzzing, CVE enrichment, AI planner, or automatic conversion of graph signals
into hypotheses. DNS captures the resolved address set and timestamp, while
hostname Nmap execution fails closed pending a future end-to-end pinned-address
transport. DNS/TLS adapters provide typed discovery facts but do not make
security judgments.

# Phase 14 Web Dashboard

The React/TypeScript/Vite Operator Console is in `web/`. It provides Project
creation, scope/budget configuration, policy and approval selection, controller
controls, pending approvals, timeline, System Model, gaps, actions, generic
tools, Attack Graph, Findings, reports, and sanitized runtime status.

```bash
cd web
npm ci
npm run dev       # 127.0.0.1:4173; /api proxies to 127.0.0.1:8000
npm run build
```

After a build FastAPI serves the bundle at `/ui`. This is a localhost-only
development control plane, not production multi-user authentication. React
escaping remains intact; target HTML is never rendered with
`dangerouslySetInnerHTML`.

# Tool Integration SDK

`tool-integration-v1` gives HTTP, DNS, TLS, Nmap, ffuf, and Nuclei a common
descriptor/profile/parser/mapper/UI contract without changing their existing
execution paths. The dashboard discovers cards from `GET /tools` and contains
no tool-specific rendering logic. See
[`docs/tool-integration.md`](docs/tool-integration.md).

# Phase 15 Persistent Web Surface

Phase 15.2 persists `web-surface-v1`, a deterministic projection of Evidence and
Observations built from bounded Burp XML exports and optional passive JSONL
template-assessment results:

```text
Burp traffic → passive content extraction → template candidates → Web Surface
             → artifact-backed Observation → existing System Model
```

All imported URLs must match the immutable research scope. XML entities/DTDs,
oversized inputs, malformed records, and parser explosions fail closed. A mixed
artifact accepts scoped entries and reports the count ignored as out of scope.
Authorization, Cookie, Set-Cookie, and Proxy-Authorization values are redacted in
parsed traffic. HTML discovery never performs a request. Template matches remain
candidate-only metadata and cannot create Findings.

WebResource identity includes method, so `GET /login` and `POST /login` remain
distinct. Query values are omitted from identity, so different values of `q`
produce one resource and one parameter. Form actions, methods, and field names
produce safe request templates; field values and credentials do not.

Operator CLI workflow:

```bash
aegis web import-burp --session <id> --file traffic.xml
aegis web import-burp --session <id> --file traffic.xml --template-file matches.jsonl
aegis web import-template --session <id> --file matches.jsonl
aegis web build --session <id>
aegis web rebuild --session <id>
aegis web show --session <id>
aegis web resources --session <id>
aegis web resource-show <resource-id>
aegis web parameters --session <id>
aegis web templates --session <id>
```

The Operator API exposes the equivalent bounded Burp import/build and read-only
surface/resource/parameter/template/candidate endpoints. The Web Surface page
shows the immutable session scope and upload limit before import, GET/POST
resources, parameters, provenance, request templates, and candidates. Imported
markup is rendered as text; no target HTML is injected into the UI.

Reports include a manifest-hashed `web-surface.json` plus explicitly separated
Observed Resources, Tool Candidates, and Verified Findings. Planner/controller
context receives only bounded semantic surface summaries—not imported bodies,
credential values, or tool-controlled display text.

Phase 15.3 adds bounded active assessment without changing Finding authority:

```text
Web Surface
  → active assessment request
  → persisted ResearchAction
  → ActionApproval when required
  → fresh ToolPolicy check
  → ToolRun → raw ToolArtifact → Observation
  → Web Surface / System Model / Attack Graph rebuild
  → tool Candidate (Nuclei)
  → optional existing Verification path
```

ffuf uses only repository-owned `web_content_small` or
`web_content_standard` wordlists. Nuclei uses only the repository-owned
`safe_templates` inventory; arbitrary template paths and code templates are not
accepted. Both integrations construct deterministic argv and execute fixed
binaries without a shell. Immutable scope, request/tool-run/duration budgets,
timeouts, concurrency, output size, parser limits, and ToolPolicy are enforced.
Tool output is untrusted data. An ffuf result may add or deduplicate a
WebResource; a Nuclei match creates an Observation and Candidate, never a
Finding.

Preview or request the active workflows:

```bash
aegis tools doctor
aegis web discover --session <id> --resource <resource-id> --preview
aegis web discover --session <id> --resource <resource-id>
aegis web assess --session <id> --resource <resource-id> --preview
aegis web assess --session <id> --resource <resource-id>
aegis controller approvals --session <id>
aegis controller approve <action-id>
aegis web tool-runs --session <id>
```

The equivalent strict Operator API is `POST /sessions/{id}/web/discover`,
`POST /sessions/{id}/web/assess`, and
`GET /sessions/{id}/web/assessment-runs`. A client boolean cannot approve an
action. In `APPROVE_EVERY_ACTION` (and active higher-cost approval), execution
stops with a persisted pending approval and no ToolRun. The existing action
approve/reject endpoints are authoritative, and approval always triggers a new
policy check before execution. In `AUTO`, validation and ToolPolicy may proceed
without a synthetic approval row.

The dashboard Web Surface page loads the persisted action/run lifecycle and
uses the same authoritative approval controls. React renders tool-controlled
text escaped. Reports continue to separate discovered resources, tool
Candidates, and verified Findings.

ffuf and Nuclei are optional external runtime dependencies and are never
installed automatically. `aegis tools doctor` reports actual availability. CI
uses sanitized deterministic adapter fixtures and does not require either
binary. For test environments that prohibit listening sockets, use:

```bash
make test-offline
make test-integration  # requires the controlled loopback laboratory
```
