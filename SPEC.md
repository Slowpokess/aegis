# Aegis Specification

**Project:** Aegis — AI-Augmented Security Research Platform  
**Status:** Initial specification  
**Purpose:** Local, controlled, evidence-driven security research and AI/agent security experimentation.

> This project is intended for local laboratories, intentionally vulnerable applications, CTF environments, systems owned by the operator, and systems for which explicit authorization to test has been obtained.

---

## 1. Project Goal

Aegis is a local research platform for:

- collecting security-relevant observations;
- normalizing and preserving evidence;
- modeling systems, identities, permissions, capabilities, and trust boundaries;
- generating testable security hypotheses with an LLM;
- designing controlled experiments;
- enforcing deterministic scope and execution policy;
- executing only policy-approved actions;
- verifying hypotheses against runtime evidence;
- measuring AI performance against laboratory ground truth;
- studying LLM, RAG, MCP, tool-use, memory, and agent-security mechanisms in controlled environments.

The long-term research loop is:

```text
TARGET
  ↓
COLLECT
  ↓
NORMALIZE
  ↓
MODEL SYSTEM
  ↓
OBSERVE
  ↓
GENERATE HYPOTHESES
  ↓
PRIORITIZE
  ↓
DESIGN EXPERIMENT
  ↓
POLICY CHECK
  ↓
EXECUTE
  ↓
COLLECT EVIDENCE
  ↓
VERIFY
  ↓
UPDATE KNOWLEDGE
  ↓
REPORT / CONTINUE
```

---

## 2. Core Principles

### 2.1 LLM is not a source of truth

The LLM may:

- summarize observations;
- correlate evidence;
- generate hypotheses;
- identify missing information;
- propose experiments;
- prioritize hypotheses;
- interpret already collected evidence.

The LLM must not:

- invent observations;
- convert an inference into an observed fact;
- expand its own scope;
- modify execution policy;
- directly execute arbitrary shell commands;
- mark a security hypothesis as confirmed solely from its own reasoning.

Runtime evidence is authoritative.

### 2.2 Evidence before conclusions

The fundamental research lifecycle is:

```text
Observation
  ↓
Hypothesis
  ↓
Experiment
  ↓
Evidence
  ↓
Control
  ↓
Verification
  ↓
Finding
```

All relevant information must be classified as one of:

```text
OBSERVED
INFERRED
UNKNOWN
```

### 2.3 Provenance

Every security-relevant fact must preserve its origin.

Examples:

- HTTP request;
- HTTP response;
- source-code location;
- deterministic tool output;
- experiment result;
- user-provided configuration.

An LLM statement is not evidence.

### 2.4 Reproducibility

A meaningful finding should be reproducible and linked to the evidence that supports it.

### 2.5 Correctness over autonomy

Priority order:

```text
Correctness
> Reproducibility
> Evidence
> Simplicity
> Autonomy
```

---

## 3. Security Model

For each target, Aegis should progressively model:

- Assets
- Identities
- Roles
- Entry Points
- Endpoints
- Data
- Trust Boundaries
- Permissions
- Capabilities
- Sensitive Operations
- Relationships

Use the general data-flow model:

```text
Source
  ↓
Transform
  ↓
Guard
  ↓
Sink
```

Use the attack-path model:

```text
Entry
  ↓
Trust Boundary
  ↓
Primitive
  ↓
Identity / Privilege
  ↓
Capability
  ↓
Sensitive Resource
  ↓
Impact
```

---

## 4. AI / Agent Security Model

For AI systems, extend the model to:

```text
Untrusted Input
  ↓
Context
  ↓
LLM
  ↓
Policy
  ↓
Tool Selection
  ↓
Authorization
  ↓
External Action
  ↓
Memory
```

Track separately:

- system instructions;
- user input;
- retrieved documents;
- RAG context;
- tool output;
- persistent memory;
- identities;
- permissions;
- capabilities.

Every context object should preserve provenance and trust classification.

---

## 5. Technology Stack

Initial stack:

- Python 3.12+
- FastAPI
- Pydantic v2
- SQLAlchemy
- SQLite for MVP
- PostgreSQL-ready storage abstraction
- httpx
- Typer
- pytest
- Docker
- Docker Compose
- NetworkX in later graph phases

LLM integration must use a provider abstraction.

Domain logic must not depend directly on a specific OpenAI, Anthropic, Gemini, or local-model SDK.

Conceptual interface:

```python
class LLMProvider(Protocol):
    async def structured_generate(
        self,
        *,
        messages: list[Message],
        schema: type[BaseModel],
    ) -> BaseModel:
        ...
```

---

## 6. Repository Structure

Target structure:

```text
aegis/
├── SPEC.md
├── AGENTS.md
├── README.md
├── TODO.md
├── CHANGELOG.md
├── pyproject.toml
├── .env.example
├── Makefile
│
├── app/
│   ├── main.py
│   ├── config.py
│   │
│   ├── domain/
│   │   ├── assets.py
│   │   ├── observations.py
│   │   ├── hypotheses.py
│   │   ├── experiments.py
│   │   ├── evidence.py
│   │   ├── findings.py
│   │   ├── identities.py
│   │   └── capabilities.py
│   │
│   ├── collectors/
│   │   └── http.py
│   │
│   ├── reasoning/
│   │   ├── hypotheses.py
│   │   ├── experiments.py
│   │   └── prioritization.py
│   │
│   ├── execution/
│   │   ├── policy.py
│   │   └── http.py
│   │
│   ├── verification/
│   │   ├── comparisons.py
│   │   └── verifier.py
│   │
│   ├── llm/
│   │   ├── base.py
│   │   └── providers/
│   │
│   ├── storage/
│   │   ├── database.py
│   │   └── repositories.py
│   │
│   ├── graph/
│   │   └── attack_graph.py
│   │
│   └── cli/
│       └── main.py
│
├── lab/
│   ├── docker-compose.yml
│   └── vulnerable_api/
│
├── evals/
│   ├── scenarios/
│   └── runner.py
│
└── tests/
```

This structure may be improved when there is a concrete architectural reason. Do not introduce abstractions merely for pattern compliance.

---

## 7. Domain Objects

### 7.1 Observation

Minimum fields:

- `id`
- `asset_id`
- `source`
- `raw_data`
- `normalized_data`
- `provenance`
- `trust`
- `observed_at`

### 7.2 Hypothesis

Minimum fields:

- `id`
- `title`
- `description`
- `evidence_ids`
- `assumptions`
- `missing_information`
- `confidence`
- `status`

Initial statuses:

```text
NEW
TESTING
SUPPORTED
REJECTED
INCONCLUSIVE
```

`confidence` is model confidence, not vulnerability severity and not proof.

### 7.3 Experiment

Minimum fields:

- `id`
- `hypothesis_id`
- changed variable;
- constants;
- action;
- expected result if true;
- expected result if false;
- risk;
- control experiment.

### 7.4 Evidence

Minimum fields:

- `id`
- `experiment_id`
- exact request;
- exact response;
- source;
- timestamp;
- integrity hash.

### 7.5 Finding

A Finding may be created only after verification.

Minimum fields:

- claim;
- evidence references;
- reproduction information;
- control;
- impact;
- confidence;
- verification status.

---

## 8. Policy Engine

The Policy Engine must be deterministic and independent of the LLM.

For the initial MVP, executable HTTP methods are restricted to:

```text
GET
HEAD
OPTIONS
```

Policy must control at minimum:

- allowed hosts;
- allowed schemes;
- HTTP methods;
- redirect behavior;
- request rate;
- timeout;
- maximum response size;
- scope boundaries.

Core invariant:

```text
LLM proposes actions.
Policy decides whether actions are permitted.
Executor performs only policy-approved actions.
```

The LLM must not directly own unrestricted shell execution.

---

## 9. HTTP Executor

The executor must:

1. accept a typed action;
2. validate it through Policy Engine;
3. execute only an approved action;
4. preserve the exact request;
5. preserve the relevant response;
6. calculate an evidence integrity hash;
7. return evidence without independently declaring a vulnerability.

Response bodies must have configurable size limits.

---

## 10. Hypothesis Engine

The Hypothesis Engine receives structured observations.

Requirements:

- configurable maximum hypotheses per cycle;
- every factual claim references concrete Observation IDs;
- evidence and inference remain separate;
- missing evidence is explicitly represented;
- invented endpoints, users, responses, headers, or test results are forbidden;
- structured output is validated with Pydantic.

Core instruction:

```text
Every factual claim must be supported by an observation ID.
Never invent observations.
If available evidence is insufficient, explicitly state what information is missing.
```

---

## 11. Experiment Engine

For suitable hypotheses, generate:

```text
confirming experiment
+
falsifying/control experiment
```

An experiment should specify:

- variable being changed;
- constants;
- expected result if hypothesis is true;
- expected result if false;
- prerequisite observations;
- risk level.

The LLM proposes the experiment.

Policy determines whether it can be executed.

---

## 12. Verification Engine

Initial verification should be primarily deterministic.

Initial comparison capabilities:

- status-code comparison;
- header comparison;
- redirect comparison;
- JSON-field comparison;
- body-length comparison;
- response hash;
- normalized-body comparison.

Possible verdicts:

```text
SUPPORTED
REJECTED
INCONCLUSIVE
```

A high-confidence security finding should normally require:

```text
positive experiment
+
control
+
reproducibility
+
observable impact
```

---

## 13. Controlled Laboratory

Create an intentionally vulnerable local FastAPI application.

Minimum endpoints:

```text
GET /api/profile
GET /api/orders
GET /api/orders/{id}
GET /api/account/settings
GET /api/admin/stats
```

Minimum synthetic users:

```text
alice
bob
admin
```

Create at least six deterministic scenarios:

1. normal authorization;
2. intentionally broken object authorization;
3. harmless response difference;
4. controlled information disclosure;
5. false-positive trap;
6. insufficient-evidence scenario.

The laboratory must be reproducible and covered by integration tests.

Ground truth must not be exposed to the research agent through the normal target interface.

Prefer localhost binding and isolated Docker networking.

---

## 14. Ground Truth

Each laboratory scenario must have a machine-readable definition.

Example:

```yaml
id: LAB-002
vulnerability: true
class: broken_object_authorization

required_evidence:
  - user_b_reads_user_a_resource

required_control:
  - user_a_reads_user_a_resource

expected_verdict: supported
```

The eval framework may access ground truth.

The research pipeline may not.

---

## 15. Evaluation Framework

For each scenario, compare Aegis output against ground truth.

Calculate:

```text
TP
FP
TN
FN
Precision
Recall
F1
```

Track additional metrics where useful:

- hypotheses generated;
- experiments executed;
- requests per verified finding;
- token consumption;
- rejected actions;
- inconclusive rate;
- evidence count;
- verified-to-unsupported finding ratio;
- execution time.

Do not claim that a model, prompt, context strategy, or architecture improved unless evaluation results support the claim.

---

## 16. Development Methodology

Do not implement the entire roadmap in one pass.

For every phase:

1. inspect the existing repository;
2. run relevant existing tests;
3. define the exact phase objective;
4. implement only what the phase requires;
5. add unit/integration tests;
6. actually execute the tests;
7. start the relevant application/services;
8. fix discovered errors;
9. record actual results;
10. update documentation;
11. stop before the next phase unless explicitly instructed.

Never report:

```text
should work
probably works
tests would pass
```

as actual validation.

If a command was not executed, say so.

---

## 17. Definition of Done

A phase is complete only when:

- required code exists;
- imports work;
- relevant application components start;
- storage/migrations work when required;
- relevant tests pass;
- Docker Compose works when required by that phase;
- documented commands were actually validated;
- the critical path contains no placeholder implementation.

Future-phase TODOs are acceptable.

Critical-path TODOs are not.

---

## 18. Safety and Scope Invariants

Do not:

- fabricate test results;
- fabricate observations;
- treat LLM output as runtime evidence;
- allow the LLM to expand target scope;
- allow the LLM to modify Policy Engine rules at runtime;
- give the model unrestricted shell access;
- treat self-reported model confidence as verification;
- add uncontrolled autonomous exploitation;
- add multi-agent complexity without demonstrated need;
- execute against external targets outside explicitly configured authorized scope.

The platform is designed around controlled research and explicit authorization.

---

# 19. Roadmap

## Phase 0 — Foundation

Implement:

- repository structure;
- configuration;
- domain models;
- SQLite;
- repository layer;
- CLI skeleton;
- health endpoint;
- tests.

No LLM functionality yet.

### Exit criteria

- project installs;
- imports succeed;
- database initializes;
- CRUD tests pass;
- health endpoint works;
- CLI works;
- test suite passes.

---

## Phase 1 — Controlled Laboratory

Implement:

- intentionally vulnerable FastAPI application;
- `alice`, `bob`, `admin`;
- controlled scenarios;
- Docker Compose;
- ground truth;
- integration tests.

### Exit criteria

Every laboratory scenario is reproducible and its expected ground truth is demonstrated by tests.

---

## Phase 2 — Observation Pipeline

Implement:

- HTTP collector;
- normalized observations;
- provenance;
- trust classification;
- evidence capture;
- deterministic HTTP execution.

### Exit criteria

Aegis can execute an allowed laboratory observation, store the exact result, and retrieve it from storage without using an LLM.

---

## Phase 3 — AI Reasoning

Implement:

- LLM provider abstraction;
- structured output;
- Hypothesis Engine;
- observation/evidence references;
- missing-information representation.

### Exit criteria

Given laboratory observations, the LLM produces schema-valid hypotheses without executing actions.

---

## Phase 4 — Experiments

Implement:

- Experiment Engine;
- confirming/control experiments;
- Policy Engine;
- HTTP Executor;
- action rejection logging.

### Exit criteria

A hypothesis can generate a typed experiment, unsafe/out-of-scope actions are rejected, and approved laboratory actions can execute.

---

## Phase 5 — Verification

Implement:

- deterministic comparisons;
- hypothesis verdict lifecycle;
- reproducibility checks;
- verified findings.

### Exit criteria

At least selected laboratory scenarios can progress through:

```text
Observation
→ Hypothesis
→ Experiment
→ Evidence
→ Control
→ Verification
```

without manually inventing a result.

---

## Phase 6 — Evaluation

Implement:

- scenario runner;
- ground-truth comparison;
- TP / FP / TN / FN;
- Precision / Recall / F1;
- token/request/experiment metrics.

### Exit criteria

Different prompt/model configurations can be objectively compared on the same laboratory scenarios.

**Phase 6 is the major milestone.**

Do not significantly increase autonomy before this measurement layer exists.

---

## Phase 7 — System Model

Implement structured representations for:

- assets;
- identities;
- roles;
- endpoints;
- trust boundaries;
- permissions;
- capabilities;
- data relationships.

### Exit criteria

Collected observations can update a persistent system model without converting unsupported inferences into facts.

---

## Phase 8 — Attack Graph

Use NetworkX or an equivalent graph abstraction.

Initial node types:

```text
Asset
Identity
Endpoint
Data
Capability
Finding
```

Initial edge types:

```text
CAN_ACCESS
AUTHENTICATES_AS
CALLS
READS
WRITES
TRUSTS
CONTROLS
```

### Exit criteria

Aegis can construct and query attack-path candidates from evidence-backed system relationships.

---

## Phase 9 — Tool Registry + Controlled Discovery Plane

Add an authoritative typed Tool Registry and a deterministic discovery plane for
explicitly scoped laboratory targets. Phase 9 supports only HTTP, DNS, TLS, and
closed-profile Nmap discovery. A tool request selects a registered capability and
profile; it never supplies an executable, shell string, or arbitrary argument list.

```text
ResearchSession
  ↓
DiscoveryPlan
  ↓
Tool Registry
  ↓
Tool Policy
  ↓
Controlled Adapter
  ↓
Raw Artifact → Observation → System Model → Attack Graph
```

Raw external output is immutable, hashed, provenance-linked, and untrusted. The
existing Rust HTTP executor remains authoritative for HTTP. External binaries use
fixed resolved paths, generated argv, sanitized environments, output limits, and
timeouts. Plan generation and execution are separate explicit actions.

### Exit criteria

At least one non-HTTP discovery tool completes the full typed registry-to-graph
lineage without scope expansion, arbitrary command execution, or fabricated facts.

---

## Phase 10 — Research Planner + Capability-Based Tool Orchestration

Phase 10 adds `planner-decision-v1` and `research-planner-v1`. A bounded,
trust-labelled `ResearchContext` is the only project-state representation supplied
to the configured LLM provider. The provider may propose only closed
`ResearchIntent` values; strict schema and semantic validation reject extra tool,
command, target, port, header, code, SQL, or argument surfaces.

Deterministic resolvers map intent to `ToolCapability`, then to a registered
tool/profile. Phase 9 Tool Policy remains the only authorization boundary and the
existing DiscoveryPlan/ToolRun pipeline remains the only target execution plane.
Research steps and intents preserve context/decision hashes and full lineage.
Satisfaction is evaluated from observations, never by the LLM. System Model and
Attack Graph remain deterministic projections, Candidate Signals remain
non-findings, and only the Verification Engine may author verified Finding state.

The loop is bounded by context, entity, signal, history, intent, step, tool-run,
and duration limits. Duplicate satisfied semantic intents, unavailable tools,
policy rejection, invalid provider output, and exhausted limits fail closed.

---

## Phase 11 — Research Strategy + Evidence-Gap Reasoning

Phase 11 adds `knowledge-v1` and `research-strategy-v1`. A deterministic
`KnowledgeState` preserves `KNOWN`, `ASSUMED`, `UNKNOWN`, `CONFLICTING`,
`UNTESTED`, and `INCONCLUSIVE` rather than flattening inference into facts.
`KNOWN` requires Observation and Evidence/artifact lineage.

Closed, persistent `EvidenceGap` and `ResearchQuestion` records are derived from
the current System Model, Attack Graph/Candidate Signals, typed Hypothesis
missing information, verification history, and research history. Strategy ranks
candidate ResearchIntents using documented ordinal information gain, relevance,
multi-gap coverage, bounded cost/risk, duplicate work, and failed attempts. It
does not claim probabilities or vulnerability severity.

```text
Evidence → KnowledgeState → EvidenceGap → ResearchQuestion
         → Research Strategy → ResearchIntent → Phase 10
```

Strategy performs no target network operation and gains no execution authority.
Selected intents still pass the Phase 10 capability/tool resolver, Phase 9 Tool
Policy, and Discovery Plane. Gap resolution is deterministic; history is retained
as resolved, blocked, or stale. The strategy cannot create System Model facts,
graph edges/signals, or Findings. Untrusted tool/target text remains data and is
never interpreted as a gap directive.

### Exit criteria

Evidence gaps are detected, ranked, handed to the controlled orchestration path,
and reevaluated after new evidence with zero policy bypass, scope expansion, or
strategy-created Findings.

---

## Phase 12 — Typed Evidence Acquisition + Closed-Loop Research Controller

Phase 12 adds `research-action-v1`, `controller-decision-v1`,
`closed-loop-controller-prompt-v1`, and `closed-loop-controller-v1`. The model
or deterministic offline controller may choose a research decision, exact model
entities, an authorized logical identity, and one of six closed action types:
`HTTP_OBSERVE`, `SERVICE_DISCOVERY`, `DNS_RESOLVE`, `TLS_INSPECT`,
`REPRODUCE_EXPERIMENT`, or `STOP_RESEARCH`.

It cannot supply a URL, credential, header, executable, shell string, argv,
environment, SQL, Python, policy exception, System Model fact, graph edge,
Candidate Signal, or Finding. Endpoint and identity references are resolved
inside the control plane. Credentials are added only after authorization and are
never included in controller context, action records, exports, or logs.

```text
KnowledgeState + EvidenceGap + Strategy
                  ↓
          ControllerDecision
                  ↓
        TypedResearchAction
                  ↓
   entity/provenance/relevance validation
                  ↓
      immutable acquisition contract
                  ↓
 Tool Policy + Rust HTTP Policy / existing executor
                  ↓
 Evidence → Observation → Model → Graph → Knowledge → Gap reevaluation
```

The exact HTTP action stores endpoint, logical identity, safe method, purpose,
and bounded expected-information selectors. For an owner-baseline gap, the
validator requires the gap's owner identity, endpoint, and resource; `/health`
or the non-owner identity cannot satisfy it. The authorized contract freezes the
resolved path, method, entity IDs, response/time limits, and policy decision
before execution.

Persistent `ResearchBudget`, `ControllerStep`, `ResearchAction`, and
`ResearchActionResult` records provide a restart-safe audit trail and bounded
ledger for steps, actions, ToolRuns, requests, duration, and LLM calls. Pause is
honored before the next atomic action boundary. Resume and reconciliation reuse
completed result/ToolRun state and do not blindly repeat completed actions.
Equivalent satisfied actions are rejected by semantic hash; explicit experiment
reproductions include a reproduction number and remain distinct.

The configured NVIDIA NIM provider is accessed only through the common strict
structured-output provider. `reasoning_content` is neither required nor
persisted. The offline deterministic controller and explicit Fake provider make
tests and laboratory proofs independent of external inference.

System Model, Attack Graph, Candidate Signal, and Finding authority do not move:
only their existing builders and deterministic Verification Engine own those
state transitions.

### Exit criteria

The controller autonomously resolves a real `MISSING_BASELINE` gap by selecting
the observed owner identity and exact resource endpoint, passing deterministic
validation/policy, capturing Evidence through the Rust executor, rebuilding all
derived state, and stopping without manual fallback, scope expansion, policy
bypass, duplicate ToolRuns, or controller-created Findings.

---

# 20. Reporting Format for Coding Agents

After every implementation phase, report:

```text
Implemented:
Files created/modified:
Architecture decisions:
Commands executed:
Actual test results:
Known limitations:
Next phase:
```

Never claim a test, command, service, or endpoint was validated unless it was actually executed.

---

# 21. Initial Instruction

When beginning from a new repository:

1. read this entire `SPEC.md`;
2. inspect the repository;
3. implement **Phase 0 only**;
4. execute all relevant tests;
5. fix failures;
6. validate documented startup/CLI commands;
7. report actual results;
8. stop.

Do not automatically proceed to Phase 1.

---

# 22. Long-Term Success Criterion

Aegis is successful when it can take evidence from a controlled target and reliably perform:

```text
Understand
→ Model
→ Observe
→ Hypothesize
→ Experiment
→ Verify
→ Measure
```

while preserving provenance, enforcing deterministic policy, distinguishing facts from inference, and producing measurable results against known ground truth.

Only after this foundation is proven should the project increase agent autonomy.
## Experimental controller autonomy mode

`AEGIS_CONTROLLER_EXPERIMENTAL_MODE=true` enables a deliberately bounded experimental mode for
the Phase 12 controller. It relaxes semantic gap relevance, resolved-gap and satisfied-action
deduplication checks so the model can perform repeated or exploratory typed observations inside an
already authorized ResearchSession. Validation records `VALIDATED_EXPERIMENTAL`, and controller
status/export records whether the mode is active.

The mode does not disable immutable scope, entity/session ownership, identity and method
allowlists, capability budgets, Tool Policy, the Rust HTTP boundary, strict typed action schemas,
credential isolation, Evidence integrity, or deterministic Finding authority. It is not an
arbitrary shell mode and cannot be enabled by an LLM decision.

---

# Phase 13 — Adaptive Research Policy and Operator Control Plane

Phase 13 adds the persistent operator hierarchy
`ResearchProject → ResearchSession → ControllerStep → ResearchAction → Evidence`.
Project configuration contains a revisioned scope, logical identity names,
finite budget, approval mode, and a code-defined `research-policy-v1` profile.
Starting a Project snapshots immutable scope into a new ResearchSession.

Research policies are `CONSERVATIVE`, `BALANCED`, and `EXPERIMENTAL`. They
adjust deterministic candidate priority using evidence novelty, remaining
budget, prior outcomes, bounded exploration, and bounded semantic repetition.
They cannot change ToolPolicy. Experimental behavior remains restricted by
scope, budget, identity authorization, capabilities, the Rust policy/executor,
and deterministic verification authority.

Operator approval modes are `AUTO`, `APPROVE_HIGHER_COST`, and
`APPROVE_EVERY_ACTION`. A required approval is persisted only after action
validation and a non-executing ToolPolicy/Rust-policy preview. Approval causes a
fresh policy evaluation at execution; it never overrides policy. Pause, resume,
stop, action rejection, and action-type blocking are persisted safe boundaries.

`research-event-v1` provides an idempotent, ordered timeline derived from actual
state transitions. `operator-api-v1` exposes local Project/session lifecycle,
overview, bounded event/action lists, gaps, assets, graph summary, findings, and
approval operations. It binds through the existing local server default
`127.0.0.1`; production multi-user authentication is intentionally outside this
phase.

`aegis-report-v1` projects only persisted facts. JSON is authoritative; static
HTML is escaped. Findings include deterministic verification and
Evidence/Observation lineage. Inference and optional LLM prose are separate from
observed facts. Raw evidence bodies and credentials are excluded. A manifest
records per-file SHA-256/size and semantic model, graph, knowledge, and scope
hashes. Reports provide integrity checking, not a signed chain of custody.

# Phase 14 — Web Dashboard and Tool Integration SDK

Phase 14 adds a localhost React/TypeScript/Vite Operator Console. Its typed
client consumes `operator-api-v1` plus generic tool, ToolRun, full model/graph,
controller plan/step/run, report, and sanitized runtime endpoints. Polling is
bounded and overview pages do not load raw Evidence bodies. React default
escaping is authoritative.

`tool-integration-v1` is the static, code-controlled extension contract. A
`ToolIntegration` contains a richer descriptor, closed profiles, strict request
schema, adapter, artifact declarations, bounded parser, observation mapper,
policy requirements, and generic UI metadata. Existing HTTP/DNS/TLS/Nmap
behavior is wrapped rather than rewritten. Dynamic imports, uploaded Python,
arbitrary executables, and shell strings are unsupported.

The controller still requests capabilities and ToolPolicy authorizes scope,
profile, risk, and execution. Parsers and mappers cannot create Findings.
Reserved future capability/artifact values establish contracts only; no Phase
15 tool is registered or executable in Phase 14.

---

## Phase 15 — Passive Web Surface Intake

Phase 15 begins the web-focused acquisition path without expanding target execution
authority. The first vertical slice accepts bounded Burp XML traffic exports and
JSONL template-assessment output as offline, untrusted artifacts. Every URL is
checked against the immutable `TargetScope`; malformed input, XML DTD/entity
declarations, and oversized payloads fail closed. Out-of-scope records cannot
expand scope; mixed imports count and ignore them while retaining scoped records.

```text
Web Target
  → HTTP / Burp-derived traffic
  → Content Discovery
  → Template Assessment
  → Artifact lineage / Observation
  → Web Surface Model
  → existing System Model → Attack Graph → Candidate Signals
  → existing Hypothesis → Experiment → Verification
```

Content discovery is deterministic and passive. It projects observed exchanges,
same-scope HTML links, asset references, and forms; it does not crawl, fuzz, or
request discovered paths. Request/response hashes are retained, sensitive headers
are redacted from parsed records, and raw response bodies are not copied into
Observations. Imported HTTP exchanges may enrich the existing System Model through
artifact-backed Observations.

Template matches are candidate assessments only. Severity is source metadata, not
an Aegis vulnerability rating, and a template result cannot create a Finding.
Only the existing experiment and deterministic verification path may promote a
candidate into verified Finding state.

### Initial exit criteria

Burp traffic and template output can be parsed into a bounded, deduplicated,
same-scope Web Surface snapshot; Burp exchanges can be projected into artifact-
backed Observations accepted by the existing System Model mapper; and no imported
template result can bypass hypothesis, experiment, or verification authority.

### Phase 15.2 — Persistent Web Surface and operator integration

`web-surface-v1` is a deterministic, rebuildable projection of Evidence and
Observations; it does not replace either source-of-truth layer. WebResource
identity is `(scheme, normalized host, effective port, HTTP method, concrete
normalized path)`. Query values and volatile timestamps/UUIDs do not affect
resource identity or the semantic surface hash. GET and POST on the same path
are distinct resources, while `/search?q=foo` and `/search?q=bar` share one
resource and one `q` parameter.

The persistent projection contains WebResource, WebParameter,
HTTPRequestTemplate, WebResourceProvenance, WebTemplateCandidate, and
WebSurfaceSnapshot. Request templates contain only method, resource identity,
content type, parameter names/locations, optional logical identity reference,
and Observation IDs. They are not executable requests. Any future replay must
still pass through TypedResearchAction, Validator, ToolPolicy, and the Rust HTTP
executor.

Burp uploads are bounded before parsing and by entry, request, response, HTML
reference, and JSONL-record limits. Mixed imports keep in-scope records and
count ignored out-of-scope records. Malformed imports retain their immutable raw
ToolArtifact with FAILED parse status and create no Observations or projection
rows. Authorization, Cookie, Proxy-Authorization, and Set-Cookie values never
enter WebParameter, HTTPRequestTemplate, API, planner context, dashboard output,
or reports.

Template assertions persist as `TOOL_REPORTED` WebTemplateCandidates with
artifact, Observation, resource, and session lineage. Tool severity remains
source metadata and does not become verified Aegis severity. The Finding
authority boundary is unchanged. WebResources link explicitly to the existing
System Endpoint projection; they do not duplicate Host, Service, or Endpoint
semantics. Attack Graph behavior is unchanged.

The localhost Operator API and `aegis web` CLI expose offline Burp/template import, build, rebuild,
summary, resource, parameter, and request-template workflows. The dashboard
renders a first-class Web Surface page with React escaping, visible OBSERVED and
TOOL-REPORTED labels, Candidate terminology, import limits/scope, provenance,
and resource detail. Reports include a redacted, hashed `web-surface.json` and
separate observed-resource, tool-candidate, and verified-Finding sections.

ffuf and Nuclei execution are explicitly outside Phase 15.2. Their future
observations/candidates must reuse this generic projection and controlled action
path rather than tool-specific Finding tables.

### Phase 15.3 — Active Web Assessment Plane

Phase 15.3 reuses the Phase 14 Tool Integration SDK and the Phase 13 controller
authority path. `WEB_CONTENT_DISCOVERY` resolves to the registered ffuf
integration and `TEMPLATE_ASSESSMENT` resolves to the registered Nuclei
integration. Controller reasoning requests only typed capabilities/actions; it
does not supply executable arguments.

ffuf accepts the closed `web_content_small` and `web_content_standard` profiles.
Their wordlists are versioned, repository-owned inventory entries. Nuclei accepts
only `safe_templates`, whose local template inventory is repository-owned,
update-disabled, and excludes arbitrary paths/code templates. Adapters use a
resolved fixed executable and deterministic argument vector with
`create_subprocess_exec`; shell strings are forbidden. The subprocess receives a
minimal locale/PATH environment rather than provider credentials. Duration,
request estimate, concurrency, result count, stdout, and stderr are bounded.
Unavailable binaries, timeout, oversized output, non-zero exit, malformed
output, disallowed profiles, and out-of-scope input produce typed failures and
never fabricated observations.

The active authorization sequence is:

```text
typed active Web action
  → action validation and immutable TargetScope validation
  → policy/budget preview
  → persisted ActionApproval=PENDING when required; stop with no ToolRun
  → authoritative operator approve/reject endpoint
  → fresh validation and ToolPolicy evaluation
  → registry-selected ToolIntegration execution
```

`AUTO` does not require a synthetic approval row. `APPROVE_EVERY_ACTION` always
waits, and active assessment is treated as higher cost by
`APPROVE_HIGHER_COST`. A request payload contains no approval-authority boolean;
unknown fields remain rejected. `REJECTED` creates no process, ToolRun,
ToolArtifact, or Observation. If tool/profile/scope/budget policy changes after
approval, the second check rejects execution.

Successful execution persists a ToolRun and immutable raw ToolArtifact, parses
bounded untrusted output, and creates artifact-backed Observations. Builders—not
the active service—derive Web Surface and System Model state; the Attack Graph is
rebuilt from the resulting System Model. ffuf observations can add or
deduplicate canonical WebResources. Nuclei observations map to semantic
`TOOL_REPORTED` WebTemplateCandidates. Passive and active matches may share one
candidate while retaining multiple provenance associations. Candidate
provenance requires same-session Candidate, WebResource, ToolRun, ToolArtifact,
and Observation lineage.

The active service, tools, and controller cannot create or verify a Finding.
The recorded `finding_delta` for direct tool execution remains zero. Any future
promotion continues through the existing Hypothesis → Experiment → Verification
authority path.

The strict localhost API exposes preview/request operations at
`POST /sessions/{session_id}/web/discover` and
`POST /sessions/{session_id}/web/assess`, plus persisted lifecycle state at
`GET /sessions/{session_id}/web/assessment-runs`. Responses include action and
approval identifiers needed by the existing approve/reject endpoints. The Web
Surface dashboard polls this lifecycle, displays waiting/running/completed/failed
state using backend vocabulary, and treats frontend approval state as display
state only.
