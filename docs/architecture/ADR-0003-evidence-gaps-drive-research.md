# ADR-0003: Evidence gaps drive research; models do not define truth

- Status: Accepted
- Date: 2026-08-23

## Decision

Aegis represents epistemic state explicitly. A statement is `KNOWN` only when a
deterministic projection can cite Observation and Evidence/artifact lineage.
Assumptions, unknowns, conflicts, untested hypotheses, and inconclusive results
remain separate classifications. Missing information is persisted as a closed,
typed `EvidenceGap`; a `ResearchIntent` is only a proposed way to address one or
more gaps.

The authoritative Phase 11 strategy is deterministic. It derives gaps from
structured project state, generates bounded ResearchQuestions, estimates ordinal
information gain and cost using documented rules, prevents duplicate satisfied
work, previews policy, and hands selected intents to Phase 10. It never executes
a target operation itself.

Untrusted HTTP, Nmap, DNS, and TLS strings are treated only as data. They are not
parsed as gap types, target selectors, priorities, or instructions. Optional LLM
assistance may later suggest explanations or summaries, but it cannot label facts,
resolve gaps, change priority policy, choose executable commands, or authorize an
action.

## Consequences

- Strategy adds no authority beyond the existing capability resolver, tool
  resolver, policy, DiscoveryPlan, and ToolRun boundary.
- Candidate Signals remain non-findings; sufficiency means only that evidence may
  enter the existing Hypothesis/Experiment/Verification pipeline.
- System Model facts, graph edges/signals, and Findings keep their existing
  authoritative builders.
- Conflicts are retained and generate a conflict gap instead of being overwritten.
- Resolved, blocked, and stale gaps remain auditable and knowledge hashes are
  canonical over semantic state.
