# ADR-0002: LLM proposes research intent, never executable commands

- Status: Accepted
- Date: 2026-08-22

## Decision

An LLM may receive only a bounded, trust-labelled `ResearchContext` and may return
only `planner-decision-v1`. Its closed `ResearchIntent` vocabulary describes an
evidence gap, subject, expected information, priority, and supporting provenance.
The schema has no tool, executable, argv, URL, port, header, code, SQL, or policy
override fields.

Deterministic code maps intent to capability and capability to a Phase 9
ToolDescriptor/profile. Tool Policy independently evaluates immutable scope,
risk, availability, profile, timeout, and rate limits before Discovery may create
a ToolRun. The LLM output is a proposal—not authorization, fact, evidence,
Candidate Signal, Hypothesis verification, or Finding.

## Consequences

- Tool/target strings are delimited untrusted context data and cannot amend the
  system prompt.
- Invalid, cross-session, redundant, out-of-scope, or unsupported proposals fail
  closed and remain auditable.
- Satisfaction comes from resulting Evidence/Observations and deterministic
  evaluators.
- System Model, Attack Graph, Candidate Signals, and verified Findings retain
  their existing authoritative builders.
- Planner autonomy is bounded by explicit context, intent, step, tool-run, and
  duration limits.
