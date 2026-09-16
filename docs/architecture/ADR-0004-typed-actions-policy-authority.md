# ADR-0004: LLM research decisions use typed actions; policy controls authority

- Status: Accepted
- Date: 2026-08-24
- Controller model: `nvidia/nemotron-3-nano-omni-30b-a3b-reasoning`
- Provider: NVIDIA NIM through the common `LLMProvider`

## Context

Phase 11 could rank a missing owner baseline but lost its endpoint and identity
specificity when it became generic HTTP metadata discovery. Giving a model a
shell, argv, raw URL, credential, or policy surface would preserve specificity
at the cost of destroying Aegis's security boundary.

## Decision

The model controls research decisions only through strict
`research-action-v1` entities. It may reference current scoped endpoint,
identity, resource, gap, question, signal, and hypothesis IDs and choose a closed
action type. Deterministic resolvers produce executable request material;
deterministic validation and policy remain authoritative.

The default configured NVIDIA core changes from Nemotron 3 Super to
`nvidia/nemotron-3-nano-omni-30b-a3b-reasoning` for the bounded controller. The
runtime environment may override the model explicitly. The Fake/deterministic
provider remains mandatory for offline tests and benchmarks. This model choice
does not grant execution authority.

## Consequences

- Exact owner-baseline observations retain endpoint and identity semantics.
- Credentials never enter prompts, typed actions, exports, or logs.
- Raw command, argument, URL, header, and policy-override fields fail strict
  schema validation.
- An immutable acquisition contract records the authorized target and bounds.
- Tool and Rust HTTP policies still decide whether execution may occur.
- Evidence determines observations; builders determine model/graph state;
  verification determines Findings.
- NVIDIA `reasoning_content` is ignored and never persisted.

Unrestricted shell execution is intentionally not an Aegis research interface.
