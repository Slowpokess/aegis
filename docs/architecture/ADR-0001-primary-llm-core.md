# ADR-0001: Primary LLM inference core

- Status: Superseded by ADR-0004 for the Phase 12 controller
- Date: 2026-08-22
- Decision: `nvidia/nemotron-3-super-120b-a12b`
- Provider: NVIDIA NIM
- Endpoint: `https://integrate.api.nvidia.com/v1`

## Context

Aegis needs a provider-independent reasoning core for evidence correlation,
structured hypothesis generation, and later capability-based planning. It must
not become a source of truth, a policy engine, or a command generator.

The NVIDIA catalog describes Nemotron 3 Super as an open 120B/12B-active hybrid
MoE with a 1M-token context, configurable reasoning, instruction following,
coding, structured-output training, and tool-use suitability. NVIDIA currently
offers a prototype/free API endpoint and downloadable weights. Free endpoint
availability is a trial service property, not a permanent cost guarantee.

Primary sources:

- https://build.nvidia.com/nvidia/nemotron-3-super-120b-a12b
- https://build.nvidia.com/nvidia/nemotron-3-super-120b-a12b/modelcard

## Decision

Use `nvidia/nemotron-3-super-120b-a12b` as the primary production inference
model. Access it through the existing typed `LLMProvider` abstraction using the
OpenAI-compatible NVIDIA NIM chat-completions endpoint and strict Pydantic
validation of structured output.

Keep the deterministic fake provider as the default for tests, benchmarks, and
offline operation. Anthropic remains an optional compatibility provider.

## Security boundary

This decision does not authorize model-driven discovery. In Phase 9:

- discovery plans expand deterministically from user-selected profiles;
- Tool Registry and Tool Policy remain authoritative;
- the model cannot provide executable paths, argv, shell strings, targets, or
  policy decisions;
- tool and target data remain untrusted even when later shown to a model;
- deterministic evaluation, not model reputation, decides whether the model is
  fit for a production workflow.

## Re-evaluation gate

Phase 10 makes only validated intent proposals operational; capability/tool
selection and authorization remain deterministic. Compare providers through the
existing Evaluation Framework and dedicated planner cases. Revisit this ADR if endpoint availability,
licensing, structured-output behavior, latency, or measured quality changes.
