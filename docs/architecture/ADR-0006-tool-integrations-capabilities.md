# ADR-0006: Tool integrations extend capabilities, not controller authority

Status: Accepted (Phase 14)

## Decision

New tools register a versioned `ToolIntegration`: descriptor, capability,
closed profiles, strict request schema, adapter, artifact parser, observation
mapper, policy requirements, and generic UI metadata.

The closed-loop controller continues to request semantic capabilities. It does
not receive executable paths, arbitrary arguments, plugin import paths, or a
shell. ToolPolicy, immutable ResearchSession scope, approval and budget remain
authoritative for every integration.

## Consequences

Normal tool additions do not modify controller reasoning, strategy,
verification, Attack Graph core, or frontend business logic. A genuinely new
semantic domain may require new observation/model vocabulary, but cannot gain
authority merely by registration. Third-party dynamic plugin loading is
deferred because it would create a code-execution and supply-chain boundary not
justified for the local Phase 14 product.
