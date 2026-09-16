# ADR-0005: Research policy controls autonomy; ToolPolicy controls authorization

Status: accepted in Phase 13.

## Decision

Aegis separates `ResearchPolicy` from `ToolPolicy`.

`ResearchPolicy` is operator-controlled and determines how the controller ranks
novel evidence, explores, revisits gaps, or repeats semantic actions. The built-in
profiles are `CONSERVATIVE`, `BALANCED`, and `EXPERIMENTAL`; settings are bounded
and cannot be changed by an LLM decision.

`ToolPolicy` remains the execution authority. Scope, port, method, identity,
capability, risk, timeout, and fixed-tool restrictions apply in every profile.
Operator approval occurs after a non-executing policy preview and cannot override
a rejection. Policy is checked again when an approved action executes.

Experimental mode therefore weakens research conservatism only. It does not
enable arbitrary shell, scope expansion, credential disclosure, graph mutation,
or LLM-created Findings.

## Consequences

- The same target may be compared under different research policies without
  changing its execution authorization.
- Repeats require a closed reason and remain bounded.
- Project scope changes create a new ResearchSession revision.
- Timeline and reports expose the selected policy, approval mode, and
  experimental marker.
