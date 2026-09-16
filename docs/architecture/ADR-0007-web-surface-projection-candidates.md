# ADR-0007: Web Surface is a deterministic projection; tool assertions are candidates

- Status: Accepted
- Date: 2026-08-25
- Scope: Phase 15.2

## Context

Passive traffic, HTML discovery, the controlled HTTP executor, and external
assessment artifacts can describe the same HTTP operation. Operators need one
durable application-surface view without weakening Evidence provenance or the
existing Finding authority boundary.

## Decision

`web-surface-v1` is a rebuildable deterministic projection of Evidence and
Observations. Its canonical resource identity includes normalized scheme, host,
effective port, method, and concrete path. Query values, UUIDs, and timestamps
are excluded from semantic identity and hashing. Multi-source Observation,
Evidence, and ToolArtifact lineage is stored separately from canonical entities.

HTTPRequestTemplate is a non-executable semantic template containing only safe
method/resource, parameter-name/schema, content-type, logical-identity-reference,
and Observation lineage. Controlled execution remains exclusively
TypedResearchAction → Validator → ToolPolicy → Rust HTTP executor.

Imported template matches are persisted as `TOOL_REPORTED` candidates. Tool
severity is retained only as tool metadata. A parser, mapper, importer, builder,
or dashboard cannot create a Finding; only the existing experiment and
deterministic verification path may do so.

## Consequences

- Repeated and multi-source imports enrich one semantic resource without losing
  provenance.
- The projection can be deleted and rebuilt without deleting Evidence or
  Observations.
- Future ffuf resources and Nuclei candidates can reuse generic entities without
  tool-specific Finding tables.
- Raw credentials and imported bodies remain outside the projection, planner
  context, dashboard payloads, and reports.
- Phase 15.2 adds no ffuf or Nuclei execution capability.
