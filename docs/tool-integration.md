# Tool Integration SDK v1

`tool-integration-v1` is Aegis' code-controlled extension boundary. A tool
integration describes capability and evidence flow; it does not grant the
controller a new execution primitive.

## Contract

Every integration supplies:

1. a unique `ToolDescriptor` and bounded category;
2. declared `ToolCapability` values;
3. unique, closed profiles with a fixed risk class;
4. a strict Pydantic request schema;
5. ToolPolicy requirements and scope limits;
6. a typed adapter (when execution is required);
7. declared artifact types;
8. a bounded `ToolArtifactParser` for artifact-producing tools;
9. an `ObservationMapper` that emits candidates, never Findings;
10. deterministic System Model mapping through Observations;
11. sanitized golden fixtures and the reusable integration test kit;
12. registration/API/export/redaction/cancellation/timeout regression tests;
13. generic UI metadata.

The registry validates versions, profile uniqueness, capability membership,
risk consistency, required parsers, and fixed binary adapters. It rejects
duplicate tool IDs. Registration is static Python/configuration wiring only:
there is no API-provided import path, uploaded plugin, `eval`, `exec`, shell
string, or arbitrary executable contract.

## Backends and artifacts

Backends are `RUST_HTTP`, `EXTERNAL_BINARY`, `PYTHON_NATIVE`, and the
architecture-only `OFFLINE_JOB`. `OFFLINE_JOB` models bounded
artifact-in/artifact-out compute; Phase 14 does not implement a scheduler or
Hashcat.

Artifact types are controlled enum values. The vocabulary includes current
HTTP/Nmap/DNS/TLS artifacts and reserved future formats such as PCAP and
directory-graph exports. Adding an enum value alone does not enable a tool.

## Test integration

`demo_tool` exists only in tests, is disabled, and returns a sanitized static
fixture. Registering it makes it visible in `ToolRegistry`, `GET /tools`, and
the generic Tools page without controller, strategy, or tool-specific frontend
changes.

## Future checklist

Before Phase 15 accepts a web-assessment integration, it must demonstrate
bounded profiles, exact scope enforcement, policy and approval handling, rate
and timeout limits, immutable artifacts, deterministic parsing, untrusted-data
classification, observation/model provenance, redaction, and UI metadata.
