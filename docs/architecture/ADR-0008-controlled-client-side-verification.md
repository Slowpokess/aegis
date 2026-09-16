# ADR-0008: Client-side verification is token-safe, browser-isolated, and non-autonomous

- Status: Accepted
- Date: 2026-09-16
- Scope: Phase 16 foundation

## Decision

Client-side candidate verification starts only from evidence-backed WebResources.
The reasoning layer may propose a typed context and an approved probe identifier;
it cannot provide a payload, browser command, cookie, CSRF token, URL outside the
resource origin, or approval authority.

CSRF tokens are never stored in proposal, action, report, model context, or tool
artifact metadata. A future executor may obtain a token only from an observed
same-origin form, meta tag, or bootstrap exchange inside a new isolated browser
session. The plan retains only Evidence lineage and token-source metadata.

Only isolated laboratory and staging targets are admissible for this first
verification class. Every run needs a persisted operator approval, a candidate
and a baseline control, no external browser egress, and a deterministic result
comparison. Production, unknown contexts, arbitrary probes, token guessing,
cross-origin callbacks, and credential/data access are fail-closed.

## Consequences

- This foundation deliberately starts no browser process and creates no Finding.
- The in-progress Playwright executor consumes the typed plan, re-checks
  approval and scope, uses an ephemeral profile, and redacts browser output.
  Phase 16.2 must persist its lifecycle and evidence through the established
  control plane before it becomes an enabled product capability.
- A successful marker is evidence for a controlled hypothesis only; the existing
  Verification Engine remains the sole Finding authority.
