# Laboratory ground truth

This directory is a developer/evaluation asset. It is not part of the vulnerable target API and is excluded from the target container build context.

Each `LAB-*.yaml` file follows the schema implemented in `lab.ground_truth.GroundTruthScenario`. The loader rejects malformed documents, duplicate IDs, and verdicts inconsistent with the explicit `vulnerability` value.

The intended consumers are:

- Phase 1 integration tests;
- the future evaluation runner;
- controlled development validation.

The future research pipeline must receive target observations, not these files. Do not mount this directory into the target container or add an HTTP route that exposes it.

Verdict mapping is deterministic:

```text
vulnerability: true  -> SUPPORTED
vulnerability: false -> REJECTED
vulnerability: null  -> INCONCLUSIVE
```

