# Aegis Rust execution plane

Phase 2 introduces two workspace crates:

- `aegis-core`: protocol version 1 types, structured errors, and canonical evidence hashing;
- `aegis-executor`: a single-operation HTTP executor communicating through JSON stdin/stdout.

The executor supports only `GET`, `HEAD`, and `OPTIONS`. It does not choose targets, expand scope, interpret responses, read ground truth, or execute shell commands. Diagnostic output goes to stderr; stdout contains one protocol JSON response.

## Build and quality gates

```bash
cargo build --manifest-path native/rust/Cargo.toml --workspace
cargo fmt --manifest-path native/rust/Cargo.toml --all --check
cargo clippy --manifest-path native/rust/Cargo.toml \
  --workspace --all-targets --all-features -- -D warnings
cargo test --manifest-path native/rust/Cargo.toml --workspace
```

The development binary is `native/rust/target/debug/aegis-executor`. Python discovers it through `AEGIS_EXECUTOR_PATH`; there is no silent Python fallback.

## Protocol version 1

One JSON request is read to EOF from stdin. Every response contains:

```text
protocol_version
ok
request_id
executor
executor_version
result or error
```

Structured error codes are defined by `aegis-core::ErrorCode`. Invalid JSON receives a structured `INVALID_INPUT` response with a null request ID. Operational rejections normally exit successfully because the JSON response is the protocol result; process-level read/serialization failures use a non-zero exit and stderr.

Redirects are disabled unless `follow_redirects=true`. Even when enabled, only same-origin redirects with the same scheme, host, and effective port are followed; cross-origin redirects remain observable 3xx responses. Timeout is enforced by reqwest. The body is consumed as a stream and at most `max_response_bytes` is retained. If additional bytes exist, `truncated=true`; the executor does not first load the complete response. `body_base64` preserves the captured bytes exactly, while `body` is their UTF-8-lossy display form.

## Canonical evidence hash

SHA-256 is calculated over `AEGIS-EVIDENCE-V1`, not only the response body. Variable fields use an unsigned big-endian 64-bit byte-length prefix followed by their bytes.

Canonical order:

```text
length + "AEGIS-EVIDENCE-V1"
length + uppercase request method
length + requested URL
u64 request-header count
  repeated sorted lowercase header name/value fields
big-endian u16 response status
u64 response-header count
  repeated sorted lowercase header name/value fields
length + captured response body bytes
```

Header values are trimmed. Repeated response header values are joined in wire order using `, `. When a response is truncated, the hash represents the exact captured evidence and `truncated=true` is part of the surrounding evidence metadata.

The Python control plane contains an independent implementation used by integration tests to verify Rust-produced hashes.
