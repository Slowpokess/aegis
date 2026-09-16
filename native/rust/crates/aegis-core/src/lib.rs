use std::collections::BTreeMap;

use base64::Engine;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub const PROTOCOL_VERSION: u32 = 1;
pub const EXECUTOR_NAME: &str = "aegis-executor";
pub const EXECUTOR_VERSION: &str = env!("CARGO_PKG_VERSION");

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ExecutorRequest {
    pub protocol_version: u32,
    pub request_id: String,
    pub method: String,
    pub url: String,
    #[serde(default)]
    pub headers: BTreeMap<String, String>,
    pub timeout_ms: u64,
    pub max_response_bytes: usize,
    #[serde(default)]
    pub follow_redirects: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ErrorCode {
    InvalidInput,
    UnsupportedProtocolVersion,
    InvalidUrl,
    MethodNotSupported,
    NetworkError,
    Timeout,
    ResponseTooLarge,
    SerializationError,
    InternalError,
    ExecutorNotFound,
    ExecutorProcessError,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ProtocolError {
    pub code: ErrorCode,
    pub message: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ExecutionResult {
    pub effective_url: String,
    pub status_code: u16,
    pub headers: BTreeMap<String, String>,
    pub body: String,
    pub body_base64: String,
    pub body_bytes: usize,
    pub truncated: bool,
    pub elapsed_ms: u64,
    pub evidence_sha256: String,
}

impl ExecutionResult {
    pub fn captured_body(&self) -> Result<Vec<u8>, base64::DecodeError> {
        base64::engine::general_purpose::STANDARD.decode(&self.body_base64)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ExecutorResponse {
    pub protocol_version: u32,
    pub ok: bool,
    pub request_id: Option<String>,
    pub executor: String,
    pub executor_version: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<ExecutionResult>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<ProtocolError>,
}

impl ExecutorResponse {
    pub fn success(request_id: String, result: ExecutionResult) -> Self {
        Self {
            protocol_version: PROTOCOL_VERSION,
            ok: true,
            request_id: Some(request_id),
            executor: EXECUTOR_NAME.to_owned(),
            executor_version: EXECUTOR_VERSION.to_owned(),
            result: Some(result),
            error: None,
        }
    }

    pub fn failure(
        request_id: Option<String>,
        code: ErrorCode,
        message: impl Into<String>,
    ) -> Self {
        Self {
            protocol_version: PROTOCOL_VERSION,
            ok: false,
            request_id,
            executor: EXECUTOR_NAME.to_owned(),
            executor_version: EXECUTOR_VERSION.to_owned(),
            result: None,
            error: Some(ProtocolError {
                code,
                message: message.into(),
            }),
        }
    }
}

/// Hashes captured HTTP evidence with an unambiguous length-prefixed encoding.
///
/// Encoding order is fixed: magic, uppercase method, requested URL, sorted request
/// headers, status (big-endian u16), sorted response headers, captured body bytes.
/// Each variable byte field is prefixed by an unsigned big-endian u64 length.
/// Header names must already be lowercase and maps are ordered by `BTreeMap`.
pub fn canonical_evidence_sha256(
    method: &str,
    url: &str,
    request_headers: &BTreeMap<String, String>,
    status_code: u16,
    response_headers: &BTreeMap<String, String>,
    body: &[u8],
) -> String {
    let mut hasher = Sha256::new();
    write_field(&mut hasher, b"AEGIS-EVIDENCE-V1");
    write_field(&mut hasher, method.to_ascii_uppercase().as_bytes());
    write_field(&mut hasher, url.as_bytes());
    write_headers(&mut hasher, request_headers);
    hasher.update(status_code.to_be_bytes());
    write_headers(&mut hasher, response_headers);
    write_field(&mut hasher, body);
    hex::encode(hasher.finalize())
}

fn write_headers(hasher: &mut Sha256, headers: &BTreeMap<String, String>) {
    hasher.update((headers.len() as u64).to_be_bytes());
    for (name, value) in headers {
        write_field(hasher, name.as_bytes());
        write_field(hasher, value.as_bytes());
    }
}

fn write_field(hasher: &mut Sha256, value: &[u8]) {
    hasher.update((value.len() as u64).to_be_bytes());
    hasher.update(value);
}

#[cfg(test)]
mod tests {
    use super::canonical_evidence_sha256;
    use std::collections::BTreeMap;

    #[test]
    fn canonical_hash_is_stable_and_sensitive_to_evidence() {
        let request_headers =
            BTreeMap::from([("accept".to_owned(), "application/json".to_owned())]);
        let response_headers =
            BTreeMap::from([("content-type".to_owned(), "application/json".to_owned())]);
        let first = canonical_evidence_sha256(
            "GET",
            "http://127.0.0.1/test",
            &request_headers,
            200,
            &response_headers,
            b"{}",
        );
        let repeated = canonical_evidence_sha256(
            "GET",
            "http://127.0.0.1/test",
            &request_headers,
            200,
            &response_headers,
            b"{}",
        );
        let changed = canonical_evidence_sha256(
            "GET",
            "http://127.0.0.1/test",
            &request_headers,
            403,
            &response_headers,
            b"{}",
        );

        assert_eq!(first, repeated);
        assert_ne!(first, changed);
        assert_eq!(first.len(), 64);
    }
}
