use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use url::Url;

pub use aegis_core::PROTOCOL_VERSION;
pub const POLICY_ENGINE: &str = "aegis-policy";
pub const POLICY_ENGINE_VERSION: &str = env!("CARGO_PKG_VERSION");

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyConfig {
    pub protocol_version: u32,
    pub allowed_hosts: Vec<String>,
    pub allowed_ports: Vec<u16>,
    pub allowed_schemes: Vec<String>,
    pub allowed_methods: Vec<String>,
    pub allowed_headers: Vec<String>,
    pub max_requests_per_minute: u32,
    pub max_response_bytes: usize,
    pub max_timeout_ms: u64,
    pub follow_redirects: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyAction {
    pub method: String,
    pub url: String,
    #[serde(default)]
    pub headers: BTreeMap<String, String>,
    pub timeout_ms: u64,
    pub max_response_bytes: usize,
    pub follow_redirects: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyRequest {
    pub protocol_version: u32,
    pub decision_id: String,
    pub policy: PolicyConfig,
    pub action: PolicyAction,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ReasonCode {
    WithinScope,
    InvalidAction,
    InvalidUrl,
    SchemeNotAllowed,
    HostNotAllowed,
    PortNotAllowed,
    MethodNotAllowed,
    TimeoutExceedsLimit,
    ResponseLimitExceedsPolicy,
    RedirectNotAllowed,
    RateLimitExceeded,
    HeaderNotAllowed,
    UnsupportedProtocolVersion,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyResponse {
    pub protocol_version: u32,
    pub decision_id: Option<String>,
    pub allowed: bool,
    pub reason_code: ReasonCode,
    pub message: String,
    pub policy_sha256: Option<String>,
    pub policy_engine: String,
    pub policy_engine_version: String,
}

impl PolicyResponse {
    fn decision(
        decision_id: Option<String>,
        allowed: bool,
        reason_code: ReasonCode,
        message: impl Into<String>,
        policy_sha256: Option<String>,
    ) -> Self {
        Self {
            protocol_version: PROTOCOL_VERSION,
            decision_id,
            allowed,
            reason_code,
            message: message.into(),
            policy_sha256,
            policy_engine: POLICY_ENGINE.to_owned(),
            policy_engine_version: POLICY_ENGINE_VERSION.to_owned(),
        }
    }
}

pub fn evaluate(request: &PolicyRequest) -> PolicyResponse {
    let decision_id = Some(request.decision_id.clone());
    if request.protocol_version != PROTOCOL_VERSION
        || request.policy.protocol_version != PROTOCOL_VERSION
    {
        return PolicyResponse::decision(
            decision_id,
            false,
            ReasonCode::UnsupportedProtocolVersion,
            "protocol version is not supported",
            None,
        );
    }
    if request.policy.allowed_hosts.is_empty()
        || request.policy.allowed_ports.is_empty()
        || request.policy.allowed_schemes.is_empty()
        || request.policy.allowed_methods.is_empty()
        || request.policy.max_requests_per_minute == 0
        || request.policy.max_response_bytes == 0
        || request.policy.max_timeout_ms == 0
    {
        return PolicyResponse::decision(
            decision_id,
            false,
            ReasonCode::InvalidAction,
            "policy configuration is malformed",
            None,
        );
    }
    let policy_hash = Some(policy_sha256(&request.policy));
    let parsed = match Url::parse(&request.action.url) {
        Ok(value)
            if !value.cannot_be_a_base()
                && value.username().is_empty()
                && value.password().is_none()
                && value.fragment().is_none() =>
        {
            value
        }
        _ => {
            return PolicyResponse::decision(
                decision_id,
                false,
                ReasonCode::InvalidUrl,
                "action URL is invalid or ambiguous",
                policy_hash,
            );
        }
    };
    let schemes = normalize(&request.policy.allowed_schemes);
    if !schemes.contains(&parsed.scheme().to_ascii_lowercase()) {
        return denied(
            decision_id,
            ReasonCode::SchemeNotAllowed,
            "scheme is outside policy",
            policy_hash,
        );
    }
    let Some(host) = parsed.host_str().map(str::to_ascii_lowercase) else {
        return denied(
            decision_id,
            ReasonCode::InvalidUrl,
            "action URL has no host",
            policy_hash,
        );
    };
    if !normalize(&request.policy.allowed_hosts).contains(&host) {
        return denied(
            decision_id,
            ReasonCode::HostNotAllowed,
            "host is outside policy",
            policy_hash,
        );
    }
    let Some(port) = parsed.port_or_known_default() else {
        return denied(
            decision_id,
            ReasonCode::InvalidUrl,
            "action URL has no usable port",
            policy_hash,
        );
    };
    if !request.policy.allowed_ports.contains(&port) {
        return denied(
            decision_id,
            ReasonCode::PortNotAllowed,
            "port is outside policy",
            policy_hash,
        );
    }
    let method = request.action.method.to_ascii_uppercase();
    if !normalize_upper(&request.policy.allowed_methods).contains(&method) {
        return denied(
            decision_id,
            ReasonCode::MethodNotAllowed,
            "method is outside policy",
            policy_hash,
        );
    }
    if request.action.timeout_ms > request.policy.max_timeout_ms {
        return denied(
            decision_id,
            ReasonCode::TimeoutExceedsLimit,
            "timeout exceeds policy",
            policy_hash,
        );
    }
    if request.action.max_response_bytes > request.policy.max_response_bytes {
        return denied(
            decision_id,
            ReasonCode::ResponseLimitExceedsPolicy,
            "response bound exceeds policy",
            policy_hash,
        );
    }
    if request.action.follow_redirects && !request.policy.follow_redirects {
        return denied(
            decision_id,
            ReasonCode::RedirectNotAllowed,
            "redirect following is denied",
            policy_hash,
        );
    }
    let allowed_headers = normalize(&request.policy.allowed_headers);
    if request
        .action
        .headers
        .keys()
        .any(|name| !allowed_headers.contains(&name.to_ascii_lowercase()))
    {
        return denied(
            decision_id,
            ReasonCode::HeaderNotAllowed,
            "action contains a denied header",
            policy_hash,
        );
    }
    PolicyResponse::decision(
        decision_id,
        true,
        ReasonCode::WithinScope,
        "action is within deterministic policy",
        policy_hash,
    )
}

fn denied(
    decision_id: Option<String>,
    code: ReasonCode,
    message: &str,
    policy_hash: Option<String>,
) -> PolicyResponse {
    PolicyResponse::decision(decision_id, false, code, message, policy_hash)
}

fn normalize(values: &[String]) -> BTreeSet<String> {
    values
        .iter()
        .map(|value| value.to_ascii_lowercase())
        .collect()
}

fn normalize_upper(values: &[String]) -> BTreeSet<String> {
    values
        .iter()
        .map(|value| value.to_ascii_uppercase())
        .collect()
}

pub fn policy_sha256(policy: &PolicyConfig) -> String {
    let mut canonical = BTreeMap::new();
    canonical.insert(
        "allowed_headers",
        serde_json::json!(normalize(&policy.allowed_headers)),
    );
    canonical.insert(
        "allowed_hosts",
        serde_json::json!(normalize(&policy.allowed_hosts)),
    );
    canonical.insert(
        "allowed_methods",
        serde_json::json!(normalize_upper(&policy.allowed_methods)),
    );
    canonical.insert(
        "allowed_ports",
        serde_json::json!(
            policy
                .allowed_ports
                .iter()
                .copied()
                .collect::<BTreeSet<_>>()
        ),
    );
    canonical.insert(
        "allowed_schemes",
        serde_json::json!(normalize(&policy.allowed_schemes)),
    );
    canonical.insert(
        "follow_redirects",
        serde_json::json!(policy.follow_redirects),
    );
    canonical.insert(
        "max_requests_per_minute",
        serde_json::json!(policy.max_requests_per_minute),
    );
    canonical.insert(
        "max_response_bytes",
        serde_json::json!(policy.max_response_bytes),
    );
    canonical.insert("max_timeout_ms", serde_json::json!(policy.max_timeout_ms));
    canonical.insert(
        "protocol_version",
        serde_json::json!(policy.protocol_version),
    );
    let bytes = serde_json::to_vec(&canonical).expect("canonical policy serialization cannot fail");
    hex::encode(Sha256::digest(bytes))
}

pub fn malformed_response(input: &[u8]) -> PolicyResponse {
    let decision_id = serde_json::from_slice::<serde_json::Value>(input)
        .ok()
        .and_then(|value| value.get("decision_id")?.as_str().map(str::to_owned));
    PolicyResponse::decision(
        decision_id,
        false,
        ReasonCode::InvalidAction,
        "input does not match the policy protocol",
        None,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request(url: &str) -> PolicyRequest {
        PolicyRequest {
            protocol_version: 1,
            decision_id: "DEC-1".into(),
            policy: PolicyConfig {
                protocol_version: 1,
                allowed_hosts: vec!["127.0.0.1".into()],
                allowed_ports: vec![8001],
                allowed_schemes: vec!["http".into()],
                allowed_methods: vec!["GET".into(), "HEAD".into(), "OPTIONS".into()],
                allowed_headers: vec!["accept".into()],
                max_requests_per_minute: 30,
                max_response_bytes: 100_000,
                max_timeout_ms: 10_000,
                follow_redirects: false,
            },
            action: PolicyAction {
                method: "GET".into(),
                url: url.into(),
                headers: BTreeMap::new(),
                timeout_ms: 5_000,
                max_response_bytes: 100_000,
                follow_redirects: false,
            },
        }
    }

    #[test]
    fn exact_scope_is_allowed_and_hash_is_stable() {
        let first = evaluate(&request("http://127.0.0.1:8001/api/orders/101"));
        let second = evaluate(&request("http://127.0.0.1:8001/api/orders/101"));
        assert!(first.allowed);
        assert_eq!(first.reason_code, ReasonCode::WithinScope);
        assert_eq!(first.policy_sha256, second.policy_sha256);
    }

    #[test]
    fn rejects_scope_and_capability_changes() {
        let cases = [
            (
                "http://127.0.0.1.attacker.invalid:8001/",
                ReasonCode::HostNotAllowed,
            ),
            ("http://127.0.0.1:9000/", ReasonCode::PortNotAllowed),
            ("https://127.0.0.1:8001/", ReasonCode::SchemeNotAllowed),
        ];
        for (url, reason) in cases {
            assert_eq!(evaluate(&request(url)).reason_code, reason);
        }
        let mut wrong_method = request("http://127.0.0.1:8001/");
        wrong_method.action.method = "POST".into();
        assert_eq!(
            evaluate(&wrong_method).reason_code,
            ReasonCode::MethodNotAllowed
        );
        let mut timeout = request("http://127.0.0.1:8001/");
        timeout.action.timeout_ms = 10_001;
        assert_eq!(
            evaluate(&timeout).reason_code,
            ReasonCode::TimeoutExceedsLimit
        );
        let mut size = request("http://127.0.0.1:8001/");
        size.action.max_response_bytes = 100_001;
        assert_eq!(
            evaluate(&size).reason_code,
            ReasonCode::ResponseLimitExceedsPolicy
        );
        let mut redirect = request("http://127.0.0.1:8001/");
        redirect.action.follow_redirects = true;
        assert_eq!(
            evaluate(&redirect).reason_code,
            ReasonCode::RedirectNotAllowed
        );
    }

    #[test]
    fn rejects_url_ambiguity_and_headers() {
        for url in [
            "http://attacker.invalid@127.0.0.1:8001/",
            "http://127.0.0.1:8001/#@attacker.invalid",
            "not a URL",
        ] {
            assert_eq!(evaluate(&request(url)).reason_code, ReasonCode::InvalidUrl);
        }
        let mut header = request("http://127.0.0.1:8001/");
        header
            .action
            .headers
            .insert("Authorization".into(), "secret".into());
        assert_eq!(evaluate(&header).reason_code, ReasonCode::HeaderNotAllowed);
    }

    #[test]
    fn rejects_protocol_and_malformed_input() {
        let mut unsupported = request("http://127.0.0.1:8001/");
        unsupported.protocol_version = 2;
        assert_eq!(
            evaluate(&unsupported).reason_code,
            ReasonCode::UnsupportedProtocolVersion
        );
        assert_eq!(
            malformed_response(b"not-json").reason_code,
            ReasonCode::InvalidAction
        );
        let mut malformed_policy = request("http://127.0.0.1:8001/");
        malformed_policy.policy.allowed_hosts.clear();
        assert_eq!(
            evaluate(&malformed_policy).reason_code,
            ReasonCode::InvalidAction
        );
    }
}
