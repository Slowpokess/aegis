use std::collections::BTreeMap;
use std::time::{Duration, Instant};

use aegis_core::{
    ErrorCode, ExecutionResult, ExecutorRequest, ExecutorResponse, PROTOCOL_VERSION,
    canonical_evidence_sha256,
};
use base64::Engine;
use reqwest::header::{HeaderMap, HeaderName, HeaderValue};
use reqwest::{Method, redirect};
use url::Url;

const MAX_TIMEOUT_MS: u64 = 60_000;
const MAX_CAPTURE_BYTES: usize = 10_000_000;

pub async fn process_input(input: &[u8]) -> ExecutorResponse {
    let request: ExecutorRequest = match serde_json::from_slice(input) {
        Ok(request) => request,
        Err(error) => {
            return ExecutorResponse::failure(
                None,
                ErrorCode::InvalidInput,
                format!("invalid executor request JSON: {error}"),
            );
        }
    };
    execute(request).await
}

pub async fn execute(request: ExecutorRequest) -> ExecutorResponse {
    let request_id = Some(request.request_id.clone());
    if request.protocol_version != PROTOCOL_VERSION {
        return ExecutorResponse::failure(
            request_id,
            ErrorCode::UnsupportedProtocolVersion,
            "unsupported executor protocol version",
        );
    }
    if request.request_id.is_empty() || request.request_id.len() > 128 {
        return ExecutorResponse::failure(
            request_id,
            ErrorCode::InvalidInput,
            "request_id must contain between 1 and 128 characters",
        );
    }
    if request.timeout_ms == 0 || request.timeout_ms > MAX_TIMEOUT_MS {
        return ExecutorResponse::failure(
            request_id,
            ErrorCode::InvalidInput,
            "timeout_ms must be between 1 and 60000",
        );
    }
    if request.max_response_bytes == 0 || request.max_response_bytes > MAX_CAPTURE_BYTES {
        return ExecutorResponse::failure(
            request_id,
            ErrorCode::InvalidInput,
            "max_response_bytes must be between 1 and 10000000",
        );
    }

    let method = match parse_method(&request.method) {
        Ok(method) => method,
        Err(response) => return response(request_id),
    };
    let url = match parse_url(&request.url) {
        Ok(url) => url,
        Err(response) => return response(request_id),
    };
    let (headers, canonical_request_headers) = match parse_headers(&request.headers) {
        Ok(headers) => headers,
        Err(message) => {
            return ExecutorResponse::failure(request_id, ErrorCode::InvalidInput, message);
        }
    };

    let redirect_policy = if request.follow_redirects {
        let allowed_origin = (
            url.scheme().to_owned(),
            url.host_str().unwrap_or_default().to_owned(),
            url.port_or_known_default(),
        );
        redirect::Policy::custom(move |attempt| {
            let candidate = attempt.url();
            let candidate_origin = (
                candidate.scheme(),
                candidate.host_str().unwrap_or_default(),
                candidate.port_or_known_default(),
            );
            if attempt.previous().len() >= 10 {
                attempt.error("too many redirects")
            } else if candidate_origin
                == (
                    allowed_origin.0.as_str(),
                    allowed_origin.1.as_str(),
                    allowed_origin.2,
                )
            {
                attempt.follow()
            } else {
                attempt.stop()
            }
        })
    } else {
        redirect::Policy::none()
    };
    let client = match reqwest::Client::builder()
        .timeout(Duration::from_millis(request.timeout_ms))
        .redirect(redirect_policy)
        .build()
    {
        Ok(client) => client,
        Err(error) => {
            return ExecutorResponse::failure(
                request_id,
                ErrorCode::InternalError,
                format!("failed to construct HTTP client: {error}"),
            );
        }
    };

    let started = Instant::now();
    let response = match client.request(method, url).headers(headers).send().await {
        Ok(response) => response,
        Err(error) => return request_error(request_id, error),
    };
    let effective_url = response.url().to_string();
    let status_code = response.status().as_u16();
    let response_headers = normalized_headers(response.headers());
    let (body, truncated) = match read_bounded_body(response, request.max_response_bytes).await {
        Ok(body) => body,
        Err(error) => return request_error(request_id, error),
    };
    let evidence_sha256 = canonical_evidence_sha256(
        &request.method,
        &request.url,
        &canonical_request_headers,
        status_code,
        &response_headers,
        &body,
    );
    let result = ExecutionResult {
        effective_url,
        status_code,
        headers: response_headers,
        body: String::from_utf8_lossy(&body).into_owned(),
        body_base64: base64::engine::general_purpose::STANDARD.encode(&body),
        body_bytes: body.len(),
        truncated,
        elapsed_ms: started.elapsed().as_millis() as u64,
        evidence_sha256,
    };
    ExecutorResponse::success(request.request_id, result)
}

type ValidationFailure = Box<dyn FnOnce(Option<String>) -> ExecutorResponse>;

fn parse_method(method: &str) -> Result<Method, ValidationFailure> {
    match method.to_ascii_uppercase().as_str() {
        "GET" => Ok(Method::GET),
        "HEAD" => Ok(Method::HEAD),
        "OPTIONS" => Ok(Method::OPTIONS),
        _ => Err(Box::new(|request_id| {
            ExecutorResponse::failure(
                request_id,
                ErrorCode::MethodNotSupported,
                "HTTP method is not supported by Phase 2 executor",
            )
        })),
    }
}

fn parse_url(raw_url: &str) -> Result<Url, ValidationFailure> {
    let url = Url::parse(raw_url).map_err(|_| {
        Box::new(|request_id| {
            ExecutorResponse::failure(request_id, ErrorCode::InvalidUrl, "invalid absolute URL")
        }) as ValidationFailure
    })?;
    if !matches!(url.scheme(), "http" | "https")
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.fragment().is_some()
    {
        return Err(Box::new(|request_id| {
            ExecutorResponse::failure(
                request_id,
                ErrorCode::InvalidUrl,
                "URL must be absolute HTTP(S) without credentials or fragment",
            )
        }));
    }
    Ok(url)
}

fn parse_headers(
    raw_headers: &BTreeMap<String, String>,
) -> Result<(HeaderMap, BTreeMap<String, String>), String> {
    let mut headers = HeaderMap::new();
    let mut canonical = BTreeMap::new();
    for (name, value) in raw_headers {
        let header_name = HeaderName::from_bytes(name.as_bytes())
            .map_err(|_| format!("invalid HTTP header name: {name}"))?;
        let header_value = HeaderValue::from_str(value)
            .map_err(|_| format!("invalid HTTP header value for: {name}"))?;
        canonical.insert(header_name.as_str().to_owned(), value.trim().to_owned());
        headers.insert(header_name, header_value);
    }
    Ok((headers, canonical))
}

fn normalized_headers(headers: &HeaderMap) -> BTreeMap<String, String> {
    let mut normalized = BTreeMap::new();
    for name in headers.keys() {
        let values = headers
            .get_all(name)
            .iter()
            .map(|value| String::from_utf8_lossy(value.as_bytes()))
            .collect::<Vec<_>>()
            .join(", ");
        normalized.insert(name.as_str().to_owned(), values);
    }
    normalized
}

async fn read_bounded_body(
    mut response: reqwest::Response,
    limit: usize,
) -> Result<(Vec<u8>, bool), reqwest::Error> {
    let mut body = Vec::with_capacity(limit.min(64 * 1024));
    let mut truncated = false;
    while let Some(chunk) = response.chunk().await? {
        let remaining = limit.saturating_sub(body.len());
        if chunk.len() > remaining {
            body.extend_from_slice(&chunk[..remaining]);
            truncated = true;
            break;
        }
        body.extend_from_slice(&chunk);
        if body.len() == limit {
            if response.chunk().await?.is_some() {
                truncated = true;
            }
            break;
        }
    }
    Ok((body, truncated))
}

fn request_error(request_id: Option<String>, error: reqwest::Error) -> ExecutorResponse {
    if error.is_timeout() {
        ExecutorResponse::failure(
            request_id,
            ErrorCode::Timeout,
            "request exceeded configured timeout",
        )
    } else {
        ExecutorResponse::failure(request_id, ErrorCode::NetworkError, "HTTP request failed")
    }
}
