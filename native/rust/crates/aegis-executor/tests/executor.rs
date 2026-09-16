use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::thread;
use std::time::Duration;

use aegis_core::{ErrorCode, ExecutorRequest, PROTOCOL_VERSION};
use aegis_executor::{execute, process_input};

fn request(url: String) -> ExecutorRequest {
    ExecutorRequest {
        protocol_version: PROTOCOL_VERSION,
        request_id: "REQ-TEST".to_owned(),
        method: "GET".to_owned(),
        url,
        headers: BTreeMap::new(),
        timeout_ms: 1_000,
        max_response_bytes: 100_000,
        follow_redirects: false,
    }
}

fn serve_once(handler: impl FnOnce(TcpStream) + Send + 'static) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind local test server");
    let address = listener.local_addr().expect("local address");
    thread::spawn(move || {
        let (stream, _) = listener.accept().expect("accept local connection");
        handler(stream);
    });
    format!("http://{address}")
}

fn read_request(stream: &mut TcpStream) {
    let mut buffer = [0_u8; 4096];
    let _ = stream.read(&mut buffer).expect("read request");
}

#[tokio::test]
async fn valid_get_returns_runtime_result() {
    let url = serve_once(|mut stream| {
        read_request(&mut stream);
        stream
            .write_all(
                b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 2\r\n\r\n{}",
            )
            .expect("write response");
    });
    let response = execute(request(url)).await;

    assert!(response.ok);
    let result = response.result.expect("execution result");
    assert_eq!(result.status_code, 200);
    assert_eq!(result.body, "{}");
    assert_eq!(result.body_bytes, 2);
}

#[tokio::test]
async fn unsupported_method_is_rejected_before_network() {
    let mut operation = request("http://127.0.0.1:1/never-called".to_owned());
    operation.method = "POST".to_owned();
    let response = execute(operation).await;

    assert!(!response.ok);
    assert_eq!(
        response.error.expect("error").code,
        ErrorCode::MethodNotSupported
    );
}

#[tokio::test]
async fn invalid_json_has_structured_error() {
    let response = process_input(b"{not-json").await;
    assert!(!response.ok);
    assert_eq!(response.error.expect("error").code, ErrorCode::InvalidInput);
}

#[tokio::test]
async fn invalid_url_is_rejected() {
    let response = execute(request("not-a-url".to_owned())).await;
    assert_eq!(response.error.expect("error").code, ErrorCode::InvalidUrl);
}

#[tokio::test]
async fn unsupported_protocol_is_rejected() {
    let mut operation = request("http://127.0.0.1:1/never-called".to_owned());
    operation.protocol_version = 999;
    let response = execute(operation).await;
    assert_eq!(
        response.error.expect("error").code,
        ErrorCode::UnsupportedProtocolVersion
    );
}

#[tokio::test]
async fn timeout_has_deterministic_code() {
    let url = serve_once(|mut stream| {
        read_request(&mut stream);
        thread::sleep(Duration::from_millis(200));
        let _ = stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n{}");
    });
    let mut operation = request(url);
    operation.timeout_ms = 20;
    let response = execute(operation).await;
    assert_eq!(response.error.expect("error").code, ErrorCode::Timeout);
}

#[tokio::test]
async fn response_body_is_bounded_while_streaming() {
    let url = serve_once(|mut stream| {
        read_request(&mut stream);
        stream
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\n0123456789")
            .expect("write response");
    });
    let mut operation = request(url);
    operation.max_response_bytes = 4;
    let response = execute(operation).await;
    let result = response.result.expect("execution result");

    assert_eq!(result.body.as_bytes(), b"0123");
    assert_eq!(result.body_bytes, 4);
    assert!(result.truncated);
}

#[tokio::test]
async fn redirects_are_not_followed_by_default() {
    let url = serve_once(|mut stream| {
        read_request(&mut stream);
        stream
            .write_all(b"HTTP/1.1 302 Found\r\nLocation: /login\r\nContent-Length: 0\r\n\r\n")
            .expect("write response");
    });
    let response = execute(request(url)).await;
    let result = response.result.expect("execution result");

    assert_eq!(result.status_code, 302);
    assert_eq!(
        result.headers.get("location").map(String::as_str),
        Some("/login")
    );
}

#[tokio::test]
async fn cross_origin_redirect_is_never_followed() {
    let url = serve_once(|mut stream| {
        read_request(&mut stream);
        stream
            .write_all(
                b"HTTP/1.1 302 Found\r\nLocation: http://127.0.0.1:1/outside\r\nContent-Length: 0\r\n\r\n",
            )
            .expect("write response");
    });
    let mut operation = request(url);
    operation.follow_redirects = true;
    let response = execute(operation).await;
    let result = response.result.expect("execution result");

    assert_eq!(result.status_code, 302);
    assert_eq!(
        result.headers.get("location").map(String::as_str),
        Some("http://127.0.0.1:1/outside")
    );
}
