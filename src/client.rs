//! The console, over HTTPS (rustls): every request signed (§4), no redirect followed, the clock offset learnt from
//! `server_time` (§4.4), problem documents read (§9).

use std::io::Read;
use std::time::Duration;

use serde_json::Value;
use ureq::Agent;

use crate::keys::AgentKey;
use crate::signing;
use crate::time;

/// `depverify-agent/<version> (linux; <arch>)` (§2).
/// The console clock may differ from the local one by this much at most: an offset beyond is ignored, so that no
/// answer can move the agent's time far enough to defeat the anti-replay store of the orders.
pub const MAX_OFFSET: i64 = 3600;

fn bounded(offset: i64) -> Option<i64> {
    (-MAX_OFFSET..=MAX_OFFSET)
        .contains(&offset)
        .then_some(offset)
}

pub fn user_agent() -> String {
    format!(
        "depverify-agent/{} (linux; {})",
        env!("CARGO_PKG_VERSION"),
        std::env::consts::ARCH
    )
}

#[derive(Debug)]
pub enum Failure {
    /// The console answered with a problem document (or an unexpected status).
    Problem {
        status: u16,
        code: String,
        retry_after: Option<u64>,
        body: Value,
    },
    /// No answer: DNS, TCP, TLS, timeout.
    Transport(String),
}

impl std::fmt::Display for Failure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Failure::Problem { status, code, .. } => write!(f, "HTTP {status} {code}"),
            Failure::Transport(e) => write!(f, "transport error: {e}"),
        }
    }
}

pub struct Reply {
    pub json: Value,
}

pub struct Console {
    base: String,
    http: Agent,
    pub offset: i64,
}

pub struct Body<'a> {
    pub bytes: &'a [u8],
    pub content_type: &'a str,
    pub gzip: bool,
}

impl Console {
    pub fn new(base: &str, ca_file: Option<&std::path::Path>, offset: i64) -> Result<Self, String> {
        let mut tls = ureq::tls::TlsConfig::builder().provider(ureq::tls::TlsProvider::Rustls);
        if let Some(file) = ca_file {
            let pem = std::fs::read(file)
                .map_err(|e| format!("AGENT_CA_FILE {}: {e}", file.display()))?;
            let certs: Vec<_> = ureq::tls::parse_pem(&pem)
                .filter_map(|item| match item {
                    Ok(ureq::tls::PemItem::Certificate(cert)) => Some(cert),
                    _ => None,
                })
                .collect();
            if certs.is_empty() {
                return Err(format!(
                    "AGENT_CA_FILE {} holds no certificate",
                    file.display()
                ));
            }
            tls = tls.root_certs(ureq::tls::RootCerts::new_with_certs(&certs));
        }
        let http: Agent = Agent::config_builder()
            .tls_config(tls.build())
            .timeout_global(Some(Duration::from_secs(90)))
            .max_redirects(0)
            .http_status_as_error(false)
            .user_agent(user_agent())
            .build()
            .into();

        Ok(Self {
            base: base.to_owned(),
            http,
            offset: bounded(offset).unwrap_or(0),
        })
    }

    /// A public file of the console (a release of the agent), at most `max` bytes; any other status is an error.
    pub fn download(&self, path: &str, max: u64) -> Result<Vec<u8>, String> {
        let request = ureq::http::Request::builder()
            .method("GET")
            .uri(format!("{}{path}", self.base.trim_end_matches('/')))
            .body(Vec::new())
            .map_err(|e| e.to_string())?;
        let mut response = self.http.run(request).map_err(|e| e.to_string())?;
        if response.status().as_u16() != 200 {
            return Err(format!("{path}: HTTP {}", response.status().as_u16()));
        }
        let mut bytes = Vec::new();
        response
            .body_mut()
            .as_reader()
            .take(max + 1)
            .read_to_end(&mut bytes)
            .map_err(|e| e.to_string())?;
        if bytes.len() as u64 > max {
            return Err(format!("{path}: larger than {max} bytes"));
        }
        Ok(bytes)
    }

    /// A signed request; a `clock_skew` corrects the offset and is tried once more, as is a signature refused
    /// (`invalid_signature`, `replayed_request`), always with a fresh nonce (§4.4, §9).
    pub fn send(
        &mut self,
        key: &AgentKey,
        method: &str,
        path: &str,
        body: Option<Body<'_>>,
    ) -> Result<Reply, Failure> {
        let mut retried = false;
        loop {
            match self.attempt(key, method, path, body.as_ref()) {
                Err(Failure::Problem {
                    code,
                    body: problem,
                    ..
                }) if !retried
                    && matches!(
                        code.as_str(),
                        "clock_skew" | "invalid_signature" | "replayed_request"
                    ) =>
                {
                    if let Some(server) = problem
                        .get("server_time")
                        .and_then(Value::as_str)
                        .and_then(time::parse_rfc3339)
                    {
                        if let Some(offset) = bounded(server - time::now()) {
                            self.offset = offset;
                        }
                    }
                    retried = true;
                }
                other => return other,
            }
        }
    }

    fn attempt(
        &mut self,
        key: &AgentKey,
        method: &str,
        path: &str,
        body: Option<&Body<'_>>,
    ) -> Result<Reply, Failure> {
        let uri = format!("{}{}", self.base, path);
        let headers = signing::sign(
            key,
            method,
            &uri,
            body.map(|b| b.bytes),
            time::now() + self.offset,
            &signing::random_nonce(),
        );
        let mut request = ureq::http::Request::builder()
            .method(method)
            .uri(&uri)
            .header("Date", &headers.date)
            .header("Signature-Input", &headers.signature_input)
            .header("Signature", &headers.signature)
            .header("Accept", "application/json");
        if let (Some(body), Some(digest)) = (body, &headers.content_digest) {
            request = request
                .header("Content-Type", body.content_type)
                .header("Content-Digest", digest);
            if body.gzip {
                request = request.header("Content-Encoding", "gzip");
            }
        }
        let request = request
            .body(body.map(|b| b.bytes.to_vec()).unwrap_or_default())
            .map_err(|e| Failure::Transport(e.to_string()))?;
        let mut response = self
            .http
            .run(request)
            .map_err(|e| Failure::Transport(e.to_string()))?;
        let status = response.status().as_u16();
        let retry_after = response
            .headers()
            .get("Retry-After")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.trim().parse().ok());
        let mut text = Vec::new();
        response
            .body_mut()
            .as_reader()
            .take(4 * 1024 * 1024)
            .read_to_end(&mut text)
            .map_err(|e| Failure::Transport(e.to_string()))?;
        let json: Value = if text.is_empty() {
            Value::Null
        } else {
            serde_json::from_slice(&text).unwrap_or(Value::Null)
        };
        if let Some(server) = json
            .get("server_time")
            .and_then(Value::as_str)
            .and_then(time::parse_rfc3339)
        {
            if let Some(offset) = bounded(server - time::now()) {
                self.offset = offset;
            }
        }
        if (200..300).contains(&status) {
            return Ok(Reply { json });
        }
        let code = json
            .get("type")
            .and_then(Value::as_str)
            .and_then(|t| t.strip_prefix("urn:depverify:problem:"))
            .map(str::to_owned)
            .unwrap_or_else(|| format!("http_{status}"));
        Err(Failure::Problem {
            status,
            code,
            retry_after,
            body: json,
        })
    }
}
