//! A read-only client of the Docker Engine API: `GET` requests only, over TCP (the `docker-socket-proxy` of the
//! container mode) or a Unix socket (host mode with `AGENT_DOCKER=1`). Responses are streamed (an image export can
//! be large).

use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpStream;
use std::os::unix::net::UnixStream;
use std::time::Duration;

use serde_json::Value;

const TIMEOUT: Duration = Duration::from_secs(300);

enum Endpoint {
    Tcp(String),
    Unix(String),
}

pub struct Docker {
    endpoint: Endpoint,
}

pub struct Response {
    pub status: u16,
    pub body: Box<dyn Read>,
}

trait Stream: Read + Write {}
impl<T: Read + Write> Stream for T {}

impl Docker {
    /// `tcp://host:port`, `http://host:port` or `unix:///path`.
    pub fn new(host: &str) -> Result<Self, String> {
        let endpoint = if let Some(path) = host.strip_prefix("unix://") {
            Endpoint::Unix(path.to_owned())
        } else if let Some(address) = host
            .strip_prefix("tcp://")
            .or_else(|| host.strip_prefix("http://"))
        {
            Endpoint::Tcp(address.trim_end_matches('/').to_owned())
        } else {
            return Err(format!(
                "unsupported Docker host {host} (tcp:// or unix://)"
            ));
        };
        Ok(Self { endpoint })
    }

    fn connect(&self) -> Result<Box<dyn Stream>, String> {
        Ok(match &self.endpoint {
            Endpoint::Tcp(address) => {
                let stream =
                    TcpStream::connect(address).map_err(|e| format!("Docker {address}: {e}"))?;
                stream.set_read_timeout(Some(TIMEOUT)).ok();
                Box::new(stream)
            }
            Endpoint::Unix(path) => {
                let stream =
                    UnixStream::connect(path).map_err(|e| format!("Docker {path}: {e}"))?;
                stream.set_read_timeout(Some(TIMEOUT)).ok();
                Box::new(stream)
            }
        })
    }

    pub fn get(&self, path: &str) -> Result<Response, String> {
        let mut stream = self.connect()?;
        write!(
            stream,
            "GET {path} HTTP/1.1\r\nHost: docker\r\nUser-Agent: {}\r\nConnection: close\r\n\r\n",
            crate::client::user_agent()
        )
        .map_err(|e| e.to_string())?;
        let mut reader = BufReader::new(stream);
        let mut line = String::new();
        reader.read_line(&mut line).map_err(|e| e.to_string())?;
        let status = line
            .split_whitespace()
            .nth(1)
            .and_then(|s| s.parse().ok())
            .ok_or_else(|| format!("bad Docker answer: {}", line.trim()))?;
        let (mut length, mut chunked) = (None, false);
        loop {
            line.clear();
            if reader.read_line(&mut line).map_err(|e| e.to_string())? == 0
                || line == "\r\n"
                || line == "\n"
            {
                break;
            }
            if let Some((name, value)) = line.split_once(':') {
                let value = value.trim();
                match name.trim().to_ascii_lowercase().as_str() {
                    "content-length" => length = value.parse::<u64>().ok(),
                    "transfer-encoding" => chunked = value.eq_ignore_ascii_case("chunked"),
                    _ => {}
                }
            }
        }
        let body: Box<dyn Read> = if chunked {
            Box::new(Chunked {
                inner: reader,
                remaining: 0,
                done: false,
            })
        } else if let Some(length) = length {
            Box::new(reader.take(length))
        } else {
            Box::new(reader)
        };
        Ok(Response { status, body })
    }

    pub fn json(&self, path: &str) -> Result<Value, String> {
        let response = self.get(path)?;
        let mut bytes = Vec::new();
        response
            .body
            .take(32 * 1024 * 1024)
            .read_to_end(&mut bytes)
            .map_err(|e| e.to_string())?;
        if response.status != 200 {
            return Err(format!("Docker GET {path}: HTTP {}", response.status));
        }
        serde_json::from_slice(&bytes).map_err(|e| format!("Docker GET {path}: {e}"))
    }

    /// One file of a running container (`GET /containers/{id}/archive`), none when absent.
    pub fn container_file(&self, id: &str, path: &str) -> Option<Vec<u8>> {
        let response = self
            .get(&format!(
                "/containers/{id}/archive?path={}",
                crate::inventory::purl::encode(path)
            ))
            .ok()?;
        if response.status != 200 {
            return None;
        }
        let mut archive = tar::Archive::new(response.body);
        let mut entry = archive
            .entries()
            .ok()?
            .filter_map(Result::ok)
            .find(|e| e.header().entry_type().is_file())?;
        let mut bytes = Vec::new();
        (&mut entry)
            .take(crate::inventory::files::MAX_FILE)
            .read_to_end(&mut bytes)
            .ok()?;
        Some(bytes)
    }
}

/// `Transfer-Encoding: chunked`.
struct Chunked<R: BufRead> {
    inner: R,
    remaining: u64,
    done: bool,
}

impl<R: BufRead> Read for Chunked<R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if self.done {
            return Ok(0);
        }
        if self.remaining == 0 {
            let mut line = String::new();
            self.inner.read_line(&mut line)?;
            if line.trim().is_empty() {
                line.clear();
                self.inner.read_line(&mut line)?;
            }
            let size = line.trim().split(';').next().unwrap_or("");
            self.remaining = u64::from_str_radix(size, 16)
                .map_err(|_| std::io::Error::other("bad chunk size"))?;
            if self.remaining == 0 {
                self.done = true;
                return Ok(0);
            }
        }
        let max = buf.len().min(self.remaining as usize);
        let read = self.inner.read(&mut buf[..max])?;
        if read == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "chunked body cut",
            ));
        }
        self.remaining -= read as u64;
        Ok(read)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn decodes_a_chunked_body() {
        let raw = b"4\r\nWiki\r\n6\r\npedia \r\nE\r\nin \r\n\r\nchunks.\r\n0\r\n\r\n";
        let mut body = String::new();
        Chunked {
            inner: Cursor::new(&raw[..]),
            remaining: 0,
            done: false,
        }
        .read_to_string(&mut body)
        .unwrap();
        assert_eq!(body, "Wikipedia in \r\n\r\nchunks.");
        assert!(Docker::new("ssh://x").is_err());
        assert!(Docker::new("tcp://proxy:2375").is_ok());
    }
}
