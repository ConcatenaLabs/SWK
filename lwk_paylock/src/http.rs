//! The completion service's HTTP listener: HTTP/1.1, one request per connection, each
//! connection on a thread of its own, every read under a deadline.
//!
//! A slow client holds only its own connection, and only until its deadline: the
//! request line and headers must arrive within [`HttpLimits::header_time`], the whole
//! request within [`HttpLimits::request_time`]. Connections beyond
//! [`HttpLimits::max_conns`] are answered `503` at once, and a client may read at most
//! [`HttpLimits::bodies_per_client`] bodies at a time (`429` beyond), so neither a slow
//! body nor a crowd of them from one client stalls intake or reads for anyone else.
//!
//! A request's body needs `Content-Length` (`411` otherwise) and may not exceed
//! [`HttpLimits::max_body`] (`413`). A request's client is the peer's address; behind a
//! reverse proxy on the same host (the peer is loopback), it is the last address in
//! `X-Forwarded-For`, the one that proxy wrote.

use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{IpAddr, SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use serde_json::{json, Value};

/// How long a request may take and how many may be read at once.
#[derive(Debug, Clone)]
pub struct HttpLimits {
    /// A request's body, in bytes.
    pub max_body: usize,
    /// The request line and headers must arrive within this.
    pub header_time: Duration,
    /// The whole request, body included, must arrive within this.
    pub request_time: Duration,
    /// Connections served at once; beyond it a connection is answered `503`.
    pub max_conns: usize,
    /// Bodies one client may be sending at once; beyond it `429`.
    pub bodies_per_client: usize,
}

impl Default for HttpLimits {
    fn default() -> Self {
        HttpLimits {
            max_body: 512 << 10,
            header_time: Duration::from_secs(5),
            request_time: Duration::from_secs(10),
            max_conns: 256,
            bodies_per_client: 4,
        }
    }
}

/// A request, read whole.
#[derive(Debug, Clone)]
pub struct Request {
    /// `GET`, `POST`, ...
    pub method: String,
    /// The path, query included.
    pub path: String,
    /// The headers, names in lower case.
    pub headers: Vec<(String, String)>,
    /// The body.
    pub body: Vec<u8>,
    /// Who sent it (see the module's documentation).
    pub client: String,
}

impl Request {
    /// A header's value, by name in any case.
    pub fn header(&self, name: &str) -> Option<&str> {
        let n = name.to_ascii_lowercase();
        self.headers
            .iter()
            .find(|(k, _)| *k == n)
            .map(|(_, v)| v.as_str())
    }
}

/// What a request is answered: a status and a JSON body.
pub type Answer = (u16, Value);

/// What the server calls for each request it has read whole.
pub type Handler = Arc<dyn Fn(&Request) -> Answer + Send + Sync>;

fn reason(code: u16) -> &'static str {
    match code {
        200 => "OK",
        400 => "Bad Request",
        401 => "Unauthorized",
        404 => "Not Found",
        408 => "Request Timeout",
        411 => "Length Required",
        413 => "Payload Too Large",
        429 => "Too Many Requests",
        431 => "Request Header Fields Too Large",
        503 => "Service Unavailable",
        _ => "",
    }
}

fn respond(stream: &mut TcpStream, code: u16, body: &Value) {
    let b = body.to_string();
    let _ = stream.set_write_timeout(Some(Duration::from_secs(5)));
    let _ = write!(
        stream,
        "HTTP/1.1 {code} {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{b}",
        reason(code),
        b.len()
    );
    let _ = stream.flush();
}

/// Reads into `buf` until `done(buf)` or `deadline`; `false` when the deadline passed or
/// the peer closed first.
fn read_until(
    stream: &mut TcpStream,
    buf: &mut Vec<u8>,
    deadline: Instant,
    max: usize,
    done: &dyn Fn(&[u8]) -> bool,
) -> Result<bool, u16> {
    let mut chunk = [0u8; 8192];
    while !done(buf) {
        let now = Instant::now();
        if now >= deadline {
            return Err(408);
        }
        let _ = stream.set_read_timeout(Some(deadline - now));
        match stream.read(&mut chunk) {
            Ok(0) => return Ok(false),
            Ok(n) => {
                buf.extend_from_slice(&chunk[..n]);
                if buf.len() > max {
                    return Err(413);
                }
            }
            Err(e)
                if e.kind() == std::io::ErrorKind::WouldBlock
                    || e.kind() == std::io::ErrorKind::TimedOut =>
            {
                return Err(408)
            }
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
            Err(_) => return Ok(false),
        }
    }
    Ok(true)
}

fn header_end(b: &[u8]) -> Option<usize> {
    b.windows(4).position(|w| w == b"\r\n\r\n").map(|p| p + 4)
}

struct Slots {
    conns: AtomicUsize,
    bodies: Mutex<HashMap<String, usize>>,
}

/// Holds a client's body slot while it reads its body.
struct BodySlot<'a>(&'a Slots, String);

impl Drop for BodySlot<'_> {
    fn drop(&mut self) {
        let mut m = self.0.bodies.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(n) = m.get_mut(&self.1) {
            *n -= 1;
            if *n == 0 {
                m.remove(&self.1);
            }
        }
    }
}

fn client_of(peer: &SocketAddr, headers: &[(String, String)]) -> String {
    let ip = peer.ip();
    if ip.is_loopback() {
        if let Some(fwd) = headers
            .iter()
            .find(|(k, _)| k == "x-forwarded-for")
            .and_then(|(_, v)| v.rsplit(',').next())
            .and_then(|s| s.trim().parse::<IpAddr>().ok())
        {
            return fwd.to_string();
        }
    }
    ip.to_string()
}

fn serve_one(
    mut stream: TcpStream,
    peer: SocketAddr,
    limits: &HttpLimits,
    slots: &Slots,
    handler: &Handler,
) {
    let start = Instant::now();
    let mut buf = vec![];
    let head = match read_until(
        &mut stream,
        &mut buf,
        start + limits.header_time,
        16 << 10,
        &|b| header_end(b).is_some(),
    ) {
        Ok(true) => header_end(&buf).expect("found"),
        Ok(false) => return,
        Err(413) => {
            return respond(
                &mut stream,
                431,
                &json!({"error": "the headers are too large"}),
            )
        }
        Err(c) => {
            return respond(
                &mut stream,
                c,
                &json!({"error": "the request took too long"}),
            )
        }
    };
    let text = String::from_utf8_lossy(&buf[..head]).to_string();
    let mut lines = text.split("\r\n");
    let mut first = lines.next().unwrap_or_default().split(' ');
    let (method, path) = match (first.next(), first.next(), first.next()) {
        (Some(m), Some(p), Some(v)) if v.starts_with("HTTP/1.") && !m.is_empty() => {
            (m.to_string(), p.to_string())
        }
        _ => {
            return respond(
                &mut stream,
                400,
                &json!({"error": "not an HTTP/1.1 request"}),
            )
        }
    };
    let headers: Vec<(String, String)> = lines
        .filter_map(|l| l.split_once(':'))
        .map(|(k, v)| (k.trim().to_ascii_lowercase(), v.trim().to_string()))
        .collect();
    let client = client_of(&peer, &headers);
    let get = |k: &str| {
        headers
            .iter()
            .find(|(n, _)| n == k)
            .map(|(_, v)| v.as_str())
    };
    let mut body = buf[head..].to_vec();
    if method != "GET" && method != "HEAD" {
        if get("transfer-encoding").is_some() {
            return respond(
                &mut stream,
                411,
                &json!({"error": "send the body with Content-Length"}),
            );
        }
        let Some(len) = get("content-length").and_then(|v| v.parse::<usize>().ok()) else {
            return respond(
                &mut stream,
                411,
                &json!({"error": "send the body with Content-Length"}),
            );
        };
        if len > limits.max_body {
            return respond(
                &mut stream,
                413,
                &json!({"error": "the request is too large"}),
            );
        }
        {
            let mut m = slots.bodies.lock().unwrap_or_else(|e| e.into_inner());
            let n = m.entry(client.clone()).or_insert(0);
            if *n >= limits.bodies_per_client {
                drop(m);
                return respond(
                    &mut stream,
                    429,
                    &json!({"error": "this client is sending other requests: try again when they are done"}),
                );
            }
            *n += 1;
        }
        let _slot = BodySlot(slots, client.clone());
        if get("expect").is_some_and(|v| v.eq_ignore_ascii_case("100-continue")) && body.len() < len
        {
            let _ = stream.write_all(b"HTTP/1.1 100 Continue\r\n\r\n");
        }
        match read_until(
            &mut stream,
            &mut body,
            start + limits.request_time,
            len + (64 << 10),
            &|b| b.len() >= len,
        ) {
            Ok(true) => body.truncate(len),
            Ok(false) => return,
            Err(_) => {
                return respond(
                    &mut stream,
                    408,
                    &json!({"error": "the request took too long"}),
                )
            }
        }
    } else {
        body.clear();
    }
    let req = Request {
        method,
        path,
        headers,
        body,
        client,
    };
    let (code, v) = handler(&req);
    respond(&mut stream, code, &v);
}

/// Serves `listener` with `handler`, each connection on a thread of its own, within
/// `limits`. Never returns.
pub fn serve(listener: TcpListener, limits: HttpLimits, handler: Handler) {
    let slots = Arc::new(Slots {
        conns: AtomicUsize::new(0),
        bodies: Mutex::new(HashMap::new()),
    });
    for conn in listener.incoming() {
        let Ok(mut stream) = conn else {
            continue;
        };
        let Ok(peer) = stream.peer_addr() else {
            continue;
        };
        if slots.conns.fetch_add(1, Ordering::SeqCst) >= limits.max_conns {
            slots.conns.fetch_sub(1, Ordering::SeqCst);
            respond(
                &mut stream,
                503,
                &json!({"error": "the service is busy: try again"}),
            );
            continue;
        }
        let (s, l, h) = (slots.clone(), limits.clone(), handler.clone());
        let spawned = std::thread::Builder::new().spawn(move || {
            serve_one(stream, peer, &l, &s, &h);
            s.conns.fetch_sub(1, Ordering::SeqCst);
        });
        if spawned.is_err() {
            slots.conns.fetch_sub(1, Ordering::SeqCst);
        }
    }
}
