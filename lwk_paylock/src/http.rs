//! The completion service's HTTP listener: HTTP/1.1, one request per connection, each
//! connection on a thread of its own, every read under a deadline.
//!
//! A slow client holds only its own connection, and only until its deadline: the
//! request line and headers must arrive within [`HttpLimits::header_time`], the whole
//! request within [`HttpLimits::request_time`].
//!
//! **No client takes every slot.** The service serves [`HttpLimits::max_conns`]
//! connections at once. One address holds at most [`HttpLimits::conns_per_client`] of
//! them (a loopback peer is the reverse proxy on this host, so there the client its
//! headers name is counted instead), and the last [`HttpLimits::reserve`] slots go only
//! to an address that holds none. A connection that has sent no headers is idle, and a
//! new one takes its place when it must: its own address's oldest idle one when that
//! address holds its share, so a flood from one address competes only with itself; and
//! when every slot is taken, the oldest idle one of the address holding the most, once
//! idle for [`HttpLimits::idle_grace`]. A client sends its headers at once, so what is
//! pushed out is a connection that sent nothing. A client may
//! be sending at most [`HttpLimits::bodies_per_client`] bodies at a time (`429` beyond).
//! So neither idle connections, nor slow bodies, nor a crowd of either from one address
//! stall intake or reads for anyone else.
//!
//! A connection refused is answered in JSON (`503`, or `429` when its address holds its
//! share), and the request it sent is read before the connection closes, so the client
//! reads the answer rather than a reset.
//!
//! A request's body needs `Content-Length` (`411` otherwise) and may not exceed
//! [`HttpLimits::max_body`] (`413`). A request's client is the peer's address (an IPv6
//! address by its /64); behind a reverse proxy on the same host (the peer is loopback),
//! it is the last address in `X-Forwarded-For`, the one that proxy wrote.

use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{IpAddr, Shutdown, SocketAddr, TcpListener, TcpStream};
use std::sync::{Arc, Mutex, MutexGuard};
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
    /// Connections served at once; beyond it a connection takes the place of an idle one,
    /// or is answered `503`.
    pub max_conns: usize,
    /// The last of those slots, which only an address holding no connection may take.
    pub reserve: usize,
    /// Connections one address (one client, once its headers name it) may hold at once;
    /// beyond it a new one takes the place of its own oldest idle one, or is answered
    /// `429`.
    pub conns_per_client: usize,
    /// Bodies one client may be sending at once; beyond it `429`.
    pub bodies_per_client: usize,
    /// How long a connection that has sent no headers is left alone before a new one may
    /// take its place: a client sends its headers at once, well within it.
    pub idle_grace: Duration,
}

impl Default for HttpLimits {
    fn default() -> Self {
        HttpLimits {
            max_body: 512 << 10,
            header_time: Duration::from_secs(5),
            request_time: Duration::from_secs(10),
            max_conns: 256,
            reserve: 32,
            conns_per_client: 16,
            bodies_per_client: 4,
            idle_grace: Duration::from_secs(1),
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

/// How long, and how much, a connection is read after its answer, so that what the
/// client sent and the service did not read (a request refused before it was read)
/// never turns the close into a reset that would discard the answer.
const LINGER_TIME: Duration = Duration::from_secs(2);
const LINGER_BYTES: usize = 1 << 20;

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
    linger(stream);
}

/// Closes the sending side and reads what the client still sends, until it closes, for
/// [`LINGER_TIME`] at most: a close with unread data is a reset, which the client's
/// system may take before the answer and discard it.
fn linger(stream: &mut TcpStream) {
    let _ = stream.shutdown(Shutdown::Write);
    let end = Instant::now() + LINGER_TIME;
    let mut chunk = [0u8; 8192];
    let mut read = 0;
    while read < LINGER_BYTES {
        let now = Instant::now();
        if now >= end {
            break;
        }
        let _ = stream.set_read_timeout(Some(end - now));
        match stream.read(&mut chunk) {
            Ok(0) => break,
            Ok(n) => read += n,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
            Err(_) => break,
        }
    }
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

/// One connection being served.
struct Conn {
    /// Whose it counts as: its peer's address until its headers name its client.
    who: String,
    /// Whether its headers are read: until then it is idle, and may give way.
    named: bool,
    opened: Instant,
    /// A handle to close it with when it gives way.
    stream: TcpStream,
}

#[derive(Default)]
struct Table {
    next: u64,
    conns: HashMap<u64, Conn>,
    bodies: HashMap<String, usize>,
}

impl Table {
    fn held_by(&self, who: &str) -> usize {
        self.conns.values().filter(|c| c.who == who).count()
    }

    /// The oldest idle connection (no headers yet, open for `grace` at least) of `who`, or
    /// of anyone when `None`: then of the address holding the most idle connections.
    fn oldest_idle(&self, who: Option<&str>, grace: Duration) -> Option<u64> {
        let idle = |c: &Conn| !c.named && c.opened.elapsed() >= grace;
        let who = match who {
            Some(w) => w.to_string(),
            None => {
                let mut counts: HashMap<&str, usize> = HashMap::new();
                for c in self.conns.values().filter(|c| idle(c)) {
                    *counts.entry(c.who.as_str()).or_insert(0) += 1;
                }
                let most = counts.values().copied().max()?;
                // Among the addresses holding the most idle connections, the one whose
                // oldest is oldest.
                self.conns
                    .values()
                    .filter(|c| idle(c) && counts.get(c.who.as_str()) == Some(&most))
                    .min_by_key(|c| c.opened)?
                    .who
                    .clone()
            }
        };
        self.conns
            .iter()
            .filter(|(_, c)| idle(c) && c.who == who)
            .min_by_key(|(_, c)| c.opened)
            .map(|(id, _)| *id)
    }

    /// Closes a connection that gives way; its thread ends at its next read.
    fn push_out(&mut self, id: u64) {
        if let Some(c) = self.conns.remove(&id) {
            let _ = c.stream.shutdown(Shutdown::Both);
        }
    }
}

struct Slots {
    table: Mutex<Table>,
    /// Refused connections, answered and closing: what their clients still send is read
    /// (by one thread, [`reap`]) until they close, for [`LINGER_TIME`] at most.
    closing: Mutex<Vec<(TcpStream, Instant, usize)>>,
}

/// The most refused connections closing at once; beyond it one is closed at once, its
/// answer written.
const MAX_CLOSING: usize = 4096;

impl Slots {
    fn table(&self) -> MutexGuard<'_, Table> {
        self.table.lock().unwrap_or_else(|e| e.into_inner())
    }
}

/// Holds a client's body slot while it reads its body.
struct BodySlot<'a>(&'a Slots, String);

impl Drop for BodySlot<'_> {
    fn drop(&mut self) {
        let mut t = self.0.table();
        if let Some(n) = t.bodies.get_mut(&self.1) {
            *n -= 1;
            if *n == 0 {
                t.bodies.remove(&self.1);
            }
        }
    }
}

/// Holds a connection's slot while it is served.
struct ConnSlot<'a>(&'a Slots, u64);

impl Drop for ConnSlot<'_> {
    fn drop(&mut self) {
        self.0.table().conns.remove(&self.1);
    }
}

/// An address as the limits count it: an IPv4 address whole, an IPv6 one by its /64 (what
/// one subscriber holds).
pub fn address_key(ip: IpAddr) -> String {
    match ip.to_canonical() {
        IpAddr::V4(a) => a.to_string(),
        IpAddr::V6(a) => {
            let s = a.segments();
            format!("{:x}:{:x}:{:x}:{:x}::/64", s[0], s[1], s[2], s[3])
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
            return address_key(fwd);
        }
    }
    address_key(ip)
}

fn serve_one(
    mut stream: TcpStream,
    peer: SocketAddr,
    id: u64,
    limits: &HttpLimits,
    slots: &Slots,
    handler: &Handler,
) {
    let _slot = ConnSlot(slots, id);
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
    // Its headers name its client: from here it counts as that client's, and is no
    // longer idle. A connection that gave way meanwhile is no longer served.
    {
        let mut t = slots.table();
        let others = t
            .conns
            .iter()
            .filter(|(k, c)| **k != id && c.named && c.who == client)
            .count();
        match t.conns.get_mut(&id) {
            None => return,
            Some(c) if others >= limits.conns_per_client => {
                c.named = true;
                drop(t);
                return respond(
                    &mut stream,
                    429,
                    &json!({"error": "this client has too many requests open: try again when they are done"}),
                );
            }
            Some(c) => {
                c.who = client.clone();
                c.named = true;
            }
        }
    }
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
            let mut t = slots.table();
            let n = t.bodies.entry(client.clone()).or_insert(0);
            if *n >= limits.bodies_per_client {
                drop(t);
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

/// What the listener does with a new connection.
enum Admit {
    /// Served, under this id.
    Serve(u64),
    /// Refused, answered with this status and message.
    Refuse(u16, &'static str),
}

/// Admits a connection from `who` (its peer's address) within the limits; `capped` says
/// whether the address's own share applies (a loopback peer is the reverse proxy on this
/// host, whose clients are counted once their headers name them). It takes the place of
/// an idle connection (one that has sent no headers): its own address's oldest, when the
/// address holds its share, or holds a connection already and only reserved slots are
/// left; when every slot is taken, the oldest of the address holding the most idle ones,
/// idle for [`HttpLimits::idle_grace`] at least.
fn admit(t: &mut Table, limits: &HttpLimits, who: &str, capped: bool, stream: &TcpStream) -> Admit {
    let held = t.held_by(who);
    let total = t.conns.len();
    let grace = limits.idle_grace;
    // An address's own idle connections give way to its new ones at once: a flood from
    // one address competes only with itself. Another address's give way only once idle
    // for the grace, so a client's connection is never pushed out before it could send.
    let make_room = if capped && held >= limits.conns_per_client {
        match t.oldest_idle(Some(who), Duration::ZERO) {
            Some(id) => Some(id),
            None => {
                return Admit::Refuse(
                    429,
                    "this address has too many connections open: try again when they are done",
                )
            }
        }
    } else if held > 0 && total >= limits.max_conns.saturating_sub(limits.reserve) {
        match t.oldest_idle(Some(who), Duration::ZERO) {
            Some(id) => Some(id),
            None => return Admit::Refuse(503, "the service is busy: try again"),
        }
    } else if total >= limits.max_conns {
        match t.oldest_idle(None, grace) {
            Some(id) => Some(id),
            None => return Admit::Refuse(503, "the service is busy: try again"),
        }
    } else {
        None
    };
    let Ok(handle) = stream.try_clone() else {
        return Admit::Refuse(503, "the service is busy: try again");
    };
    if let Some(id) = make_room {
        t.push_out(id);
    }
    t.next += 1;
    let id = t.next;
    t.conns.insert(
        id,
        Conn {
            who: who.to_string(),
            named: false,
            opened: Instant::now(),
            stream: handle,
        },
    );
    Admit::Serve(id)
}

/// Answers a refused connection without waiting on it (the answer fits the socket's
/// buffer), and hands it to [`reap`] to close.
fn refuse(slots: &Slots, mut stream: TcpStream, code: u16, message: &str) {
    let b = json!({ "error": message }).to_string();
    let _ = stream.set_nonblocking(true);
    let _ = write!(
        stream,
        "HTTP/1.1 {code} {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{b}",
        reason(code),
        b.len()
    );
    let _ = stream.shutdown(Shutdown::Write);
    let mut c = slots.closing.lock().unwrap_or_else(|e| e.into_inner());
    if c.len() < MAX_CLOSING {
        c.push((stream, Instant::now(), 0));
    }
}

/// Reads what refused connections still send, and closes each once its client has, or
/// after [`LINGER_TIME`] or [`LINGER_BYTES`]: a close with unread data would be a reset,
/// which may reach the client before it reads its answer.
fn reap(slots: &Slots) {
    let mut chunk = [0u8; 8192];
    loop {
        std::thread::sleep(Duration::from_millis(20));
        let mut c = slots.closing.lock().unwrap_or_else(|e| e.into_inner());
        c.retain_mut(|(stream, since, read)| {
            if since.elapsed() >= LINGER_TIME || *read >= LINGER_BYTES {
                return false;
            }
            loop {
                match stream.read(&mut chunk) {
                    Ok(0) => return false,
                    Ok(n) => *read += n,
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => return true,
                    Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
                    Err(_) => return false,
                }
                if *read >= LINGER_BYTES {
                    return false;
                }
            }
        });
    }
}

/// Serves `listener` with `handler`, each connection on a thread of its own, within
/// `limits`. Never returns.
pub fn serve(listener: TcpListener, limits: HttpLimits, handler: Handler) {
    let slots = Arc::new(Slots {
        table: Mutex::new(Table::default()),
        closing: Mutex::new(vec![]),
    });
    let reaper = slots.clone();
    std::thread::spawn(move || reap(&reaper));
    for conn in listener.incoming() {
        let Ok(stream) = conn else {
            // Out of descriptors, say: a moment for connections to close.
            std::thread::sleep(Duration::from_millis(10));
            continue;
        };
        let Ok(peer) = stream.peer_addr() else {
            continue;
        };
        let who = address_key(peer.ip());
        let capped = !peer.ip().to_canonical().is_loopback();
        let admitted = admit(&mut slots.table(), &limits, &who, capped, &stream);
        match admitted {
            Admit::Serve(id) => {
                let (s, l, h) = (slots.clone(), limits.clone(), handler.clone());
                let spawned = std::thread::Builder::new()
                    .spawn(move || serve_one(stream, peer, id, &l, &s, &h));
                if spawned.is_err() {
                    slots.table().conns.remove(&id);
                }
            }
            Admit::Refuse(code, message) => refuse(&slots, stream, code, message),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A connected stream (the server's end), for the table to hold.
    fn stream(l: &TcpListener) -> (TcpStream, TcpStream) {
        let c = TcpStream::connect(l.local_addr().unwrap()).unwrap();
        (l.accept().unwrap().0, c)
    }

    #[test]
    fn connections_are_shared_between_addresses() {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let limits = HttpLimits {
            max_conns: 8,
            reserve: 2,
            conns_per_client: 3,
            idle_grace: Duration::from_millis(50),
            ..HttpLimits::default()
        };
        let mut t = Table::default();
        let mut keep = vec![];
        let mut admit_one = |t: &mut Table, who: &str, capped: bool| {
            let (s, c) = stream(&l);
            let a = admit(t, &limits, who, capped, &s);
            keep.push((s, c));
            a
        };
        // One address: its share; then a new one takes the place of its own oldest idle
        // one at once, and is refused only when none of its own is idle.
        for _ in 0..3 {
            assert!(matches!(admit_one(&mut t, "a", true), Admit::Serve(_)));
        }
        let oldest = *t.conns.keys().min().unwrap();
        assert!(matches!(admit_one(&mut t, "a", true), Admit::Serve(_)));
        assert!(!t.conns.contains_key(&oldest));
        assert_eq!(t.held_by("a"), 3);
        for c in t.conns.values_mut() {
            c.named = true;
        }
        assert!(matches!(
            admit_one(&mut t, "a", true),
            Admit::Refuse(429, _)
        ));
        // A loopback peer (the proxy) has no share of its own: up to the reserve.
        for _ in 0..3 {
            assert!(matches!(admit_one(&mut t, "p", false), Admit::Serve(_)));
        }
        assert_eq!(t.conns.len(), 6);
        // Only reserved slots are left: the proxy, holding some, takes the place of its
        // own idle one; with none idle it is refused; an address holding none takes one.
        let before: Vec<u64> = t.conns.keys().copied().collect();
        assert!(matches!(admit_one(&mut t, "p", false), Admit::Serve(_)));
        assert_eq!((t.conns.len(), t.held_by("p")), (6, 3));
        assert!(before.iter().any(|k| !t.conns.contains_key(k)));
        for c in t.conns.values_mut() {
            c.named = c.who == "a" || c.who == "p";
        }
        assert!(matches!(
            admit_one(&mut t, "p", false),
            Admit::Refuse(503, _)
        ));
        assert!(matches!(admit_one(&mut t, "b", true), Admit::Serve(_)));
        assert!(matches!(admit_one(&mut t, "c", true), Admit::Serve(_)));
        assert_eq!(t.conns.len(), 8);
        // Every slot taken, the named ones never give way.
        for c in t.conns.values_mut() {
            c.named = true;
        }
        assert!(matches!(
            admit_one(&mut t, "d", true),
            Admit::Refuse(503, _)
        ));
        // Idle ones do, once idle for the grace: the oldest of the address holding the
        // most.
        for c in t.conns.values_mut().filter(|c| c.who == "p") {
            c.named = false;
            c.opened = Instant::now();
        }
        assert!(matches!(
            admit_one(&mut t, "d", true),
            Admit::Refuse(503, _)
        ));
        std::thread::sleep(Duration::from_millis(60));
        assert!(matches!(admit_one(&mut t, "d", true), Admit::Serve(_)));
        assert_eq!(t.held_by("p"), 2);
        assert_eq!(t.held_by("d"), 1);
    }

    #[test]
    fn an_address_is_counted_by_its_subscriber() {
        let k = |s: &str| address_key(s.parse().unwrap());
        assert_eq!(k("198.51.100.7"), "198.51.100.7");
        assert_eq!(k("::ffff:198.51.100.7"), "198.51.100.7");
        assert_eq!(k("2001:db8:1:2:aaaa::1"), k("2001:db8:1:2:bbbb::9"));
        assert_ne!(k("2001:db8:1:2::1"), k("2001:db8:1:3::1"));
    }
}
