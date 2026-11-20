//! A stand-in relay for unit tests: an HTTP server on loopback that
//! answers each call from a closure and records it.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// Every call received, as "METHOD path" (without the query string).
pub type Calls = Arc<Mutex<Vec<String>>>;

/// Serve on `127.0.0.1`: each call gets `respond("METHOD path")`, a
/// status and a JSON body. GETs (long polls) are answered after 50 ms.
pub async fn serve<F>(respond: F) -> (String, Calls)
where
    F: Fn(&str) -> (u16, String) + Send + Sync + 'static,
{
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    let calls = Calls::default();
    let log = calls.clone();
    let respond = Arc::new(respond);
    tokio::spawn(async move {
        while let Ok((mut socket, _)) = listener.accept().await {
            let (log, respond) = (log.clone(), respond.clone());
            tokio::spawn(async move {
                let Some(call) = read_request(&mut socket).await else {
                    return;
                };
                log.lock().unwrap().push(call.clone());
                if call.starts_with("GET ") {
                    tokio::time::sleep(Duration::from_millis(50)).await;
                }
                let (status, body) = respond(&call);
                let reply = format!(
                    "HTTP/1.1 {status} X\r\nContent-Type: application/json\r\n\
                     Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                let _ = socket.write_all(reply.as_bytes()).await;
                let _ = socket.shutdown().await;
            });
        }
    });
    (base, calls)
}

/// The calls whose "METHOD path" ends with `/cancel`.
pub fn cancels(calls: &Calls) -> Vec<String> {
    calls
        .lock()
        .unwrap()
        .iter()
        .filter(|c| c.starts_with("POST ") && c.ends_with("/cancel"))
        .cloned()
        .collect()
}

/// Wait up to 3 s for a cancellation, and return the cancel calls.
pub async fn until_cancelled(calls: &Calls) -> Vec<String> {
    for _ in 0..60 {
        let found = cancels(calls);
        if !found.is_empty() {
            return found;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    Vec::new()
}

/// Read one HTTP request: its "METHOD path". `None` if the connection
/// closed first.
async fn read_request(socket: &mut tokio::net::TcpStream) -> Option<String> {
    let mut raw = Vec::new();
    let mut buf = [0u8; 4096];
    let (head_end, body_len) = loop {
        let n = socket.read(&mut buf).await.ok().filter(|&n| n > 0)?;
        raw.extend_from_slice(&buf[..n]);
        if let Some(end) = raw.windows(4).position(|w| w == b"\r\n\r\n") {
            let head = String::from_utf8_lossy(&raw[..end]).to_lowercase();
            let len = head
                .lines()
                .find_map(|l| l.strip_prefix("content-length:"))
                .and_then(|v| v.trim().parse::<usize>().ok())
                .unwrap_or(0);
            break (end + 4, len);
        }
    };
    while raw.len() < head_end + body_len {
        let n = socket.read(&mut buf).await.ok().filter(|&n| n > 0)?;
        raw.extend_from_slice(&buf[..n]);
    }
    let text = String::from_utf8_lossy(&raw);
    let mut parts = text.lines().next()?.split(' ');
    let method = parts.next()?;
    let path = parts.next()?.split('?').next()?;
    Some(format!("{method} {path}"))
}
