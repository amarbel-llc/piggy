//! The control socket: how the operator loads a route's secret.
//!
//! `piggy pass show <entry> | pigtrough load github-api` sends the secret on
//! stdin, never in argv or the environment (FDR 0009, "Loading"; FDR 0008
//! candidate 3). The socket sits beside the proxy socket, `0600` in the same
//! `0700` directory, and every connection passes the same peer-UID check as
//! the proxy socket. One request per connection: the route name, a newline,
//! the secret, then end of stream; the answer is one line, `ok` or
//! `error: <reason>`, and never echoes the secret.

use std::io;
use std::sync::Arc;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{UnixListener, UnixStream};
use zeroize::Zeroizing;

use crate::holder::SecretHolder;
use crate::route::Route;

/// The most a load request may hold: a route name and a token.
pub const MAX_LOAD: usize = 64 * 1024;

/// Serve load requests on `listener` for `route`, whose secret is `holder`,
/// until the listener fails.
pub async fn serve_control<A>(
    listener: UnixListener,
    route: &'static Route,
    holder: Arc<SecretHolder>,
    admit: A,
) -> io::Result<()>
where
    A: Fn(&UnixStream) -> bool,
{
    loop {
        let (mut stream, _) = listener.accept().await?;
        if !admit(&stream) {
            eprintln!("pigtrough control: refused a connection from another user");
            continue;
        }
        let holder = holder.clone();
        tokio::spawn(async move {
            let answer = match read_request(&mut stream).await {
                Ok(request) => load(route, &holder, &request),
                Err(_) => "error: the request could not be read".to_owned(),
            };
            eprintln!("pigtrough control: load {}: {answer}", route.name);
            let _ = stream.write_all(format!("{answer}\n").as_bytes()).await;
        });
    }
}

async fn read_request(stream: &mut UnixStream) -> io::Result<Zeroizing<Vec<u8>>> {
    let mut request = Zeroizing::new(Vec::new());
    let read = (&mut *stream)
        .take(MAX_LOAD as u64 + 1)
        .read_to_end(&mut request)
        .await?;
    if read > MAX_LOAD {
        return Err(io::Error::other("load request too large"));
    }
    Ok(request)
}

/// Apply one load request; the answer names no part of the secret.
fn load(route: &Route, holder: &SecretHolder, request: &[u8]) -> String {
    let Some(newline) = request.iter().position(|b| *b == b'\n') else {
        return "error: no route name".to_owned();
    };
    let (name, secret) = (&request[..newline], &request[newline + 1..]);
    if name != route.name.as_bytes() {
        return "error: unknown route".to_owned();
    }
    match holder.load(secret) {
        Ok(()) => "ok".to_owned(),
        Err(e) => format!("error: {e}"),
    }
}

/// The client half: send `secret` for `route_name` to the control socket at
/// `path` and return the server's answer line.
pub fn send_load(path: &std::path::Path, route_name: &str, secret: &[u8]) -> io::Result<String> {
    use std::io::{Read, Write};
    let mut stream = std::os::unix::net::UnixStream::connect(path)?;
    let mut request = Zeroizing::new(Vec::with_capacity(route_name.len() + 1 + secret.len()));
    request.extend_from_slice(route_name.as_bytes());
    request.push(b'\n');
    request.extend_from_slice(secret);
    stream.write_all(&request)?;
    stream.shutdown(std::net::Shutdown::Write)?;
    let mut answer = String::new();
    stream.take(4096).read_to_string(&mut answer)?;
    Ok(answer.trim_end().to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::route::GITHUB_API;

    #[test]
    fn load_requests_name_their_route_and_never_echo() {
        let holder = SecretHolder::empty();
        assert_eq!(
            load(&GITHUB_API, &holder, b"github-api\npiggy-test-tok\n"),
            "ok"
        );
        assert!(holder.current().is_some());
        for (request, answer) in [
            (&b"piggy-test-tok"[..], "error: no route name"),
            (b"other-route\npiggy-test-tok", "error: unknown route"),
            (b"github-api\n", "error: the secret is empty"),
        ] {
            assert_eq!(load(&GITHUB_API, &holder, request), answer);
        }
        let answer = load(&GITHUB_API, &holder, b"github-api\npiggy test tok");
        assert!(
            answer.starts_with("error:") && !answer.contains("piggy"),
            "{answer}"
        );
    }
}
