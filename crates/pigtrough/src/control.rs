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

use crate::holder::Mount;

/// The most a load request may hold: a route name and a token.
pub const MAX_LOAD: usize = 64 * 1024;

/// Serve load requests on `listener` for the mounted routes, each filling
/// its own holder, until the listener fails.
pub async fn serve_control<A>(
    listener: UnixListener,
    mounts: Vec<Mount>,
    admit: A,
) -> io::Result<()>
where
    A: Fn(&UnixStream) -> bool,
{
    let mounts = Arc::new(mounts);
    loop {
        let (mut stream, _) = listener.accept().await?;
        if !admit(&stream) {
            eprintln!("pigtrough control: refused a connection from another user");
            continue;
        }
        let mounts = mounts.clone();
        tokio::spawn(async move {
            let (route, answer) = match read_request(&mut stream).await {
                Ok(request) => load(&mounts, &request),
                Err(_) => (None, "error: the request could not be read".to_owned()),
            };
            eprintln!("pigtrough control: load {}: {answer}", route.unwrap_or("?"));
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

/// Apply one load request to the mount it names; the answer names no part
/// of the secret. The first part is the route's name when the request named
/// a mounted one (for the control log), else `None`: a client-supplied name
/// is never echoed.
fn load(mounts: &[Mount], request: &[u8]) -> (Option<&'static str>, String) {
    let Some(newline) = request.iter().position(|b| *b == b'\n') else {
        return (None, "error: no route name".to_owned());
    };
    let (name, secret) = (&request[..newline], &request[newline + 1..]);
    let Some(mount) = mounts.iter().find(|m| m.route.name.as_bytes() == name) else {
        return (None, "error: unknown route".to_owned());
    };
    let answer = match mount.holder.load(secret) {
        Ok(()) => "ok".to_owned(),
        Err(e) => format!("error: {e}"),
    };
    (Some(mount.route.name), answer)
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
    use crate::route::{GITHUB_API, Route};

    #[test]
    fn load_requests_name_their_route_and_never_echo() {
        let mount = Mount::empty(&GITHUB_API);
        let mounts = [mount.clone()];
        assert_eq!(
            load(&mounts, b"github-api\npiggy-test-tok\n"),
            (Some("github-api"), "ok".to_owned())
        );
        assert!(mount.holder.current().is_some());
        for (request, answer) in [
            (&b"piggy-test-tok"[..], "error: no route name"),
            (b"other-route\npiggy-test-tok", "error: unknown route"),
        ] {
            assert_eq!(load(&mounts, request), (None, answer.to_owned()));
        }
        assert_eq!(
            load(&mounts, b"github-api\n"),
            (Some("github-api"), "error: the secret is empty".to_owned())
        );
        let (_, answer) = load(&mounts, b"github-api\npiggy test tok");
        assert!(
            answer.starts_with("error:") && !answer.contains("piggy"),
            "{answer}"
        );
    }

    #[test]
    fn each_route_fills_only_its_own_holder() {
        static OTHER: Route = Route {
            name: "other",
            upstream: crate::route::Upstream {
                host: "other.invalid",
                port: 443,
            },
            scheme: crate::route::Scheme::Token,
            secret: "piggy-test/none",
            owners: &[],
            allow: &[],
            forward_headers: &[],
            limits: crate::route::Limits::DEFAULT,
        };
        let (a, b) = (Mount::empty(&GITHUB_API), Mount::empty(&OTHER));
        let mounts = [a.clone(), b.clone()];
        assert_eq!(load(&mounts, b"other\ntok-b").1, "ok");
        assert!(a.holder.current().is_none());
        assert!(b.holder.current().is_some());
        assert_eq!(load(&mounts, b"github-api\ntok-a").1, "ok");
        assert!(a.holder.current().is_some());
    }
}
