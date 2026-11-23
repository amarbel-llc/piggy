//! The agent's listening socket, kept alive through descriptor exhaustion
//! (piggy#326).
//!
//! `ssh_agent_lib::agent::listen` returns at the first `accept()` error, and
//! the agent exits with it. A proxy that ran out of descriptors (a flapping
//! upstream, or an upstream that leads back into this agent) therefore went
//! down for every client, its card keys and its healthy upstreams included,
//! over a condition that clears as soon as the in-flight connections close.
//! [`ResilientListener`] retries such errors after a short pause instead, so
//! the agent stays up and serves again once descriptors free up.

use std::io;
use std::time::Duration;

use ssh_agent_lib::agent::{Agent, ListeningSocket, Session};
use tokio::net::{UnixListener, UnixStream};

use super::holder::PeerStatus;
use super::session::PiggyAgent;

/// How long `accept` waits before trying again after a transient error. Long
/// enough not to spin on a descriptor table that stays full, short enough
/// that clients barely notice once it drains.
const ACCEPT_RETRY_PAUSE: Duration = Duration::from_millis(100);

/// The agent's [`UnixListener`], whose `accept` rides out errors that clear
/// on their own.
#[derive(Debug)]
pub struct ResilientListener(pub UnixListener);

#[ssh_agent_lib::async_trait]
impl ListeningSocket for ResilientListener {
    type Stream = UnixStream;

    async fn accept(&mut self) -> io::Result<UnixStream> {
        loop {
            match self.0.accept().await {
                Ok((stream, _addr)) => return Ok(stream),
                Err(e) if accept_error_is_transient(&e) => {
                    tracing::warn!(
                        "accept failed ({e}); retrying in {} ms rather than exiting",
                        ACCEPT_RETRY_PAUSE.as_millis()
                    );
                    tokio::time::sleep(ACCEPT_RETRY_PAUSE).await;
                }
                Err(e) => return Err(e),
            }
        }
    }
}

/// `ssh_agent_lib`'s blanket `Agent` impl covers a bare `UnixListener` only.
/// A holder reads the peer of every connection here, before its first
/// request (FDR 0006 phase (d)); any other agent does not look.
impl Agent<ResilientListener> for PiggyAgent {
    fn new_session(&mut self, socket: &UnixStream) -> impl Session {
        self.session_for_connection(socket)
    }
}

impl PiggyAgent {
    /// The session for one accepted connection (what `new_session` returns,
    /// as the concrete type so a test can look at it).
    pub(super) fn session_for_connection(&self, socket: &UnixStream) -> PiggyAgent {
        // Every connection is its own: numbered here, whatever the agent is,
        // and its socket is watched for a hangup while a relayed sign waits.
        let session = self.clone().numbered().with_client_socket(socket);
        if !session.is_holder() {
            return session;
        }
        let peer = match super::peer::peer_of(socket) {
            Ok(peer) => {
                tracing::debug!(%peer, "holder: connection accepted");
                PeerStatus::Known(peer)
            }
            Err(e) => {
                tracing::warn!("holder: connection from an unreadable peer: {e}");
                PeerStatus::Unknown(e.to_string())
            }
        };
        session.with_peer(peer)
    }
}

/// How often a waiting sign looks at its client's socket.
const CLIENT_WATCH_INTERVAL: std::time::Duration = std::time::Duration::from_millis(250);

/// Resolves when the peer of `fd` has hung up. ssh-agent-lib answers one
/// request at a time and reads nothing while a handler runs, so a client that
/// goes away mid-request is not seen by it (shown by
/// `the_library_does_not_cancel_a_handler_when_its_connection_closes`): this
/// looks for it every [`CLIENT_WATCH_INTERVAL`] with `poll(2)` and no event
/// asked for, so it reads and consumes nothing.
///
/// Only POLLHUP (or an error) counts, never end-of-file on the read side. On
/// Linux a Unix stream socket reports POLLHUP when the peer has fully
/// closed (both directions are then shut), and a client that merely did
/// `shutdown(SHUT_WR)` after its request (socat, `nc -N`) and still waits for
/// the answer is NOT hung up: it is not reported, and a request byte still
/// unread does not hide a hangup either (the peek this replaces did both
/// wrong). On macOS and the BSDs I have not verified when a Unix socket
/// reports POLLHUP (THEORY: the same, for a full close); no test runs there.
#[cfg(not(target_os = "linux"))]
pub async fn peer_closed(_fd: std::sync::Arc<std::os::fd::OwnedFd>) {
    // Not verified off Linux: poll(2) with no event asked may report nothing
    // for a closed Unix socket there, so no hangup is seen and a queued sign
    // waits out its queue timeout (it fails safe: nothing is signed).
    std::future::pending::<()>().await;
}

/// See the doc comment above ([`peer_closed`] on Linux).
#[cfg(target_os = "linux")]
pub async fn peer_closed(fd: std::sync::Arc<std::os::fd::OwnedFd>) {
    use std::os::fd::AsRawFd;
    loop {
        let mut watched = libc::pollfd {
            fd: fd.as_raw_fd(),
            events: 0,
            revents: 0,
        };
        // SAFETY: one pollfd in a local, a zero timeout, on a descriptor this
        // Arc keeps open for the whole call.
        let n = unsafe { libc::poll(&raw mut watched, 1, 0) };
        if n > 0 && watched.revents & (libc::POLLHUP | libc::POLLERR | libc::POLLNVAL) != 0 {
            return;
        }
        if n < 0 && io::Error::last_os_error().kind() != io::ErrorKind::Interrupted {
            return;
        }
        tokio::time::sleep(CLIENT_WATCH_INTERVAL).await;
    }
}

/// Whether an `accept` error passes once in-flight work finishes: out of
/// descriptors (per process or system-wide), out of buffer or kernel memory,
/// or a client that gave up before it was accepted.
fn accept_error_is_transient(e: &io::Error) -> bool {
    matches!(
        e.raw_os_error(),
        Some(libc::EMFILE | libc::ENFILE | libc::ENOBUFS | libc::ENOMEM | libc::ECONNABORTED)
    ) || e.kind() == io::ErrorKind::Interrupted
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn a_hung_up_client_is_noticed_and_a_waiting_one_is_not() {
        use std::os::fd::AsFd;
        let (ours, theirs) = tokio::net::UnixStream::pair().unwrap();
        let watched = std::sync::Arc::new(ours.as_fd().try_clone_to_owned().unwrap());
        // Nothing sent, nothing closed: not closed, however long we look.
        let still_open = tokio::time::timeout(
            std::time::Duration::from_millis(600),
            peer_closed(watched.clone()),
        )
        .await;
        assert!(
            still_open.is_err(),
            "a client that is merely waiting was reported gone"
        );
        // A client that half-closed (socat, `nc -N`) and still waits for the
        // answer is not a hangup. A pair with NOTHING unread, so the read side
        // reports end-of-file and the old EOF test would have said "gone".
        let (half_ours, half_theirs) = tokio::net::UnixStream::pair().unwrap();
        let half_watched = std::sync::Arc::new(half_ours.as_fd().try_clone_to_owned().unwrap());
        let half_theirs = half_theirs.into_std().unwrap();
        half_theirs.shutdown(std::net::Shutdown::Write).unwrap();
        let half_closed = tokio::time::timeout(
            std::time::Duration::from_millis(600),
            peer_closed(half_watched),
        )
        .await;
        assert!(
            half_closed.is_err(),
            "a half-closed client that still waits was taken for a hangup"
        );
        drop(half_theirs);
        // The client goes away with its request byte still unread: noticed
        // (an unread byte used to hide the hangup), and nothing was consumed.
        let theirs = theirs.into_std().unwrap();
        std::io::Write::write_all(&mut &theirs, b"x").unwrap();
        drop(theirs);
        tokio::time::timeout(
            std::time::Duration::from_secs(2),
            peer_closed(watched.clone()),
        )
        .await
        .expect("a hangup is noticed");
        let mut buf = [0u8; 1];
        ours.readable().await.unwrap();
        assert_eq!(
            ours.try_read(&mut buf).unwrap(),
            1,
            "watching consumed the byte"
        );
    }

    /// The listener's session for a connection is numbered and watches its
    /// socket, whatever the agent is (a front included): the one-sign-at-a-time
    /// limit rests on it.
    #[tokio::test]
    async fn the_session_for_an_accepted_connection_is_numbered_and_watched() {
        let front = PiggyAgent::new(Vec::new()).with_proxy_only(true);
        let (a, _a_peer) = tokio::net::UnixStream::pair().unwrap();
        let (b, _b_peer) = tokio::net::UnixStream::pair().unwrap();
        let first = front.session_for_connection(&a);
        let second = front.session_for_connection(&b);
        assert_ne!(first.connection_id(), 0);
        assert_ne!(second.connection_id(), 0);
        assert_ne!(first.connection_id(), second.connection_id());
        assert!(first.is_watching_client());
    }

    #[test]
    fn descriptor_and_memory_exhaustion_are_transient() {
        for errno in [libc::EMFILE, libc::ENFILE, libc::ENOBUFS, libc::ENOMEM] {
            assert!(
                accept_error_is_transient(&io::Error::from_raw_os_error(errno)),
                "errno {errno}"
            );
        }
    }

    #[test]
    fn a_broken_listener_is_not_transient() {
        for errno in [libc::EBADF, libc::EINVAL, libc::ENOTSOCK] {
            assert!(
                !accept_error_is_transient(&io::Error::from_raw_os_error(errno)),
                "errno {errno}"
            );
        }
    }
}
