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
/// `the_connection_is_closed_when_a_sign_times_out`): this looks for it,
/// without consuming a byte (MSG_PEEK), every [`CLIENT_WATCH_INTERVAL`].
pub async fn peer_closed(fd: std::sync::Arc<std::os::fd::OwnedFd>) {
    use std::os::fd::AsRawFd;
    loop {
        let mut byte = 0u8;
        // SAFETY: a one-byte peek into a local buffer, on a descriptor this
        // Arc keeps open for the whole call.
        let n = unsafe {
            libc::recv(
                fd.as_raw_fd(),
                std::ptr::addr_of_mut!(byte).cast(),
                1,
                libc::MSG_PEEK | libc::MSG_DONTWAIT,
            )
        };
        if n == 0 {
            return;
        }
        if n < 0 {
            let e = io::Error::last_os_error();
            if !matches!(
                e.kind(),
                io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
            ) {
                return;
            }
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
        // A pending request byte is not a hangup either, and is not consumed.
        theirs.writable().await.unwrap();
        assert_eq!(theirs.try_write(b"x").unwrap(), 1);
        let with_data = tokio::time::timeout(
            std::time::Duration::from_millis(600),
            peer_closed(watched.clone()),
        )
        .await;
        assert!(with_data.is_err(), "pipelined data was taken for a hangup");
        let mut buf = [0u8; 1];
        ours.readable().await.unwrap();
        assert_eq!(
            ours.try_read(&mut buf).unwrap(),
            1,
            "the peek consumed the byte"
        );
        // The client hangs up: noticed within a watch interval or two.
        drop(theirs);
        tokio::time::timeout(std::time::Duration::from_secs(2), peer_closed(watched))
            .await
            .expect("a hangup is noticed");
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
