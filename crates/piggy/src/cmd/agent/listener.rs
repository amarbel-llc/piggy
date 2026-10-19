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
impl Agent<ResilientListener> for PiggyAgent {
    fn new_session(&mut self, _socket: &UnixStream) -> impl Session {
        self.clone()
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
