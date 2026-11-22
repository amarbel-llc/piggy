//! hogtie: one door to root for agent sessions (hogtie(8)).
//!
//! Stage 1: a root-owned socket hands out single-use nonces; `sudo hogtie
//! exec RESPONSE ACTION [ARGS]` runs one declared action when RESPONSE is a
//! signature over that nonce, the caller's account, the action and its
//! arguments, made by a key that an operator-signed OpenSSH user
//! certificate (the grant) names the action for.

pub mod config;
pub mod grant;
pub mod message;
pub mod nonce;
pub mod response;
pub mod serve;
pub mod sshwire;
#[cfg(any(test, feature = "test-harness"))]
pub mod testkit;
pub mod util;
pub mod verify;
