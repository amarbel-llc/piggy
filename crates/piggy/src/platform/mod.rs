//! Platform-layer Rust port of piggy.sh's `clip` / `qrcode` / `tmpdir`
//! helpers, plus the `SHRED`/`BASE64`/`GETOPT` defaults.
//!
//! Step 9 of issue #96 — these modules compile as dead-but-tested code
//! until step 10 (which ports `show`/`insert`/`edit`/`generate` off
//! `src/piggy.sh`) calls into them. Until then the bash helpers in
//! `src/piggy.sh` and `src/platform/darwin.sh` remain authoritative.
//!
//! Linux is exercised by unit tests in this worktree; macOS code paths
//! are `#[cfg(target_os = "macos")]`-gated so they compile but are not
//! Linux-testable. See module-level doc comments for the per-helper
//! bash-to-Rust mapping.
//!
//! `#![allow(dead_code)]` applied module-wide: every public item here
//! has no caller yet — by design, since step 10 (the user-facing
//! wiring) is a separate PR. The unit tests in each submodule exercise
//! the surface so it stays correct in the meantime; clippy with
//! `-D warnings` would otherwise treat the dead code as an error.

#![allow(dead_code)]

pub(crate) mod clipboard;
pub(crate) mod qrcode;
pub(crate) mod shred;
pub(crate) mod tmpdir;
