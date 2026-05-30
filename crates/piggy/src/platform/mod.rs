//! Platform-layer Rust port of the legacy `clip` / `qrcode` / `tmpdir`
//! helpers from `src/piggy.sh` (now retired) plus the `SHRED` default.
//!
//! Submodules:
//! - [`clipboard`] — `wl-copy` / `xclip` / `pbcopy` tool selection and
//!   the deferred-restore plan consumed by the
//!   `internal-clipboard-restore` worker (`show -c`, `generate -c`).
//! - [`qrcode`] — `qrencode` + viewer plan (`show -q`, `generate -q`).
//! - [`shred`] — `shred -f -z` / macOS `srm -f -z` defaults consumed by
//!   `SecureTmpdir`'s disk-fallback Drop path.
//! - [`tmpdir`] — RAII `SecureTmpdir` guard used by `edit` to hold
//!   the editor's plaintext working copy.
//!
//! Linux is exercised by unit tests in this worktree; macOS code paths
//! are `#[cfg(target_os = "macos")]`-gated so they compile but are not
//! Linux-testable.

pub(crate) mod clipboard;
pub(crate) mod qrcode;
pub(crate) mod shred;
pub(crate) mod tmpdir;
