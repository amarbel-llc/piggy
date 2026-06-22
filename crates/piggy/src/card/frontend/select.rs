//! Frontend selection shared by every interactive command (RFC 0006 §6).
//!
//! `--frontend tty|jsonrpc [--socket PATH]` maps to a `Box<dyn Frontend>` here,
//! so `card init`, `sign-bytes`, and the rest of the #200 retrofit reach the
//! same binding logic instead of each rebuilding it. `operation` is the command
//! label threaded into the tty prompts / askpass context and the JSON-RPC
//! `initialize` handshake.

use std::io::BufReader;
use std::os::unix::net::UnixStream;
use std::path::Path;

use crate::card::frontend::jsonrpc::JsonRpcFrontend;
use crate::card::frontend::tty::TtyFrontend;
use crate::card::protocol::Frontend;

/// Which interaction binding to use (RFC 0006 §6). `tty` is the interim default;
/// see piggy#197 for the eventual GUI-auto-launch default.
#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum FrontendKind {
    /// In-process terminal / askpass (default).
    Tty,
    /// JSON-RPC over an `AF_UNIX` socket (`--socket`); an external program
    /// (e.g. a charmbracelet TUI) drives the interactions.
    Jsonrpc,
}

/// Build the interaction frontend. For JSON-RPC the socket is connected here —
/// before any card operation — so `--frontend jsonrpc` without a usable channel
/// fails fast (RFC 0006 §6). `operation` names the command (e.g. `"card init"`,
/// `"sign-bytes"`) in prompts and the handshake.
pub fn build_frontend(
    kind: FrontendKind,
    socket: Option<&Path>,
    operation: &str,
) -> Result<Box<dyn Frontend>, String> {
    match kind {
        FrontendKind::Tty => Ok(Box::new(TtyFrontend::new(operation))),
        FrontendKind::Jsonrpc => {
            let path = socket.ok_or("--frontend jsonrpc requires --socket <PATH>")?;
            let stream = UnixStream::connect(path)
                .map_err(|e| format!("connect frontend socket {}: {e}", path.display()))?;
            let reader = BufReader::new(
                stream
                    .try_clone()
                    .map_err(|e| format!("clone socket handle: {e}"))?,
            );
            Ok(Box::new(JsonRpcFrontend::new(
                reader,
                stream,
                operation.to_string(),
            )))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn jsonrpc_without_socket_fails_fast() {
        // RFC 0006 §6: no usable channel → error before any card op. Card-free.
        let err = build_frontend(FrontendKind::Jsonrpc, None, "sign-bytes")
            .map(|_| ())
            .unwrap_err();
        assert!(err.contains("--socket"), "got {err}");
    }
}
