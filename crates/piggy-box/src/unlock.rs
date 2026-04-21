use std::path::Path;

use crate::ebox::Ebox;
use crate::error::{BoxError, Result};
use crate::template::EboxConfigType;

/// Attempt to unlock an ebox by trying PRIMARY configs first:
///   1. SSH agent (`ecdh@joyent.com` extension) via SSH_AUTH_SOCK
///   2. Direct PCSC card access
///
/// Interactive recovery (challenge-response) is out of scope for v1.
pub fn unlock_ebox(ebox: &mut Ebox, agent_socket: Option<&Path>) -> Result<()> {
    let primary_indices: Vec<usize> = ebox
        .configs
        .iter()
        .enumerate()
        .filter(|(_, c)| c.config_type == EboxConfigType::Primary)
        .map(|(i, _)| i)
        .collect();

    for idx in primary_indices {
        if let Some(sock) = agent_socket {
            match try_agent_unlock(ebox, idx, sock) {
                Ok(()) => return Ok(()),
                Err(e) => {
                    tracing::debug!("agent unlock failed for config {idx}: {e}");
                }
            }
        }

        match try_card_unlock(ebox, idx) {
            Ok(()) => return Ok(()),
            Err(e) => {
                tracing::debug!("card unlock failed for config {idx}: {e}");
            }
        }
    }

    Err(BoxError::UnlockFailed)
}

fn try_agent_unlock(_ebox: &mut Ebox, _config_idx: usize, _agent_socket: &Path) -> Result<()> {
    // TODO: implement SSH agent ECDH extension
    Err(BoxError::UnlockFailed)
}

fn try_card_unlock(_ebox: &mut Ebox, _config_idx: usize) -> Result<()> {
    // TODO: implement direct PCSC card unlock
    Err(BoxError::UnlockFailed)
}
