//! The password-store half of management-key escrow (piggy#258): resolves the
//! recipients the store declares for the escrow path, encrypts the key there,
//! and records it in the store's git history. The policy, ordering, and
//! recipient guard live in the lib's [`piggy::card::seal`]; this is the
//! substrate it is injected with.

use std::io::Cursor;

use piggy::card::rotate::{Recorded, RotateStore};
use piggy::card::seal::{KeyEscrow, ManagementKeySealer};
use piggy_ids::RecipientFile;
use piggy_markl::Id;
use zeroize::Zeroizing;

use crate::store::{StoreEntry, sneaky_path_reason, store_root};

/// Seals into the password store at [`store_root`].
pub(crate) struct StoreSealer;

impl ManagementKeySealer for StoreSealer {
    fn prepare(&self, pass_name: &str) -> Result<Box<dyn KeyEscrow>, String> {
        if let Some(reason) = sneaky_path_reason(pass_name) {
            return Err(format!("invalid store path {pass_name:?} ({reason})"));
        }
        if pass_name.is_empty() {
            return Err(format!(
                "invalid store path {pass_name:?} (must be a non-empty path relative to the store)"
            ));
        }
        let entry = StoreEntry::resolve(store_root(), pass_name)?;
        if entry.ebox.exists() {
            return Err(format!(
                "{} already exists; refusing to overwrite it",
                entry.ebox.display()
            ));
        }
        let file = RecipientFile::read(&entry.piggy_ids).map_err(|e| e.to_string())?;
        let recipients = file
            .encryption_recipients()
            .map(|r| r.id().clone())
            .collect();
        Ok(Box::new(StoreEscrow {
            entry,
            pass_name: pass_name.to_string(),
            recipients,
        }))
    }

    fn recover(&self, pass_name: &str) -> Result<Zeroizing<String>, String> {
        let line = Zeroizing::new(crate::crypt::decrypt_first_line(pass_name)?);
        let text = std::str::from_utf8(&line)
            .map_err(|_| format!("{pass_name} does not hold a management key (not text)"))?;
        Ok(Zeroizing::new(text.trim().to_string()))
    }
}

/// The pass-name checked and resolved against the store, for the
/// rotation's questions and moves.
fn checked_entry(pass_name: &str) -> Result<StoreEntry, String> {
    if let Some(reason) = sneaky_path_reason(pass_name) {
        return Err(format!("invalid store path {pass_name:?} ({reason})"));
    }
    if pass_name.is_empty() {
        return Err(format!(
            "invalid store path {pass_name:?} (must be a non-empty path relative to the store)"
        ));
    }
    StoreEntry::resolve(store_root(), pass_name)
}

/// What `git` made of a change under the store: told to the rotation, which
/// tells the operator, instead of the best-effort silence `pass insert` has.
fn recorded(result: Option<Result<(), i32>>) -> Recorded {
    match result {
        None => Recorded::NoGitStore,
        Some(Ok(())) => Recorded::Committed,
        Some(Err(code)) => Recorded::CommitFailed(format!("git exited {code}")),
    }
}

impl RotateStore for StoreSealer {
    fn exists(&self, name: &str) -> Result<bool, String> {
        Ok(checked_entry(name)?.ebox.exists())
    }

    fn recipients_for(&self, name: &str) -> Result<Vec<Id>, String> {
        let entry = checked_entry(name)?;
        let file = RecipientFile::read(&entry.piggy_ids).map_err(|e| e.to_string())?;
        Ok(file
            .encryption_recipients()
            .map(|r| r.id().clone())
            .collect())
    }

    /// The entry decrypted on the local card with `pin`, which the caller
    /// obtained through its own typed channel; no askpass, no agent.
    fn recover_with_pin(&self, name: &str, pin: &str) -> Result<Zeroizing<String>, String> {
        let entry = checked_entry(name)?;
        let input = std::fs::read(&entry.ebox)
            .map_err(|e| format!("open {}: {e}", entry.ebox.display()))?;
        let plaintext = Zeroizing::new(
            piggy::cmd::pivy_box::Decryptor::local_card_with_pin(Zeroizing::new(pin.to_owned()))?
                .decrypt(&input)?,
        );
        let end = plaintext
            .iter()
            .position(|b| *b == b'\n')
            .unwrap_or(plaintext.len());
        let line = std::str::from_utf8(&plaintext[..end])
            .map_err(|_| format!("{name} does not hold a management key (not text)"))?;
        Ok(Zeroizing::new(line.trim().to_owned()))
    }

    fn record(&self, name: &str, message: &str) -> Recorded {
        let Ok(entry) = checked_entry(name) else {
            return Recorded::CommitFailed(format!("{name}: not a store path"));
        };
        recorded(
            crate::git_ops::find_inner_git_dir(&entry.ebox, &entry.root)
                .map(|work_tree| crate::git_ops::add_and_commit(&work_tree, &entry.ebox, message)),
        )
    }

    /// One `rename(2)` within the entry's directory, so the entry is either
    /// the old key or the new one and never absent, then one commit that
    /// records the entry and the pending path's removal.
    fn promote(&self, pending: &str, entry: &str) -> Result<Recorded, String> {
        let from = checked_entry(pending)?;
        let to = checked_entry(entry)?;
        to.create_parent()?;
        std::fs::rename(&from.ebox, &to.ebox).map_err(|e| {
            format!(
                "rename {} over {}: {e}",
                from.ebox.display(),
                to.ebox.display()
            )
        })?;
        Ok(recorded(
            crate::git_ops::find_inner_git_dir(&to.ebox, &to.root).map(|work_tree| {
                crate::git_ops::add_and_commit_with(
                    &work_tree,
                    &to.ebox,
                    &[from.ebox.as_path()],
                    &format!("Promote {pending} over {entry}."),
                )
            }),
        ))
    }

    fn remove(&self, name: &str) -> Result<Recorded, String> {
        let entry = checked_entry(name)?;
        std::fs::remove_file(&entry.ebox)
            .map_err(|e| format!("remove {}: {e}", entry.ebox.display()))?;
        Ok(recorded(
            crate::git_ops::find_inner_git_dir(&entry.ebox, &entry.root).map(|work_tree| {
                crate::git_ops::commit(
                    &work_tree,
                    &format!("Remove {name}."),
                    &[entry.ebox.as_path()],
                )
            }),
        ))
    }
}

struct StoreEscrow {
    entry: StoreEntry,
    pass_name: String,
    recipients: Vec<Id>,
}

impl KeyEscrow for StoreEscrow {
    fn pass_name(&self) -> &str {
        &self.pass_name
    }

    fn recipients(&self) -> &[Id] {
        &self.recipients
    }

    fn seal(&mut self, key_hex: &str) -> Result<(), String> {
        self.entry.create_parent()?;
        // A trailing newline, like `pass insert`, so `pass show` prints it cleanly.
        let plaintext = Zeroizing::new(format!("{key_hex}\n"));
        crate::crypt::encrypt(
            &self.entry.piggy_ids,
            &self.entry.ebox,
            Cursor::new(plaintext.as_bytes()),
        )
    }

    fn rollback(&mut self) {
        let _ = std::fs::remove_file(&self.entry.ebox);
    }

    fn commit(&mut self) {
        self.entry
            .commit(&format!("Seal management key to {}.", self.pass_name));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn absolute_pass_name_is_refused() {
        let err = StoreSealer
            .prepare("/elsewhere/management-key")
            .err()
            .expect("refused");
        assert!(err.contains("absolute path"), "{err}");
    }

    #[test]
    fn parent_dir_pass_name_is_refused() {
        let err = StoreSealer
            .prepare("../elsewhere/management-key")
            .err()
            .expect("refused");
        assert!(err.contains("`..`"), "{err}");
    }
}
