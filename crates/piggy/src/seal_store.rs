//! The password-store half of management-key escrow (piggy#258): resolves the
//! recipients the store declares for the escrow path, encrypts the key there,
//! and records it in the store's git history. The policy, ordering, and
//! recipient guard live in the lib's [`piggy::card::seal`]; this is the
//! substrate it is injected with.

use std::io::Cursor;

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
