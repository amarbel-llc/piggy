//! The password-store half of management-key escrow (piggy#258): resolves the
//! recipients the store declares for the escrow path, encrypts the key there,
//! and records it in the store's git history. The policy, ordering, and
//! recipient guard live in the lib's [`piggy::card::seal`]; this is the
//! substrate it is injected with.

use std::io::Cursor;
use std::path::PathBuf;

use piggy::card::seal::{KeyEscrow, ManagementKeySealer};
use piggy_ids::RecipientFile;
use piggy_markl::Id;
use zeroize::Zeroizing;

use crate::store::{find_piggy_ids, path_parent_for_search, sneaky_path_reason, store_root};

/// Seals into the password store at [`store_root`].
pub(crate) struct StoreSealer;

impl ManagementKeySealer for StoreSealer {
    fn prepare(&self, pass_name: &str) -> Result<Box<dyn KeyEscrow>, String> {
        if let Some(reason) = sneaky_path_reason(pass_name) {
            return Err(format!("invalid store path {pass_name:?} ({reason})"));
        }
        if pass_name.is_empty() || std::path::Path::new(pass_name).is_absolute() {
            return Err(format!(
                "invalid store path {pass_name:?} (must be a non-empty path relative to the store)"
            ));
        }
        let root = store_root();
        let ebox = root.join(format!("{pass_name}.ebox"));
        if ebox.exists() {
            return Err(format!(
                "{} already exists; refusing to overwrite it",
                ebox.display()
            ));
        }
        let piggy_ids = find_piggy_ids(&root, &path_parent_for_search(pass_name))
            .and_then(|p| crate::pigpen_pointer::resolve_piggy_ids_path(&p))?;
        let text = std::fs::read_to_string(&piggy_ids)
            .map_err(|e| format!("reading {}: {e}", piggy_ids.display()))?;
        let file = RecipientFile::parse(&text)
            .map_err(|e| format!("parsing {}: {e}", piggy_ids.display()))?;
        let recipients = file
            .encryption_recipients()
            .map(|r| r.id().clone())
            .collect();
        Ok(Box::new(StoreEscrow {
            root,
            pass_name: pass_name.to_string(),
            ebox,
            piggy_ids,
            recipients,
        }))
    }
}

struct StoreEscrow {
    root: PathBuf,
    pass_name: String,
    ebox: PathBuf,
    piggy_ids: PathBuf,
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
        if let Some(parent) = self.ebox.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|e| format!("create {}: {e}", parent.display()))?;
        }
        // A trailing newline, like `pass insert`, so `pass show` prints it cleanly.
        let plaintext = Zeroizing::new(format!("{key_hex}\n"));
        crate::crypt::encrypt(
            &self.piggy_ids,
            &self.ebox,
            Cursor::new(plaintext.as_bytes()),
        )
    }

    fn rollback(&mut self) {
        let _ = std::fs::remove_file(&self.ebox);
    }

    fn commit(&mut self) {
        if let Some(work_tree) = crate::git_ops::find_inner_git_dir(&self.ebox, &self.root) {
            let _ = crate::git_ops::add_and_commit(
                &work_tree,
                &self.ebox,
                &format!("Seal management key to {}.", self.pass_name),
            );
        }
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
        assert!(err.contains("relative to the store"), "{err}");
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
