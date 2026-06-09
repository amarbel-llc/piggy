//! The age-plugin v1 state machines: recipient (encrypt) and identity
//! (decrypt). Mirrors the shape of age-plugin-yubikey's `plugin.rs`, minus
//! the card handling — our decrypt delegates the ECDH to piggy-agent.

use std::collections::{HashMap, HashSet};
use std::io;

use age_core::format::{FileKey, Stanza};
use age_plugin::{
    Callbacks, PluginHandler,
    identity::{self, IdentityPluginV1},
    recipient::{self, RecipientPluginV1},
};

use crate::identity::{Identity, agent_oracle};
use crate::p256_stanza::{self, RecipientLine};
use crate::recipient::Recipient;

pub(crate) struct Handler;

impl PluginHandler for Handler {
    type RecipientV1 = RecipientPlugin;
    type IdentityV1 = IdentityPlugin;

    fn recipient_v1(self) -> io::Result<Self::RecipientV1> {
        Ok(RecipientPlugin::default())
    }

    fn identity_v1(self) -> io::Result<Self::IdentityV1> {
        Ok(IdentityPlugin::default())
    }
}

#[derive(Default)]
pub(crate) struct RecipientPlugin {
    recipients: Vec<Recipient>,
}

impl RecipientPluginV1 for RecipientPlugin {
    fn add_recipient(
        &mut self,
        index: usize,
        plugin_name: &str,
        bytes: &[u8],
    ) -> Result<(), recipient::Error> {
        match Recipient::from_bytes(plugin_name, bytes) {
            Some(recipient) => {
                self.recipients.push(recipient);
                Ok(())
            }
            None => Err(recipient::Error::Recipient {
                index,
                message: "invalid age1piggy recipient".to_owned(),
            }),
        }
    }

    fn add_identity(
        &mut self,
        index: usize,
        plugin_name: &str,
        bytes: &[u8],
    ) -> Result<(), recipient::Error> {
        // An identity is just a public key — which is exactly a recipient.
        // This makes `age -e -i piggy-identity.txt` work.
        match Identity::from_bytes(plugin_name, bytes) {
            Some(identity) => {
                self.recipients
                    .push(Recipient::from_compressed(*identity.compressed()));
                Ok(())
            }
            None => Err(recipient::Error::Identity {
                index,
                message: "invalid AGE-PLUGIN-PIGGY identity".to_owned(),
            }),
        }
    }

    fn labels(&mut self) -> HashSet<String> {
        HashSet::new()
    }

    fn wrap_file_keys(
        &mut self,
        file_keys: Vec<FileKey>,
        mut _callbacks: impl Callbacks<recipient::Error>,
    ) -> io::Result<Result<Vec<Vec<Stanza>>, Vec<recipient::Error>>> {
        let stanzas = file_keys
            .into_iter()
            .map(|file_key| {
                self.recipients
                    .iter()
                    .map(|r| r.wrap_file_key(&file_key))
                    .collect()
            })
            .collect();
        Ok(Ok(stanzas))
    }
}

#[derive(Default)]
pub(crate) struct IdentityPlugin {
    identities: Vec<Identity>,
}

impl IdentityPluginV1 for IdentityPlugin {
    fn add_identity(
        &mut self,
        index: usize,
        plugin_name: &str,
        bytes: &[u8],
    ) -> Result<(), identity::Error> {
        match Identity::from_bytes(plugin_name, bytes) {
            Some(identity) => {
                self.identities.push(identity);
                Ok(())
            }
            None => Err(identity::Error::Identity {
                index,
                message: "invalid AGE-PLUGIN-PIGGY identity".to_owned(),
            }),
        }
    }

    fn unwrap_file_keys(
        &mut self,
        files: Vec<Vec<Stanza>>,
        mut callbacks: impl Callbacks<identity::Error>,
    ) -> io::Result<HashMap<usize, Result<FileKey, Vec<identity::Error>>>> {
        let mut file_keys: HashMap<usize, Result<FileKey, Vec<identity::Error>>> = HashMap::new();
        if self.identities.is_empty() {
            return Ok(file_keys);
        }

        // One agent connection for the whole run. If it can't be built,
        // nothing is decryptable — surface it once and bail.
        let mut oracle = match agent_oracle() {
            Ok(oracle) => oracle,
            Err(message) => {
                callbacks
                    .error(identity::Error::Internal { message })?
                    .unwrap();
                return Ok(file_keys);
            }
        };

        for (file_index, stanzas) in files.into_iter().enumerate() {
            for (stanza_index, stanza) in stanzas.iter().enumerate() {
                // This file is already unwrapped.
                if matches!(file_keys.get(&file_index), Some(Ok(_))) {
                    break;
                }
                let line = match RecipientLine::from_stanza(stanza) {
                    None => continue, // not our stanza type
                    Some(Err(())) => {
                        callbacks
                            .error(identity::Error::Stanza {
                                file_index,
                                stanza_index,
                                message: "invalid piv-p256 stanza".to_owned(),
                            })?
                            .unwrap();
                        continue;
                    }
                    Some(Ok(line)) => line,
                };

                // A stanza matches at most one of our identities (by tag).
                let Some(identity) = self.identities.iter().find(|id| id.tag() == line.tag) else {
                    continue;
                };

                match p256_stanza::unwrap_file_key(&line, identity.compressed(), &mut oracle) {
                    Ok(file_key) => {
                        file_keys.insert(file_index, Ok(file_key));
                    }
                    Err(e) => {
                        callbacks
                            .error(identity::Error::Stanza {
                                file_index,
                                stanza_index,
                                message: e.to_string(),
                            })?
                            .unwrap();
                    }
                }
            }
        }

        Ok(file_keys)
    }
}
