//! Card management: the interaction protocol (RFC 0006) and the provisioning
//! engine (piggy#194).
//!
//! [`protocol`] defines the transport-agnostic [`protocol::Frontend`] trait and
//! its serde payload types — the single contract both bindings speak.
//! [`frontend`] holds the bindings: the default in-process tty frontend and the
//! JSON-RPC frontend an external TUI drives over a socket. [`engine`]
//! orchestrates `piggy card init`'s full setup against a `&mut dyn Frontend`,
//! staying agnostic to which binding is in use. [`seal`] escrows a generated
//! management key into the password store (piggy#258).

pub mod add_key_cmd;
pub mod attestation_cmd;
pub mod engine;
pub mod frontend;
pub mod init_cmd;
pub mod protocol;
pub mod seal;
pub mod slot_policy;

/// How a card command was asked for: on the command line, or as a `piggy
/// manage` JSON-RPC method (RFC 0007). A usage error names the option the
/// way the caller spelled it. This is the request's binding, not the
/// interaction frontend's: `card add-key --frontend jsonrpc` was still
/// asked for with CLI flags.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RequestBinding {
    Cli,
    JsonRpc,
}

impl RequestBinding {
    /// The option whose JSON-RPC param is `param` (`pin_policy`):
    /// `--pin-policy` on the command line, `'pin_policy'` over JSON-RPC.
    pub fn option(self, param: &str) -> String {
        match self {
            Self::Cli => format!("--{}", param.replace('_', "-")),
            Self::JsonRpc => format!("'{param}'"),
        }
    }

    /// The boolean option `param` turned on: `--replace`, or
    /// `'replace': true`.
    pub fn switch_on(self, param: &str) -> String {
        match self {
            Self::Cli => self.option(param),
            Self::JsonRpc => format!("{}: true", self.option(param)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::RequestBinding;

    #[test]
    fn each_binding_spells_an_option_its_own_way() {
        assert_eq!(RequestBinding::Cli.option("pin_policy"), "--pin-policy");
        assert_eq!(RequestBinding::JsonRpc.option("pin_policy"), "'pin_policy'");
        assert_eq!(RequestBinding::Cli.switch_on("replace"), "--replace");
        assert_eq!(
            RequestBinding::JsonRpc.switch_on("replace"),
            "'replace': true"
        );
    }
}
