//! hogtie's one configuration file, `/etc/hogtie/hogtie.toml`, root-owned
//! and later written by the host's NixOS configuration: the verifier's
//! settings and the registry of actions. Every key is checked; an unknown
//! key, a relative path or a parameter the argv does not use refuses the
//! whole file (fail closed: no action runs from a file hogtie doubts).
//!
//! ```toml
//! host = "flic"
//! ssh_keygen ="/nix/store/...-openssh/bin/ssh-keygen"
//! ca_keys = ["ecdsa-sha2-nistp256 AAAA..."]
//! max_grant_seconds = 2592000
//!
//! [action.restic-snapshots]
//! program = "/nix/store/...-restic/bin/restic"
//! argv = ["snapshots", "--json", "--repo", "{repo}"]
//! env = { RESTIC_PASSWORD_FILE = "/run/secrets/restic" }
//! param = [{ name = "repo", kind = "choice", values = ["/srv/backup/a"] }]
//! ```
//!
//! `host` is this host's name, as grants name it (`<host>:<action>`).
//! Parameters are positional and all required. Kinds: `choice` (one of
//! `values`) and `pattern` (characters from `chars`, a class such as
//! `a-z0-9._-` with no `/`, at most `max_len`, never starting with `-`,
//! never only dots). There is no `path` kind in stage 1: declare paths as a
//! `choice`. A `{name}` in argv must be a whole element.

use crate::message::{is_action_name, is_host_name};
use crate::verify::CaKey;
use serde::Deserialize;
use std::collections::BTreeMap;
use std::fmt;
use std::path::PathBuf;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawConfig {
    host: String,
    ssh_keygen: String,
    ca_keys: Vec<String>,
    max_grant_seconds: u64,
    #[serde(default)]
    action: BTreeMap<String, RawAction>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawAction {
    program: String,
    #[serde(default)]
    argv: Vec<String>,
    #[serde(default)]
    env: BTreeMap<String, String>,
    #[serde(default)]
    param: Vec<RawParam>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawParam {
    name: String,
    kind: String,
    values: Option<Vec<String>>,
    chars: Option<String>,
    max_len: Option<usize>,
    under: Option<String>,
}

pub struct Config {
    /// This host's name, as grants name it (`<host>:<action>`).
    pub host: String,
    pub ssh_keygen: PathBuf,
    pub cas: Vec<CaKey>,
    pub max_grant_seconds: u64,
    pub actions: BTreeMap<String, Action>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Action {
    pub program: PathBuf,
    pub argv: Vec<ArgvItem>,
    pub env: Vec<(String, String)>,
    pub params: Vec<Param>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ArgvItem {
    Literal(String),
    Param(usize),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Param {
    pub name: String,
    pub kind: ParamKind,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParamKind {
    Choice(Vec<String>),
    Pattern { chars: CharClass, max_len: usize },
}

/// A set of printable ASCII characters, parsed from `a-z0-9._-` style text.
/// A range `x-y` is only lowercase to lowercase, uppercase to uppercase or
/// digit to digit; any other `x-y` (such as `+-.`, which is the range `+`
/// to `.`) is refused as ambiguous: a literal `-` goes first or last. `/` is
/// refused outright: a value is never a path (finding 5).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CharClass([bool; 128]);

fn same_kind(lo: u8, hi: u8) -> bool {
    (lo.is_ascii_lowercase() && hi.is_ascii_lowercase())
        || (lo.is_ascii_uppercase() && hi.is_ascii_uppercase())
        || (lo.is_ascii_digit() && hi.is_ascii_digit())
}

impl CharClass {
    pub fn parse(spec: &str) -> Result<Self, String> {
        let b = spec.as_bytes();
        if b.is_empty() {
            return Err("an empty character class".into());
        }
        if let Some(c) = b.iter().find(|c| !(0x21..=0x7e).contains(*c)) {
            return Err(format!(
                "character class holds byte {c:#04x}: printable ASCII only, no space"
            ));
        }
        if b.contains(&b'/') {
            return Err("a character class may not hold '/': a value is never a path".into());
        }
        let mut set = [false; 128];
        let mut i = 0;
        while i < b.len() {
            if i + 2 < b.len() && b[i + 1] == b'-' {
                let (lo, hi) = (b[i], b[i + 2]);
                if !same_kind(lo, hi) {
                    return Err(format!(
                        "{}-{} is an ambiguous range: ranges are a-z, A-Z or 0-9 pieces; \
                         put a literal '-' first or last",
                        lo as char, hi as char
                    ));
                }
                if lo > hi {
                    return Err(format!(
                        "range {}-{} runs backwards",
                        lo as char, hi as char
                    ));
                }
                for c in lo..=hi {
                    set[c as usize] = true;
                }
                i += 3;
            } else {
                set[b[i] as usize] = true;
                i += 1;
            }
        }
        Ok(Self(set))
    }

    pub fn contains(&self, c: char) -> bool {
        (c as u32) < 128 && self.0[c as usize]
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfigError(pub String);

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "configuration: {}", self.0)
    }
}

fn err<T>(msg: impl Into<String>) -> Result<T, ConfigError> {
    Err(ConfigError(msg.into()))
}

/// An absolute path with no empty, `.` or `..` component and no trailing
/// slash, checked on the text (std's `components` would quietly normalize).
pub fn is_plain_absolute(p: &str) -> bool {
    match p.strip_prefix('/') {
        Some(rest) => {
            !rest.is_empty()
                && rest
                    .split('/')
                    .all(|c| !c.is_empty() && c != "." && c != "..")
        }
        None => false,
    }
}

fn is_env_name(n: &str) -> bool {
    let b = n.as_bytes();
    !b.is_empty()
        && (b[0].is_ascii_uppercase() || b[0] == b'_')
        && b.iter()
            .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || *c == b'_')
}

fn is_param_name(n: &str) -> bool {
    let b = n.as_bytes();
    !b.is_empty()
        && b[0].is_ascii_lowercase()
        && b.iter()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || *c == b'_')
}

impl Config {
    pub fn parse(text: &str) -> Result<Self, ConfigError> {
        let raw: RawConfig = toml::from_str(text).map_err(|e| ConfigError(e.to_string()))?;
        if !is_host_name(&raw.host) {
            return err(format!(
                "host name {:?} is not [a-z0-9][a-z0-9-]{{0,62}}",
                raw.host
            ));
        }
        if !is_plain_absolute(&raw.ssh_keygen) {
            return err(format!(
                "ssh_keygen {:?} is not a plain absolute path",
                raw.ssh_keygen
            ));
        }
        if raw.ca_keys.is_empty() {
            return err("ca_keys is empty");
        }
        let cas = raw
            .ca_keys
            .iter()
            .map(|k| CaKey::parse(k).map_err(ConfigError))
            .collect::<Result<Vec<_>, _>>()?;
        if raw.max_grant_seconds == 0 {
            return err("max_grant_seconds is 0");
        }
        let mut actions = BTreeMap::new();
        for (name, a) in raw.action {
            if !is_action_name(&name) {
                return err(format!(
                    "action name {name:?} is not [a-z0-9][a-z0-9-]{{0,62}}"
                ));
            }
            let action = Action::from_raw(a)
                .map_err(|ConfigError(e)| ConfigError(format!("action {name}: {e}")))?;
            actions.insert(name, action);
        }
        Ok(Self {
            host: raw.host,
            ssh_keygen: PathBuf::from(raw.ssh_keygen),
            cas,
            max_grant_seconds: raw.max_grant_seconds,
            actions,
        })
    }
}

impl Param {
    fn from_raw(p: RawParam) -> Result<Self, ConfigError> {
        if !is_param_name(&p.name) {
            return err(format!(
                "parameter name {:?} is not [a-z][a-z0-9_]*",
                p.name
            ));
        }
        let unused = |what: &str, present: bool| -> Result<(), ConfigError> {
            if present {
                err(format!(
                    "parameter {}: {what} does not belong to kind {:?}",
                    p.name, p.kind
                ))
            } else {
                Ok(())
            }
        };
        let kind = match p.kind.as_str() {
            "choice" => {
                unused("chars", p.chars.is_some())?;
                unused("max_len", p.max_len.is_some())?;
                unused("under", p.under.is_some())?;
                let values = p.values.clone().unwrap_or_default();
                if values.is_empty() {
                    return err(format!("parameter {}: a choice needs values", p.name));
                }
                if values.iter().any(|v| v.is_empty() || v.contains('\0')) {
                    return err(format!(
                        "parameter {}: an empty value or one with a NUL",
                        p.name
                    ));
                }
                ParamKind::Choice(values)
            }
            "pattern" => {
                unused("values", p.values.is_some())?;
                unused("under", p.under.is_some())?;
                let chars = CharClass::parse(p.chars.as_deref().unwrap_or(""))
                    .map_err(|e| ConfigError(format!("parameter {}: {e}", p.name)))?;
                let max_len = p.max_len.unwrap_or(0);
                if max_len == 0 || max_len > crate::message::MAX_ARG_LEN {
                    return err(format!(
                        "parameter {}: max_len must be 1..={}",
                        p.name,
                        crate::message::MAX_ARG_LEN
                    ));
                }
                ParamKind::Pattern { chars, max_len }
            }
            "path" => {
                // A path checked and then used by name can be swapped under
                // the check by anyone who can write a directory on its way.
                return err(format!(
                    "parameter {}: the `path` kind is not in stage 1 (a path checked then used \
                     can be swapped under it); declare the paths as a `choice`",
                    p.name
                ));
            }
            other => return err(format!("parameter {}: unknown kind {other:?}", p.name)),
        };
        Ok(Self { name: p.name, kind })
    }
}

impl Action {
    fn from_raw(a: RawAction) -> Result<Self, ConfigError> {
        if !is_plain_absolute(&a.program) {
            return err(format!(
                "program {:?} is not a plain absolute path",
                a.program
            ));
        }
        let params = a
            .param
            .into_iter()
            .map(Param::from_raw)
            .collect::<Result<Vec<_>, _>>()?;
        for (i, p) in params.iter().enumerate() {
            if params[..i].iter().any(|q| q.name == p.name) {
                return err(format!("parameter {} is declared twice", p.name));
            }
        }
        let mut used = vec![0usize; params.len()];
        let mut argv = Vec::new();
        for item in a.argv {
            if item.contains('\0') {
                return err("an argv element holds a NUL");
            }
            let placeholder = item.strip_prefix('{').and_then(|s| s.strip_suffix('}'));
            match placeholder {
                Some(name) => {
                    let i = params.iter().position(|p| p.name == name).ok_or_else(|| {
                        ConfigError(format!("argv names undeclared parameter {name:?}"))
                    })?;
                    used[i] += 1;
                    argv.push(ArgvItem::Param(i));
                }
                None if item.contains(['{', '}']) => {
                    return err(format!(
                        "argv element {item:?}: a {{name}} must be a whole element"
                    ));
                }
                None => argv.push(ArgvItem::Literal(item)),
            }
        }
        if let Some(i) = used.iter().position(|n| *n != 1) {
            return err(format!(
                "parameter {} is used {} times in argv, not once",
                params[i].name, used[i]
            ));
        }
        let mut env = Vec::new();
        for (k, v) in a.env {
            if !is_env_name(&k) || v.contains('\0') {
                return err(format!(
                    "env {k:?}: names are [A-Z_][A-Z0-9_]*, values hold no NUL"
                ));
            }
            env.push((k, v));
        }
        Ok(Self {
            program: PathBuf::from(a.program),
            argv,
            env,
            params,
        })
    }

    /// The argv to run (program first), the caller's `args` checked
    /// against the declared parameters.
    pub fn build(&self, args: &[String]) -> Result<Vec<String>, String> {
        if args.len() != self.params.len() {
            return Err(format!(
                "{} arguments given, the action takes {}",
                args.len(),
                self.params.len()
            ));
        }
        let values = self
            .params
            .iter()
            .zip(args)
            .map(|(p, v)| check_value(p, v).map_err(|e| format!("argument {}: {e}", p.name)))
            .collect::<Result<Vec<_>, _>>()?;
        let mut out = vec![self.program.to_string_lossy().into_owned()];
        for item in &self.argv {
            out.push(match item {
                ArgvItem::Literal(s) => s.clone(),
                ArgvItem::Param(i) => values[*i].clone(),
            });
        }
        Ok(out)
    }
}

fn check_value(p: &Param, v: &str) -> Result<String, String> {
    match &p.kind {
        ParamKind::Choice(values) => {
            if values.iter().any(|c| c == v) {
                Ok(v.to_string())
            } else {
                Err(format!("{v:?} is not one of the declared choices"))
            }
        }
        ParamKind::Pattern { chars, max_len } => {
            if v.is_empty() || v.len() > *max_len {
                return Err(format!("length {} is outside 1..={max_len}", v.len()));
            }
            if v.starts_with('-') {
                return Err("a value may not start with '-'".into());
            }
            if v.bytes().all(|c| c == b'.') {
                return Err("a value may not be only dots ('.' and '..' name directories)".into());
            }
            match v.chars().find(|c| !chars.contains(*c)) {
                Some(c) => Err(format!("character {c:?} is outside the declared class")),
                None => Ok(v.to_string()),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const CA: &str =
        "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIIBUQsc6D9Eg6hS69yeYbBYlO6zT3ibUsrNMB9YMF+vS";

    fn conf(actions: &str) -> String {
        format!(
            "host = \"h1\"\nssh_keygen = \"/usr/bin/ssh-keygen\"\nca_keys = [\"{CA}\"]\nmax_grant_seconds = 86400\n{actions}"
        )
    }

    fn parse(actions: &str) -> Result<Config, ConfigError> {
        Config::parse(&conf(actions))
    }

    fn refused(actions: &str, needle: &str) {
        match parse(actions) {
            Err(ConfigError(e)) => assert!(e.contains(needle), "{e:?} lacks {needle:?}"),
            Ok(_) => panic!("accepted: {actions}"),
        }
    }

    const RESTIC: &str = r#"
[action.restic-snapshots]
program = "/bin/restic"
argv = ["snapshots", "--repo", "{repo}", "--tag", "{tag}"]
env = { RESTIC_PASSWORD_FILE = "/run/secrets/restic" }
param = [
  { name = "repo", kind = "choice", values = ["/srv/a", "/srv/b"] },
  { name = "tag", kind = "pattern", chars = "a-z0-9._-", max_len = 16 },
]
"#;

    #[test]
    fn a_registry_is_read() {
        let c = parse(RESTIC).unwrap();
        let a = &c.actions["restic-snapshots"];
        assert_eq!(a.program, PathBuf::from("/bin/restic"));
        assert_eq!(
            a.env,
            [("RESTIC_PASSWORD_FILE".into(), "/run/secrets/restic".into())]
        );
        assert_eq!(
            a.build(&["/srv/b".into(), "daily-1".into()]).unwrap(),
            [
                "/bin/restic",
                "snapshots",
                "--repo",
                "/srv/b",
                "--tag",
                "daily-1"
            ]
        );
    }

    #[test]
    fn arguments_are_checked_against_their_kinds() {
        let c = parse(RESTIC).unwrap();
        let a = &c.actions["restic-snapshots"];
        for (args, needle) in [
            (vec!["/srv/c", "x"], "not one of the declared choices"),
            (vec!["/srv/a", "-rf"], "may not start with '-'"),
            (vec!["/srv/a", "."], "only dots"),
            (vec!["/srv/a", ".."], "only dots"),
            (vec!["/srv/a", "a b"], "outside the declared class"),
            (vec!["/srv/a", "A"], "outside the declared class"),
            (vec!["/srv/a", ""], "length 0"),
            (vec!["/srv/a", &"x".repeat(17)], "length 17"),
            (vec!["/srv/a"], "1 arguments given, the action takes 2"),
            (vec!["/srv/a", "x", "extra"], "3 arguments given"),
        ] {
            let args: Vec<String> = args.into_iter().map(String::from).collect();
            let e = a.build(&args).unwrap_err();
            assert!(e.contains(needle), "{args:?}: {e}");
        }
    }

    #[test]
    fn the_path_kind_is_not_in_stage_1() {
        // A path checked and then used by name can be swapped under the
        // check (review finding 1): the kind is refused at load.
        refused(
            "[action.ls]\nprogram = \"/bin/ls\"\nargv = [\"{p}\"]\nparam = [{ name = \"p\", kind = \"path\", under = \"/srv\" }]\n",
            "not in stage 1",
        );
    }

    #[test]
    fn a_class_with_a_slash_or_an_ambiguous_range_is_refused() {
        for (chars, needle) in [
            ("a-z/", "'/'"),
            ("a-z0-9._/-", "'/'"),
            ("+-.", "ambiguous"),
            ("%-_", "ambiguous"),
            ("a-Z", "ambiguous"),
            ("0-z", "ambiguous"),
        ] {
            refused(
                &format!(
                    "[action.x]\nprogram = \"/bin/x\"\nargv = [\"{{r}}\"]\nparam = [{{ name = \"r\", kind = \"pattern\", chars = \"{chars}\", max_len = 3 }}]\n"
                ),
                needle,
            );
        }
        for ok in ["a-z0-9._-", "A-Z", "0-9", "a-c", "-a", "a-", "._-"] {
            assert!(CharClass::parse(ok).is_ok(), "{ok}");
        }
    }

    #[test]
    fn free_form_and_malformed_registries_are_refused() {
        refused("[action.x]\nprogram = \"bin/x\"\n", "plain absolute path");
        refused(
            "[action.x]\nprogram = \"/bin/../x\"\n",
            "plain absolute path",
        );
        refused("[action.X]\nprogram = \"/bin/x\"\n", "action name");
        refused(
            "[action.x]\nprogram = \"/bin/x\"\nargs = []\n",
            "unknown field",
        );
        refused(
            "[action.x]\nprogram = \"/bin/x\"\nargv = [\"--repo={r}\"]\nparam = [{ name = \"r\", kind = \"choice\", values = [\"a\"] }]\n",
            "whole element",
        );
        refused(
            "[action.x]\nprogram = \"/bin/x\"\nargv = [\"{r}\"]\n",
            "undeclared parameter",
        );
        refused(
            "[action.x]\nprogram = \"/bin/x\"\nparam = [{ name = \"r\", kind = \"choice\", values = [\"a\"] }]\n",
            "used 0 times",
        );
        refused(
            "[action.x]\nprogram = \"/bin/x\"\nargv = [\"{r}\", \"{r}\"]\nparam = [{ name = \"r\", kind = \"choice\", values = [\"a\"] }]\n",
            "used 2 times",
        );
        refused(
            "[action.x]\nprogram = \"/bin/x\"\nargv = [\"{r}\"]\nparam = [{ name = \"r\", kind = \"regex\" }]\n",
            "unknown kind",
        );
        refused(
            "[action.x]\nprogram = \"/bin/x\"\nargv = [\"{r}\"]\nparam = [{ name = \"r\", kind = \"choice\", values = [] }]\n",
            "needs values",
        );
        refused(
            "[action.x]\nprogram = \"/bin/x\"\nargv = [\"{r}\"]\nparam = [{ name = \"r\", kind = \"choice\", values = [\"a\"], under = \"/x\" }]\n",
            "does not belong",
        );
        refused(
            "[action.x]\nprogram = \"/bin/x\"\nargv = [\"{r}\"]\nparam = [{ name = \"r\", kind = \"pattern\", chars = \"a-z\" }]\n",
            "max_len",
        );
        refused(
            "[action.x]\nprogram = \"/bin/x\"\nargv = [\"{r}\"]\nparam = [{ name = \"r\", kind = \"pattern\", chars = \"a z\", max_len = 3 }]\n",
            "no space",
        );
        refused(
            "[action.x]\nprogram = \"/bin/x\"\nargv = [\"{r}\"]\nparam = [{ name = \"r\", kind = \"pattern\", chars = \"z-a\", max_len = 3 }]\n",
            "backwards",
        );
        refused(
            "[action.x]\nprogram = \"/bin/x\"\nenv = { path = \"/bin\" }\n",
            "env",
        );
        refused(
            "[action.x]\nprogram = \"/bin/x\"\nargv = [\"{r}\", \"{s}\"]\nparam = [{ name = \"r\", kind = \"choice\", values = [\"a\"] }, { name = \"r\", kind = \"choice\", values = [\"a\"] }]\n",
            "declared twice",
        );
    }

    #[test]
    fn the_verifier_settings_are_checked() {
        let c = |s: &str| {
            Config::parse(s)
                .err()
                .map(|ConfigError(e)| e)
                .unwrap_or_default()
        };
        let h = "host = \"h1\"\n";
        assert!(
            c(&format!(
                "{h}ssh_keygen = \"ssh-keygen\"\nca_keys = []\nmax_grant_seconds = 1\n"
            ))
            .contains("plain absolute")
        );
        assert!(
            c(&format!(
                "{h}ssh_keygen = \"/k\"\nca_keys = []\nmax_grant_seconds = 1\n"
            ))
            .contains("ca_keys is empty")
        );
        assert!(
            c(&format!(
                "{h}ssh_keygen = \"/k\"\nca_keys = [\"{CA}\"]\nmax_grant_seconds = 0\n"
            ))
            .contains("is 0")
        );
        assert!(
            c(&format!("{h}ssh_keygen = \"/k\"\nca_keys = [\"{CA}\"]\n"))
                .contains("max_grant_seconds")
        );
        assert!(
            c(&format!(
                "{h}ssh_keygen = \"/k\"\nca_keys = [\"{CA}\"]\nmax_grant_seconds = 1\nextra = 1\n"
            ))
            .contains("unknown field")
        );
    }

    #[test]
    fn the_host_name_is_required_and_checked() {
        let rest = format!("ssh_keygen = \"/k\"\nca_keys = [\"{CA}\"]\nmax_grant_seconds = 1\n");
        let e = |s: String| {
            Config::parse(&s)
                .err()
                .map(|ConfigError(e)| e)
                .unwrap_or_default()
        };
        assert!(e(rest.clone()).contains("host"), "missing host");
        for bad in ["", "Flic", "a:b", "a.example", "*"] {
            assert!(
                e(format!("host = \"{bad}\"\n{rest}")).contains("host name"),
                "{bad:?}"
            );
        }
        assert_eq!(
            Config::parse(&format!("host = \"flic\"\n{rest}"))
                .unwrap()
                .host,
            "flic"
        );
    }

    #[test]
    fn a_rsa_or_dsa_ca_is_refused() {
        // ssh-rsa may verify with SHA-1; hogtie pins the CA to EC types.
        let rsa = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAAAgQC7";
        let e = Config::parse(&format!(
            "host = \"h1\"\nssh_keygen = \"/k\"\nca_keys = [\"{rsa}\"]\nmax_grant_seconds = 1\n"
        ))
        .err()
        .map(|ConfigError(e)| e)
        .unwrap_or_default();
        assert!(e.contains("ssh-ed25519 or ecdsa"), "{e}");
    }

    #[test]
    fn character_classes_parse_ranges_and_literal_hyphens() {
        let c = CharClass::parse("a-c._-").unwrap();
        for ch in ['a', 'b', 'c', '.', '_', '-'] {
            assert!(c.contains(ch), "{ch}");
        }
        for ch in ['d', 'A', ' ', 'é'] {
            assert!(!c.contains(ch), "{ch}");
        }
        assert!(CharClass::parse("-a").unwrap().contains('-'));
    }
}
