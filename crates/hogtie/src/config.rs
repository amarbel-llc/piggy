//! hogtie's one configuration file, `/etc/hogtie/hogtie.toml`, root-owned
//! and later written by the host's NixOS configuration: the verifier's
//! settings and the registry of actions. Every key is checked; an unknown
//! key, a relative path or a parameter the argv does not use refuses the
//! whole file (fail closed: no action runs from a file hogtie doubts).
//!
//! ```toml
//! ssh_keygen = "/nix/store/...-openssh/bin/ssh-keygen"
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
//! Parameters are positional and all required. Kinds: `choice` (one of
//! `values`), `pattern` (characters from `chars`, a class such as
//! `a-z0-9._-`, at most `max_len`, never starting with `-`), `path` (an
//! absolute path under `under`, passed on as its real path, which must
//! still be under `under`). A `{name}` in argv must be a whole element.

use crate::message::is_action_name;
use crate::verify::CaKey;
use serde::Deserialize;
use std::collections::BTreeMap;
use std::fmt;
use std::path::{Path, PathBuf};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawConfig {
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
    Path { under: PathBuf },
}

/// A set of printable ASCII characters, parsed from `a-z0-9._-` style text.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CharClass([bool; 128]);

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
        let mut set = [false; 128];
        let mut i = 0;
        while i < b.len() {
            if i + 2 < b.len() && b[i + 1] == b'-' {
                let (lo, hi) = (b[i], b[i + 2]);
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
                unused("values", p.values.is_some())?;
                unused("chars", p.chars.is_some())?;
                unused("max_len", p.max_len.is_some())?;
                let under = p.under.clone().unwrap_or_default();
                if !is_plain_absolute(&under) {
                    return err(format!(
                        "parameter {}: under {under:?} is not a plain absolute path (and not /)",
                        p.name
                    ));
                }
                ParamKind::Path {
                    under: PathBuf::from(under),
                }
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
    /// against the declared parameters. A path is resolved here and passed
    /// on resolved.
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

fn is_under(path: &Path, dir: &Path) -> bool {
    path.starts_with(dir) && path != dir
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
            match v.chars().find(|c| !chars.contains(*c)) {
                Some(c) => Err(format!("character {c:?} is outside the declared class")),
                None => Ok(v.to_string()),
            }
        }
        ParamKind::Path { under } => {
            if !is_plain_absolute(v) || !is_under(Path::new(v), under) {
                return Err(format!(
                    "{v:?} is not a plain absolute path under {}",
                    under.display()
                ));
            }
            let real_under =
                std::fs::canonicalize(under).map_err(|e| format!("{}: {e}", under.display()))?;
            let real = std::fs::canonicalize(v).map_err(|e| format!("{v}: {e}"))?;
            if !is_under(&real, &real_under) {
                return Err(format!(
                    "{v:?} resolves to {}, outside {}",
                    real.display(),
                    real_under.display()
                ));
            }
            real.into_os_string()
                .into_string()
                .map_err(|_| "the resolved path is not UTF-8".to_string())
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
            "ssh_keygen = \"/usr/bin/ssh-keygen\"\nca_keys = [\"{CA}\"]\nmax_grant_seconds = 86400\n{actions}"
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
    fn a_path_parameter_stays_under_its_directory() {
        let dir = crate::util::PrivateDir::new(&std::env::temp_dir(), "hogtie-cfg").unwrap();
        let base = dir.path();
        std::fs::create_dir(base.join("repos")).unwrap();
        std::fs::create_dir(base.join("repos/a")).unwrap();
        std::fs::create_dir(base.join("secret")).unwrap();
        std::os::unix::fs::symlink(base.join("secret"), base.join("repos/link")).unwrap();
        let c = parse(&format!(
            "[action.ls]\nprogram = \"/bin/ls\"\nargv = [\"{{p}}\"]\nparam = [{{ name = \"p\", kind = \"path\", under = \"{}/repos\" }}]\n",
            base.display()
        ))
        .unwrap();
        let a = &c.actions["ls"];
        let ok = format!("{}/repos/a", base.display());
        let real = std::fs::canonicalize(&ok).unwrap();
        assert_eq!(a.build(&[ok]).unwrap()[1], real.to_str().unwrap());
        for (v, needle) in [
            (
                format!("{}/repos/../secret", base.display()),
                "not a plain absolute path",
            ),
            (
                format!("{}/repos/./a", base.display()),
                "not a plain absolute path",
            ),
            (
                format!("{}/repos", base.display()),
                "not a plain absolute path under",
            ),
            (
                format!("{}/secret", base.display()),
                "not a plain absolute path under",
            ),
            ("repos/a".to_string(), "not a plain absolute path"),
            (format!("{}/repos/link", base.display()), "outside"),
            (format!("{}/repos/missing", base.display()), "No such file"),
        ] {
            let e = a.build(&[v.clone()]).unwrap_err();
            assert!(e.contains(needle), "{v}: {e}");
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
            "[action.x]\nprogram = \"/bin/x\"\nargv = [\"{r}\"]\nparam = [{ name = \"r\", kind = \"path\", under = \"/\" }]\n",
            "not a plain absolute path",
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
        assert!(
            c("ssh_keygen = \"ssh-keygen\"\nca_keys = []\nmax_grant_seconds = 1\n")
                .contains("plain absolute")
        );
        assert!(
            c("ssh_keygen = \"/k\"\nca_keys = []\nmax_grant_seconds = 1\n")
                .contains("ca_keys is empty")
        );
        assert!(
            c(&format!(
                "ssh_keygen = \"/k\"\nca_keys = [\"{CA}\"]\nmax_grant_seconds = 0\n"
            ))
            .contains("is 0")
        );
        assert!(
            c(&format!("ssh_keygen = \"/k\"\nca_keys = [\"{CA}\"]\n"))
                .contains("max_grant_seconds")
        );
        assert!(
            c(&format!(
                "ssh_keygen = \"/k\"\nca_keys = [\"{CA}\"]\nmax_grant_seconds = 1\nextra = 1\n"
            ))
            .contains("unknown field")
        );
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
