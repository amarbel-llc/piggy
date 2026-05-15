//! `piggy pass recipients` — partial Rust port.
//!
//! Currently in Rust: `list`. `list-available` is dispatched directly
//! through `fallback::exec_piggy_ids` from main.rs (no module wiring
//! needed). `add`, `remove`, and `sync` still execute in bash via
//! `fallback::exec_bash_subcmds`.
//!
//! Mirrors `cmd_pass_recipients_list` in `src/piggy.sh:788`: parse an
//! optional `-p <subfolder>`, find the relevant `piggy-ids` via the
//! walk-up rule, write the file's contents to stdout.

use std::io::Write as _;

use crate::store::{find_piggy_ids, store_root};

/// Exit code conventions:
/// - 0: piggy-ids found and printed
/// - 1: usage error or no piggy-ids in the walk chain
/// - 2: IO error while reading the file
pub fn list(args: &[String]) -> i32 {
    let subfolder = match parse_subfolder(args) {
        Ok(s) => s,
        Err(msg) => {
            eprintln!("piggy pass recipients list: {msg}");
            return 1;
        }
    };

    let root = store_root();
    let ids_path = match find_piggy_ids(&root, &subfolder) {
        Ok(p) => p,
        Err(msg) => {
            eprintln!("piggy pass recipients list: {msg}");
            return 1;
        }
    };

    let contents = match std::fs::read(&ids_path) {
        Ok(b) => b,
        Err(err) => {
            eprintln!(
                "piggy pass recipients list: read {}: {}",
                ids_path.display(),
                err
            );
            return 2;
        }
    };

    let mut stdout = std::io::stdout().lock();
    if let Err(err) = stdout.write_all(&contents) {
        eprintln!("piggy pass recipients list: write stdout: {err}");
        return 2;
    }
    0
}

/// Parse `-p <subfolder>`. Everything else is a usage error — mirrors
/// the bash `case ... *) die "unexpected argument" ;;` arm.
fn parse_subfolder(args: &[String]) -> Result<String, String> {
    let mut subfolder = String::new();
    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "-p" => match iter.next() {
                Some(v) => subfolder = v.clone(),
                None => return Err("-p requires a subfolder argument".into()),
            },
            other => return Err(format!("unexpected argument: {other}")),
        }
    }
    Ok(subfolder)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_subfolder_empty_args() {
        assert_eq!(parse_subfolder(&[]).unwrap(), "");
    }

    #[test]
    fn parse_subfolder_with_p_flag() {
        let v = vec!["-p".to_string(), "work".to_string()];
        assert_eq!(parse_subfolder(&v).unwrap(), "work");
    }

    #[test]
    fn parse_subfolder_p_without_value_errors() {
        let v = vec!["-p".to_string()];
        let err = parse_subfolder(&v).unwrap_err();
        assert!(err.contains("-p"), "got: {err}");
    }

    #[test]
    fn parse_subfolder_unexpected_argument_errors() {
        let v = vec!["bogus".to_string()];
        let err = parse_subfolder(&v).unwrap_err();
        assert!(err.contains("unexpected"), "got: {err}");
    }

    #[test]
    fn parse_subfolder_positional_after_p_errors() {
        let v = vec!["-p".to_string(), "work".to_string(), "extra".to_string()];
        let err = parse_subfolder(&v).unwrap_err();
        assert!(err.contains("unexpected"), "got: {err}");
    }
}
