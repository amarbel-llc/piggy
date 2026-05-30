//! `piggy help` — pass-style usage banner.
//!
//! Native Rust port of `cmd_usage` in `src/piggy.sh` (Split B of
//! piggy#96, the final piece that retires the bash dispatcher).
//!
//! The text is reproduced byte-for-byte from the bash `<<-_EOF`
//! heredoc, including the literal tab character that appears in
//! front of the `find` blurb ("    \tList passwords that match
//! pass-names." — bash's `<<-` strips only LEADING tabs, so the
//! interior tab survives into the output).
//!
//! Runtime substitutions:
//!   - `$CLIP_TIME` → `PIGGY_CLIP_TIME` (default 45),
//!   - `$GENERATED_LENGTH` → `PIGGY_GENERATED_LENGTH` (default 25),
//!   - `${EDITOR:-vi}` → `EDITOR` (default `vi`).
//!
//! The header self-line `piggy <version>+<commit>` is the same
//! `piggy_version_line` shape the bash banner used. It's the only
//! point of overlap with `piggy version`, which renders the
//! eng-versioning(7) component table below the self-line; `piggy
//! help` does not.

const DEFAULT_CLIP_TIME: &str = "45";
const DEFAULT_GENERATED_LENGTH: &str = "25";

/// Print the bash `cmd_usage` text. Always returns 0.
pub fn run() -> i32 {
    let clip_time = env_or("PIGGY_CLIP_TIME", DEFAULT_CLIP_TIME);
    let generated_length = env_or("PIGGY_GENERATED_LENGTH", DEFAULT_GENERATED_LENGTH);
    // Bash `piggy_version_line` was `${PIGGY_VERSION:-dev}` /
    // `${PIGGY_COMMIT:-unknown}`. The compile-time `env!("PIGGY_VERSION")`
    // resolves to the build.rs-provided value (which is "dev" for an
    // unset version.env). Using it preserves the bash fallback shape
    // for both nix-wrapped and dev `cargo build` paths.
    let version = env_or("PIGGY_VERSION", env!("PIGGY_VERSION"));
    let commit = env_or("PIGGY_COMMIT", "unknown");
    let editor = env_or("EDITOR", "vi");

    print!(
        "{}",
        render(&version, &commit, &clip_time, &generated_length, &editor)
    );
    0
}

fn env_or(key: &str, default: &str) -> String {
    std::env::var(key)
        .ok()
        .filter(|v| !v.is_empty())
        .unwrap_or_else(|| default.to_string())
}

/// Render the help text. Kept pure so the unit tests can verify
/// byte-equivalence with the bash output without touching env state.
fn render(
    version: &str,
    commit: &str,
    clip_time: &str,
    generated_length: &str,
    editor: &str,
) -> String {
    // The text below is reproduced byte-for-byte from the bash
    // heredoc. The literal tab on the "List passwords that match
    // pass-names." line is intentional (bash `<<-` does not strip
    // interior tabs). Do not "fix" it.
    format!(
        "\
piggy {version}+{commit}

Usage:
    piggy pass init [-p subfolder] [-k <markl-id> | -g <guid>]
        Initialize new password storage with a piggy-recipient-v1
        markl ID. Writes <store>/[subfolder/]piggy-ids.
        With no -k, auto-detects from the attached PIV card's slot 9D.
        Use -g <guid> to disambiguate when multiple cards are attached.
    piggy pass recipients <list|add|remove|sync> [-p subfolder] ...
        Manage recipients in piggy-ids. See \"piggy pass recipients --help\".
    piggy pass ls [subfolder]
        List passwords.
    piggy pass find pass-names...
    \tList passwords that match pass-names.
    piggy pass show [--clip[=line-number],-c[line-number]] pass-name
        Show existing password and optionally put it on the clipboard.
        If put on the clipboard, it will be cleared in {clip_time} seconds.
    piggy pass grep [GREPOPTIONS] search-string
        Search for password files containing search-string when decrypted.
    piggy pass insert [--echo,-e | --multiline,-m] [--force,-f] pass-name
        Insert new password. Optionally, echo the password back to the console
        during entry. Or, optionally, the entry may be multiline. Prompt before
        overwriting existing password unless forced.
    piggy pass edit pass-name
        Insert a new password or edit an existing password using {editor}.
    piggy pass generate [--no-symbols,-n] [--clip,-c] [--in-place,-i | --force,-f] pass-name [pass-length]
        Generate a new password of pass-length (or {generated_length} if unspecified) with optionally no symbols.
        Optionally put it on the clipboard and clear board after {clip_time} seconds.
        Prompt before overwriting existing password unless forced.
        Optionally replace only the first line of an existing file with a new password.
    piggy pass rm [--recursive,-r] [--force,-f] pass-name
        Remove existing password or directory, optionally forcefully.
    piggy pass mv [--force,-f] old-path new-path
        Renames or moves old-path to new-path, optionally forcefully, selectively reencrypting.
    piggy pass cp [--force,-f] old-path new-path
        Copies old-path to new-path, optionally forcefully, selectively reencrypting.
    piggy pass git git-command-args...
        If the password store is a git repository, execute a git command
        specified by git-command-args.
    piggy list [--format human|ndjson]
        Enumerate every populated PIV slot across all attached cards
        (9A/9C/9D/9E + retired 82-95) with their markl IDs. See
        piggy(1) for the per-slot purpose mapping.
    piggy help
        Show this text.
    piggy version
        Show version information.
"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn self_line_is_first_line() {
        let out = render("0.1.1", "abc1234", "45", "25", "vi");
        assert_eq!(out.lines().next().unwrap(), "piggy 0.1.1+abc1234");
    }

    #[test]
    fn blank_line_between_self_line_and_usage() {
        let out = render("0.1.1", "abc1234", "45", "25", "vi");
        let mut lines = out.lines();
        lines.next(); // self-line
        assert_eq!(lines.next().unwrap(), "");
        assert_eq!(lines.next().unwrap(), "Usage:");
    }

    #[test]
    fn clip_time_substitution_is_present() {
        let out = render("0.1.1", "abc1234", "90", "25", "vi");
        assert!(
            out.contains("cleared in 90 seconds"),
            "missing clip-time substitution: {out}"
        );
        assert!(
            out.contains("clear board after 90 seconds"),
            "missing clip-time substitution in generate blurb: {out}"
        );
    }

    #[test]
    fn generated_length_substitution_is_present() {
        let out = render("0.1.1", "abc1234", "45", "32", "vi");
        assert!(
            out.contains("(or 32 if unspecified)"),
            "missing generated-length substitution: {out}"
        );
    }

    #[test]
    fn editor_substitution_is_present() {
        let out = render("0.1.1", "abc1234", "45", "25", "nano");
        assert!(
            out.contains("edit an existing password using nano."),
            "missing editor substitution: {out}"
        );
    }

    #[test]
    fn find_blurb_preserves_literal_tab() {
        let out = render("0.1.1", "abc1234", "45", "25", "vi");
        // Bash `<<-` strips leading tabs but not interior ones; the
        // bash heredoc has `\t    \tList passwords...` so the rendered
        // output is `    \tList passwords...`. Pin both — drift here
        // would be a regression.
        assert!(
            out.contains("\n    \tList passwords that match pass-names.\n"),
            "missing literal tab on find blurb: {out:?}"
        );
    }

    #[test]
    fn lists_every_pass_subcommand() {
        let out = render("0.1.1", "abc1234", "45", "25", "vi");
        for fragment in [
            "piggy pass init",
            "piggy pass recipients",
            "piggy pass ls",
            "piggy pass find",
            "piggy pass show",
            "piggy pass grep",
            "piggy pass insert",
            "piggy pass edit",
            "piggy pass generate",
            "piggy pass rm",
            "piggy pass mv",
            "piggy pass cp",
            "piggy pass git",
            "piggy list",
            "piggy help",
            "piggy version",
        ] {
            assert!(out.contains(fragment), "missing {fragment:?}: {out}");
        }
    }
}
