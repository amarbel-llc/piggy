//! `piggy-askpass-gtk`: the dialog `contrib/piggy-askpass.sh` shows an
//! operator act's PIN prompt in (RFC 0012 §2.6), on Linux desktops.
//!
//! It exists because the dialogs zenity and yad build do not do everything
//! an operator act needs at once: zenity's form neither fills its width with
//! the class band nor lets the act's text through without markup escaping,
//! and yad never presents its window, so the prompt opens without focus. This
//! one takes focus, shows the text literally (it is read from stdin and set as
//! plain text, never parsed as markup), and puts the class band across the
//! whole width. The shell script decides when to use it and keeps zenity as
//! the fallback.

mod dialog;
mod options;

use std::io::{Read, Write};
use std::process::ExitCode;

/// How the dialog ended, and the exit status each ending reports. The
/// statuses are zenity's, which `piggy-askpass.sh` already passes through.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    Confirmed { pin: String },
    Cancelled,
    TimedOut,
}

const EXIT_CONFIRMED: u8 = 0;
const EXIT_CANCELLED: u8 = 1;
const EXIT_USAGE: u8 = 2;
const EXIT_TIMED_OUT: u8 = 5;

impl Outcome {
    fn exit_status(&self) -> u8 {
        match self {
            Outcome::Confirmed { .. } => EXIT_CONFIRMED,
            Outcome::Cancelled => EXIT_CANCELLED,
            Outcome::TimedOut => EXIT_TIMED_OUT,
        }
    }
}

fn main() -> ExitCode {
    let options = match options::parse(std::env::args().skip(1)) {
        Ok(options) => options,
        Err(error) => {
            eprintln!("piggy-askpass-gtk: {error}\n\n{}", options::USAGE);
            return ExitCode::from(EXIT_USAGE);
        }
    };

    let mut text = String::new();
    if let Err(error) = std::io::stdin().read_to_string(&mut text) {
        eprintln!("piggy-askpass-gtk: could not read the text from stdin: {error}");
        return ExitCode::from(EXIT_USAGE);
    }
    let text = text.trim_end_matches('\n');

    let outcome = match dialog::run(&options, text) {
        Ok(outcome) => outcome,
        Err(error) => {
            eprintln!("piggy-askpass-gtk: {error}");
            return ExitCode::from(EXIT_USAGE);
        }
    };

    if let Outcome::Confirmed { pin } = &outcome {
        let mut stdout = std::io::stdout().lock();
        if writeln!(stdout, "{pin}")
            .and_then(|()| stdout.flush())
            .is_err()
        {
            return ExitCode::from(EXIT_CANCELLED);
        }
    }
    ExitCode::from(outcome.exit_status())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn each_ending_reports_the_status_zenity_would() {
        let confirmed = Outcome::Confirmed {
            pin: "123456".into(),
        };
        assert_eq!(confirmed.exit_status(), 0);
        assert_eq!(Outcome::Cancelled.exit_status(), 1);
        assert_eq!(Outcome::TimedOut.exit_status(), 5);
    }
}
