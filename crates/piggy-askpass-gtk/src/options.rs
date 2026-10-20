//! The command line of `piggy-askpass-gtk`, parsed without touching GTK so it
//! can be tested on a host with no display.

use std::fmt;

/// What the dialog shows and how it answers. The act's text is not here: it
/// arrives on stdin, so no byte of it passes through an argument vector.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Options {
    pub title: String,
    pub ok_label: String,
    /// Seconds before the dialog gives up; `None` waits forever.
    pub timeout_secs: Option<u32>,
    pub band: Option<Band>,
    /// A word the operator must type, in a field of its own, before the
    /// confirm button can be pressed. Return then submits nothing: the
    /// button has to be clicked.
    pub confirm_word: Option<String>,
}

/// The coloured strip across the top of the dialog that names the act's
/// class before a word of its text is read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Band {
    pub text: String,
    pub background: HexColour,
    pub foreground: HexColour,
}

/// A `#rrggbb` colour. Only this form is accepted, so a colour can be put in a
/// stylesheet without any way to escape from the declaration it sits in.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HexColour(String);

impl HexColour {
    pub fn parse(value: &str) -> Result<Self, UsageError> {
        let digits = value
            .strip_prefix('#')
            .filter(|d| d.len() == 6 && d.bytes().all(|b| b.is_ascii_hexdigit()));
        match digits {
            Some(_) => Ok(Self(value.to_owned())),
            None => Err(UsageError(format!(
                "colour {value:?} is not of the form #rrggbb"
            ))),
        }
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UsageError(pub String);

impl fmt::Display for UsageError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

pub const USAGE: &str = "\
usage: piggy-askpass-gtk --title TITLE --ok-label LABEL [--timeout SECONDS]
                         [--band TEXT --band-background #rrggbb --band-foreground #rrggbb]
                         [--confirm-word WORD]  < text

Shows TEXT (read from stdin, shown literally) under an optional coloured band,
with a PIN field, and prints the PIN on stdout when confirmed.
Exit status: 0 confirmed, 1 cancelled, 2 usage or no display, 5 timed out.";

/// Parses the arguments after the program name. Each option takes a value,
/// given either as `--name value` or as `--name=value`.
pub fn parse<I, S>(args: I) -> Result<Options, UsageError>
where
    I: IntoIterator<Item = S>,
    S: Into<String>,
{
    let mut title = None;
    let mut ok_label = None;
    let mut timeout_secs = None;
    let mut band_text = None;
    let mut band_background = None;
    let mut band_foreground = None;
    let mut confirm_word = None;

    let mut args = args.into_iter().map(Into::into);
    while let Some(arg) = args.next() {
        let (name, inline_value) = match arg.split_once('=') {
            Some((name, value)) if name.starts_with("--") => {
                (name.to_owned(), Some(value.to_owned()))
            }
            _ => (arg.clone(), None),
        };
        let slot = match name.as_str() {
            "--title" => &mut title,
            "--ok-label" => &mut ok_label,
            "--timeout" => &mut timeout_secs,
            "--band" => &mut band_text,
            "--band-background" => &mut band_background,
            "--band-foreground" => &mut band_foreground,
            "--confirm-word" => &mut confirm_word,
            _ => return Err(UsageError(format!("unknown argument {arg:?}"))),
        };
        let value = match inline_value {
            Some(value) => value,
            None => args
                .next()
                .ok_or_else(|| UsageError(format!("{name} needs a value")))?,
        };
        if slot.replace(value).is_some() {
            return Err(UsageError(format!("{name} given twice")));
        }
    }

    let title = title.ok_or_else(|| UsageError("--title is required".into()))?;
    let ok_label = ok_label.ok_or_else(|| UsageError("--ok-label is required".into()))?;
    let timeout_secs = match timeout_secs {
        None => None,
        Some(value) => match value.parse::<u32>() {
            Ok(0) => None,
            Ok(secs) => Some(secs),
            Err(_) => {
                return Err(UsageError(format!(
                    "--timeout {value:?} is not a whole number of seconds"
                )));
            }
        },
    };
    let band = match (band_text, band_background, band_foreground) {
        (None, None, None) => None,
        (Some(text), Some(background), Some(foreground)) => Some(Band {
            text,
            background: HexColour::parse(&background)?,
            foreground: HexColour::parse(&foreground)?,
        }),
        _ => {
            return Err(UsageError(
                "--band, --band-background and --band-foreground go together".into(),
            ));
        }
    };
    if confirm_word.as_deref() == Some("") {
        return Err(UsageError("--confirm-word must not be empty".into()));
    }

    Ok(Options {
        title,
        ok_label,
        timeout_secs,
        band,
        confirm_word,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn escalation_args() -> Vec<&'static str> {
        vec![
            "--title",
            "piggy operator act: ESCALATION (grants authority)",
            "--ok-label=Grant escalation",
            "--timeout",
            "120",
            "--band",
            "⚠  ESCALATION — you are GRANTING AUTHORITY  ⚠",
            "--band-background=#c01c28",
            "--band-foreground",
            "#ffffff",
            "--confirm-word",
            "ESCALATE",
        ]
    }

    #[test]
    fn an_escalation_command_line_parses_in_both_value_forms() {
        let options = parse(escalation_args()).unwrap();
        assert_eq!(options.ok_label, "Grant escalation");
        assert_eq!(options.timeout_secs, Some(120));
        assert_eq!(options.confirm_word.as_deref(), Some("ESCALATE"));
        let band = options.band.unwrap();
        assert_eq!(band.background.as_str(), "#c01c28");
        assert_eq!(band.foreground.as_str(), "#ffffff");
    }

    #[test]
    fn a_value_may_itself_contain_an_equals_sign() {
        let options = parse(["--title=a=b", "--ok-label", "x=y"]).unwrap();
        assert_eq!(options.title, "a=b");
        assert_eq!(options.ok_label, "x=y");
    }

    #[test]
    fn title_and_ok_label_are_required() {
        assert!(parse(["--ok-label", "OK"]).is_err());
        assert!(parse(["--title", "T"]).is_err());
    }

    #[test]
    fn a_zero_timeout_waits_forever_and_a_bad_one_is_refused() {
        let options = parse(["--title", "T", "--ok-label", "OK", "--timeout", "0"]).unwrap();
        assert_eq!(options.timeout_secs, None);
        assert!(parse(["--title", "T", "--ok-label", "OK", "--timeout", "-1"]).is_err());
        assert!(parse(["--title", "T", "--ok-label", "OK", "--timeout", "1.5"]).is_err());
    }

    #[test]
    fn a_band_needs_all_three_of_its_options() {
        assert!(parse(["--title", "T", "--ok-label", "OK", "--band", "B"]).is_err());
    }

    #[test]
    fn a_colour_that_could_escape_its_declaration_is_refused() {
        for colour in [
            "red",
            "#c01c2",
            "#c01c28; } * { color: red",
            "#gggggg",
            "c01c28",
        ] {
            assert!(HexColour::parse(colour).is_err(), "{colour:?} accepted");
        }
        assert!(HexColour::parse("#C01c28").is_ok());
    }

    #[test]
    fn unknown_repeated_and_valueless_options_are_refused() {
        assert!(parse(["--title", "T", "--ok-label", "OK", "--markup"]).is_err());
        assert!(parse(["--title", "T", "--title", "U", "--ok-label", "OK"]).is_err());
        assert!(parse(["--title", "T", "--ok-label"]).is_err());
        assert!(parse(["--title", "T", "--ok-label", "OK", "--confirm-word="]).is_err());
    }
}
