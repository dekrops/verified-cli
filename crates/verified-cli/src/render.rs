//! Terminal output: results on standard output, diagnostics on standard
//! error, color only where a terminal wants it.

use std::io::Write as _;

use anstream::{AutoStream, ColorChoice};
use anstyle::{AnsiColor, Style};

use crate::cli::Global;

/// How results are written.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Mode {
    Human,
    Json,
    Quiet,
}

/// How a value should read at a glance.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Tone {
    /// Checked and established.
    Established,
    /// Not checked: nothing is known.
    Unknown,
    /// Refused, or not established.
    Negative,
    /// Plain information.
    Plain,
}

impl Tone {
    fn style(self) -> Style {
        match self {
            Self::Established => AnsiColor::Green.on_default(),
            Self::Unknown => AnsiColor::Yellow.on_default(),
            Self::Negative => AnsiColor::Red.on_default().bold(),
            Self::Plain => Style::new(),
        }
    }
}

/// One line of a report: an aligned label and what was found.
pub(crate) struct Row {
    pub(crate) label: &'static str,
    pub(crate) tone: Tone,
    pub(crate) text: String,
}

impl Row {
    pub(crate) fn new(label: &'static str, tone: Tone, text: impl Into<String>) -> Self {
        Self {
            label,
            tone,
            text: text.into(),
        }
    }
}

pub(crate) struct Output {
    pub(crate) mode: Mode,
    pub(crate) verbose: bool,
    unicode: bool,
    stdout: AutoStream<std::io::Stdout>,
    stderr: AutoStream<std::io::Stderr>,
}

/// The width of the label column, shared by every report.
const LABEL_WIDTH: usize = 22;

impl Output {
    pub(crate) fn new(global: &Global) -> Self {
        let choice = if global.no_color {
            ColorChoice::Never
        } else {
            ColorChoice::Auto
        };
        let mode = if global.json {
            Mode::Json
        } else if global.quiet {
            Mode::Quiet
        } else {
            Mode::Human
        };
        Self {
            mode,
            verbose: global.verbose,
            unicode: locale_is_utf8(),
            stdout: AutoStream::new(std::io::stdout(), choice),
            stderr: AutoStream::new(std::io::stderr(), choice),
        }
    }

    // A closed pipe is the reader's decision, not an error worth reporting:
    // write failures are ignored and the exit code still tells the result.

    /// Writes a heading line of a human report.
    pub(crate) fn heading(&mut self, text: &str) {
        let bold = Style::new().bold();
        let _ = writeln!(self.stdout, "{bold}{text}{bold:#}");
    }

    /// Writes aligned rows of a human report. A row with an empty label
    /// continues the one above it.
    pub(crate) fn rows(&mut self, rows: &[Row]) {
        for Row { label, tone, text } in rows {
            let style = tone.style();
            let _ = writeln!(self.stdout, "{label:<LABEL_WIDTH$}{style}{text}{style:#}");
        }
    }

    /// Writes a plain line of a human report.
    pub(crate) fn line(&mut self, text: &str) {
        let _ = writeln!(self.stdout, "{text}");
    }

    /// Writes a JSON result.
    pub(crate) fn json(&mut self, value: &serde_json::Value) {
        let _ = writeln!(self.stdout, "{value:#}");
    }

    /// Writes a diagnostic to standard error.
    pub(crate) fn error(&mut self, message: &str) {
        let style = Tone::Negative.style();
        let _ = writeln!(self.stderr, "{style}error:{style:#} {message}");
    }

    /// Shortens a hexadecimal digest for people, unless `--verbose`.
    pub(crate) fn short(&self, hex: &str) -> String {
        const KEEP: usize = 12;
        if self.verbose || hex.len() <= KEEP {
            hex.to_owned()
        } else {
            format!("{}{}", &hex[..KEEP], if self.unicode { "…" } else { "..." })
        }
    }
}

fn locale_is_utf8() -> bool {
    ["LC_ALL", "LC_CTYPE", "LANG"]
        .into_iter()
        .find_map(|name| std::env::var(name).ok().filter(|value| !value.is_empty()))
        .is_some_and(|value| {
            let value = value.to_ascii_lowercase();
            value.contains("utf-8") || value.contains("utf8")
        })
}
