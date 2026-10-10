//! Instants.

use std::fmt;

/// A point in time, as the protocol spells one.
///
/// The only accepted spelling is the canonical one: `YYYY-MM-DDTHH:MM:SSZ`,
/// or with a fraction of exactly 3, 6 or 9 digits using the shortest group
/// that represents it. Every instant therefore has one spelling, and
/// comparing instants is comparing what they denote.
///
/// Time is never read from a clock anywhere in this workspace: every instant
/// comes from a package or from the relying party's configuration.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Instant {
    seconds: i64,
    nanos: u32,
}

fn number(digits: &[u8]) -> Option<u32> {
    digits.iter().try_fold(0u32, |n, b| {
        b.is_ascii_digit().then(|| n * 10 + u32::from(b - b'0'))
    })
}

const fn is_leap(year: i64) -> bool {
    year % 4 == 0 && (year % 100 != 0 || year % 400 == 0)
}

const fn days_in_month(year: i64, month: u32) -> u32 {
    match month {
        2 if is_leap(year) => 29,
        2 => 28,
        4 | 6 | 9 | 11 => 30,
        _ => 31,
    }
}

/// Days from 1970-01-01 to a date of the proleptic Gregorian calendar.
const fn days_from_civil(year: i64, month: u32, day: u32) -> i64 {
    let year = if month <= 2 { year - 1 } else { year };
    let era = year.div_euclid(400);
    let year_of_era = year.rem_euclid(400);
    let shifted_month = (month as i64 + 9) % 12;
    let day_of_year = (153 * shifted_month + 2) / 5 + day as i64 - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    era * 146_097 + day_of_era - 719_468
}

impl Instant {
    /// Reads the canonical spelling of an instant. Anything else, including
    /// another spelling of a real instant, is `None`.
    #[must_use]
    pub fn parse(text: &str) -> Option<Self> {
        let bytes = text.as_bytes();
        let (date_time, fraction) = match bytes.len() {
            20 => (&bytes[..19], &[][..]),
            24 | 27 | 30 if bytes[19] == b'.' => (&bytes[..19], &bytes[20..bytes.len() - 1]),
            _ => return None,
        };
        let separators = [(4, b'-'), (7, b'-'), (10, b'T'), (13, b':'), (16, b':')];
        if bytes.last() != Some(&b'Z') || separators.iter().any(|&(i, c)| date_time[i] != c) {
            return None;
        }
        let year = i64::from(number(&date_time[0..4])?);
        let month = number(&date_time[5..7])?;
        let day = number(&date_time[8..10])?;
        let hour = number(&date_time[11..13])?;
        let minute = number(&date_time[14..16])?;
        let second = number(&date_time[17..19])?;
        let in_range = (1..=12).contains(&month)
            && (1..=days_in_month(year, month)).contains(&day)
            && hour < 24
            && minute < 60
            && second < 60;
        if !in_range {
            return None;
        }
        let nanos = if fraction.is_empty() {
            0
        } else {
            // The shortest group that represents the fraction: never all
            // zeros, and never a longer group ending in a whole shorter one.
            let all_zero = fraction.iter().all(|b| *b == b'0');
            let shortenable = fraction.len() > 3 && fraction.ends_with(b"000");
            if all_zero || shortenable {
                return None;
            }
            let scale = [0, 0, 0, 1_000_000, 0, 0, 1_000, 0, 0, 1][fraction.len()];
            number(fraction)? * scale
        };
        let seconds = days_from_civil(year, month, day) * 86_400
            + i64::from(hour) * 3_600
            + i64::from(minute) * 60
            + i64::from(second);
        Some(Self { seconds, nanos })
    }

    /// Whole seconds since 1970-01-01T00:00:00Z, rounded toward the past:
    /// the second the instant falls in.
    #[must_use]
    pub const fn epoch_seconds(self) -> i64 {
        self.seconds
    }
}

impl fmt::Display for Instant {
    /// Seconds and nanoseconds since the epoch. The protocol's own spelling
    /// is kept wherever a package's text must be reproduced; this is for
    /// diagnostics only.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}.{:09}s", self.seconds, self.nanos)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn at(text: &str) -> Instant {
        Instant::parse(text).unwrap_or_else(|| panic!("{text} should parse"))
    }

    #[test]
    fn reads_the_canonical_spelling() {
        assert_eq!(at("1970-01-01T00:00:00Z").epoch_seconds(), 0);
        assert_eq!(at("2026-01-01T00:00:00Z").epoch_seconds(), 1_767_225_600);
        assert_eq!(at("1969-12-31T23:59:59.500Z").epoch_seconds(), -1);
        assert_eq!(at("2000-02-29T12:00:00Z").epoch_seconds(), 951_825_600);
        assert_eq!(at("0000-01-01T00:00:00Z").epoch_seconds(), -62_167_219_200);
        assert_eq!(at("9999-12-31T23:59:59Z").epoch_seconds(), 253_402_300_799);
    }

    #[test]
    fn orders_by_what_is_denoted() {
        let ordered = [
            "1969-12-31T23:59:59.999999999Z",
            "1970-01-01T00:00:00Z",
            "1970-01-01T00:00:00.000000001Z",
            "1970-01-01T00:00:00.000001Z",
            "1970-01-01T00:00:00.001Z",
            "1970-01-01T00:00:01Z",
            "2026-06-30T10:15:30.250Z",
        ];
        for pair in ordered.windows(2) {
            assert!(at(pair[0]) < at(pair[1]), "{pair:?}");
        }
    }

    #[test]
    fn refuses_every_other_spelling() {
        for bad in [
            "",
            "2026-01-01",
            "2026-01-01T00:00:00",
            "2026-01-01T00:00:00z",
            "2026-01-01t00:00:00Z",
            "2026-01-01 00:00:00Z",
            "2026-01-01T00:00:00+00:00",
            "2026-01-01T00:00Z",
            // Fractions that are not the shortest group.
            "2026-01-01T00:00:00.000Z",
            "2026-01-01T00:00:00.5Z",
            "2026-01-01T00:00:00.50Z",
            "2026-01-01T00:00:00.500000Z",
            "2026-01-01T00:00:00.500000000Z",
            "2026-01-01T00:00:00.000001000Z",
            "2026-01-01T00:00:00.0000Z",
            // Not instants.
            "2026-02-30T00:00:00Z",
            "2025-02-29T00:00:00Z",
            "2026-13-01T00:00:00Z",
            "2026-00-10T00:00:00Z",
            "2026-01-00T00:00:00Z",
            "2026-01-01T24:00:00Z",
            "2026-01-01T00:60:00Z",
            "2026-01-01T23:59:60Z",
            "+2026-01-01T00:00:00Z",
            "２０２６-01-01T00:00:00Z",
            "2026-01-01T00:00:00.٣٣٣Z",
        ] {
            assert_eq!(Instant::parse(bad), None, "{bad}");
        }
    }
}
