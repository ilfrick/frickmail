use chrono::{FixedOffset, NaiveDateTime, TimeZone};

const MAILSO_RFC822_MIN_TIMESTAMP: i64 = 398_045_302;

pub fn legacy_rfc2822_timestamp(value: &str) -> Option<i64> {
    let mut value = value.trim().to_string();
    if value.is_empty() {
        return None;
    }

    if value.ends_with(')') {
        if let Some(comment_start) = value.rfind(" (") {
            let comment = &value[comment_start + 2..value.len() - 1];
            if !comment.is_empty() && comment.chars().all(|ch| ch.is_ascii_alphanumeric()) {
                value.truncate(comment_start);
            }
        }
    }
    if let Some((_, without_weekday)) = value.split_once(',') {
        value = without_weekday.trim().to_string();
    }

    let mut tokens = value
        .split_whitespace()
        .map(str::to_string)
        .collect::<Vec<_>>();
    if let Some(time) = tokens.iter_mut().find(|token| {
        let mut parts = token.split(':');
        matches!(
            (parts.next(), parts.next(), parts.next()),
            (Some(hours), Some(minutes), None)
                if !hours.is_empty()
                    && !minutes.is_empty()
                    && hours.chars().all(|ch| ch.is_ascii_digit())
                    && minutes.chars().all(|ch| ch.is_ascii_digit())
        )
    }) {
        time.push_str(":00");
    }
    value = tokens.join(" ");

    parse_numeric_offset_timestamp(&value)
        .or_else(|| parse_timezone_abbreviation_timestamp(&value))
        .filter(|timestamp| *timestamp >= MAILSO_RFC822_MIN_TIMESTAMP)
}

fn parse_numeric_offset_timestamp(value: &str) -> Option<i64> {
    for format in ["%e %b %Y %H:%M:%S %z", "%d %b %Y %H:%M:%S %z"] {
        if let Ok(date) = chrono::DateTime::parse_from_str(value, format) {
            return Some(date.timestamp());
        }
    }
    None
}

fn parse_timezone_abbreviation_timestamp(value: &str) -> Option<i64> {
    let (date_time, zone) = value.rsplit_once(' ')?;
    let offset = FixedOffset::east_opt(timezone_abbreviation_offset(zone)?)?;
    let date_time = NaiveDateTime::parse_from_str(date_time, "%e %b %Y %H:%M:%S")
        .or_else(|_| NaiveDateTime::parse_from_str(date_time, "%d %b %Y %H:%M:%S"))
        .ok()?;

    offset
        .from_local_datetime(&date_time)
        .single()
        .map(|date| date.timestamp())
}

fn timezone_abbreviation_offset(zone: &str) -> Option<i32> {
    let offset = match zone.to_ascii_uppercase().as_str() {
        "UTC" | "GMT" | "Z" => 0,
        "A" => 60 * 60,
        "B" => 2 * 60 * 60,
        "C" => 3 * 60 * 60,
        "D" => 4 * 60 * 60,
        "E" => 5 * 60 * 60,
        "F" => 6 * 60 * 60,
        "G" => 7 * 60 * 60,
        "H" => 8 * 60 * 60,
        "I" => 9 * 60 * 60,
        "K" => 10 * 60 * 60,
        "L" => 11 * 60 * 60,
        "M" => 12 * 60 * 60,
        "N" => -60 * 60,
        "O" => -2 * 60 * 60,
        "P" => -3 * 60 * 60,
        "Q" => -4 * 60 * 60,
        "R" => -5 * 60 * 60,
        "S" => -6 * 60 * 60,
        "T" => -7 * 60 * 60,
        "U" => -8 * 60 * 60,
        "V" => -9 * 60 * 60,
        "W" => -10 * 60 * 60,
        "X" => -11 * 60 * 60,
        "Y" => -12 * 60 * 60,
        "EST" => -5 * 60 * 60,
        "EDT" => -4 * 60 * 60,
        "CST" => -6 * 60 * 60,
        "CDT" => -5 * 60 * 60,
        "MST" => -7 * 60 * 60,
        "MDT" => -6 * 60 * 60,
        "PST" => -8 * 60 * 60,
        "PDT" => -7 * 60 * 60,
        "AST" => -4 * 60 * 60,
        "ADT" => -3 * 60 * 60,
        "HST" => -10 * 60 * 60,
        "AKST" => -9 * 60 * 60,
        "AKDT" => -8 * 60 * 60,
        "WET" => 0,
        "WEST" => 60 * 60,
        "CET" | "MET" => 60 * 60,
        "CEST" | "MEST" => 2 * 60 * 60,
        "EET" => 2 * 60 * 60,
        "EEST" => 3 * 60 * 60,
        "BST" => 60 * 60,
        "MSK" => 3 * 60 * 60,
        "IST" => 2 * 60 * 60,
        "IDT" => 3 * 60 * 60,
        "IDDT" => 4 * 60 * 60,
        "JST" => 9 * 60 * 60,
        "HKT" | "AWST" => 8 * 60 * 60,
        "WIB" => 7 * 60 * 60,
        "WITA" => 8 * 60 * 60,
        "WIT" => 9 * 60 * 60,
        "PKT" => 5 * 60 * 60,
        "WAT" => 60 * 60,
        "CAT" | "SAST" => 2 * 60 * 60,
        "AEST" => 10 * 60 * 60,
        "AEDT" => 11 * 60 * 60,
        "ACST" => (9 * 60 + 30) * 60,
        "ACDT" => (10 * 60 + 30) * 60,
        "NZST" => 12 * 60 * 60,
        "NZDT" => 13 * 60 * 60,
        _ => return None,
    };
    Some(offset)
}

#[cfg(test)]
mod tests {
    use super::legacy_rfc2822_timestamp;

    #[test]
    fn matches_mailso_rfc2822_normalization_and_cutoff() {
        let expected = Some(1_057_049_557);

        assert_eq!(
            legacy_rfc2822_timestamp("Mon, 1 Jul 2003 10:52:37 +0200"),
            expected
        );
        assert_eq!(
            legacy_rfc2822_timestamp("1 Jul 2003 10:52 +0200"),
            Some(1_057_049_520)
        );
        assert_eq!(
            legacy_rfc2822_timestamp("1 Jul 2003 10:52:37 +0200 (CEST)"),
            expected
        );
        assert_eq!(
            legacy_rfc2822_timestamp("Tue, 1 Jul 2003 10:52:37 CEST"),
            expected
        );
        assert_eq!(
            legacy_rfc2822_timestamp("1 Jul 2003 10:52 CEST"),
            Some(1_057_049_520)
        );
        assert_eq!(
            legacy_rfc2822_timestamp("1 Jul 2003 10:52:37 EDT"),
            Some(1_057_071_157)
        );
        assert_eq!(
            legacy_rfc2822_timestamp("1 Jul 2003 10:52:37 B"),
            Some(1_057_049_557)
        );
        assert_eq!(legacy_rfc2822_timestamp("1 Jul 2003 10:52:37 UT"), None);
        assert_eq!(legacy_rfc2822_timestamp("1 Jan 1970 00:00:00 +0000"), None);
        assert_eq!(legacy_rfc2822_timestamp("not a date"), None);
        assert_eq!(legacy_rfc2822_timestamp("not a date (broken) \u{e9}"), None);
    }
}
