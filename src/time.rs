//! Time without a date library: RFC 3339 timestamps (protocol §2) and IMF-fixdate (`Date` header, §4.1).

use std::time::{SystemTime, UNIX_EPOCH};

/// Seconds since the Unix epoch, from the local clock.
pub fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// Days since 1970-01-01 to a civil date (Howard Hinnant's algorithm).
fn civil(days: i64) -> (i64, u32, u32) {
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let month = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (yoe + era * 400 + i64::from(month <= 2), month, day)
}

/// A civil date to days since 1970-01-01.
fn days_from_civil(year: i64, month: u32, day: u32) -> i64 {
    let y = if month <= 2 { year - 1 } else { year };
    let era = y.div_euclid(400);
    let yoe = y.rem_euclid(400);
    let m = i64::from(month);
    let doy = (153 * (if m > 2 { m - 3 } else { m + 9 }) + 2) / 5 + i64::from(day) - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

/// `2026-11-09T08:00:00Z`.
pub fn rfc3339(unix: i64) -> String {
    let (y, m, d) = civil(unix.div_euclid(86_400));
    let s = unix.rem_euclid(86_400);
    format!(
        "{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}Z",
        s / 3600,
        s % 3600 / 60,
        s % 60
    )
}

/// Reads `YYYY-MM-DDTHH:MM:SS` followed by `Z` (or fractional seconds, ignored), as the console writes it.
pub fn parse_rfc3339(text: &str) -> Option<i64> {
    let b = text.as_bytes();
    if b.len() < 20
        || b[4] != b'-'
        || b[7] != b'-'
        || b[10] != b'T'
        || b[13] != b':'
        || b[16] != b':'
    {
        return None;
    }
    let n = |r: std::ops::Range<usize>| text.get(r)?.parse::<i64>().ok();
    let (year, month, day) = (n(0..4)?, n(5..7)?, n(8..10)?);
    let (hour, minute, second) = (n(11..13)?, n(14..16)?, n(17..19)?);
    if !(1..=12).contains(&month)
        || !(1..=31).contains(&day)
        || hour > 23
        || minute > 59
        || second > 60
    {
        return None;
    }
    let rest = &text[19..];
    let rest = rest.trim_start_matches(|c: char| c == '.' || c.is_ascii_digit());
    if rest != "Z" && rest != "+00:00" {
        return None;
    }
    Some(
        days_from_civil(year, month as u32, day as u32) * 86_400
            + hour * 3600
            + minute * 60
            + second,
    )
}

/// `Mon, 09 Nov 2026 08:00:00 GMT`.
pub fn imf_fixdate(unix: i64) -> String {
    const DAYS: [&str; 7] = ["Thu", "Fri", "Sat", "Sun", "Mon", "Tue", "Wed"];
    const MONTHS: [&str; 12] = [
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    ];
    let days = unix.div_euclid(86_400);
    let (y, m, d) = civil(days);
    let s = unix.rem_euclid(86_400);
    format!(
        "{}, {d:02} {} {y:04} {:02}:{:02}:{:02} GMT",
        DAYS[days.rem_euclid(7) as usize],
        MONTHS[(m - 1) as usize],
        s / 3600,
        s % 3600 / 60,
        s % 60
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn formats_and_parses_the_protocol_timestamps() {
        assert_eq!(rfc3339(1_794_211_200), "2026-11-09T08:00:00Z");
        assert_eq!(imf_fixdate(1_794_211_200), "Mon, 09 Nov 2026 08:00:00 GMT");
        assert_eq!(parse_rfc3339("2026-11-09T08:00:00Z"), Some(1_794_211_200));
        assert_eq!(
            parse_rfc3339("2026-11-09T08:00:00.123456Z"),
            Some(1_794_211_200)
        );
        assert_eq!(
            parse_rfc3339("2026-11-09T08:00:00+00:00"),
            Some(1_794_211_200)
        );
        assert_eq!(parse_rfc3339("2026-11-09 08:00:00"), None);
        assert_eq!(rfc3339(0), "1970-01-01T00:00:00Z");
        assert_eq!(rfc3339(951_782_400), "2000-02-29T00:00:00Z");
        for t in [0, 951_782_400, 1_794_211_200, 4_102_444_799] {
            assert_eq!(parse_rfc3339(&rfc3339(t)), Some(t));
        }
    }
}
