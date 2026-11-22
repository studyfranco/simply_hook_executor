//! UTC timestamps shared by the database and the JSON API.

use sea_orm::{DatabaseBackend, Value};
use serde::{Deserialize, Deserializer, Serializer, de, ser};
use time::{OffsetDateTime, PrimitiveDateTime, macros::format_description};

/// Returns the current UTC time without an offset, as stored in the database.
#[must_use]
pub fn now_utc() -> PrimitiveDateTime {
    let now = OffsetDateTime::now_utc();
    PrimitiveDateTime::new(now.date(), now.time())
}

/// Defines the comparison boundary for a timestamp stored as SQLite text.
#[derive(Clone, Copy)]
pub(crate) enum Bound {
    Lower,
    Upper,
}

pub(crate) fn database_bound(
    backend: DatabaseBackend,
    value: PrimitiveDateTime,
    bound: Bound,
) -> Value {
    if backend != DatabaseBackend::Sqlite {
        return value.into();
    }

    // Legacy SQLite rows omitted zero fractions and otherwise used 3, 6, or
    // 9 digits. The new driver trims trailing zeros and always writes a dot.
    // Select the shortest or longest spelling of the same instant so a
    // comparison can include or exclude all spellings and still use the index.
    let format = match bound {
        Bound::Lower if value.nanosecond() == 0 => {
            format_description!("[year]-[month]-[day] [hour]:[minute]:[second]")
        }
        Bound::Lower => {
            format_description!("[year]-[month]-[day] [hour]:[minute]:[second].[subsecond]")
        }
        Bound::Upper => {
            format_description!(
                "[year]-[month]-[day] [hour]:[minute]:[second].[subsecond digits:9]"
            )
        }
    };
    value
        .format(format)
        .map_or_else(|_| value.into(), Into::into)
}

fn format_timestamp(value: PrimitiveDateTime) -> Result<String, time::error::Format> {
    let format = if value.nanosecond() == 0 {
        format_description!("[year]-[month]-[day]T[hour]:[minute]:[second]")
    } else if value.nanosecond().is_multiple_of(1_000_000) {
        format_description!("[year]-[month]-[day]T[hour]:[minute]:[second].[subsecond digits:3]")
    } else if value.nanosecond().is_multiple_of(1_000) {
        format_description!("[year]-[month]-[day]T[hour]:[minute]:[second].[subsecond digits:6]")
    } else {
        format_description!("[year]-[month]-[day]T[hour]:[minute]:[second].[subsecond digits:9]")
    };
    value.format(format)
}

fn parse_timestamp(value: &str) -> Result<PrimitiveDateTime, time::error::Parse> {
    PrimitiveDateTime::parse(
        value,
        format_description!(
            "[year]-[month]-[day]T[hour]:[minute]:[second][optional [.[subsecond]]]"
        ),
    )
}

pub(crate) fn serialize<S: Serializer>(
    value: &PrimitiveDateTime,
    serializer: S,
) -> Result<S::Ok, S::Error> {
    serializer.serialize_str(&format_timestamp(*value).map_err(ser::Error::custom)?)
}

pub(crate) fn deserialize<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<PrimitiveDateTime, D::Error> {
    parse_timestamp(&String::deserialize(deserializer)?).map_err(de::Error::custom)
}

pub(crate) mod optional {
    use std::borrow::Borrow;

    use serde::{Deserialize, Deserializer, Serializer, de};
    use time::PrimitiveDateTime;

    use super::parse_timestamp;

    pub(crate) fn serialize<S: Serializer>(
        value: impl Borrow<Option<PrimitiveDateTime>>,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        match value.borrow() {
            Some(value) => super::serialize(value, serializer),
            None => serializer.serialize_none(),
        }
    }

    pub(crate) fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Option<PrimitiveDateTime>, D::Error> {
        Option::<String>::deserialize(deserializer)?
            .as_deref()
            .map(parse_timestamp)
            .transpose()
            .map_err(de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use time::macros::datetime;

    #[derive(Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
    struct Timestamp(#[serde(with = "super")] PrimitiveDateTime);

    #[test]
    fn json_preserves_naive_iso_timestamp_precision() {
        for (date, expected) in [
            (datetime!(2026-11-22 12:34:56), "2026-11-22T12:34:56"),
            (datetime!(2026-11-22 12:34:56.1), "2026-11-22T12:34:56.100"),
            (
                datetime!(2026-11-22 12:34:56.1234),
                "2026-11-22T12:34:56.123400",
            ),
            (
                datetime!(2026-11-22 12:34:56.1234567),
                "2026-11-22T12:34:56.123456700",
            ),
        ] {
            let json = serde_json::to_string(&Timestamp(date)).unwrap();
            assert_eq!(json, format!("\"{expected}\""));
            assert_eq!(
                serde_json::from_str::<Timestamp>(&json).unwrap(),
                Timestamp(date)
            );
        }
    }
}
