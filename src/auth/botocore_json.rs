//! JSON exactly as botocore writes it: Python's `json.dumps` defaults (`", "` and `": "`
//! separators, non-ASCII escaped as `\uXXXX`, no trailing newline) and `%Y-%m-%dT%H:%M:%SZ`
//! timestamps. Files gac shares with the AWS CLI are byte-for-byte what the CLI would write.

use std::io;

use jiff::Timestamp;
use serde::Serialize;
use serde_json::ser::Formatter;

/// Serializes `value` the way `json.dumps(value)` would.
pub fn to_string<T: Serialize>(value: &T) -> String {
    let mut out = Vec::new();
    let mut serializer = serde_json::Serializer::with_formatter(&mut out, PythonFormatter);
    value
        .serialize(&mut serializer)
        .expect("serializing plain data to memory cannot fail");
    String::from_utf8(out).expect("the formatter writes ASCII only")
}

struct PythonFormatter;

impl Formatter for PythonFormatter {
    fn begin_array_value<W: ?Sized + io::Write>(
        &mut self,
        w: &mut W,
        first: bool,
    ) -> io::Result<()> {
        if first { Ok(()) } else { w.write_all(b", ") }
    }

    fn begin_object_key<W: ?Sized + io::Write>(
        &mut self,
        w: &mut W,
        first: bool,
    ) -> io::Result<()> {
        if first { Ok(()) } else { w.write_all(b", ") }
    }

    fn begin_object_value<W: ?Sized + io::Write>(&mut self, w: &mut W) -> io::Result<()> {
        w.write_all(b": ")
    }

    fn write_string_fragment<W: ?Sized + io::Write>(
        &mut self,
        w: &mut W,
        fragment: &str,
    ) -> io::Result<()> {
        // `ensure_ascii=True`: everything outside ASCII becomes UTF-16 `\uXXXX` escapes.
        for c in fragment.chars() {
            if c.is_ascii() {
                w.write_all(&[c as u8])?;
            } else {
                let mut units = [0u16; 2];
                for unit in c.encode_utf16(&mut units) {
                    write!(w, "\\u{unit:04x}")?;
                }
            }
        }
        Ok(())
    }
}

/// `serde` support for the timestamp format botocore writes, accepting any RFC 3339 on read
/// (aws-config writes fractional seconds).
pub mod timestamp {
    use super::Timestamp;
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn format(ts: Timestamp) -> String {
        ts.strftime("%Y-%m-%dT%H:%M:%SZ").to_string()
    }

    pub fn parse(text: &str) -> Option<Timestamp> {
        // Older botocore caches end in `UTC` instead of `Z`.
        let text = text
            .strip_suffix("UTC")
            .map_or_else(|| text.to_owned(), |t| format!("{t}Z"));
        text.parse().ok()
    }

    #[allow(clippy::trivially_copy_pass_by_ref)] // the signature serde's `with` expects
    pub fn serialize<S: Serializer>(ts: &Timestamp, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&format(*ts))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Timestamp, D::Error> {
        let text = String::deserialize(deserializer)?;
        parse(&text).ok_or_else(|| serde::de::Error::custom(format!("invalid timestamp `{text}`")))
    }

    pub mod optional {
        use super::Timestamp;
        use serde::{Deserialize, Deserializer, Serializer};

        #[allow(clippy::ref_option)] // the signature serde's `with` expects
        pub fn serialize<S: Serializer>(
            ts: &Option<Timestamp>,
            serializer: S,
        ) -> Result<S::Ok, S::Error> {
            match ts {
                Some(ts) => serializer.serialize_some(&super::format(*ts)),
                None => serializer.serialize_none(),
            }
        }

        pub fn deserialize<'de, D: Deserializer<'de>>(
            deserializer: D,
        ) -> Result<Option<Timestamp>, D::Error> {
            Option::<String>::deserialize(deserializer)?
                .map(|text| {
                    super::parse(&text).ok_or_else(|| {
                        serde::de::Error::custom(format!("invalid timestamp `{text}`"))
                    })
                })
                .transpose()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    #[test]
    fn matches_python_json_dumps() {
        let mut map = BTreeMap::new();
        map.insert("a", serde_json::json!(["x", 1, null, true]));
        map.insert(
            "b",
            serde_json::json!({"nested": "caf\u{e9} \u{1F600} \"q\" \\ \n"}),
        );
        // python3 -c 'import json; print(json.dumps({"a": ["x", 1, None, True], "b": {"nested": "café 😀 \"q\" \\ \n"}}))'
        assert_eq!(
            to_string(&map),
            "{\"a\": [\"x\", 1, null, true], \"b\": {\"nested\": \"caf\\u00e9 \\ud83d\\ude00 \\\"q\\\" \\\\ \\n\"}}"
        );
    }

    #[test]
    fn timestamps_round_trip_and_accept_rfc3339_variants() {
        let ts = timestamp::parse("2026-10-25T06:01:31Z").unwrap();
        assert_eq!(timestamp::format(ts), "2026-10-25T06:01:31Z");
        let fractional = timestamp::parse("2026-10-25T06:01:13.210505Z").unwrap();
        assert_eq!(timestamp::format(fractional), "2026-10-25T06:01:13Z");
        assert!(timestamp::parse("2026-10-25T06:01:31+00:00").is_some());
        assert!(timestamp::parse("2026-10-25T06:01:31UTC").is_some());
        assert!(timestamp::parse("yesterday").is_none());
    }
}
