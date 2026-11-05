//! Managed blocks: the only part of an AWS file gac ever writes.
//!
//! A block is delimited by a BEGIN line that also stores the settings that produced it and an
//! END line naming the same session. Updating replaces the block's bytes in place; a new block is
//! appended. Every byte outside a block is left exactly as it was.
//!
//! ```text
//! # BEGIN gac sync session=corp mode=sso name={account}/{role}
//! # Managed by gac: edits inside this block are replaced on the next sync.
//! [profile payments-prod/ReadOnly]
//! ...
//! # END gac sync session=corp
//! ```

use std::fmt::Write as _;
use std::ops::Range;

use percent_encoding::{AsciiSet, CONTROLS, percent_decode_str, utf8_percent_encode};

const BEGIN: &str = "# BEGIN gac sync ";
const END: &str = "# END gac sync ";
pub const NOTICE: &str = "# Managed by gac: edits inside this block are replaced on the next sync.";

/// Characters escaped in BEGIN-line values, so a value is always one space-free token.
const VALUE_ESCAPES: &AsciiSet = &CONTROLS.add(b' ').add(b'%').add(b'=');

/// The settings stored in a BEGIN line, in order. `session` is always first.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Header {
    pub session: String,
    pub settings: Vec<(String, String)>,
}

impl Header {
    pub fn get(&self, key: &str) -> Option<&str> {
        self.settings
            .iter()
            .find(|(k, _)| k == key)
            .map(|(_, v)| v.as_str())
    }

    pub fn get_all<'a>(&'a self, key: &'a str) -> impl Iterator<Item = &'a str> + 'a {
        self.settings
            .iter()
            .filter(move |(k, _)| k == key)
            .map(|(_, v)| v.as_str())
    }

    fn begin_line(&self) -> String {
        let mut line = format!("{BEGIN}session={}", encode(&self.session));
        for (key, value) in &self.settings {
            let _ = write!(line, " {key}={}", encode(value));
        }
        line
    }

    fn end_line(&self) -> String {
        format!("{END}session={}", encode(&self.session))
    }
}

fn encode(value: &str) -> String {
    utf8_percent_encode(value, VALUE_ESCAPES).to_string()
}

fn decode(value: &str) -> Option<String> {
    percent_decode_str(value).decode_utf8().ok().map(Into::into)
}

/// A block found in a file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Block {
    /// Byte range from the start of the BEGIN line through the END line's line ending.
    pub range: Range<usize>,
    pub header: Header,
}

impl Block {
    /// The names of the `[profile NAME]` sections inside the block, as gac writes them.
    pub fn profile_names<'a>(&self, content: &'a str) -> impl Iterator<Item = &'a str> + 'a {
        content[self.range.clone()]
            .lines()
            .filter_map(|line| line.strip_prefix("[profile ")?.strip_suffix(']'))
    }
}

/// Markers that do not form well-nested, unique blocks. gac refuses to write until they are
/// fixed by hand.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum MarkerError {
    #[error("line {line}: unreadable gac BEGIN marker")]
    BadBegin { line: usize },
    #[error("line {line}: gac BEGIN marker inside the block that starts on line {open}")]
    Nested { line: usize, open: usize },
    #[error("line {line}: gac END marker without a matching BEGIN")]
    StrayEnd { line: usize },
    #[error("line {line}: gac END marker for session `{found}` closes the block for `{expected}`")]
    Mismatched {
        line: usize,
        expected: String,
        found: String,
    },
    #[error("line {line}: gac block for session `{session}` has no END marker")]
    Unterminated { line: usize, session: String },
    #[error("line {line}: second gac block for session `{session}`")]
    Duplicate { line: usize, session: String },
}

/// Finds every block in `content`.
pub fn scan(content: &str) -> Result<Vec<Block>, MarkerError> {
    let mut blocks: Vec<Block> = Vec::new();
    let mut open: Option<(usize, usize, Header)> = None; // (start offset, line number, header)
    let mut offset = 0;
    for (index, raw) in content.split_inclusive('\n').enumerate() {
        let line_no = index + 1;
        let line = raw.trim_end_matches(['\n', '\r']);
        if let Some(rest) = line.strip_prefix(BEGIN) {
            if let Some((_, open_line, _)) = &open {
                return Err(MarkerError::Nested {
                    line: line_no,
                    open: *open_line,
                });
            }
            let header = parse_header(rest).ok_or(MarkerError::BadBegin { line: line_no })?;
            if blocks.iter().any(|b| b.header.session == header.session) {
                return Err(MarkerError::Duplicate {
                    line: line_no,
                    session: header.session,
                });
            }
            open = Some((offset, line_no, header));
        } else if let Some(rest) = line.strip_prefix(END) {
            let Some((start, _, header)) = open.take() else {
                return Err(MarkerError::StrayEnd { line: line_no });
            };
            let found = rest
                .trim()
                .strip_prefix("session=")
                .and_then(decode)
                .unwrap_or_default();
            if found != header.session {
                return Err(MarkerError::Mismatched {
                    line: line_no,
                    expected: header.session,
                    found,
                });
            }
            blocks.push(Block {
                range: start..offset + raw.len(),
                header,
            });
        }
        offset += raw.len();
    }
    if let Some((_, line, header)) = open {
        return Err(MarkerError::Unterminated {
            line,
            session: header.session,
        });
    }
    Ok(blocks)
}

fn parse_header(rest: &str) -> Option<Header> {
    let mut tokens = rest.split(' ').filter(|t| !t.is_empty());
    let session = decode(tokens.next()?.strip_prefix("session=")?)?;
    if session.is_empty() {
        return None;
    }
    let settings = tokens
        .map(|token| {
            let (key, value) = token.split_once('=')?;
            Some((key.to_owned(), decode(value)?))
        })
        .collect::<Option<Vec<_>>>()?;
    Some(Header { session, settings })
}

/// The line ending a file already uses, so a block written into it matches.
pub fn line_ending(content: &str) -> &'static str {
    match content.find('\n') {
        Some(i) if i > 0 && content.as_bytes()[i - 1] == b'\r' => "\r\n",
        _ => "\n",
    }
}

/// Renders a complete block: BEGIN, notice, body lines, END.
pub fn render(header: &Header, body: &[String], eol: &str) -> String {
    let mut out = String::new();
    for line in std::iter::once(header.begin_line())
        .chain(std::iter::once(NOTICE.to_owned()))
        .chain(body.iter().cloned())
        .chain(std::iter::once(header.end_line()))
    {
        out.push_str(&line);
        out.push_str(eol);
    }
    out
}

/// Replaces the block for `session` with `block`, or appends `block` after a blank line.
pub fn upsert(content: &str, session: &str, block: &str) -> Result<String, MarkerError> {
    let blocks = scan(content)?;
    if let Some(existing) = blocks.iter().find(|b| b.header.session == session) {
        let mut out = String::with_capacity(content.len() + block.len());
        out.push_str(&content[..existing.range.start]);
        out.push_str(block);
        out.push_str(&content[existing.range.end..]);
        return Ok(out);
    }
    Ok(append(content, block))
}

/// Appends `text` to `content`, after a line ending and one blank line where needed. The
/// original bytes stay a prefix of the result.
pub fn append(content: &str, text: &str) -> String {
    let eol = line_ending(content);
    let mut out = content.to_owned();
    if !out.is_empty() {
        if !out.ends_with('\n') {
            out.push_str(eol);
        }
        // One blank line between the user's last line and the new text, unless one is there.
        let last_line = out
            .strip_suffix('\n')
            .unwrap_or(&out)
            .rsplit('\n')
            .next()
            .unwrap_or_default();
        if !last_line.trim().is_empty() {
            out.push_str(eol);
        }
    }
    out.push_str(text);
    out
}

/// Removes the block with this range, leaving the rest byte for byte.
pub fn without(content: &str, block: &Block) -> String {
    format!(
        "{}{}",
        &content[..block.range.start],
        &content[block.range.end..]
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    fn header(session: &str) -> Header {
        Header {
            session: session.to_owned(),
            settings: vec![
                ("mode".into(), "sso".into()),
                ("name".into(), "{account}/{role}".into()),
            ],
        }
    }

    fn block(session: &str, body: &[&str], eol: &str) -> String {
        let body: Vec<String> = body.iter().map(|s| (*s).to_owned()).collect();
        render(&header(session), &body, eol)
    }

    #[test]
    fn renders_the_documented_shape() {
        let rendered = block("corp", &["[profile a/b]", "sso_session = corp"], "\n");
        insta::assert_snapshot!(rendered, @r"
        # BEGIN gac sync session=corp mode=sso name={account}/{role}
        # Managed by gac: edits inside this block are replaced on the next sync.
        [profile a/b]
        sso_session = corp
        # END gac sync session=corp
        ");
    }

    #[test]
    fn header_values_round_trip_through_escaping() {
        let original = Header {
            session: "corp".into(),
            settings: vec![
                ("include".into(), "pay* with space=and%percent".into()),
                ("include".into(), "dev/*".into()),
            ],
        };
        let rendered = render(&original, &[], "\n");
        assert!(rendered.starts_with("# BEGIN gac sync session=corp include=pay*%20with%20space%3Dand%25percent include=dev/*\n"));
        let blocks = scan(&rendered).unwrap();
        assert_eq!(blocks[0].header, original);
        assert_eq!(blocks[0].header.get_all("include").count(), 2);
    }

    #[test]
    fn appends_after_a_blank_line_and_replaces_in_place() {
        let user = "[profile mine]\nregion = us-east-1";
        let first = upsert(user, "corp", &block("corp", &["one"], "\n")).unwrap();
        assert_eq!(
            first,
            format!("{user}\n\n{}", block("corp", &["one"], "\n")),
            "a newline and a blank separator are added, nothing else"
        );
        let with_suffix = format!("{first}[profile after]\nregion = eu-west-1\n");
        let second = upsert(&with_suffix, "corp", &block("corp", &["two"], "\n")).unwrap();
        assert_eq!(
            second,
            format!(
                "{user}\n\n{}[profile after]\nregion = eu-west-1\n",
                block("corp", &["two"], "\n")
            )
        );
    }

    #[test]
    fn keeps_crlf_files_crlf() {
        let user = "[default]\r\nregion = us-east-1\r\n";
        let eol = line_ending(user);
        assert_eq!(eol, "\r\n");
        let out = upsert(user, "corp", &block("corp", &["x"], eol)).unwrap();
        assert!(out.starts_with(user));
        assert!(!out.replace("\r\n", "").contains('\n'));
        assert_eq!(scan(&out).unwrap().len(), 1);
    }

    #[test]
    fn rejects_broken_markers() {
        let begin = "# BEGIN gac sync session=a mode=sso\n";
        let end_a = "# END gac sync session=a\n";
        assert_eq!(
            scan(&format!("{begin}x\n")).unwrap_err(),
            MarkerError::Unterminated {
                line: 1,
                session: "a".into()
            }
        );
        assert_eq!(scan(end_a).unwrap_err(), MarkerError::StrayEnd { line: 1 });
        assert!(matches!(
            scan(&format!("{begin}{begin}")).unwrap_err(),
            MarkerError::Nested { .. }
        ));
        assert!(matches!(
            scan(&format!("{begin}# END gac sync session=b\n")).unwrap_err(),
            MarkerError::Mismatched { .. }
        ));
        assert!(matches!(
            scan(&format!("{begin}{end_a}{begin}{end_a}")).unwrap_err(),
            MarkerError::Duplicate { .. }
        ));
        assert!(matches!(
            scan("# BEGIN gac sync nosession\n").unwrap_err(),
            MarkerError::BadBegin { .. }
        ));
    }

    #[test]
    fn leaves_other_sessions_blocks_alone() {
        let a = block("a", &["a1"], "\n");
        let b = block("b", &["b1"], "\n");
        let content = format!("{a}\n{b}");
        let out = upsert(&content, "b", &block("b", &["b2"], "\n")).unwrap();
        assert_eq!(out, format!("{a}\n{}", block("b", &["b2"], "\n")));
    }

    /// Arbitrary user-owned config text: any lines that are not gac markers.
    fn user_text() -> impl Strategy<Value = String> {
        let line = prop_oneof![
            Just(String::new()),
            "[a-z \\[\\]=#;._/-]{0,30}",
            "\\[profile [a-z]{1,8}\\]",
            "[a-z_]{1,10} = [a-z0-9 ]{0,10}",
            "# [ -~]{0,40}",
            "\t[a-z]+ = x",
        ];
        (
            proptest::collection::vec(line, 0..12),
            prop_oneof![Just("\n"), Just("\r\n")],
            any::<bool>(),
        )
            .prop_map(|(lines, eol, trailing)| {
                let mut text = lines.join(eol);
                if trailing && !text.is_empty() {
                    text.push_str(eol);
                }
                text
            })
            .prop_filter("no gac markers", |t| {
                !t.contains("# BEGIN gac") && !t.contains("# END gac")
            })
    }

    proptest! {
        #[test]
        fn never_changes_a_byte_outside_the_block(
            before in user_text(),
            after in user_text(),
            body1 in proptest::collection::vec("[a-z]{1,8}", 0..5),
            body2 in proptest::collection::vec("[a-z]{1,8}", 0..5),
        ) {
            let render_body = |body: &[String], content: &str| {
                render(&header("corp"), body, line_ending(content))
            };

            // First sync appends; the user's text stays a byte-exact prefix.
            let first = upsert(&before, "corp", &render_body(&body1, &before)).unwrap();
            prop_assert!(first.starts_with(&before));
            let separator = &first[before.len()..first.len() - render_body(&body1, &before).len()];
            prop_assert!(separator.chars().all(|c| c == '\n' || c == '\r'));

            // The user adds text after the block; a re-sync replaces only the block.
            let edited = format!("{first}{after}");
            let block1 = scan(&edited).unwrap()[0].range.clone();
            let second = upsert(&edited, "corp", &render_body(&body2, &before)).unwrap();
            let block2 = scan(&second).unwrap()[0].range.clone();
            prop_assert_eq!(&second[..block2.start], &edited[..block1.start]);
            prop_assert_eq!(&second[block2.end..], &edited[block1.end..]);

            // Syncing the same body again is a no-op.
            let third = upsert(&second, "corp", &render_body(&body2, &before)).unwrap();
            prop_assert_eq!(third, second);
        }
    }
}
