//! The default block: the `[default]` profile, which gac writes only once the user has handed it
//! over. Its body is a plain config section, so the keys it holds are read back from the lines.
//!
//! ```text
//! # BEGIN gac-redux default
//! # Managed by gac-redux: `gac select` replaces this block.
//! [default]
//! sso_session = corp
//! region = us-west-2
//! sso_account_id = 111122223333
//! sso_role_name = ReadOnly
//! # END gac-redux default
//! ```
//!
//! `gac select --clear` takes the account and role out again, leaving the rest as it was.

use std::ops::Range;

const BEGIN: &str = "# BEGIN gac-redux default";
const END: &str = "# END gac-redux default";
pub const NOTICE: &str = "# Managed by gac-redux: `gac select` replaces this block.";

/// The keys that pick an account and role; everything else in the section is the user's.
pub const ACCOUNT_KEY: &str = "sso_account_id";
pub const ROLE_KEY: &str = "sso_role_name";
pub const SESSION_KEY: &str = "sso_session";

/// Where the `[default]` profile is, and who owns it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Found {
    /// No `[default]` section at all.
    Absent,
    /// A section the user wrote. gac takes it over only with consent.
    HandWritten(Section),
    /// The default block.
    Managed(Section),
}

/// A `[default]` section: its byte range in the file (the whole block, when managed) and its
/// lines, starting with the `[default]` header.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Section {
    pub range: Range<usize>,
    pub lines: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum DefaultError {
    #[error("line {line}: the gac default block has no END marker")]
    Unterminated { line: usize },
    #[error("line {line}: gac default END marker without a matching BEGIN")]
    StrayEnd { line: usize },
    #[error("line {line}: a second gac default block")]
    Duplicate { line: usize },
    #[error("line {line}: the gac default block does not hold a [default] section")]
    NoSection { line: usize },
    #[error("line {line}: a second [default] section")]
    TwoSections { line: usize },
    #[error("line {line}: [profile default] in the config file names the default profile too")]
    ProfileDefault { line: usize },
}

/// Finds the `[default]` profile in the config file's `content`.
pub fn find(content: &str) -> Result<Found, DefaultError> {
    let lines: Vec<(usize, &str)> = content
        .split_inclusive('\n')
        .scan(0, |offset, raw| {
            let start = *offset;
            *offset += raw.len();
            Some((start, raw))
        })
        .collect();
    let text = |raw: &str| raw.trim_end_matches(['\n', '\r']).to_owned();

    let mut managed: Option<Section> = None;
    let mut hand: Option<Section> = None;
    let mut index = 0;
    while index < lines.len() {
        let (start, raw) = lines[index];
        let line = text(raw);
        let line_no = index + 1;
        if line.trim_end() == BEGIN {
            if managed.is_some() {
                return Err(DefaultError::Duplicate { line: line_no });
            }
            let close = (index + 1..lines.len())
                .find(|&i| text(lines[i].1).trim_end() == END)
                .ok_or(DefaultError::Unterminated { line: line_no })?;
            let body: Vec<String> = lines[index + 1..close]
                .iter()
                .map(|(_, raw)| text(raw))
                .filter(|l| l != NOTICE)
                .collect();
            if !body
                .first()
                .is_some_and(|l| section_name(l) == Some(Name::Default))
            {
                return Err(DefaultError::NoSection { line: line_no });
            }
            let (end_start, end_raw) = lines[close];
            managed = Some(Section {
                range: start..end_start + end_raw.len(),
                lines: body,
            });
            index = close + 1;
            continue;
        }
        if line.trim_end() == END {
            return Err(DefaultError::StrayEnd { line: line_no });
        }
        match section_name(&line) {
            Some(Name::ProfileDefault) => {
                return Err(DefaultError::ProfileDefault { line: line_no });
            }
            Some(Name::Default) => {
                if hand.is_some() {
                    return Err(DefaultError::TwoSections { line: line_no });
                }
                // The section runs to the next header or marker; blank and comment lines at its
                // end belong to what follows.
                let mut stop = index + 1;
                let mut last = index;
                while stop < lines.len() {
                    let next = text(lines[stop].1);
                    if section_name(&next).is_some() || next.starts_with("# BEGIN ") {
                        break;
                    }
                    if !is_blank_or_comment(&next) {
                        last = stop;
                    }
                    stop += 1;
                }
                let (last_start, last_raw) = lines[last];
                hand = Some(Section {
                    range: start..last_start + last_raw.len(),
                    lines: lines[index..=last]
                        .iter()
                        .map(|(_, raw)| text(raw))
                        .collect(),
                });
                index = last + 1;
                continue;
            }
            _ => {}
        }
        index += 1;
    }
    match (managed, hand) {
        (Some(_), Some(hand)) => Err(DefaultError::TwoSections {
            line: content[..hand.range.start].lines().count() + 1,
        }),
        (Some(section), None) => Ok(Found::Managed(section)),
        (None, Some(section)) => Ok(Found::HandWritten(section)),
        (None, None) => Ok(Found::Absent),
    }
}

#[derive(Debug, PartialEq, Eq)]
enum Name {
    Default,
    ProfileDefault,
    Other,
}

/// The kind of section a header line opens, if it is one.
fn section_name(line: &str) -> Option<Name> {
    let inner = line.trim().strip_prefix('[')?.strip_suffix(']')?.trim();
    let words: Vec<&str> = inner.split_whitespace().collect();
    Some(match words.as_slice() {
        ["default"] => Name::Default,
        ["profile", "default"] => Name::ProfileDefault,
        _ => Name::Other,
    })
}

fn is_blank_or_comment(line: &str) -> bool {
    let trimmed = line.trim_start();
    trimmed.is_empty() || trimmed.starts_with('#') || trimmed.starts_with(';')
}

impl Section {
    /// A new `[default]` section with no keys.
    pub fn empty() -> Self {
        Self {
            range: 0..0,
            lines: vec!["[default]".to_owned()],
        }
    }

    /// The value of `key`, as the AWS CLI reads a simple `key = value` line.
    pub fn get(&self, key: &str) -> Option<&str> {
        self.key_lines()
            .find(|(_, k)| *k == key)
            .and_then(|(i, _)| self.lines[i].split_once('='))
            .map(|(_, value)| value.trim())
    }

    /// Sets `key` to `value`: in place when the key is there, otherwise after the last of the
    /// `after` keys present, or right after the header.
    pub fn set(&mut self, key: &str, value: &str, after: &[&str]) {
        if let Some(index) = self.position(key) {
            let (left, _) = self.lines[index]
                .split_once('=')
                .expect("a key line has `=`");
            self.lines[index] = format!("{left}= {value}");
            return;
        }
        let anchor = self
            .key_lines()
            .filter(|(_, k)| after.contains(k))
            .map(|(i, _)| self.value_end(i))
            .max()
            .unwrap_or(1);
        self.lines.insert(anchor, format!("{key} = {value}"));
    }

    /// Removes `key` and its continuation lines.
    pub fn remove(&mut self, key: &str) {
        if let Some(index) = self.position(key) {
            let end = self.value_end(index);
            self.lines.drain(index..end);
        }
    }

    /// Lines up the `=` of every key when the section was written that way (any key padded with
    /// more than one space), so an added key matches the user's style.
    pub fn align(&mut self) {
        let keys: Vec<(usize, String)> = self.key_lines().map(|(i, k)| (i, k.to_owned())).collect();
        let padded = keys.iter().any(|(i, k)| {
            self.lines[*i]
                .strip_prefix(k.as_str())
                .is_some_and(|rest| rest.starts_with("  "))
        });
        if !padded {
            return;
        }
        let width = keys.iter().map(|(_, k)| k.len()).max().unwrap_or(0);
        for (index, key) in keys {
            let value = self.lines[index]
                .split_once('=')
                .map(|(_, v)| v.trim().to_owned())
                .unwrap_or_default();
            self.lines[index] = format!("{key:<width$} = {value}");
        }
    }

    /// Renders the section as the default block.
    pub fn render(&self, eol: &str) -> String {
        let mut out = String::new();
        for line in [BEGIN, NOTICE]
            .into_iter()
            .chain(self.lines.iter().map(String::as_str))
            .chain([END])
        {
            out.push_str(line);
            out.push_str(eol);
        }
        out
    }

    fn position(&self, key: &str) -> Option<usize> {
        self.key_lines().find(|(_, k)| *k == key).map(|(i, _)| i)
    }

    /// The index and key of every top-level `key = value` line after the header.
    fn key_lines(&self) -> impl Iterator<Item = (usize, &str)> {
        self.lines
            .iter()
            .enumerate()
            .skip(1)
            .filter_map(|(i, line)| {
                if line.starts_with([' ', '\t']) || is_blank_or_comment(line) {
                    return None;
                }
                let (key, _) = line.split_once('=')?;
                Some((i, key.trim()))
            })
    }

    /// One past the last line of the value that starts at `index`, continuation lines included.
    fn value_end(&self, index: usize) -> usize {
        let mut end = index + 1;
        while self
            .lines
            .get(end)
            .is_some_and(|l| l.starts_with([' ', '\t']) && !l.trim().is_empty())
        {
            end += 1;
        }
        end
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const HAND: &str = "\
[sso-session corp]
sso_start_url = https://corp.awsapps.com/start

# No account here on purpose.
[default]
sso_session = corp
region      = us-west-2

# about the next one
[profile dev]
region = eu-west-1
";

    #[test]
    fn finds_a_hand_written_section_without_the_comments_that_follow_it() {
        let Found::HandWritten(section) = find(HAND).unwrap() else {
            panic!("expected a hand-written section");
        };
        assert_eq!(
            &HAND[section.range.clone()],
            "[default]\nsso_session = corp\nregion      = us-west-2\n"
        );
        assert_eq!(section.get("sso_session"), Some("corp"));
        assert_eq!(section.get("region"), Some("us-west-2"));
    }

    #[test]
    fn sets_and_clears_the_account_in_the_users_style() {
        let Found::HandWritten(mut section) = find(HAND).unwrap() else {
            panic!("expected a hand-written section");
        };
        let original = section.lines.clone();
        section.set(SESSION_KEY, "corp", &[]);
        section.set(ACCOUNT_KEY, "111122223333", &[SESSION_KEY, "region"]);
        section.set(ROLE_KEY, "ReadOnly", &[ACCOUNT_KEY]);
        section.align();
        insta::assert_snapshot!(section.render("\n"), @r"
        # BEGIN gac-redux default
        # Managed by gac-redux: `gac select` replaces this block.
        [default]
        sso_session    = corp
        region         = us-west-2
        sso_account_id = 111122223333
        sso_role_name  = ReadOnly
        # END gac-redux default
        ");

        let rendered = HAND.replace(&HAND[section.range.clone()], &section.render("\n"));
        let Found::Managed(mut managed) = find(&rendered).unwrap() else {
            panic!("expected the managed block");
        };
        assert_eq!(managed.get(ACCOUNT_KEY), Some("111122223333"));
        managed.remove(ACCOUNT_KEY);
        managed.remove(ROLE_KEY);
        managed.align();
        assert_eq!(
            managed.lines,
            ["[default]", "sso_session = corp", "region      = us-west-2"],
            "clearing restores the section's own alignment"
        );
        assert_eq!(managed.lines, original);
    }

    #[test]
    fn an_unpadded_section_stays_unpadded() {
        let mut section = Section::empty();
        section.set(SESSION_KEY, "corp", &[]);
        section.set(ACCOUNT_KEY, "111122223333", &[SESSION_KEY]);
        section.align();
        assert_eq!(
            section.lines,
            [
                "[default]",
                "sso_session = corp",
                "sso_account_id = 111122223333"
            ]
        );
    }

    #[test]
    fn rejects_layouts_it_cannot_own() {
        assert_eq!(find("[x]\n").unwrap(), Found::Absent);
        assert_eq!(
            find("[default]\n[default]\n").unwrap_err(),
            DefaultError::TwoSections { line: 2 }
        );
        assert_eq!(
            find("[profile  default]\n").unwrap_err(),
            DefaultError::ProfileDefault { line: 1 }
        );
        assert_eq!(
            find("# BEGIN gac-redux default\n[default]\n").unwrap_err(),
            DefaultError::Unterminated { line: 1 }
        );
        assert_eq!(
            find("# END gac-redux default\n").unwrap_err(),
            DefaultError::StrayEnd { line: 1 }
        );
        assert_eq!(
            find("# BEGIN gac-redux default\nx = 1\n# END gac-redux default\n").unwrap_err(),
            DefaultError::NoSection { line: 1 }
        );
        let block = Section::empty().render("\n");
        assert!(matches!(
            find(&format!("{block}[default]\n")).unwrap_err(),
            DefaultError::TwoSections { .. }
        ));
    }
}
