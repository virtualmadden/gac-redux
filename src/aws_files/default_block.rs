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

use crate::aws_files::section::{self, Section};

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

/// Finds the `[default]` profile in the config file's `content`. A managed section's range is
/// the whole block.
pub fn find(content: &str) -> Result<Found, DefaultError> {
    let lines = section::lines(content);
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
                let found = section::at(&lines, index);
                index += found.lines.len();
                hand = Some(found);
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

/// A new `[default]` section with no keys.
pub fn empty() -> Section {
    Section::new("[default]")
}

/// Renders the section as the default block.
pub fn render(section: &Section, eol: &str) -> String {
    let mut out = String::new();
    for line in [BEGIN, NOTICE]
        .into_iter()
        .chain(section.lines.iter().map(String::as_str))
        .chain([END])
    {
        out.push_str(line);
        out.push_str(eol);
    }
    out
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
        insta::assert_snapshot!(render(&section, "\n"), @r"
        # BEGIN gac-redux default
        # Managed by gac-redux: `gac select` replaces this block.
        [default]
        sso_session    = corp
        region         = us-west-2
        sso_account_id = 111122223333
        sso_role_name  = ReadOnly
        # END gac-redux default
        ");

        let rendered = HAND.replace(&HAND[section.range.clone()], &render(&section, "\n"));
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
        let mut section = empty();
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
        let block = render(&empty(), "\n");
        assert!(matches!(
            find(&format!("{block}[default]\n")).unwrap_err(),
            DefaultError::TwoSections { .. }
        ));
    }
}
