//! One section of the config file as editable lines, for the few edits gac makes to sections it
//! did not write wholesale: the `[default]` profile `gac select` manages, and the fixes of
//! `gac doctor --fix`. An edit changes only the keys it names and keeps every other line as it
//! was.

use std::ops::Range;

use crate::aws_files::{default_block, managed_block};

/// A section: its byte range in the file and its lines, starting with the header.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Section {
    pub range: Range<usize>,
    pub lines: Vec<String>,
}

/// The section a fix edits.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Target<'a> {
    /// `[profile NAME]`, or `[default]` for the default profile.
    Profile(&'a str),
    /// `[sso-session NAME]`.
    SsoSession(&'a str),
}

/// Who wrote a section, which decides whether gac may edit it without asking.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Owner {
    /// Inside one of gac's blocks.
    Gac,
    /// Anywhere else.
    User,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum FindError {
    #[error("there is no {0} section")]
    Missing(String),
    #[error("{0} is written more than once, and the SDKs merge the copies")]
    Duplicate(String),
    #[error("the gac markers are broken")]
    BrokenMarkers,
}

impl Target<'_> {
    fn matches(self, line: &str) -> bool {
        let Some(words) = header_words(line) else {
            return false;
        };
        match (self, words.as_slice()) {
            (Self::Profile(name), ["profile", n])
            | (Self::SsoSession(name), ["sso-session", n]) => *n == name,
            (Self::Profile("default"), ["default"]) => true,
            _ => false,
        }
    }
}

impl std::fmt::Display for Target<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Profile("default") => f.write_str("[default]"),
            Self::Profile(name) => write!(f, "[profile {name}]"),
            Self::SsoSession(name) => write!(f, "[sso-session {name}]"),
        }
    }
}

/// The words of a section header line, e.g. `["profile", "dev"]`, if it is one.
fn header_words(line: &str) -> Option<Vec<&str>> {
    let inner = line.trim().strip_prefix('[')?.strip_suffix(']')?;
    Some(inner.split_whitespace().collect())
}

pub fn is_header(line: &str) -> bool {
    header_words(line).is_some()
}

pub fn is_blank_or_comment(line: &str) -> bool {
    let trimmed = line.trim_start();
    trimmed.is_empty() || trimmed.starts_with('#') || trimmed.starts_with(';')
}

/// The lines of `content` with their byte offsets, without line endings.
pub fn lines(content: &str) -> Vec<(usize, &str)> {
    content
        .split_inclusive('\n')
        .scan(0, |offset, raw| {
            let start = *offset;
            *offset += raw.len();
            Some((start, raw))
        })
        .collect()
}

fn text(raw: &str) -> &str {
    raw.trim_end_matches(['\n', '\r'])
}

/// The section whose header is line `index`: it runs to the next header or gac marker, and the
/// blank and comment lines at its end belong to what follows.
pub fn at(lines: &[(usize, &str)], index: usize) -> Section {
    let mut stop = index + 1;
    let mut last = index;
    while stop < lines.len() {
        let next = text(lines[stop].1);
        if is_header(next) || next.starts_with("# BEGIN ") || next.starts_with("# END ") {
            break;
        }
        if !is_blank_or_comment(next) {
            last = stop;
        }
        stop += 1;
    }
    let (start, _) = lines[index];
    let (last_start, last_raw) = lines[last];
    Section {
        range: start..last_start + last_raw.len(),
        lines: lines[index..=last]
            .iter()
            .map(|(_, raw)| text(raw).to_owned())
            .collect(),
    }
}

/// Finds the one section `target` names in the config file's `content`, and who wrote it.
pub fn find(content: &str, target: Target<'_>) -> Result<(Section, Owner), FindError> {
    let mut gac: Vec<Range<usize>> = managed_block::scan(content)
        .map_err(|_| FindError::BrokenMarkers)?
        .into_iter()
        .map(|block| block.range)
        .collect();
    match default_block::find(content) {
        Ok(default_block::Found::Managed(section)) => gac.push(section.range),
        Ok(_) => {}
        Err(_) => return Err(FindError::BrokenMarkers),
    }
    let lines = lines(content);
    let mut found = None;
    for (index, (start, raw)) in lines.iter().enumerate() {
        if !target.matches(text(raw)) {
            continue;
        }
        if found.is_some() {
            return Err(FindError::Duplicate(target.to_string()));
        }
        let owner = if gac.iter().any(|range| range.contains(start)) {
            Owner::Gac
        } else {
            Owner::User
        };
        found = Some((at(&lines, index), owner));
    }
    found.ok_or_else(|| FindError::Missing(target.to_string()))
}

impl Section {
    /// A new section with only its header.
    pub fn new(header: &str) -> Self {
        Self {
            range: 0..0,
            lines: vec![header.to_owned()],
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
        if self.is_padded() {
            self.pad();
        }
    }

    /// Makes `change`, then lines up the `=` of every key if the section was written that way
    /// before it, even when the change removed the only padded key.
    pub fn edit(&mut self, change: impl FnOnce(&mut Self)) {
        let padded = self.is_padded();
        change(self);
        if padded {
            self.pad();
        }
    }

    fn is_padded(&self) -> bool {
        self.key_lines().any(|(i, k)| {
            self.lines[i]
                .strip_prefix(k)
                .is_some_and(|rest| rest.starts_with("  "))
        })
    }

    fn pad(&mut self) {
        let keys: Vec<(usize, String)> = self.key_lines().map(|(i, k)| (i, k.to_owned())).collect();
        let width = keys.iter().map(|(_, k)| k.len()).max().unwrap_or(0);
        for (index, key) in keys {
            let value = self.lines[index]
                .split_once('=')
                .map(|(_, v)| v.trim().to_owned())
                .unwrap_or_default();
            self.lines[index] = format!("{key:<width$} = {value}");
        }
    }

    /// The section's lines, each ended with `eol`.
    pub fn render(&self, eol: &str) -> String {
        let mut out = String::new();
        for line in &self.lines {
            out.push_str(line);
            out.push_str(eol);
        }
        out
    }

    /// `content` with this section, edited, in place of the bytes it was read from.
    pub fn splice_into(&self, content: &str) -> String {
        let eol = managed_block::line_ending(content);
        let mut rendered = self.render(eol);
        let original = &content[self.range.clone()];
        if !original.ends_with('\n') {
            rendered.truncate(rendered.len() - eol.len());
        }
        format!(
            "{}{rendered}{}",
            &content[..self.range.start],
            &content[self.range.end..]
        )
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

    const CONFIG: &str = "\
[sso-session corp]
sso_start_url = https://corp.awsapps.com/start
sso_region    = us-east-1

# old style
[profile  legacy]
sso_start_url = https://old.awsapps.com/start
sso_region = eu-west-1
sso_account_id = 111122223333

# BEGIN gac-redux sync session=mine
[sso-session mine]
sso_start_url = https://mine.awsapps.com/start
sso_region = us-west-2
# END gac-redux sync session=mine
";

    #[test]
    fn finds_sections_and_who_wrote_them() {
        let (section, owner) = find(CONFIG, Target::Profile("legacy")).unwrap();
        assert_eq!(owner, Owner::User);
        assert_eq!(section.lines[0], "[profile  legacy]");
        assert_eq!(section.get("sso_region"), Some("eu-west-1"));
        assert!(
            CONFIG[section.range.clone()].ends_with("111122223333\n"),
            "the comment and blank line before the block are not part of it"
        );

        let (section, owner) = find(CONFIG, Target::SsoSession("mine")).unwrap();
        assert_eq!(owner, Owner::Gac);
        assert_eq!(section.lines.len(), 3, "the END marker is not part of it");

        assert_eq!(
            find(CONFIG, Target::Profile("nope")).unwrap_err(),
            FindError::Missing("[profile nope]".into())
        );
        let twice = format!("{CONFIG}[sso-session corp]\nsso_region = us-east-1\n");
        assert_eq!(
            find(&twice, Target::SsoSession("corp")).unwrap_err(),
            FindError::Duplicate("[sso-session corp]".into())
        );
        assert_eq!(
            find("[default]\nregion = x\n", Target::Profile("default"))
                .unwrap()
                .0
                .lines,
            ["[default]", "region = x"]
        );
    }

    #[test]
    fn an_edit_changes_only_its_own_lines() {
        let (mut section, _) = find(CONFIG, Target::SsoSession("corp")).unwrap();
        section.set(
            "sso_registration_scopes",
            "sso:account:access",
            &["sso_region"],
        );
        section.align();
        let updated = section.splice_into(CONFIG);
        assert_eq!(
            updated,
            CONFIG.replace(
                "sso_region    = us-east-1\n",
                "sso_region              = us-east-1\nsso_registration_scopes = sso:account:access\n"
            )
            .replace("sso_start_url = https://corp", "sso_start_url           = https://corp")
        );

        let crlf = "[profile a]\r\nregion = x";
        let (mut section, _) = find(crlf, Target::Profile("a")).unwrap();
        section.set("output", "json", &["region"]);
        assert_eq!(
            section.splice_into(crlf),
            "[profile a]\r\nregion = x\r\noutput = json",
            "line endings and a missing final newline are kept"
        );
    }
}
