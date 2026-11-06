//! A health report: each finding has a level and, when something is wrong, a suggested fix,
//! which some findings can apply themselves. The framework knows nothing about AWS; the checks
//! live in [`aws`] and the fixes they can apply in [`fix`].

pub mod aws;
pub mod fix;

use std::fmt::Write as _;

use serde::Serialize;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Level {
    Ok,
    Warn,
    Fail,
}

impl Level {
    fn label(self) -> &'static str {
        match self {
            Self::Ok => "ok",
            Self::Warn => "warn",
            Self::Fail => "FAIL",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Finding {
    pub check: &'static str,
    pub level: Level,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fix: Option<String>,
    /// `--fix` can apply the fix.
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub fixable: bool,
}

#[derive(Debug, Default, Serialize)]
pub struct Report {
    pub findings: Vec<Finding>,
}

impl Report {
    pub fn ok(&mut self, check: &'static str, message: impl Into<String>) {
        self.push(check, Level::Ok, message.into(), None);
    }

    pub fn warn(
        &mut self,
        check: &'static str,
        message: impl Into<String>,
        fix: impl Into<String>,
    ) {
        self.push(check, Level::Warn, message.into(), Some(fix.into()));
    }

    /// A warning whose fix `--fix` can apply.
    pub fn warn_fixable(
        &mut self,
        check: &'static str,
        message: impl Into<String>,
        fix: impl Into<String>,
    ) {
        self.warn(check, message, fix);
        self.findings
            .last_mut()
            .expect("a finding was just pushed")
            .fixable = true;
    }

    pub fn fail(
        &mut self,
        check: &'static str,
        message: impl Into<String>,
        fix: impl Into<String>,
    ) {
        self.push(check, Level::Fail, message.into(), Some(fix.into()));
    }

    fn push(&mut self, check: &'static str, level: Level, message: String, fix: Option<String>) {
        self.findings.push(Finding {
            check,
            level,
            message,
            fix,
            fixable: false,
        });
    }

    pub fn has_failures(&self) -> bool {
        self.findings.iter().any(|f| f.level == Level::Fail)
    }

    pub fn render(&self) -> String {
        let mut out = String::new();
        for finding in &self.findings {
            let _ = writeln!(
                out,
                "[{}] {}: {}",
                finding.level.label(),
                finding.check,
                finding.message
            );
            if let Some(fix) = &finding.fix {
                for (index, line) in fix.lines().enumerate() {
                    let lead = if index == 0 { "fix:" } else { "    " };
                    let _ = writeln!(out, "       {lead} {line}");
                }
            }
        }
        let count = |level| self.findings.iter().filter(|f| f.level == level).count();
        let plural = |n: usize, word: &str| format!("{n} {word}{}", if n == 1 { "" } else { "s" });
        let _ = writeln!(
            out,
            "\n{} ok, {}, {}",
            count(Level::Ok),
            plural(count(Level::Warn), "warning"),
            plural(count(Level::Fail), "failure")
        );
        let fixable = self.findings.iter().filter(|f| f.fixable).count();
        if fixable > 0 {
            let _ = writeln!(out, "--fix can apply {fixable} of the fixes.");
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn renders_findings_with_fixes() {
        let mut report = Report::default();
        report.ok("a", "fine");
        report.warn("b", "meh", "do this\nthen that");
        report.warn_fixable("d", "fixable", "gac can");
        report.fail("c", "broken", "fix it");
        assert!(report.has_failures());
        insta::assert_snapshot!(report.render(), @r"
        [ok] a: fine
        [warn] b: meh
               fix: do this
                    then that
        [warn] d: fixable
               fix: gac can
        [FAIL] c: broken
               fix: fix it

        1 ok, 2 warnings, 1 failure
        --fix can apply 1 of the fixes.
        ");
    }
}
