//! A read-only health report: each finding has a level and, when something is wrong, a
//! suggested fix. The framework knows nothing about AWS; the checks live in [`aws`].

pub mod aws;

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
        report.fail("c", "broken", "fix it");
        assert!(report.has_failures());
        insta::assert_snapshot!(report.render(), @r"
        [ok] a: fine
        [warn] b: meh
               fix: do this
                    then that
        [FAIL] c: broken
               fix: fix it

        1 ok, 1 warning, 1 failure
        ");
    }
}
