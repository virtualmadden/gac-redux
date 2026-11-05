//! What `sync` writes: profile names from a template, the account and role selection, the
//! settings stored in the block's BEGIN line, and the rendered profiles.

use std::collections::BTreeMap;
use std::fmt;
use std::str::FromStr;

use globset::{GlobBuilder, GlobSet, GlobSetBuilder};

use crate::aws_files::SsoSessionConfig;
use crate::aws_files::managed_block::Header;
use crate::domain::{ProfileName, Region, RoleName, SessionName, is_sdk_identifier_char};
use crate::error::{Error, Result};
use crate::portal::Account;

pub const DEFAULT_TEMPLATE: &str = "{account}/{role}";

const PLACEHOLDERS: &[&str] = &["account", "account_id", "role", "session"];

/// The profile-name template, such as `{account}/{role}`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NameTemplate(String);

impl Default for NameTemplate {
    fn default() -> Self {
        Self(DEFAULT_TEMPLATE.to_owned())
    }
}

impl fmt::Display for NameTemplate {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl FromStr for NameTemplate {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        let invalid = |why: String| {
            Error::usage(format!("invalid name template `{s}`: {why}")).with_hint(
                "use {account}, {account_id}, {role} and {session}, e.g. `{account}/{role}`",
            )
        };
        let mut rest = s;
        let mut placeholders = 0;
        while let Some(open) = rest.find(['{', '}']) {
            if rest.as_bytes()[open] == b'}' {
                return Err(invalid("unmatched `}`".into()));
            }
            let after = &rest[open + 1..];
            let close = after
                .find('}')
                .ok_or_else(|| invalid("unmatched `{`".into()))?;
            let name = &after[..close];
            if !PLACEHOLDERS.contains(&name) {
                return Err(invalid(format!("unknown placeholder `{{{name}}}`")));
            }
            placeholders += 1;
            rest = &after[close + 1..];
        }
        if placeholders == 0 {
            return Err(invalid(
                "it has no placeholders, so every profile would share one name".into(),
            ));
        }
        Ok(Self(s.to_owned()))
    }
}

impl NameTemplate {
    fn render(
        &self,
        account: &Account,
        role: &RoleName,
        session: &SessionName,
    ) -> Result<ProfileName> {
        let name = self
            .0
            .replace("{account_id}", account.id.as_str())
            .replace("{account}", &account_slug(account))
            .replace("{role}", &role_slug(role.as_str()))
            .replace("{session}", session.as_str());
        name.parse().map_err(|_| {
            Error::usage(format!(
                "the template `{self}` produces `{name}`, which the AWS SDKs would ignore"
            ))
        })
    }
}

/// An account name as it appears in profile names: lower case, with every run of characters
/// outside the SDK identifier set (and `/`, the separator) folded into one `-`.
pub fn account_slug(account: &Account) -> String {
    let slug = fold(&account.name.to_lowercase());
    if slug.is_empty() {
        account.id.to_string()
    } else {
        slug
    }
}

/// A role name as it appears in profile names: case kept, invalid characters folded into `-`.
fn role_slug(role: &str) -> String {
    let slug = fold(role);
    if slug.is_empty() {
        "role".to_owned()
    } else {
        slug
    }
}

fn fold(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for c in text.chars() {
        if is_sdk_identifier_char(c) && c != '/' {
            out.push(c);
        } else if !out.ends_with('-') {
            out.push('-');
        }
    }
    out.trim_matches('-').to_owned()
}

/// Which accounts and roles to sync. Globs match case-insensitively against `ACCOUNT/ROLE`,
/// where ACCOUNT may be the account name, its slug or its id. Excludes win.
#[derive(Debug, Clone)]
pub struct Selection {
    include: Option<GlobSet>,
    exclude: Option<GlobSet>,
}

impl Selection {
    pub fn new(include: &[String], exclude: &[String]) -> Result<Self> {
        Ok(Self {
            include: glob_set(include)?,
            exclude: glob_set(exclude)?,
        })
    }

    fn matches(&self, account: &Account, role: &RoleName, profile: &ProfileName) -> bool {
        let candidates = [
            format!("{}/{role}", account.name),
            format!("{}/{role}", account_slug(account)),
            format!("{}/{role}", account.id),
            profile.to_string(),
        ];
        let hit = |set: &GlobSet| candidates.iter().any(|c| set.is_match(c));
        self.include.as_ref().is_none_or(hit) && !self.exclude.as_ref().is_some_and(hit)
    }
}

fn glob_set(patterns: &[String]) -> Result<Option<GlobSet>> {
    if patterns.is_empty() {
        return Ok(None);
    }
    let mut builder = GlobSetBuilder::new();
    for pattern in patterns {
        let glob = GlobBuilder::new(pattern)
            .case_insensitive(true)
            .literal_separator(false)
            .build()
            .map_err(|err| Error::usage(format!("invalid glob `{pattern}`: {err}")))?;
        builder.add(glob);
    }
    builder
        .build()
        .map(Some)
        .map_err(|err| Error::usage(format!("invalid globs: {err}")))
}

/// The output mode of a sync block. Only native `sso-session` profiles exist so far;
/// `credential_process` profiles are the planned second mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Mode {
    #[default]
    Sso,
}

impl Mode {
    fn as_str(self) -> &'static str {
        match self {
            Self::Sso => "sso",
        }
    }
}

/// The settings that produced a block, stored in its BEGIN line (S7): there is no gac config file.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct SyncSettings {
    pub mode: Mode,
    pub name: NameTemplate,
    pub region: Option<Region>,
    pub include: Vec<String>,
    pub exclude: Vec<String>,
}

impl SyncSettings {
    pub fn from_header(header: &Header) -> Result<Self> {
        let unreadable = |what: &str| {
            Error::config(format!(
                "the gac block for session `{}` has an unreadable {what}",
                header.session
            ))
            .with_hint("pass the settings again on the command line, with --reset")
        };
        let mode = match header.get("mode") {
            None | Some("sso") => Mode::Sso,
            Some(_) => return Err(unreadable("mode")),
        };
        Ok(Self {
            mode,
            name: header
                .get("name")
                .map(str::parse)
                .transpose()
                .map_err(|_| unreadable("name template"))?
                .unwrap_or_default(),
            region: header
                .get("region")
                .map(str::parse)
                .transpose()
                .map_err(|_| unreadable("region"))?,
            include: header.get_all("include").map(str::to_owned).collect(),
            exclude: header.get_all("exclude").map(str::to_owned).collect(),
        })
    }

    pub fn to_header(&self, session: &SessionName) -> Header {
        let mut settings = vec![
            ("mode".to_owned(), self.mode.as_str().to_owned()),
            ("name".to_owned(), self.name.to_string()),
        ];
        if let Some(region) = &self.region {
            settings.push(("region".to_owned(), region.to_string()));
        }
        settings.extend(
            self.include
                .iter()
                .map(|g| ("include".to_owned(), g.clone())),
        );
        settings.extend(
            self.exclude
                .iter()
                .map(|g| ("exclude".to_owned(), g.clone())),
        );
        Header {
            session: session.to_string(),
            settings,
        }
    }
}

/// One profile a sync block will contain.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlannedProfile {
    pub name: ProfileName,
    pub account: Account,
    pub role: RoleName,
}

/// Every selected account and role, named and sorted by account name, account id and role.
pub fn plan(
    accounts: &[Account],
    settings: &SyncSettings,
    session: &SessionName,
) -> Result<Vec<PlannedProfile>> {
    let selection = Selection::new(&settings.include, &settings.exclude)?;
    let mut planned = Vec::new();
    let mut seen: BTreeMap<ProfileName, (String, String)> = BTreeMap::new();
    for account in accounts {
        for role in &account.roles {
            let name = settings.name.render(account, role, session)?;
            if !selection.matches(account, role, &name) {
                continue;
            }
            let this = (account.id.to_string(), role.to_string());
            if let Some((other_account, other_role)) = seen.insert(name.clone(), this) {
                return Err(Error::usage(format!(
                    "the template `{}` gives `{name}` to both {other_account}/{other_role} and {}/{role}",
                    settings.name, account.id
                ))
                .with_hint("make names unique, e.g. --name '{account}-{account_id}/{role}'"));
            }
            planned.push(PlannedProfile {
                name,
                account: account.clone(),
                role: role.clone(),
            });
        }
    }
    Ok(planned)
}

/// An `[sso-session]` section that gac owns, as `gac setup` writes it into the session's block.
pub fn render_session(session: &SsoSessionConfig) -> Vec<String> {
    let mut lines = vec![
        format!("[sso-session {}]", session.name),
        format!("sso_start_url = {}", session.start_url),
        format!("sso_region = {}", session.region),
    ];
    if !session.scopes.is_empty() {
        lines.push(format!(
            "sso_registration_scopes = {}",
            session.scopes.join(", ")
        ));
    }
    lines
}

/// The block body: one native `sso-session` profile per planned entry.
pub fn render_body(
    profiles: &[PlannedProfile],
    session: &SessionName,
    region: Option<&Region>,
) -> Vec<String> {
    let mut lines = Vec::new();
    for (index, profile) in profiles.iter().enumerate() {
        if index > 0 {
            lines.push(String::new());
        }
        lines.push(format!("[profile {}]", profile.name));
        lines.push(format!("sso_session = {session}"));
        lines.push(format!("sso_account_id = {}", profile.account.id));
        lines.push(format!("sso_role_name = {}", profile.role));
        if let Some(region) = region {
            lines.push(format!("region = {region}"));
        }
    }
    lines
}

#[cfg(test)]
mod tests {
    use super::*;

    fn account(id: &str, name: &str, roles: &[&str]) -> Account {
        Account {
            id: id.parse().unwrap(),
            name: name.into(),
            email: None,
            roles: roles.iter().map(|r| r.parse().unwrap()).collect(),
        }
    }

    fn session() -> SessionName {
        "corp".parse().unwrap()
    }

    fn names(planned: &[PlannedProfile]) -> Vec<String> {
        planned.iter().map(|p| p.name.to_string()).collect()
    }

    #[test]
    fn slugs_fit_the_sdk_identifier_set() {
        let a = account("111122223333", "Payments Prod (EU)", &[]);
        assert_eq!(account_slug(&a), "payments-prod-eu");
        assert_eq!(account_slug(&account("111122223333", "a/b", &[])), "a-b");
        assert_eq!(
            account_slug(&account("111122223333", "  ", &[])),
            "111122223333"
        );
        assert_eq!(role_slug("Admin=Role,X"), "Admin-Role-X");
    }

    #[test]
    fn validates_templates() {
        assert!("{account}/{role}".parse::<NameTemplate>().is_ok());
        assert!(
            "{session}.{account_id}.{role}"
                .parse::<NameTemplate>()
                .is_ok()
        );
        assert!("{acct}/{role}".parse::<NameTemplate>().is_err());
        assert!("{account/{role}".parse::<NameTemplate>().is_err());
        assert!("account}".parse::<NameTemplate>().is_err());
        assert!("static".parse::<NameTemplate>().is_err());
    }

    #[test]
    fn plans_selected_profiles_in_order() {
        let accounts = [
            account(
                "111122223333",
                "payments-prod",
                &["AdministratorAccess", "ReadOnly"],
            ),
            account("444455556666", "Shared Services", &["ReadOnly"]),
        ];
        let all = plan(&accounts, &SyncSettings::default(), &session()).unwrap();
        assert_eq!(
            names(&all),
            [
                "payments-prod/AdministratorAccess",
                "payments-prod/ReadOnly",
                "shared-services/ReadOnly"
            ]
        );

        let filtered = SyncSettings {
            include: vec!["*/readonly".into()],
            exclude: vec!["Shared Services/*".into()],
            ..SyncSettings::default()
        };
        assert_eq!(
            names(&plan(&accounts, &filtered, &session()).unwrap()),
            ["payments-prod/ReadOnly"]
        );

        let by_id = SyncSettings {
            include: vec!["4444*".into()],
            ..SyncSettings::default()
        };
        assert_eq!(
            names(&plan(&accounts, &by_id, &session()).unwrap()),
            ["shared-services/ReadOnly"]
        );
    }

    #[test]
    fn refuses_colliding_names() {
        let accounts = [
            account("111122223333", "dup", &["ReadOnly"]),
            account("444455556666", "DUP", &["ReadOnly"]),
        ];
        let err = plan(&accounts, &SyncSettings::default(), &session()).unwrap_err();
        assert!(
            err.to_string().contains("gives `dup/ReadOnly` to both"),
            "{err}"
        );
        let unique = SyncSettings {
            name: "{account}-{account_id}/{role}".parse().unwrap(),
            ..SyncSettings::default()
        };
        assert_eq!(plan(&accounts, &unique, &session()).unwrap().len(), 2);
    }

    #[test]
    fn settings_round_trip_through_the_header() {
        let settings = SyncSettings {
            mode: Mode::Sso,
            name: "{account_id}/{role}".parse().unwrap(),
            region: Some("eu-west-1".parse().unwrap()),
            include: vec!["pay*".into(), "dev ops/*".into()],
            exclude: vec!["*/Admin*".into()],
        };
        let header = settings.to_header(&session());
        assert_eq!(SyncSettings::from_header(&header).unwrap(), settings);
        let bare = Header {
            session: "corp".into(),
            settings: vec![],
        };
        assert_eq!(
            SyncSettings::from_header(&bare).unwrap(),
            SyncSettings::default()
        );
    }

    #[test]
    fn renders_native_profiles() {
        let accounts = [account(
            "111122223333",
            "payments-prod",
            &["AdministratorAccess", "ReadOnly"],
        )];
        let planned = plan(&accounts, &SyncSettings::default(), &session()).unwrap();
        let region: Region = "us-east-1".parse().unwrap();
        insta::assert_snapshot!(render_body(&planned, &session(), Some(&region)).join("\n"), @r"
        [profile payments-prod/AdministratorAccess]
        sso_session = corp
        sso_account_id = 111122223333
        sso_role_name = AdministratorAccess
        region = us-east-1

        [profile payments-prod/ReadOnly]
        sso_session = corp
        sso_account_id = 111122223333
        sso_role_name = ReadOnly
        region = us-east-1
        ");
    }
}
