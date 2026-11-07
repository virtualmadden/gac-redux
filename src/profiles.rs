//! What `sync` writes: profile names from a template, the account and role selection, the
//! settings stored in the block's BEGIN line, and the rendered profiles: native `sso-session`
//! profiles, or `credential_process` profiles that run `gac credential-process`, and chained
//! `role_arn` profiles on top of them.

use std::collections::BTreeMap;
use std::fmt;
use std::str::FromStr;

use globset::{GlobBuilder, GlobSet, GlobSetBuilder};

use crate::auth::assume::RoleArn;
use crate::aws_files::SsoSessionConfig;
use crate::aws_files::managed_block::{self, Header};
use crate::domain::{
    AccountId, ProfileName, Region, RoleName, SessionName, StartUrl, is_sdk_identifier_char,
};
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

/// A chained-profile setting: from every synced profile matching the glob `source`, assume
/// `role_arn`, in which `{account_id}` is the source profile's account.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Chain {
    pub source: String,
    pub role_arn: String,
}

impl Chain {
    /// The role ARN for a source profile in `account`.
    fn role_arn(&self, account: &AccountId) -> Result<RoleArn> {
        self.role_arn
            .replace("{account_id}", account.as_str())
            .parse()
    }
}

impl fmt::Display for Chain {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}={}", self.source, self.role_arn)
    }
}

impl FromStr for Chain {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        let invalid = |why: &str| {
            Error::usage(format!("invalid --chain `{s}`: {why}")).with_hint(
                "use SOURCE=ROLE_ARN, e.g. '*/Admin=arn:aws:iam::{account_id}:role/Deploy'",
            )
        };
        let (source, role_arn) = s
            .split_once('=')
            .ok_or_else(|| invalid("there is no `=` between the source and the role ARN"))?;
        if source.is_empty() {
            return Err(invalid("the source glob is empty"));
        }
        glob_set(&[source.to_owned()])?;
        let chain = Self {
            source: source.to_owned(),
            role_arn: role_arn.to_owned(),
        };
        let sample: AccountId = "111122223333".parse().expect("a valid account id");
        chain
            .role_arn(&sample)
            .map_err(|_| invalid("the part after `=` is not an IAM role ARN"))?;
        Ok(chain)
    }
}

/// The output mode of a sync block.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, clap::ValueEnum)]
pub enum Mode {
    /// Native `sso-session` profiles, which the AWS CLI and current SDKs resolve themselves.
    #[default]
    Sso,
    /// `credential_process` profiles that run `gac credential-process`, for tools and older SDKs
    /// without SSO support.
    Process,
}

impl Mode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Sso => "sso",
            Self::Process => "process",
        }
    }
}

/// The `credential_process` command of a process-mode profile. It names `gac` on `PATH`, so an
/// upgrade that moves the binary does not break the profiles.
pub fn process_command(session: &SessionName, account: &AccountId, role: &RoleName) -> String {
    format!("gac credential-process --session {session} --account-id {account} --role-name {role}")
}

/// The session, account and role of a `credential_process` command gac wrote.
pub fn parse_process_command(command: &str) -> Option<(SessionName, AccountId, RoleName)> {
    let words: Vec<&str> = command.split_whitespace().collect();
    let ["gac", "credential-process", flags @ ..] = words.as_slice() else {
        return None;
    };
    let value = |flag: &str| {
        flags
            .iter()
            .position(|w| *w == flag)
            .and_then(|i| flags.get(i + 1))
    };
    Some((
        value("--session")?.parse().ok()?,
        value("--account-id")?.parse().ok()?,
        value("--role-name")?.parse().ok()?,
    ))
}

/// The settings that produced a block, stored in its BEGIN line (S7): there is no gac config file.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct SyncSettings {
    pub mode: Mode,
    pub name: NameTemplate,
    pub region: Option<Region>,
    pub include: Vec<String>,
    pub exclude: Vec<String>,
    pub chain: Vec<Chain>,
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
            Some("process") => Mode::Process,
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
            chain: header
                .get_all("chain")
                .map(str::parse)
                .collect::<Result<_>>()
                .map_err(|_| unreadable("chain"))?,
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
        settings.extend(
            self.chain
                .iter()
                .map(|c| ("chain".to_owned(), c.to_string())),
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
    /// The account and role it signs in as: the assumed role's, for a chained profile.
    pub account: Account,
    pub role: RoleName,
    pub chained: Option<Chained>,
}

/// How a chained profile gets its role: assumed from a synced profile's credentials.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Chained {
    pub source: ProfileName,
    pub role_arn: RoleArn,
}

/// Every selected account and role, named and sorted by account name, account id and role,
/// then each chained profile, in the order of the chain settings.
pub fn plan(
    accounts: &[Account],
    settings: &SyncSettings,
    session: &SessionName,
) -> Result<Vec<PlannedProfile>> {
    let selection = Selection::new(&settings.include, &settings.exclude)?;
    let mut planned = Vec::new();
    // Each name and what it was given to, to report a collision.
    let mut seen: BTreeMap<ProfileName, String> = BTreeMap::new();
    let mut claim = |name: &ProfileName, what: String| match seen.insert(name.clone(), what.clone())
    {
        Some(other) => Err(Error::usage(format!(
            "the template `{}` gives `{name}` to both {other} and {what}",
            settings.name
        ))
        .with_hint(
            "make names unique, e.g. --name '{account}-{account_id}/{role}', or narrow --chain",
        )),
        None => Ok(()),
    };
    for account in accounts {
        for role in &account.roles {
            let name = settings.name.render(account, role, session)?;
            if !selection.matches(account, role, &name) {
                continue;
            }
            claim(&name, format!("{}/{role}", account.id))?;
            planned.push(PlannedProfile {
                name,
                account: account.clone(),
                role: role.clone(),
                chained: None,
            });
        }
    }
    let synced = planned.clone();
    for chain in &settings.chain {
        let source = Selection::new(std::slice::from_ref(&chain.source), &[])?;
        for from in synced
            .iter()
            .filter(|p| source.matches(&p.account, &p.role, &p.name))
        {
            let role_arn = chain.role_arn(&from.account.id)?;
            // Named like any profile: by the account it lands in, known or not, and the role.
            let account = accounts
                .iter()
                .find(|a| a.id == *role_arn.account())
                .cloned()
                .unwrap_or_else(|| Account {
                    id: role_arn.account().clone(),
                    name: role_arn.account().to_string(),
                    email: None,
                    roles: Vec::new(),
                });
            let name = settings.name.render(&account, role_arn.role(), session)?;
            claim(&name, format!("{role_arn} chained from `{}`", from.name))?;
            planned.push(PlannedProfile {
                name,
                account,
                role: role_arn.role().clone(),
                chained: Some(Chained {
                    source: from.name.clone(),
                    role_arn,
                }),
            });
        }
    }
    Ok(planned)
}

/// `text` with a new block for the session that holds only its `[sso-session]`, as `gac setup`
/// writes it; `gac sync` adds the profiles later.
pub fn append_session_block(text: &str, session: &SsoSessionConfig) -> String {
    let header = Header {
        session: session.name.to_string(),
        settings: Vec::new(),
    };
    let block = managed_block::render(
        &header,
        &render_session(session),
        managed_block::line_ending(text),
    );
    managed_block::append(text, &block)
}

/// The first label of the portal host, e.g. `my-portal` for `https://my-portal.awsapps.com/start`.
pub fn suggest_session_name(start_url: &StartUrl) -> SessionName {
    url::Url::parse(start_url.as_str())
        .ok()
        .and_then(|url| {
            url.host_str()
                .map(|h| h.split('.').next().unwrap_or(h).to_owned())
        })
        .and_then(|label| label.parse().ok())
        .unwrap_or_else(|| "default".parse().expect("a valid session name"))
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

/// The block body: one profile per planned entry, in the block's mode.
pub fn render_body(
    profiles: &[PlannedProfile],
    session: &SessionName,
    mode: Mode,
    region: Option<&Region>,
) -> Vec<String> {
    let mut lines = Vec::new();
    for (index, profile) in profiles.iter().enumerate() {
        if index > 0 {
            lines.push(String::new());
        }
        lines.push(format!("[profile {}]", profile.name));
        if let Some(chained) = &profile.chained {
            lines.push(format!("role_arn = {}", chained.role_arn));
            lines.push(format!("source_profile = {}", chained.source));
            if let Some(region) = region {
                lines.push(format!("region = {region}"));
            }
            continue;
        }
        match mode {
            Mode::Sso => {
                lines.push(format!("sso_session = {session}"));
                lines.push(format!("sso_account_id = {}", profile.account.id));
                lines.push(format!("sso_role_name = {}", profile.role));
            }
            Mode::Process => lines.push(format!(
                "credential_process = {}",
                process_command(session, &profile.account.id, &profile.role)
            )),
        }
        if let Some(region) = region {
            lines.push(format!("region = {region}"));
        }
    }
    lines
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_back_the_process_command_it_writes() {
        let account: AccountId = "111122223333".parse().unwrap();
        let role: RoleName = "Admin+Ops".parse().unwrap();
        let command = process_command(&session(), &account, &role);
        assert_eq!(
            command,
            "gac credential-process --session corp --account-id 111122223333 --role-name Admin+Ops"
        );
        assert_eq!(
            parse_process_command(&command),
            Some((session(), account, role))
        );
        assert_eq!(parse_process_command("aws-vault exec x --json"), None);
        assert_eq!(
            parse_process_command("gac credential-process --session corp"),
            None
        );
    }

    #[test]
    fn suggests_the_portal_label() {
        let url: StartUrl = "https://my-portal.awsapps.com/start".parse().unwrap();
        assert_eq!(suggest_session_name(&url).as_str(), "my-portal");
    }

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
    fn chains_assume_a_role_from_each_matching_profile() {
        let accounts = [
            account("111122223333", "payments-prod", &["Admin", "ReadOnly"]),
            account("444455556666", "shared", &["Admin"]),
        ];
        let settings = SyncSettings {
            chain: vec![
                "*/Admin=arn:aws:iam::{account_id}:role/Deploy"
                    .parse()
                    .unwrap(),
                "payments-prod/ReadOnly=arn:aws:iam::999988887777:role/ops/Audit"
                    .parse()
                    .unwrap(),
            ],
            ..SyncSettings::default()
        };
        let planned = plan(&accounts, &settings, &session()).unwrap();
        assert_eq!(
            names(&planned),
            [
                "payments-prod/Admin",
                "payments-prod/ReadOnly",
                "shared/Admin",
                "payments-prod/Deploy",
                "shared/Deploy",
                // An account the portal does not list is named by its id.
                "999988887777/Audit",
            ]
        );
        let deploy = planned[3].chained.as_ref().unwrap();
        assert_eq!(deploy.source.as_str(), "payments-prod/Admin");
        assert_eq!(
            deploy.role_arn.as_str(),
            "arn:aws:iam::111122223333:role/Deploy"
        );
        let body = render_body(&planned[3..4], &session(), Mode::Process, None).join("\n");
        assert_eq!(
            body,
            "[profile payments-prod/Deploy]\nrole_arn = arn:aws:iam::111122223333:role/Deploy\nsource_profile = payments-prod/Admin"
        );

        // One target from two sources is one name twice.
        let colliding = SyncSettings {
            chain: vec!["*=arn:aws:iam::999988887777:role/Audit".parse().unwrap()],
            ..SyncSettings::default()
        };
        let err = plan(&accounts, &colliding, &session())
            .unwrap_err()
            .to_string();
        assert!(err.contains("gives `999988887777/Audit` to both"), "{err}");

        for bad in [
            "*/Admin",
            "=arn:aws:iam::1:role/x",
            "*/Admin=Deploy",
            "[=arn:aws:iam::111122223333:role/x",
        ] {
            assert!(bad.parse::<Chain>().is_err(), "{bad}");
        }
    }

    #[test]
    fn settings_round_trip_through_the_header() {
        let settings = SyncSettings {
            mode: Mode::Sso,
            name: "{account_id}/{role}".parse().unwrap(),
            region: Some("eu-west-1".parse().unwrap()),
            include: vec!["pay*".into(), "dev ops/*".into()],
            exclude: vec!["*/Admin*".into()],
            chain: vec![
                "*/Admin=arn:aws:iam::{account_id}:role/Deploy"
                    .parse()
                    .unwrap(),
            ],
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
        insta::assert_snapshot!(render_body(&planned, &session(), Mode::Sso, Some(&region)).join("\n"), @r"
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
