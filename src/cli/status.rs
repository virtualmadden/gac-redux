//! `gac status`: sessions, token and registration expiry, and sync blocks. Never a secret.

use std::fmt::Write as _;

use jiff::{SignedDuration, Timestamp};
use serde::Serialize;

use crate::auth::token::{TokenState, TokenStore};
use crate::auth::{Session, botocore_json::timestamp};
use crate::aws_files::AwsFiles;
use crate::aws_files::managed_block::{self, Block};
use crate::cli::StatusArgs;
use crate::cli::context::Context;
use crate::error::{Error, Result};
use crate::profiles::SyncSettings;
use crate::ui;

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct Status {
    config_file: String,
    sessions: Vec<SessionStatus>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct SessionStatus {
    name: String,
    kind: &'static str,
    /// Set when the `[default]` profile uses this session.
    #[serde(skip_serializing_if = "Option::is_none")]
    default_profile: Option<DefaultProfile>,
    #[serde(skip_serializing_if = "Option::is_none")]
    start_url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    region: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
    token: TokenStatus,
    #[serde(skip_serializing_if = "Option::is_none")]
    sync_block: Option<BlockStatus>,
}

/// The account and role of the `[default]` profile; both absent when it names none.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct DefaultProfile {
    #[serde(skip_serializing_if = "Option::is_none")]
    account_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    role_name: Option<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct TokenStatus {
    /// `valid`, `refresh-due`, `expired`, `missing` or `unreadable`.
    state: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    expires_at: Option<String>,
    refreshable: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    registration_expires_at: Option<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct BlockStatus {
    profiles: usize,
    mode: &'static str,
    name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    region: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    include: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    exclude: Vec<String>,
}

pub async fn run(ctx: &Context, args: StatusArgs) -> Result<()> {
    let files = ctx.files().await?;
    let blocks = managed_block::scan(files.config_text()).unwrap_or_else(|err| {
        ui::warn(format!("ignoring sync blocks: {err} (see gac doctor)"));
        Vec::new()
    });
    let store = ctx.token_store();
    let now = Timestamp::now();

    let mut sessions: Vec<SessionStatus> = files
        .session_names()
        .into_iter()
        .map(|name| named_status(&files, &store, &blocks, name, now))
        .collect();
    sessions.extend(files.legacy_sso_profiles().into_iter().map(|legacy| {
        let session = Session::from(legacy.clone());
        SessionStatus {
            name: legacy.profile,
            kind: "legacy-profile",
            default_profile: None,
            start_url: Some(legacy.start_url.to_string()),
            region: Some(legacy.region.to_string()),
            error: None,
            token: token_status(&store, &session, now),
            sync_block: None,
        }
    }));

    let status = Status {
        config_file: ctx.paths.config_file().display().to_string(),
        sessions,
    };
    let text = if args.json {
        let mut json =
            serde_json::to_string_pretty(&status).expect("serializing plain data cannot fail");
        json.push('\n');
        json
    } else {
        render(&status, now)
    };
    ui::output(text).map_err(|err| Error::io("could not write to stdout", err))
}

fn named_status(
    files: &AwsFiles,
    store: &impl TokenStore,
    blocks: &[Block],
    name: &str,
    now: Timestamp,
) -> SessionStatus {
    let default_profile = files
        .config_profile("default")
        .filter(|p| p.get("sso_session") == Some(name))
        .map(|p| DefaultProfile {
            account_id: p.get("sso_account_id").map(str::to_owned),
            role_name: p.get("sso_role_name").map(str::to_owned),
        });
    let sync_block = blocks
        .iter()
        .find(|b| b.header.session == name)
        .map(|block| block_status(files.config_text(), block));
    match name.parse().and_then(|n| files.sso_session(&n)) {
        Ok(config) => {
            let session = Session::from(config);
            SessionStatus {
                name: name.to_owned(),
                kind: "sso-session",
                default_profile,
                start_url: Some(session.start_url.to_string()),
                region: Some(session.region.to_string()),
                error: None,
                token: token_status(store, &session, now),
                sync_block,
            }
        }
        Err(err) => SessionStatus {
            name: name.to_owned(),
            kind: "sso-session",
            default_profile,
            start_url: None,
            region: None,
            error: Some(err.to_string()),
            token: TokenStatus {
                state: "missing",
                expires_at: None,
                refreshable: false,
                registration_expires_at: None,
            },
            sync_block,
        },
    }
}

fn token_status(store: &impl TokenStore, session: &Session, now: Timestamp) -> TokenStatus {
    match store.load(session.cache_key()) {
        Ok(Some(token)) => TokenStatus {
            state: match token.state(now) {
                TokenState::Valid => "valid",
                TokenState::RefreshDue => "refresh-due",
                TokenState::Expired => "expired",
            },
            expires_at: Some(timestamp::format(token.expires_at)),
            refreshable: token.is_refreshable(now),
            registration_expires_at: token.registration_expires_at.map(timestamp::format),
        },
        Ok(None) => TokenStatus {
            state: "missing",
            expires_at: None,
            refreshable: false,
            registration_expires_at: None,
        },
        Err(_) => TokenStatus {
            state: "unreadable",
            expires_at: None,
            refreshable: false,
            registration_expires_at: None,
        },
    }
}

fn block_status(config: &str, block: &Block) -> BlockStatus {
    let profiles = block.profile_names(config).count();
    let settings = SyncSettings::from_header(&block.header).unwrap_or_default();
    BlockStatus {
        profiles,
        mode: "sso",
        name: settings.name.to_string(),
        region: settings.region.map(|r| r.to_string()),
        include: settings.include,
        exclude: settings.exclude,
    }
}

fn render(status: &Status, now: Timestamp) -> String {
    let mut out = String::new();
    if status.sessions.is_empty() {
        let _ = writeln!(
            out,
            "No sessions in {}. Run `gac setup`.",
            status.config_file
        );
        return out;
    }
    for (index, s) in status.sessions.iter().enumerate() {
        if index > 0 {
            out.push('\n');
        }
        let kind = if s.kind == "sso-session" {
            "session"
        } else {
            "legacy profile"
        };
        let default = if s.default_profile.is_some() {
            " (default)"
        } else {
            ""
        };
        let _ = writeln!(out, "{kind} {}{default}", s.name);
        if let Some(error) = &s.error {
            let _ = writeln!(out, "  error         {error}");
            continue;
        }
        if let Some(url) = &s.start_url {
            let _ = writeln!(out, "  start URL     {url}");
        }
        if let Some(region) = &s.region {
            let _ = writeln!(out, "  region        {region}");
        }
        let _ = writeln!(out, "  token         {}", describe_token(&s.token, now));
        if let Some(at) = &s.token.registration_expires_at {
            let _ = writeln!(out, "  registration  expires {at}");
        }
        if let Some(profile) = &s.default_profile {
            let line = match (&profile.account_id, &profile.role_name) {
                (Some(account), Some(role)) => format!("account {account}, role {role}"),
                _ => "no account or role (run `gac select`)".to_owned(),
            };
            let _ = writeln!(out, "  [default]     {line}");
        }
        if s.kind == "sso-session" {
            let block = s.sync_block.as_ref().map_or_else(
                || "none (run `gac sync`)".to_owned(),
                |b| {
                    let plural = if b.profiles == 1 { "" } else { "s" };
                    format!("{} profile{plural}, name={}", b.profiles, b.name)
                },
            );
            let _ = writeln!(out, "  sync block    {block}");
        }
    }
    out
}

fn describe_token(token: &TokenStatus, now: Timestamp) -> String {
    let Some(expires_at) = &token.expires_at else {
        return match token.state {
            "unreadable" => "unreadable (log in again)".to_owned(),
            _ => "not logged in".to_owned(),
        };
    };
    let left = timestamp::parse(expires_at).map(|at| at.duration_since(now));
    let refresh = if token.refreshable {
        ", refreshable"
    } else {
        ""
    };
    match (token.state, left) {
        // Only the service knows whether the refresh token outlived the portal session.
        ("expired", _) if token.refreshable => {
            format!("expired at {expires_at}; the next use tries a refresh")
        }
        ("expired", _) => format!("expired at {expires_at}"),
        (_, Some(left)) => format!("valid until {expires_at} ({} left){refresh}", human(left)),
        _ => format!("valid until {expires_at}{refresh}"),
    }
}

fn human(duration: SignedDuration) -> String {
    let minutes = duration.as_secs().max(0) / 60;
    match (minutes / (60 * 24), minutes / 60 % 24, minutes % 60) {
        (0, 0, m) => format!("{m}m"),
        (0, h, m) => format!("{h}h {m}m"),
        (d, h, _) => format!("{d}d {h}h"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn formats_durations_compactly() {
        assert_eq!(human(SignedDuration::from_mins(5)), "5m");
        assert_eq!(human(SignedDuration::from_mins(432)), "7h 12m");
        assert_eq!(human(SignedDuration::from_hours(50)), "2d 2h");
        assert_eq!(human(SignedDuration::from_secs(-5)), "0m");
    }
}
