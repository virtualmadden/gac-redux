//! End-to-end tests of the `gac` binary against the mock Identity Center, each in its own
//! sandbox HOME.

mod support;

use predicates::prelude::*;
use serde_json::{Value, json};
use support::mock_idc::account;
use support::{SESSION, START_URL, Sandbox, assert_no_secrets, stderr, stdout};

fn login_device(sandbox: &Sandbox) {
    sandbox
        .gac()
        .args(["login", "--device-code", "--no-browser"])
        .assert()
        .success();
}

fn login_pkce(sandbox: &Sandbox, extra: &[&str]) -> std::process::Output {
    let mut args = vec!["login", "--no-browser"];
    args.extend_from_slice(extra);
    support::drive_browser(sandbox.spawn_gac(&args))
}

#[test]
fn bare_command_prints_help() {
    let sandbox = Sandbox::new();
    sandbox
        .gac()
        .assert()
        .code(2)
        .stderr(predicate::str::contains("Usage: gac"));
    let help = sandbox.gac().arg("--help").assert().success();
    insta::assert_snapshot!(String::from_utf8_lossy(&help.get_output().stdout));
}

/// The block `gac setup` writes for the `corp` session.
const SETUP_BLOCK: &str = "\
# BEGIN gac sync session=corp
# Managed by gac: edits inside this block are replaced on the next sync.
[sso-session corp]
sso_start_url = https://mock-example.awsapps.com/start
sso_region = us-west-2
sso_registration_scopes = sso:account:access
# END gac sync session=corp
";

#[test]
fn setup_writes_its_session_inside_a_managed_block() {
    let sandbox = Sandbox::new();
    let original = "# my settings\n[default]\nregion = eu-west-1";
    sandbox.write_config(original);
    sandbox
        .gac()
        .args([
            "setup",
            "--session",
            "corp",
            "--start-url",
            START_URL,
            "--region",
            "us-west-2",
        ])
        .assert()
        .success()
        .stderr(predicate::str::contains("Added [sso-session corp]"));
    let set_up = format!("{original}\n\n{SETUP_BLOCK}");
    assert_eq!(sandbox.config(), set_up);

    // Running it again reuses the session and changes nothing.
    sandbox
        .gac()
        .args(["setup", "--session", "corp", "--start-url", START_URL])
        .assert()
        .success()
        .stderr(predicate::str::contains("reusing it"));
    // Asking for different settings under the same name is refused.
    sandbox
        .gac()
        .args(["setup", "--session", "corp", "--region", "eu-central-1"])
        .assert()
        .code(1)
        .stderr(predicate::str::contains("already exists"));
    assert_eq!(sandbox.config(), set_up);

    // Sync fills the same block and keeps the session in it; nothing outside the block changes.
    login_device(&sandbox);
    sandbox
        .gac()
        .arg("sync")
        .assert()
        .success()
        .stderr(predicate::str::contains("Synced 5 profiles"));
    let synced = sandbox.config();
    let block = synced
        .strip_prefix(&format!("{original}\n\n"))
        .unwrap_or_else(|| panic!("the user's bytes are a prefix:\n{synced}"));
    let head = SETUP_BLOCK
        .replacen(
            "session=corp\n",
            "session=corp mode=sso name={account}/{role}\n",
            1,
        )
        .replace("# END gac sync session=corp\n", "");
    assert!(block.starts_with(&format!("{head}\n[profile ")), "{block}");
    assert!(block.ends_with("# END gac sync session=corp\n"));
    assert!(block.contains("[profile payments-prod/ReadOnly]\nsso_session = corp\n"));
    sandbox
        .gac()
        .args(["sync", "--reset"])
        .assert()
        .success()
        .stderr(predicate::str::contains("Already up to date"));
    assert_eq!(sandbox.config(), synced);
    sandbox.gac().args(["list", "--refresh"]).assert().success();
}

#[test]
fn setup_reuses_a_session_from_aws_configure_sso() {
    let sandbox = Sandbox::with_session();
    sandbox
        .gac()
        .args(["setup", "--start-url", START_URL])
        .assert()
        .success()
        .stderr(predicate::str::contains(
            "[sso-session corp] already exists",
        ));
    assert_eq!(sandbox.config(), SESSION);
}

#[test]
fn setup_without_a_terminal_needs_its_flags() {
    let sandbox = Sandbox::new();
    sandbox
        .gac()
        .args(["setup", "--region", "us-west-2"])
        .assert()
        .code(2)
        .stderr(predicate::str::contains("--start-url is required"));
}

#[test]
fn pkce_login_writes_a_token_the_aws_cli_can_use() {
    let sandbox = Sandbox::with_session();
    let output = login_pkce(&sandbox, &[]);
    assert!(output.status.success(), "{}", stderr(&output));
    assert!(stderr(&output).contains("Logged in to session `corp`"));
    assert_eq!(stdout(&output), "", "stdout carries only requested data");

    let text = sandbox.token_text("corp");
    assert_eq!(
        support::key_order(&text),
        [
            "startUrl",
            "region",
            "accessToken",
            "expiresAt",
            "clientId",
            "clientSecret",
            "registrationExpiresAt",
            "refreshToken"
        ]
    );
    assert!(text.starts_with(&format!(
        "{{\"startUrl\": \"{START_URL}\", \"region\": \"us-west-2\", "
    )));
    let token = sandbox.token("corp");
    assert!(token["expiresAt"].as_str().unwrap().ends_with('Z'));
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(sandbox.token_path("corp"))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600);
        let dir = std::fs::metadata(sandbox.token_path("corp").parent().unwrap()).unwrap();
        assert_eq!(dir.permissions().mode() & 0o777, 0o700);
    }
    assert_eq!(sandbox.mock.counter("token_code"), 1);

    // The registration is cached: a second login does not register again.
    let again = login_pkce(&sandbox, &[]);
    assert!(again.status.success(), "{}", stderr(&again));
    assert_eq!(sandbox.mock.counter("register"), 1);
}

#[test]
fn pkce_login_reports_a_denied_sign_in() {
    let sandbox = Sandbox::with_session();
    sandbox.mock.deny_authorize();
    let output = login_pkce(&sandbox, &[]);
    assert_eq!(output.status.code(), Some(1));
    assert!(
        stderr(&output).contains("access_denied"),
        "{}",
        stderr(&output)
    );
    assert!(!sandbox.token_path("corp").exists());
}

#[test]
fn device_login_polls_until_approved() {
    let sandbox = Sandbox::with_session();
    sandbox.mock.set_pending_polls(2);
    sandbox
        .gac()
        .args(["login", "--device-code", "--no-browser"])
        .assert()
        .success()
        .stderr(predicate::str::contains("MOCK-CODE"))
        .stderr(predicate::str::contains(
            "Only approve a code you requested yourself",
        ));
    assert_eq!(sandbox.mock.counter("token_device"), 1);
    assert!(sandbox.token("corp")["refreshToken"].is_string());
}

#[test]
fn ssh_sessions_default_to_the_device_code_flow() {
    let sandbox = Sandbox::with_session();
    sandbox
        .gac()
        .env("SSH_CONNECTION", "10.0.0.1 50000 10.0.0.2 22")
        .args(["login", "--no-browser"])
        .assert()
        .success()
        .stderr(predicate::str::contains("SSH session detected"));
    assert_eq!(sandbox.mock.counter("token_device"), 1);
    assert_eq!(sandbox.mock.counter("token_code"), 0);
}

#[test]
fn port_never_picks_the_flow() {
    let sandbox = Sandbox::with_session();
    sandbox
        .gac()
        .env("SSH_CONNECTION", "10.0.0.1 50000 10.0.0.2 22")
        .args(["login", "--no-browser", "--port", "8400"])
        .assert()
        .code(2)
        .stderr(predicate::str::contains("device code flow"))
        .stderr(predicate::str::contains("--pkce"));
    sandbox
        .gac()
        .args(["login", "--device-code", "--no-browser", "--port", "8400"])
        .assert()
        .code(2)
        .stderr(predicate::str::contains("--pkce"));
    assert_eq!(sandbox.mock.counter("register"), 0);
    assert!(!sandbox.token_path("corp").exists());
}

#[test]
fn legacy_profiles_log_in_with_a_start_url_key() {
    let sandbox = Sandbox::new();
    sandbox.write_config(&format!(
        "[profile old]\nsso_start_url = {START_URL}\nsso_region = us-west-2\nsso_account_id = 111122223333\nsso_role_name = ReadOnly\n"
    ));
    // Like the AWS CLI, legacy profiles sign in with the device code flow only: their client is
    // registered without scopes, which a PKCE /authorize request cannot match.
    sandbox
        .gac()
        .args(["login", "--pkce", "--no-browser", "--profile", "old"])
        .assert()
        .code(2)
        .stderr(predicate::str::contains("inline start URL"));
    assert_eq!(sandbox.mock.counter("register"), 0);
    sandbox
        .gac()
        .args(["login", "--no-browser", "--profile", "old"])
        .assert()
        .success()
        .stderr(predicate::str::contains("inline start URL"));
    assert_eq!(sandbox.mock.counter("token_code"), 0);
    assert_eq!(sandbox.mock.counter("token_device"), 1);
    let token = sandbox.token(START_URL);
    assert!(
        token.get("refreshToken").is_none(),
        "legacy logins are not refreshable"
    );
    let status = sandbox.gac().args(["status", "--json"]).assert().success();
    let status: Value = serde_json::from_slice(&status.get_output().stdout).unwrap();
    assert_eq!(status["sessions"][0]["kind"], "legacy-profile");
    assert_eq!(status["sessions"][0]["token"]["state"], "valid");
}

#[test]
fn several_sessions_need_a_choice() {
    let sandbox = Sandbox::new();
    sandbox.write_config(&format!(
        "{SESSION}\n[sso-session other]\nsso_start_url = https://other.awsapps.com/start\nsso_region = us-east-1\n"
    ));
    sandbox
        .gac()
        .args(["list"])
        .assert()
        .code(2)
        .stderr(predicate::str::contains("corp, other"))
        .stderr(predicate::str::contains("--session"));
    sandbox
        .gac()
        .env("GAC_SESSION", "corp")
        .args(["list"])
        .assert()
        .code(3);
}

#[test]
fn an_exported_gac_session_yields_to_profile_and_all() {
    let sandbox = Sandbox::new();
    sandbox.write_config(&format!(
        "{SESSION}\n[sso-session other]\nsso_start_url = https://other.awsapps.com/start\nsso_region = us-east-1\n\n[profile dev]\nsso_session = corp\nsso_account_id = 111122223333\nsso_role_name = ReadOnly\n"
    ));
    sandbox
        .gac()
        .env("GAC_SESSION", "other")
        .args(["login", "--device-code", "--no-browser", "--profile", "dev"])
        .assert()
        .success()
        .stderr(predicate::str::contains("Logged in to session `corp`"));
    assert!(sandbox.token_path("corp").exists());
    sandbox
        .gac()
        .env("GAC_SESSION", "other")
        .args(["logout", "--all"])
        .assert()
        .success()
        .stderr(predicate::str::contains("Logged out of session `corp`."));
    assert!(!sandbox.token_path("corp").exists());
    // A --session typed on the command line still conflicts.
    sandbox
        .gac()
        .args(["login", "--session", "other", "--profile", "dev"])
        .assert()
        .code(2)
        .stderr(predicate::str::contains("cannot be used with"));
}

#[test]
fn list_uses_the_inventory_cache() {
    let sandbox = Sandbox::with_session();
    login_device(&sandbox);
    let listed = sandbox.gac().arg("list").assert().success();
    insta::assert_snapshot!(String::from_utf8_lossy(&listed.get_output().stdout), @r"
    ACCOUNT ID    ACCOUNT NAME     ROLE
    111122223333  payments-prod    AdministratorAccess
    111122223333  payments-prod    ReadOnly
    777788889999  sandbox          PowerUser
    777788889999  sandbox          ReadOnly
    444455556666  Shared Services  ReadOnly
    ");
    assert_eq!(sandbox.mock.counter("accounts"), 1);

    sandbox.gac().arg("list").assert().success();
    assert_eq!(sandbox.mock.counter("accounts"), 1, "served from the cache");
    let json = sandbox
        .gac()
        .args(["list", "--json", "--refresh"])
        .assert()
        .success();
    assert_eq!(
        sandbox.mock.counter("accounts"),
        2,
        "--refresh asks the portal"
    );
    let json: Value = serde_json::from_slice(&json.get_output().stdout).unwrap();
    assert_eq!(json["session"], "corp");
    assert_eq!(json["accounts"][0]["accountId"], "111122223333");
    assert_eq!(
        json["accounts"][0]["roles"],
        json!(["AdministratorAccess", "ReadOnly"])
    );
}

#[test]
fn the_inventory_cache_is_bound_to_the_token_that_listed_it() {
    let listed_ids = |sandbox: &Sandbox| -> Vec<String> {
        let json = sandbox.gac().args(["list", "--json"]).assert().success();
        let json: Value = serde_json::from_slice(&json.get_output().stdout).unwrap();
        json["accounts"]
            .as_array()
            .unwrap()
            .iter()
            .map(|a| a["accountId"].as_str().unwrap().to_owned())
            .collect()
    };
    let sandbox = Sandbox::with_session();
    login_device(&sandbox);
    let first = sandbox.token("corp");
    assert_eq!(listed_ids(&sandbox).len(), 3);
    assert_eq!(listed_ids(&sandbox).len(), 3);
    assert_eq!(sandbox.mock.counter("accounts"), 1, "served from the cache");

    // Another identity signs in on the same portal, and another tool (the AWS CLI) replaces the
    // shared token: the listing made with the first token is not reused.
    sandbox.mock.set_accounts(vec![account(
        "444455556666",
        "Shared Services",
        &["ReadOnly"],
    )]);
    login_device(&sandbox);
    let second = sandbox.token("corp");
    sandbox.write_token("corp", &first);
    assert_eq!(listed_ids(&sandbox).len(), 3, "still the first token");
    sandbox.write_token("corp", &second);
    assert_eq!(listed_ids(&sandbox), ["444455556666"]);
    assert_eq!(sandbox.mock.counter("accounts"), 2);

    // Logged out (the token is gone, as after `aws sso logout` too): no listing is served.
    sandbox.gac().arg("logout").assert().success();
    sandbox
        .gac()
        .arg("list")
        .assert()
        .code(3)
        .stderr(predicate::str::contains("gac login --session corp"));
    sandbox.gac().arg("sync").assert().code(3);
    assert_eq!(sandbox.mock.counter("accounts"), 2);
}

#[test]
fn the_fan_out_survives_portal_throttling() {
    let accounts: Vec<_> = (0..24)
        .map(|i| {
            account(
                &format!("{:012}", 100_000_000_000_u64 + i),
                &format!("acct-{i:02}"),
                &["Admin", "ReadOnly"],
            )
        })
        .collect();
    let sandbox = Sandbox::with_accounts(accounts);
    sandbox.write_config(SESSION);
    login_device(&sandbox);
    sandbox.mock.set_rate_limit(6);
    let listed = sandbox.gac().args(["list", "--json"]).assert().success();
    let json: Value = serde_json::from_slice(&listed.get_output().stdout).unwrap();
    let accounts = json["accounts"].as_array().unwrap();
    assert_eq!(accounts.len(), 24);
    assert!(
        accounts
            .iter()
            .all(|a| a["roles"].as_array().unwrap().len() == 2)
    );
}

#[test]
fn tokens_refresh_inside_the_fifteen_minute_window_exactly_once() {
    let sandbox = Sandbox::with_session();
    sandbox.mock.set_access_ttl(300);
    login_device(&sandbox);
    let before = sandbox.token("corp");
    sandbox.mock.set_access_ttl(8 * 3600);

    // Several processes find the token due at once; the lock lets exactly one refresh it.
    let children: Vec<_> = (0..6)
        .map(|_| sandbox.spawn_gac(&["list", "--refresh"]))
        .collect();
    for child in children {
        let output = child.wait_with_output().unwrap();
        assert!(output.status.success(), "{}", stderr(&output));
    }
    assert_eq!(sandbox.mock.counter("refresh"), 1);
    assert_eq!(sandbox.mock.counter("refresh_rejected"), 0);
    let after = sandbox.token("corp");
    assert_ne!(after["accessToken"], before["accessToken"]);
    assert_ne!(
        after["refreshToken"], before["refreshToken"],
        "the refresh token rotated"
    );
    assert_eq!(after["clientSecret"], before["clientSecret"]);
    assert_eq!(after["startUrl"], START_URL);
}

#[test]
fn an_expired_token_without_refresh_requires_login() {
    let sandbox = Sandbox::with_session();
    sandbox.write_token(
        "corp",
        &json!({"startUrl": START_URL, "region": "us-west-2", "accessToken": "FAKE-OLD", "expiresAt": "2020-01-01T00:00:00Z"}),
    );
    sandbox
        .gac()
        .arg("list")
        .assert()
        .code(3)
        .stderr(predicate::str::contains("the SSO token expired"))
        .stderr(predicate::str::contains("gac login --session corp"));
}

#[test]
fn a_revoked_token_requires_login() {
    let sandbox = Sandbox::with_session();
    login_device(&sandbox);
    let token = sandbox.token("corp");
    sandbox.mock.set_accounts(vec![]);
    // Simulate a revocation the cache does not know about.
    let mut forged = token.clone();
    forged["accessToken"] = json!("FAKE-REVOKED");
    sandbox.write_token("corp", &forged);
    sandbox
        .gac()
        .args(["list", "--refresh"])
        .assert()
        .code(3)
        .stderr(predicate::str::contains("rejected the SSO token"));
}

#[test]
fn sync_writes_an_idempotent_block_and_never_touches_other_bytes() {
    let sandbox = Sandbox::new();
    let before = "# hand-written\r\n[profile mine]\r\nregion = eu-west-1\r\n\r\n";
    let after = "[profile tail]\r\nregion = us-east-2\r\n";
    // A CRLF file with the session in the middle of user content.
    let session_crlf = SESSION.replace('\n', "\r\n");
    sandbox.write_config(&format!("{before}{session_crlf}\r\n{after}"));
    let original = sandbox.config();
    login_device(&sandbox);

    let dry = sandbox.gac().args(["sync", "--dry-run"]).assert().success();
    let diff = String::from_utf8_lossy(&dry.get_output().stdout).into_owned();
    assert!(
        diff.contains("+# BEGIN gac sync session=corp mode=sso name={account}/{role}"),
        "{diff}"
    );
    assert!(diff.contains("+[profile payments-prod/ReadOnly]"));
    assert_eq!(sandbox.config(), original, "a dry run writes nothing");

    sandbox
        .gac()
        .arg("sync")
        .assert()
        .success()
        .stderr(predicate::str::contains("Synced 5 profiles"));
    let synced = sandbox.config();
    assert!(
        synced.starts_with(&original),
        "the original bytes are a prefix"
    );
    let block = &synced[original.len()..];
    assert!(
        !block.replace("\r\n", "").contains('\n'),
        "the block uses the file's CRLF endings"
    );
    insta::assert_snapshot!(block.replace("\r\n", "\n"));

    // A second sync changes nothing at all.
    sandbox
        .gac()
        .arg("sync")
        .assert()
        .success()
        .stderr(predicate::str::contains("Already up to date"));
    assert_eq!(sandbox.config(), synced);

    // The user edits around the block; a sync after the portal changes rewrites only the block.
    let edited = format!("{synced}[profile later]\r\nregion = ap-south-1\r\n");
    sandbox.write_config(&edited);
    sandbox.mock.set_accounts(vec![account(
        "111122223333",
        "payments-prod",
        &["ReadOnly"],
    )]);
    sandbox
        .gac()
        .args(["sync", "--refresh"])
        .assert()
        .success()
        .stderr(predicate::str::contains("(0 added, 4 removed)"));
    let pruned = sandbox.config();
    let begin = pruned.find("# BEGIN gac").unwrap();
    let end = pruned.find("# END gac sync session=corp\r\n").unwrap()
        + "# END gac sync session=corp\r\n".len();
    assert_eq!(&pruned[..begin], &edited[..begin]);
    assert_eq!(&pruned[end..], "[profile later]\r\nregion = ap-south-1\r\n");
    assert!(!pruned.contains("AdministratorAccess"));
}

#[test]
fn sync_remembers_its_settings_in_the_begin_line() {
    let sandbox = Sandbox::with_session();
    login_device(&sandbox);
    sandbox
        .gac()
        .args([
            "sync",
            "--include",
            "*/ReadOnly",
            "--exclude",
            "sandbox/*",
            "--region",
            "eu-west-1",
            "--name",
            "{account_id}.{role}",
        ])
        .assert()
        .success();
    let config = sandbox.config();
    assert!(config.contains(
        "# BEGIN gac sync session=corp mode=sso name={account_id}.{role} region=eu-west-1 include=*/ReadOnly exclude=sandbox/*\n"
    ));
    assert!(config.contains("[profile 111122223333.ReadOnly]\nsso_session = corp\nsso_account_id = 111122223333\nsso_role_name = ReadOnly\nregion = eu-west-1\n"));
    assert!(!config.contains("777788889999"));

    // A plain sync keeps the stored settings; --reset drops them.
    sandbox
        .gac()
        .arg("sync")
        .assert()
        .success()
        .stderr(predicate::str::contains("Already up to date"));
    sandbox.gac().args(["sync", "--reset"]).assert().success();
    assert!(
        sandbox
            .config()
            .contains("# BEGIN gac sync session=corp mode=sso name={account}/{role}\n")
    );
}

#[test]
fn sync_never_creates_the_t5_layout() {
    let sandbox = Sandbox::with_session();
    sandbox.write_config(&format!(
        "{SESSION}\n[profile sandbox/ReadOnly]\nregion = us-east-1\n"
    ));
    sandbox.write_credentials("[payments-prod/ReadOnly]\naws_access_key_id = AKIAEXAMPLEEXAMPLE\naws_secret_access_key = FAKE-STATIC\n");
    login_device(&sandbox);
    sandbox
        .gac()
        .arg("sync")
        .assert()
        .success()
        .stderr(predicate::str::contains(
            "skipped profile `payments-prod/ReadOnly`",
        ))
        .stderr(predicate::str::contains("(T5)"))
        .stderr(predicate::str::contains(
            "skipped profile `sandbox/ReadOnly`",
        ));
    let config = sandbox.config();
    assert!(!config.contains("[profile payments-prod/ReadOnly]"));
    assert_eq!(
        config.matches("[profile sandbox/ReadOnly]").count(),
        1,
        "the user's profile is not shadowed"
    );
    assert!(config.contains("[profile payments-prod/AdministratorAccess]"));
    sandbox
        .gac()
        .arg("doctor")
        .assert()
        .stdout(predicate::str::contains("[ok] t5"));
}

#[test]
fn sync_refuses_to_write_around_broken_markers() {
    let sandbox = Sandbox::new();
    let broken = format!("{SESSION}\n# BEGIN gac sync session=corp mode=sso\n[profile x]\n");
    sandbox.write_config(&broken);
    login_device(&sandbox);
    sandbox
        .gac()
        .arg("sync")
        .assert()
        .code(1)
        .stderr(predicate::str::contains("has no END marker"));
    assert_eq!(sandbox.config(), broken);
}

#[test]
fn sync_refuses_colliding_names() {
    let sandbox = Sandbox::with_accounts(vec![
        account("111122223333", "dup", &["ReadOnly"]),
        account("444455556666", "DUP", &["ReadOnly"]),
    ]);
    sandbox.write_config(SESSION);
    login_device(&sandbox);
    sandbox
        .gac()
        .arg("sync")
        .assert()
        .code(2)
        .stderr(predicate::str::contains("{account}-{account_id}/{role}"));
    assert_eq!(sandbox.config(), SESSION);
}

#[test]
fn status_shows_sessions_and_blocks_without_secrets() {
    let sandbox = Sandbox::with_session();
    sandbox
        .gac()
        .arg("status")
        .assert()
        .success()
        .stdout(predicate::str::contains("not logged in"));
    login_device(&sandbox);
    sandbox.gac().arg("sync").assert().success();
    let human = sandbox.gac().arg("status").assert().success();
    let human = String::from_utf8_lossy(&human.get_output().stdout).into_owned();
    assert!(human.contains("session corp"));
    assert!(human.contains("refreshable"));
    assert!(human.contains("5 profiles, name={account}/{role}"));

    let json = sandbox.gac().args(["status", "--json"]).assert().success();
    let text = String::from_utf8_lossy(&json.get_output().stdout).into_owned();
    assert_no_secrets(&text, &sandbox.mock.secrets(), "status --json");
    let json: Value = serde_json::from_str(&text).unwrap();
    let session = &json["sessions"][0];
    assert_eq!(session["name"], "corp");
    assert_eq!(session["token"]["state"], "valid");
    assert_eq!(session["token"]["refreshable"], true);
    assert!(session["token"]["registrationExpiresAt"].is_string());
    assert_eq!(session["syncBlock"]["profiles"], 5);
}

#[test]
fn logout_revokes_and_deletes_the_token() {
    let sandbox = Sandbox::with_session();
    login_device(&sandbox);
    let access = sandbox.token("corp")["accessToken"]
        .as_str()
        .unwrap()
        .to_owned();
    sandbox
        .gac()
        .arg("logout")
        .assert()
        .success()
        .stderr(predicate::str::contains("Logged out of session `corp`."));
    assert_eq!(sandbox.mock.counter("logout"), 1);
    assert!(!sandbox.mock.is_live(&access));
    assert!(!sandbox.token_path("corp").exists());
    sandbox.gac().args(["list", "--refresh"]).assert().code(3);
    sandbox
        .gac()
        .args(["logout", "--all"])
        .assert()
        .success()
        .stderr(predicate::str::contains(
            "Session `corp` was not logged in.",
        ));
}

#[test]
fn doctor_flags_problems_with_fixes() {
    let sandbox = Sandbox::new();
    sandbox.write_config(&format!(
        "{SESSION}\n[profile dev]\nsso_session = corp\nsso_account_id = 111122223333\nsso_role_name = ReadOnly\n"
    ));
    sandbox.write_credentials(
        "[dev]\naws_access_key_id = AKIAEXAMPLEEXAMPLE\naws_secret_access_key = FAKE-STATIC\n",
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(
            sandbox.credentials_path(),
            std::fs::Permissions::from_mode(0o644),
        )
        .unwrap();
    }
    let config_before = sandbox.config();
    let output = sandbox.gac().arg("doctor").assert().code(1);
    let report = String::from_utf8_lossy(&output.get_output().stdout).into_owned();
    assert!(
        report.contains("[FAIL] t5: profile `dev` has static keys"),
        "{report}"
    );
    assert!(report.contains("fix: delete the [dev] section"));
    assert!(report.contains("session `corp` is not logged in"));
    #[cfg(unix)]
    assert!(
        report.contains("is 644: other users can read it"),
        "{report}"
    );
    assert_eq!(sandbox.config(), config_before, "doctor is read-only");

    let json = sandbox.gac().args(["doctor", "--json"]).assert().code(1);
    let json: Value = serde_json::from_slice(&json.get_output().stdout).unwrap();
    assert!(
        json["findings"]
            .as_array()
            .unwrap()
            .iter()
            .any(|f| f["check"] == "t5" && f["level"] == "fail")
    );
}

#[test]
fn the_fix_for_an_orphaned_block_is_one_setup_accepts() {
    let sandbox = Sandbox::new();
    let block = "# BEGIN gac sync session=corp mode=sso\n[profile dev]\nsso_session = corp\n# END gac sync session=corp\n";
    sandbox.write_config(&format!("[default]\nregion = eu-west-1\n\n{block}"));
    let hint =
        "delete the gac block for session `corp` by hand, then run `gac setup --session corp`";

    let doctor = sandbox.gac().arg("doctor").assert();
    let report = String::from_utf8_lossy(&doctor.get_output().stdout).into_owned();
    assert!(report.contains(&format!("fix: {hint}")), "{report}");
    let sync = sandbox
        .gac()
        .args(["sync", "--session", "corp"])
        .assert()
        .failure();
    let error = stderr(sync.get_output());
    assert!(
        error
            .split_whitespace()
            .collect::<Vec<_>>()
            .join(" ")
            .contains(hint),
        "{error}"
    );
    let setup = [
        "setup",
        "--session",
        "corp",
        "--start-url",
        START_URL,
        "--region",
        "us-west-2",
    ];
    sandbox.gac().args(setup).assert().failure();

    // Following the hint works.
    sandbox.write_config("[default]\nregion = eu-west-1\n");
    sandbox.gac().args(setup).assert().success();
}

#[test]
fn verbose_output_never_contains_a_secret() {
    let sandbox = Sandbox::with_session();
    sandbox.mock.set_access_ttl(300);
    let mut transcript = String::new();
    let mut run = |args: &[&str]| {
        let output = sandbox.gac().args(args).output().unwrap();
        assert!(output.status.success(), "{args:?}: {}", stderr(&output));
        transcript.push_str(&stdout(&output));
        transcript.push_str(&stderr(&output));
    };
    run(&["-vv", "login", "--device-code", "--no-browser"]);
    sandbox.mock.set_access_ttl(8 * 3600);
    run(&["-vv", "list", "--refresh"]); // refreshes the token
    run(&["-vv", "sync"]);
    run(&["-vv", "status", "--json"]);
    run(&["-vv", "doctor"]);
    run(&["-vv", "logout"]);
    let pkce = login_pkce(&sandbox, &["-vv"]);
    assert!(pkce.status.success());
    transcript.push_str(&stdout(&pkce));
    transcript.push_str(&stderr(&pkce));

    assert_eq!(
        sandbox.mock.counter("refresh"),
        1,
        "the refresh path was exercised"
    );
    assert!(
        transcript.contains("DEBUG") || transcript.contains("TRACE"),
        "-vv logs"
    );
    assert_no_secrets(&transcript, &sandbox.mock.secrets(), "-vv output");
}
