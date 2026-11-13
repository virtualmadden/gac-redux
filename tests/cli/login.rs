//! `gac setup`, `gac login` and `gac logout`, and how a command picks its session.

use super::*;

/// The block `gac setup` writes for the `corp` session.
const SETUP_BLOCK: &str = "\
# BEGIN gac-redux sync session=corp
# Managed by gac-redux: edits inside this block are replaced on the next sync.
[sso-session corp]
sso_start_url = https://mock-example.awsapps.com/start
sso_region = us-west-2
sso_registration_scopes = sso:account:access
# END gac-redux sync session=corp
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
        .replace("# END gac-redux sync session=corp\n", "");
    assert!(block.starts_with(&format!("{head}\n[profile ")), "{block}");
    assert!(block.ends_with("# END gac-redux sync session=corp\n"));
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

// Regression: ISSUE-002 - an unreachable endpoint printed the SDK's debug dump and no hint
// Found by /qa on 2026-11-13
#[test]
fn login_explains_an_unreachable_endpoint() {
    let sandbox = Sandbox::with_session();
    let closed = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let endpoint = format!("http://{}", closed.local_addr().unwrap());
    drop(closed);
    let output = sandbox
        .gac()
        .env("AWS_ENDPOINT_URL_SSO_OIDC", &endpoint)
        .args(["login", "--device-code", "--no-browser"])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(1));
    let text = stderr(&output);
    assert!(
        text.contains("RegisterClient failed: could not reach"),
        "{text}"
    );
    assert!(
        text.contains("help: check the network and HTTPS_PROXY"),
        "{text}"
    );
    assert!(!text.contains("DispatchFailure"), "{text}");
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
        .stderr(predicate::str::contains("gac select"))
        .stderr(predicate::str::contains("--session"));
    sandbox
        .gac()
        .env("GAC_REDUX_SESSION", "corp")
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
        .env("GAC_REDUX_SESSION", "other")
        .args(["login", "--device-code", "--no-browser", "--profile", "dev"])
        .assert()
        .success()
        .stderr(predicate::str::contains("Logged in to session `corp`"));
    assert!(sandbox.token_path("corp").exists());
    sandbox
        .gac()
        .env("GAC_REDUX_SESSION", "other")
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
fn logout_sweeps_the_aws_clis_sso_role_credentials_like_aws_sso_logout() {
    let sandbox = Sandbox::with_session();
    login_device(&sandbox);
    let cache = sandbox.home().join(".aws/cli/cache");
    std::fs::create_dir_all(&cache).unwrap();
    let sso = json!({"ProviderType": "sso", "Credentials": {"AccessKeyId": "ASIAMOCK"}});
    std::fs::write(cache.join("this-session.json"), sso.to_string()).unwrap();
    std::fs::write(cache.join("other-session.json"), sso.to_string()).unwrap();
    let assume_role = json!({"ProviderType": "assume-role", "Credentials": {}});
    std::fs::write(cache.join("assume-role.json"), assume_role.to_string()).unwrap();
    std::fs::write(cache.join("session.db"), "SQLite format 3\0").unwrap();

    sandbox
        .gac()
        .arg("logout")
        .assert()
        .success()
        .stderr(predicate::str::contains(
            "Deleted 2 role credentials the AWS CLI had cached from SSO tokens",
        ));
    assert!(!cache.join("this-session.json").exists());
    assert!(!cache.join("other-session.json").exists());
    assert!(cache.join("assume-role.json").exists());
    assert!(cache.join("session.db").exists());

    sandbox
        .gac()
        .arg("logout")
        .assert()
        .success()
        .stderr(predicate::str::contains("Deleted").not());
}

#[test]
fn logout_owns_up_to_an_unreadable_token() {
    let sandbox = Sandbox::with_session();
    sandbox.write_token(
        "corp",
        &json!({"accessToken": "FAKE-x", "expiresAt": "soon"}),
    );
    sandbox
        .gac()
        .arg("logout")
        .assert()
        .success()
        .stderr(predicate::str::contains("unreadable token"))
        .stderr(predicate::str::contains("not logged in").not());
    assert_eq!(sandbox.mock.counter("logout"), 0);
    assert!(!sandbox.token_path("corp").exists());
}

#[test]
fn logout_all_names_what_it_could_not_log_out() {
    let sandbox = Sandbox::new();
    sandbox.write_config(&format!(
        "{SESSION}\n[sso-session broken]\nsso_start_url = https://other.awsapps.com/start\n\n[profile old]\nsso_start_url = https://old.awsapps.com/start\n"
    ));
    sandbox
        .gac()
        .args([
            "login",
            "--session",
            "corp",
            "--device-code",
            "--no-browser",
        ])
        .assert()
        .success();
    sandbox
        .gac()
        .args(["logout", "--all"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("Logged out of session `corp`."))
        .stderr(predicate::str::contains(
            "[sso-session broken] has no sso_region",
        ))
        .stderr(predicate::str::contains(
            "profile `old` has sso_start_url but no sso_region",
        ));
    assert!(!sandbox.token_path("corp").exists());
}
