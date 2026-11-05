//! Interop with the real AWS CLI v2 and the Rust SDK's aws-config, in sandbox HOMEs against the
//! mock Identity Center.
//!
//! - The AWS CLI and aws-config read the token cache gac writes, and refresh it in place.
//! - gac consumes caches written by `aws sso login`, with either flow.
//! - Profiles written by `gac sync` resolve in both.
//! - `aws sso logout` sweeps gac's token.
//!
//! The AWS CLI tests skip when `aws` is not installed, unless `GAC_REQUIRE_AWS_CLI` is set (CI).

mod support;

use std::process::{Command, Output, Stdio};

use serde_json::Value;
use support::{SESSION, START_URL, Sandbox, drive_browser, key_order, stderr, stdout};

/// A profile that resolves through the `corp` session.
const DEV_PROFILE: &str = "
[profile dev]
sso_session = corp
sso_account_id = 111122223333
sso_role_name = ReadOnly
region = us-west-2
";

fn sandbox_with_dev() -> Sandbox {
    let sandbox = Sandbox::new();
    sandbox.write_config(&format!("{SESSION}{DEV_PROFILE}"));
    sandbox
}

fn gac_login(sandbox: &Sandbox) {
    sandbox
        .gac()
        .args(["login", "--device-code", "--no-browser"])
        .assert()
        .success();
}

fn run(mut cmd: Command) -> Output {
    let output = cmd.output().unwrap();
    assert!(
        output.status.success(),
        "{cmd:?} failed:\nstdout: {}\nstderr: {}",
        stdout(&output),
        stderr(&output)
    );
    output
}

/// `aws configure export-credentials`: resolves the profile through the CLI's SSO provider.
fn aws_export(sandbox: &Sandbox, profile: &str) -> Option<Value> {
    let mut cmd = sandbox.aws()?;
    cmd.args([
        "configure",
        "export-credentials",
        "--profile",
        profile,
        "--format",
        "process",
    ]);
    Some(serde_json::from_slice(&run(cmd).stdout).unwrap())
}

#[test]
fn the_aws_cli_reads_a_token_gac_wrote() {
    let sandbox = sandbox_with_dev();
    gac_login(&sandbox);
    let Some(creds) = aws_export(&sandbox, "dev") else {
        return;
    };
    assert_eq!(creds["Version"], 1);
    assert_eq!(creds["AccessKeyId"], "ASIAMOCK11112222");
    assert_eq!(sandbox.mock.counter("credentials"), 1);
    assert_eq!(
        sandbox.mock.counter("refresh"),
        0,
        "a fresh token is used as it is"
    );
}

#[test]
fn the_aws_cli_refreshes_a_token_gac_wrote() {
    let sandbox = sandbox_with_dev();
    sandbox.mock.set_access_ttl(300);
    gac_login(&sandbox);
    let before = sandbox.token("corp");
    sandbox.mock.set_access_ttl(8 * 3600);

    let Some(creds) = aws_export(&sandbox, "dev") else {
        return;
    };
    assert_eq!(creds["AccessKeyId"], "ASIAMOCK11112222");
    assert_eq!(
        sandbox.mock.counter("refresh"),
        1,
        "the CLI refreshed inside its 15-minute window"
    );
    let after = sandbox.token("corp");
    assert_ne!(after["accessToken"], before["accessToken"]);
    assert_ne!(after["refreshToken"], before["refreshToken"]);

    // gac keeps working from the cache the CLI rewrote.
    let status = sandbox.gac().args(["status", "--json"]).assert().success();
    let status: Value = serde_json::from_slice(&status.get_output().stdout).unwrap();
    assert_eq!(status["sessions"][0]["token"]["state"], "valid");
    sandbox.gac().args(["list", "--refresh"]).assert().success();
    assert_eq!(sandbox.mock.counter("refresh"), 1);
}

#[test]
fn aws_config_reads_and_refreshes_a_token_gac_wrote() {
    let sandbox = sandbox_with_dev();
    gac_login(&sandbox);
    assert_eq!(sdk_probe(&sandbox, "dev").unwrap(), "ASIAMOCK11112222");
    assert_eq!(sandbox.mock.counter("refresh"), 0);

    // aws-config refreshes inside its own 5-minute window.
    sandbox.mock.set_access_ttl(200);
    gac_login(&sandbox);
    let before = sandbox.token("corp");
    sandbox.mock.set_access_ttl(8 * 3600);
    assert_eq!(sdk_probe(&sandbox, "dev").unwrap(), "ASIAMOCK11112222");
    assert_eq!(sandbox.mock.counter("refresh"), 1);
    let after = sandbox.token("corp");
    assert_ne!(after["refreshToken"], before["refreshToken"]);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(sandbox.token_path("corp"))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600, "aws-config kept the file private");
    }
    sandbox.gac().args(["list", "--refresh"]).assert().success();
}

#[test]
fn gac_consumes_a_cache_from_aws_sso_login_with_a_device_code() {
    let sandbox = sandbox_with_dev();
    let Some(mut aws) = sandbox.aws() else { return };
    aws.args([
        "sso",
        "login",
        "--sso-session",
        "corp",
        "--use-device-code",
        "--no-browser",
    ]);
    run(aws);
    assert!(sandbox.token_path("corp").exists());

    sandbox.gac().args(["list", "--refresh"]).assert().success();
    sandbox.gac().arg("sync").assert().success();
    assert_eq!(
        sandbox.mock.counter("register"),
        1,
        "gac did not register or log in again"
    );
    assert_eq!(sandbox.mock.counter("token_device"), 1);
}

#[test]
fn gac_consumes_a_cache_from_aws_sso_login_with_pkce() {
    let sandbox = sandbox_with_dev();
    let Some(mut aws) = sandbox.aws() else { return };
    aws.args(["sso", "login", "--sso-session", "corp", "--no-browser"])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let output = drive_browser(aws.spawn().unwrap());
    assert!(
        output.status.success(),
        "{}{}",
        stdout(&output),
        stderr(&output)
    );
    assert_eq!(sandbox.mock.counter("token_code"), 1);

    sandbox.gac().args(["list", "--refresh"]).assert().success();
    assert_eq!(sandbox.mock.counter("register"), 1);
}

#[test]
fn gac_writes_the_same_bytes_shape_as_the_aws_cli() {
    let cli = sandbox_with_dev();
    let Some(mut aws) = cli.aws() else { return };
    aws.args([
        "sso",
        "login",
        "--sso-session",
        "corp",
        "--use-device-code",
        "--no-browser",
    ]);
    run(aws);
    let gac = sandbox_with_dev();
    gac_login(&gac);

    let (cli_text, gac_text) = (cli.token_text("corp"), gac.token_text("corp"));
    assert_eq!(key_order(&cli_text), key_order(&gac_text), "key order");
    // Python json.dumps separators and `Z` timestamps, no trailing newline.
    for text in [&cli_text, &gac_text] {
        assert!(text.starts_with(&format!(
            "{{\"startUrl\": \"{START_URL}\", \"region\": \"us-west-2\", \"accessToken\": \""
        )));
        assert!(!text.ends_with('\n'));
        let token: Value = serde_json::from_str(text).unwrap();
        for key in ["expiresAt", "registrationExpiresAt"] {
            let at = token[key].as_str().unwrap();
            assert_eq!(at.len(), 20, "{key}: {at}");
            assert!(at.ends_with('Z'));
        }
    }
}

#[test]
fn a_token_gac_refreshed_stays_usable_by_the_aws_cli() {
    let sandbox = sandbox_with_dev();
    let Some(mut aws) = sandbox.aws() else { return };
    sandbox.mock.set_access_ttl(300);
    aws.args([
        "sso",
        "login",
        "--sso-session",
        "corp",
        "--use-device-code",
        "--no-browser",
    ]);
    run(aws);
    sandbox.mock.set_access_ttl(8 * 3600);

    sandbox.gac().args(["list", "--refresh"]).assert().success();
    assert_eq!(
        sandbox.mock.counter("refresh"),
        1,
        "gac refreshed the CLI's token"
    );
    let creds = aws_export(&sandbox, "dev").unwrap();
    assert_eq!(creds["AccessKeyId"], "ASIAMOCK11112222");
    assert_eq!(
        sandbox.mock.counter("refresh"),
        1,
        "the CLI used gac's refreshed token"
    );
}

#[test]
fn synced_profiles_resolve_in_the_aws_cli_and_aws_config() {
    let sandbox = Sandbox::new();
    sandbox.write_config(SESSION);
    gac_login(&sandbox);
    sandbox
        .gac()
        .args(["sync", "--region", "us-west-2"])
        .assert()
        .success();

    assert_eq!(
        sdk_probe(&sandbox, "shared-services/ReadOnly").unwrap(),
        "ASIAMOCK44445555"
    );
    let Some(creds) = aws_export(&sandbox, "payments-prod/AdministratorAccess") else {
        return;
    };
    assert_eq!(creds["AccessKeyId"], "ASIAMOCK11112222");
}

#[test]
fn aws_sso_logout_sweeps_the_token_gac_wrote() {
    let sandbox = sandbox_with_dev();
    gac_login(&sandbox);
    let Some(mut aws) = sandbox.aws() else { return };
    aws.args(["sso", "logout"]);
    run(aws);
    assert!(!sandbox.token_path("corp").exists());
    assert_eq!(
        sandbox.mock.counter("logout"),
        1,
        "startUrl and region let the CLI revoke it"
    );
    sandbox
        .gac()
        .arg("status")
        .assert()
        .success()
        .stdout(predicates::str::contains("not logged in"));
}

/// Resolves `profile` with aws-config in a child process whose HOME is the sandbox. The child is
/// this test binary, re-run to execute only [`sdk_probe_child`].
fn sdk_probe(sandbox: &Sandbox, profile: &str) -> Result<String, String> {
    let mut cmd = Command::new(std::env::current_exe().unwrap());
    cmd.args([
        "sdk_probe_child",
        "--exact",
        "--nocapture",
        "--test-threads=1",
    ]);
    sandbox.confine(&mut cmd);
    cmd.env("GAC_SDK_PROBE_PROFILE", profile);
    let output = cmd.output().unwrap();
    let out = stdout(&output);
    // libtest prints the marker on the line that names the test.
    if let Some(key) = out
        .split("GAC_SDK_PROBE_OK ")
        .nth(1)
        .and_then(|rest| rest.split_whitespace().next())
    {
        Ok(key.to_owned())
    } else {
        Err(format!(
            "aws-config could not resolve `{profile}`:\n{out}\n{}",
            stderr(&output)
        ))
    }
}

#[test]
fn sdk_probe_child() {
    use aws_config::BehaviorVersion;
    use aws_credential_types::provider::ProvideCredentials;

    let Ok(profile) = std::env::var("GAC_SDK_PROBE_PROFILE") else {
        return; // Only meaningful when run by `sdk_probe`.
    };
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    runtime.block_on(async {
        let config = aws_config::defaults(BehaviorVersion::latest())
            .profile_name(&profile)
            .load()
            .await;
        let provider = config
            .credentials_provider()
            .expect("a credentials provider");
        match provider.provide_credentials().await {
            Ok(creds) => println!("GAC_SDK_PROBE_OK {}", creds.access_key_id()),
            Err(err) => println!("GAC_SDK_PROBE_ERR {err:?}"),
        }
    });
}
