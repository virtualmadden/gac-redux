//! The token cache, its refresh, and the inventory cache behind `gac list`.

use super::*;

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

/// About 6 s: 25 portal calls against a limit of 6 a second, which throttles the fan-out of 8.
/// `src/portal.rs` covers throttling heavy enough to exhaust the SDK's retry budget.
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
    let start = std::time::Instant::now();
    let listed = sandbox.gac().args(["list", "--json"]).assert().success();
    let elapsed = start.elapsed();
    let json: Value = serde_json::from_slice(&listed.get_output().stdout).unwrap();
    let accounts = json["accounts"].as_array().unwrap();
    assert_eq!(accounts.len(), 24);
    assert!(
        accounts
            .iter()
            .all(|a| a["roles"].as_array().unwrap().len() == 2)
    );
    assert!(
        sandbox.mock.counter("throttled") > 0,
        "the portal throttled the fan-out"
    );
    // 25 calls at 6 a second take about 4 s, and the listing about 6 s. With the SDK's 20 s
    // maximum backoff, adaptive retry stalled it to about 20 s.
    assert!(
        elapsed < std::time::Duration::from_secs(10),
        "the throttled listing took {elapsed:?}"
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
fn an_expired_token_whose_refresh_is_rejected_is_not_promised_a_refresh() {
    let sandbox = Sandbox::with_session();
    role_profiles_config(&sandbox);
    login_device(&sandbox);
    // The portal session ended: the cache still has a refresh token, but the service rejects it.
    let mut token = sandbox.token("corp");
    token["expiresAt"] = json!("2020-01-01T00:00:00Z");
    token["refreshToken"] = json!("FAKE-ENDED");
    sandbox.write_token("corp", &token);

    // whoami reads only local files, so it suits a shell prompt: it states what the next use does.
    sandbox
        .gac()
        .arg("whoami")
        .assert()
        .success()
        .stdout(predicate::str::contains(
            "expired at 2020-01-01T00:00:00Z; the next use tries a refresh",
        ));
    assert_eq!(sandbox.mock.counter("refresh_rejected"), 0);

    // status and doctor try the refresh, so they report what the next use will find.
    let output = sandbox.gac().arg("status").assert().success();
    let out = stdout(output.get_output());
    assert_eq!(sandbox.mock.counter("refresh_rejected"), 1);
    assert!(
        out.contains("expired at 2020-01-01T00:00:00Z and could not be refreshed: CreateToken failed: InvalidGrantException"),
        "{out}"
    );
    assert!(!out.contains("tries a refresh"), "{out}");
    let output = sandbox.gac().args(["status", "--json"]).assert().success();
    let json: Value = serde_json::from_slice(&output.get_output().stdout).unwrap();
    let token_json = &json["sessions"][0]["token"];
    assert_eq!(token_json["state"], "expired");
    assert_eq!(token_json["refreshable"], false);
    assert!(
        token_json["refreshError"]
            .as_str()
            .unwrap()
            .contains("InvalidGrantException"),
        "{token_json}"
    );

    let output = sandbox.gac().arg("doctor").assert().success();
    let out = stdout(output.get_output());
    assert!(
        out.contains("[warn] sessions: session `corp`: the token expired at 2020-01-01T00:00:00Z and could not be refreshed: CreateToken failed: InvalidGrantException"),
        "{out}"
    );
    assert!(out.contains("fix: run `gac login --session corp`"), "{out}");
    assert!(!out.contains("tries to refresh"), "{out}");

    let output = sandbox.gac().arg("list").assert().code(3);
    let err = stderr(output.get_output());
    assert_eq!(sandbox.mock.counter("refresh_rejected"), 4);
    // At the default width of 80 the timestamp lands on the wrap point; it must stay whole.
    assert!(err.contains("2020-01-01T00:00:00Z"), "{err}");
    assert!(err.contains("could not be refreshed"), "{err}");
    assert!(err.contains("InvalidGrantException"), "{err}");
    assert!(err.contains("gac login --session corp"), "{err}");
    assert!(
        !err.contains("WARN"),
        "the reason is in the error, not a separate log line: {err}"
    );
}

/// Every command that needs a token, with the portal session ended under a valid-looking
/// refresh token: each tries the refresh once and asks for a login with the service's reason.
#[test]
fn every_command_that_refreshes_asks_for_a_login_when_the_portal_session_ended() {
    let sandbox = Sandbox::with_session();
    role_profiles_config(&sandbox);
    login_device(&sandbox);
    let mut ended = sandbox.token("corp");
    ended["expiresAt"] = json!("2020-01-01T00:00:00Z");
    ended["refreshToken"] = json!("FAKE-ENDED");
    let exec: Vec<String> = ["exec", "--"]
        .into_iter()
        .map(String::from)
        .chain(exit_with("0"))
        .collect();
    let commands: Vec<Vec<String>> = vec![
        vec!["list".into(), "--refresh".into()],
        vec!["sync".into(), "--refresh".into()],
        vec!["select".into(), "payments-prod/ReadOnly".into()],
        exec,
        vec!["env".into()],
        vec!["console".into(), "--print".into()],
        vec![
            "credential-process".into(),
            "--session".into(),
            "corp".into(),
            "--account-id".into(),
            "777788889999".into(),
            "--role-name".into(),
            "PowerUser".into(),
        ],
    ];
    for args in commands {
        sandbox.write_token("corp", &ended);
        let rejected = sandbox.mock.counter("refresh_rejected");
        let output = sandbox.gac().args(&args).assert().code(3);
        let err = stderr(output.get_output());
        assert!(err.contains("InvalidGrantException"), "{args:?}: {err}");
        assert!(err.contains("gac login --session corp"), "{args:?}: {err}");
        assert!(
            sandbox.mock.counter("refresh_rejected") > rejected,
            "{args:?} tried the refresh"
        );
    }
}

#[test]
fn status_and_doctor_refresh_an_expired_token_the_service_still_accepts() {
    for command in ["status", "doctor"] {
        let sandbox = Sandbox::with_session();
        login_device(&sandbox);
        let mut token = sandbox.token("corp");
        token["expiresAt"] = json!("2020-01-01T00:00:00Z");
        sandbox.write_token("corp", &token);

        let output = sandbox.gac().arg(command).assert().success();
        let out = stdout(output.get_output());
        assert_eq!(sandbox.mock.counter("refresh"), 1, "{command}");
        let expected = match command {
            "status" => "token         valid until",
            _ => "[ok] sessions: session `corp`: logged in until",
        };
        assert!(out.contains(expected), "{command}: {out}");
        let after = sandbox.token("corp");
        assert_ne!(after["accessToken"], token["accessToken"], "{command}");
        assert_ne!(after["expiresAt"], token["expiresAt"], "{command}");
    }
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
