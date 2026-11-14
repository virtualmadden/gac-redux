//! Commands that use a role: `exec`, `env`, `console`, `whoami` and `credential-process`.

use super::*;

#[test]
fn exec_runs_a_command_as_the_default_profiles_role_and_caches_the_credentials() {
    let sandbox = Sandbox::with_session();
    login_device(&sandbox);
    sandbox
        .gac()
        .args(["select", "sandbox/PowerUser"])
        .assert()
        .success();

    let mut args = vec!["exec", "--"];
    args.extend(print_env());
    let output = sandbox
        .gac()
        .args(&args)
        .env("AWS_PROFILE", "default")
        .env("AWS_ACCESS_KEY_ID", "AKIASTALE")
        .assert()
        .success();
    let env = parse_env(&stdout(output.get_output()));
    assert_eq!(env["AWS_ACCESS_KEY_ID"], "ASIAMOCK77778888");
    let secrets = sandbox.mock.secrets();
    assert!(secrets.contains(&env["AWS_SECRET_ACCESS_KEY"]));
    assert!(secrets.contains(&env["AWS_SESSION_TOKEN"]));
    assert!(env["AWS_CREDENTIAL_EXPIRATION"].ends_with('Z'));
    assert_eq!(env["GAC_REDUX_EXEC"], "the [default] profile");
    assert!(!env.contains_key("AWS_PROFILE"), "AWS_PROFILE is unset");
    assert!(!env.contains_key("AWS_REGION"), "no region is known");
    assert_eq!(sandbox.mock.counter("credentials"), 1);

    // The entry is where the AWS CLI looks for it, private, and reused by the next run.
    let cache = role_cache_path(&sandbox, "777788889999", "PowerUser");
    let entry: Value = serde_json::from_slice(&std::fs::read(&cache).unwrap()).unwrap();
    assert_eq!(entry["ProviderType"], "sso");
    assert_eq!(entry["Credentials"]["AccessKeyId"], "ASIAMOCK77778888");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&cache).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
    }
    sandbox.gac().args(&args).assert().success();
    assert_eq!(
        sandbox.mock.counter("credentials"),
        1,
        "the second run uses the cache"
    );
    assert_no_secrets(&stderr(output.get_output()), &secrets, "exec");
}

#[test]
fn exec_takes_the_role_from_a_target_or_a_profile() {
    let sandbox = Sandbox::with_session();
    login_device(&sandbox);
    sandbox.write_config(&format!(
        "{SESSION}\n[profile dev]\nsso_session = corp\nsso_account_id = 111122223333\nsso_role_name = ReadOnly\nregion = eu-west-1\n"
    ));
    let env_of = |args: &[&str], extra: &[(&str, &str)]| {
        let mut all = args.to_vec();
        all.push("--");
        all.extend(print_env());
        let mut cmd = sandbox.gac();
        cmd.args(&all);
        for (name, value) in extra {
            cmd.env(name, value);
        }
        let output = cmd.assert().success();
        parse_env(&stdout(output.get_output()))
    };

    let env = env_of(&["exec", "shared-services/ReadOnly"], &[]);
    assert_eq!(env["AWS_ACCESS_KEY_ID"], "ASIAMOCK44445555");
    assert_eq!(env["GAC_REDUX_EXEC"], "Shared Services/ReadOnly");

    let env = env_of(&["exec", "--profile", "dev"], &[]);
    assert_eq!(env["AWS_ACCESS_KEY_ID"], "ASIAMOCK11112222");
    assert_eq!(env["AWS_REGION"], "eu-west-1");
    assert_eq!(env["AWS_DEFAULT_REGION"], "eu-west-1");

    // AWS_PROFILE picks the profile, an inherited region beats the profile's, --region beats both.
    let env = env_of(
        &["exec"],
        &[("AWS_PROFILE", "dev"), ("AWS_REGION", "us-east-2")],
    );
    assert_eq!(env["AWS_ACCESS_KEY_ID"], "ASIAMOCK11112222");
    assert_eq!(env["AWS_REGION"], "us-east-2");
    let env = env_of(
        &["exec", "--profile", "dev", "--region", "ap-south-1"],
        &[("AWS_REGION", "us-east-2")],
    );
    assert_eq!(env["AWS_REGION"], "ap-south-1");

    // Without [default], a profile or a target there is nothing to pick.
    let mut args = vec!["exec", "--"];
    args.extend(print_env());
    let output = sandbox.gac().args(&args).assert().code(1);
    assert!(
        stderr(output.get_output()).contains("there is no [default] profile"),
        "{}",
        stderr(output.get_output())
    );
    sandbox
        .gac()
        .args(["exec", "nope/ReadOnly", "--", "x"])
        .assert()
        .code(2)
        .stderr(predicate::str::contains(
            "no account and role match `nope/ReadOnly`",
        ));
}

#[test]
fn exec_passes_the_exit_code_through_and_refuses_to_nest() {
    let sandbox = Sandbox::with_session();
    login_device(&sandbox);
    let mut args: Vec<String> = ["exec", "sandbox/ReadOnly", "--"]
        .map(String::from)
        .to_vec();
    args.extend(exit_with("7"));
    sandbox.gac().args(&args).assert().code(7);

    sandbox
        .gac()
        .args(&args)
        .env("GAC_REDUX_EXEC", "payments-prod/ReadOnly")
        .assert()
        .code(2)
        .stderr(predicate::str::contains(
            "already running inside `gac exec` as payments-prod/ReadOnly",
        ));
    sandbox
        .gac()
        .args(["exec", "--force", "sandbox/ReadOnly", "--"])
        .args(exit_with("0"))
        .env("GAC_REDUX_EXEC", "payments-prod/ReadOnly")
        .assert()
        .success();

    sandbox
        .gac()
        .args(["exec", "sandbox/ReadOnly", "--", "gac-no-such-command"])
        .assert()
        .code(127)
        .stderr(predicate::str::contains(
            "could not run `gac-no-such-command`",
        ));
}

#[test]
fn exec_and_env_without_a_session_point_to_setup() {
    let sandbox = Sandbox::new();
    for command in [&["exec", "--", "x"][..], &["env"]] {
        sandbox
            .gac()
            .args(command)
            .assert()
            .code(1)
            .stderr(predicate::str::contains("there is no [default] profile"))
            .stderr(predicate::str::contains(
                "run `gac setup`, then `gac select`",
            ));
    }
}

#[test]
fn exec_without_a_login_exits_3() {
    let sandbox = Sandbox::with_session();
    sandbox.write_config(&format!(
        "{SESSION}\n[profile dev]\nsso_session = corp\nsso_account_id = 111122223333\nsso_role_name = ReadOnly\n"
    ));
    sandbox
        .gac()
        .args(["exec", "--profile", "dev", "--"])
        .args(exit_with("0"))
        .assert()
        .code(3)
        .stderr(predicate::str::contains("gac login --session corp"));
    assert_eq!(sandbox.mock.counter("credentials"), 0);
}

#[test]
fn whoami_answers_from_local_files_alone() {
    let sandbox = Sandbox::with_session();
    role_profiles_config(&sandbox);
    let portal_calls = |sandbox: &Sandbox| {
        [
            "accounts",
            "roles",
            "credentials",
            "refresh",
            "unauthorized",
        ]
        .map(|name| sandbox.mock.counter(name))
    };

    // Without a login it still answers, from the files alone.
    let output = sandbox.gac().arg("whoami").assert().success();
    let text = String::from_utf8_lossy(&output.get_output().stdout).into_owned();
    for line in [
        "profile      [default] (no --profile or AWS_PROFILE)\n",
        "session      corp\n",
        "account      111122223333\n",
        "role         ReadOnly\n",
        "region       not set\n",
        "token        not logged in; run `gac login --session corp`\n",
        "credentials  none cached; the next use fetches them\n",
    ] {
        assert!(text.contains(line), "{line:?} in\n{text}");
    }

    // After a listing and a use, the account name and both expiries come from the caches,
    // without another portal call.
    login_device(&sandbox);
    sandbox.gac().arg("list").assert().success();
    sandbox
        .gac()
        .args(["exec", "--"])
        .args(exit_with("0"))
        .assert()
        .success();
    let before = portal_calls(&sandbox);
    let output = sandbox.gac().args(["whoami", "--json"]).assert().success();
    let json: Value = serde_json::from_slice(&output.get_output().stdout).unwrap();
    assert_eq!(json["profile"], "default");
    assert_eq!(json["source"], "[default]");
    assert_eq!(json["accountId"], "111122223333");
    assert_eq!(json["accountName"], "payments-prod");
    assert_eq!(json["roleName"], "ReadOnly");
    assert_eq!(json["token"]["state"], "valid");
    assert_eq!(json["credentials"]["state"], "valid");
    assert_eq!(json["environmentCredentials"], false);
    let text = sandbox.gac().arg("whoami").output().unwrap();
    let text = String::from_utf8_lossy(&text.stdout).into_owned();
    assert!(
        text.contains("account      111122223333 (payments-prod)\n"),
        "{text}"
    );
    assert!(text.contains("credentials  cached until "), "{text}");
    assert_eq!(portal_calls(&sandbox), before);
}

#[test]
fn whoami_names_the_rule_that_picked_the_profile() {
    let sandbox = Sandbox::with_session();
    role_profiles_config(&sandbox);
    login_device(&sandbox);
    sandbox.gac().arg("list").assert().success();
    sandbox
        .gac()
        .args(["whoami", "--profile", "dev"])
        .assert()
        .success()
        .stdout(predicate::str::contains(
            "profile      dev (from --profile)\n",
        ))
        .stdout(predicate::str::contains(
            "account      777788889999 (sandbox)\n",
        ))
        .stdout(predicate::str::contains("region       eu-west-1\n"))
        .stdout(predicate::str::contains("credentials  none cached"));
    sandbox
        .gac()
        .arg("whoami")
        .env("AWS_PROFILE", "dev")
        .env("AWS_REGION", "us-east-2")
        .assert()
        .success()
        .stdout(predicate::str::contains(
            "profile      dev (from AWS_PROFILE)\n",
        ))
        .stdout(predicate::str::contains(
            "region       us-east-2 (from AWS_REGION)\n",
        ));
    sandbox
        .gac()
        .arg("whoami")
        .env("AWS_PROFILE", "nope")
        .assert()
        .code(1)
        .stderr(predicate::str::contains(
            "no profile `nope` in the AWS config file (from AWS_PROFILE)",
        ))
        .stderr(predicate::str::contains(
            "unset AWS_PROFILE to use [default]",
        ));

    // Inside `gac exec`, the keys in the environment win over any profile.
    sandbox
        .gac()
        .arg("whoami")
        .env("AWS_ACCESS_KEY_ID", "ASIAEXAMPLE")
        .env("GAC_REDUX_EXEC", "profile `dev`")
        .assert()
        .success()
        .stdout(predicate::str::contains(
            "AWS_ACCESS_KEY_ID is set by `gac exec` as profile `dev`: AWS tools use those keys, not this profile.",
        ));
}

#[test]
fn console_signs_in_as_the_role_through_the_federation_endpoint() {
    let sandbox = Sandbox::with_session();
    role_profiles_config(&sandbox);
    login_device(&sandbox);
    let link = |args: &[&str]| -> url::Url {
        let output = sandbox
            .gac()
            .args(["console", "--print"])
            .args(args)
            .assert()
            .success();
        let stdout = String::from_utf8(output.get_output().stdout.clone()).unwrap();
        url::Url::parse(stdout.trim_end()).unwrap()
    };
    let query = |url: &url::Url, key: &str| {
        url.query_pairs()
            .find(|(k, _)| k == key)
            .map(|(_, v)| v.into_owned())
    };

    let url = link(&["--profile", "dev"]);
    assert_eq!(url.path(), "/federation");
    assert_eq!(query(&url, "Action").as_deref(), Some("login"));
    assert_eq!(
        query(&url, "Issuer").as_deref(),
        Some("https://mock-example.awsapps.com/start")
    );
    assert_eq!(
        query(&url, "Destination").as_deref(),
        Some("https://console.aws.amazon.com/console/home?region=eu-west-1")
    );
    let token = query(&url, "SigninToken").unwrap();
    assert!(
        sandbox.mock.secrets().contains(&token),
        "the mock's sign-in token"
    );
    assert_eq!(sandbox.mock.counter("signin_token"), 1);

    // The role credentials come from the cache the second time; the sign-in token is new.
    let url = link(&[
        "--profile",
        "dev",
        "--destination",
        "s3/home",
        "--region",
        "us-east-2",
    ]);
    assert_eq!(
        query(&url, "Destination").as_deref(),
        Some("https://console.aws.amazon.com/s3/home?region=us-east-2")
    );
    assert_eq!(sandbox.mock.counter("credentials"), 1);
    assert_eq!(sandbox.mock.counter("signin_token"), 2);
    assert_eq!(
        query(&link(&[]), "Destination").as_deref(),
        Some("https://console.aws.amazon.com/console/home"),
        "[default] names no region"
    );

    // Over SSH the link is printed for the person, on stderr.
    sandbox
        .gac()
        .args(["console", "-p", "dev"])
        .env("SSH_CONNECTION", "10.0.0.1 22 10.0.0.2 22")
        .assert()
        .success()
        .stdout("")
        .stderr(predicate::str::contains(
            "Open this link to sign in to the AWS console as profile `dev`.",
        ))
        .stderr(predicate::str::contains("SigninToken="));
}

// Regression: #78 - a cleartext endpoint override was sent the role's credentials
#[test]
fn console_refuses_a_cleartext_federation_endpoint() {
    let sandbox = Sandbox::with_session();
    role_profiles_config(&sandbox);
    login_device(&sandbox);
    sandbox
        .gac()
        .args(["console", "--print", "--profile", "dev"])
        .env(
            "GAC_REDUX_FEDERATION_ENDPOINT",
            "http://signin.example.com/federation",
        )
        .assert()
        .code(1)
        .stdout("")
        .stderr(predicate::str::contains(
            "GAC_REDUX_FEDERATION_ENDPOINT must be an https:// URL",
        ))
        .stderr(predicate::str::contains(
            "help: unset GAC_REDUX_FEDERATION_ENDPOINT",
        ));
    // Refused before the role's credentials were fetched, so none were sent anywhere.
    assert_eq!(sandbox.mock.counter("credentials"), 0);
    assert_eq!(sandbox.mock.counter("signin_token"), 0);
}

#[test]
fn console_replaces_cached_credentials_the_endpoint_refuses() {
    let sandbox = Sandbox::with_session();
    role_profiles_config(&sandbox);
    login_device(&sandbox);
    // Credentials the mock never issued, as if revoked before they expired.
    let path = role_cache_path(&sandbox, "777788889999", "PowerUser");
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(
        &path,
        r#"{"ProviderType":"sso","Credentials":{"AccessKeyId":"ASIAREVOKED","SecretAccessKey":"x","SessionToken":"y","Expiration":"2099-01-01T00:00:00Z"}}"#,
    )
    .unwrap();
    sandbox
        .gac()
        .args(["console", "--print", "-p", "dev"])
        .assert()
        .success()
        .stdout(predicate::str::contains("SigninToken="));
    assert_eq!(
        sandbox.mock.counter("signin_token"),
        2,
        "refused, then retried"
    );
    assert_eq!(
        sandbox.mock.counter("credentials"),
        1,
        "fetched once, fresh"
    );
    let cached = std::fs::read_to_string(&path).unwrap();
    assert!(!cached.contains("ASIAREVOKED"), "{cached}");
}

#[test]
fn console_without_a_login_exits_3() {
    let sandbox = Sandbox::with_session();
    role_profiles_config(&sandbox);
    sandbox
        .gac()
        .args(["console", "--print"])
        .assert()
        .code(3)
        .stdout("");
    assert_eq!(sandbox.mock.counter("signin_token"), 0);
}

#[test]
fn exec_follows_a_role_chain_and_caches_each_role() {
    let sandbox = Sandbox::with_session();
    sandbox.write_config(&format!(
        "{SESSION}\n\
         [profile admin]\nsso_session = corp\nsso_account_id = 111122223333\nsso_role_name = AdministratorAccess\n\n\
         [profile deploy]\nrole_arn = arn:aws:iam::111122223333:role/Deploy\nsource_profile = admin\n\
         role_session_name = ci\nexternal_id = ext-1\nduration_seconds = 1800\n\n\
         [profile audit]\nrole_arn = arn:aws:iam::999988887777:role/Audit\nsource_profile = deploy\nregion = eu-west-1\n"
    ));
    login_device(&sandbox);

    let env = exec_env(&sandbox, "deploy");
    let assumed = sandbox.mock.assumed();
    assert_eq!(assumed.len(), 1);
    assert_eq!(assumed[0].role_arn, "arn:aws:iam::111122223333:role/Deploy");
    assert_eq!(
        assumed[0].signed_by, "ASIAMOCK11112222",
        "signed with the SSO role's keys"
    );
    assert_eq!(assumed[0].session_name, "ci");
    assert_eq!(assumed[0].external_id.as_deref(), Some("ext-1"));
    assert_eq!(assumed[0].duration_seconds.as_deref(), Some("1800"));
    assert_eq!(env["AWS_ACCESS_KEY_ID"], assumed[0].issued);

    // Two links: the second role is assumed with the first one's keys, and both are cached.
    let env = exec_env(&sandbox, "audit");
    let assumed = sandbox.mock.assumed();
    assert_eq!(assumed.len(), 2, "deploy came from the cache");
    assert_eq!(assumed[1].role_arn, "arn:aws:iam::999988887777:role/Audit");
    assert_eq!(assumed[1].signed_by, assumed[0].issued);
    assert!(
        assumed[1].session_name.starts_with("gac-redux-"),
        "{:?}",
        assumed[1]
    );
    assert_eq!(env["AWS_ACCESS_KEY_ID"], assumed[1].issued);
    assert_eq!(env["AWS_REGION"], "eu-west-1");
    exec_env(&sandbox, "audit");
    assert_eq!(sandbox.mock.assumed().len(), 2);
    assert_eq!(sandbox.mock.counter("credentials"), 1);

    // whoami names the final role and where the chain starts, from the caches.
    sandbox
        .gac()
        .args(["whoami", "-p", "audit"])
        .assert()
        .success()
        .stdout(predicate::str::contains("account      999988887777\n"))
        .stdout(predicate::str::contains("role         Audit\n"))
        .stdout(predicate::str::contains(
            "assumed via  AdministratorAccess in 111122223333 (SSO), then arn:aws:iam::111122223333:role/Deploy\n",
        ))
        .stdout(predicate::str::contains("credentials  cached until "));

    // The console signs in with the final role's keys.
    sandbox
        .gac()
        .args(["console", "--print", "-p", "audit"])
        .assert()
        .success();
    assert_eq!(sandbox.mock.counter("signin_token"), 1);
}

#[test]
fn chains_gac_cannot_follow_say_why() {
    let sandbox = Sandbox::with_session();
    sandbox.write_config(&format!(
        "{SESSION}\n\
         [profile admin]\nsso_session = corp\nsso_account_id = 111122223333\nsso_role_name = AdministratorAccess\n\n\
         [profile mfa]\nrole_arn = arn:aws:iam::111122223333:role/Deploy\nsource_profile = admin\nmfa_serial = arn:aws:iam::111122223333:mfa/me\n\n\
         [profile ec2]\nrole_arn = arn:aws:iam::111122223333:role/Deploy\ncredential_source = Ec2InstanceMetadata\n\n\
         [profile loop-a]\nrole_arn = arn:aws:iam::111122223333:role/A\nsource_profile = loop-b\n\n\
         [profile loop-b]\nrole_arn = arn:aws:iam::111122223333:role/B\nsource_profile = loop-a\n\n\
         [profile orphan]\nrole_arn = arn:aws:iam::111122223333:role/Deploy\nsource_profile = gone\n"
    ));
    for (profile, message) in [
        (
            "mfa",
            "profile `mfa` uses mfa_serial (an MFA prompt), which gac does not follow",
        ),
        (
            "ec2",
            "profile `ec2` uses credential_source, which gac does not follow",
        ),
        ("loop-a", "is longer than 5 links"),
        (
            "orphan",
            "no profile `gone` in the AWS config file, though a source_profile names it",
        ),
    ] {
        sandbox
            .gac()
            .args(["exec", "--profile", profile, "--", "x"])
            .assert()
            .code(1)
            .stderr(predicate::str::contains(message));
    }
    assert_eq!(sandbox.mock.counter("credentials"), 0);
}

#[test]
fn env_prints_the_credentials_for_every_shell() {
    let sandbox = Sandbox::with_session();
    login_device(&sandbox);
    let print = |format: &str| {
        let output = sandbox
            .gac()
            .args([
                "env",
                "sandbox/ReadOnly",
                "--region",
                "eu-west-1",
                "--format",
                format,
            ])
            .assert()
            .success()
            .stderr("");
        redacted(&sandbox, &stdout(output.get_output()))
    };
    insta::assert_snapshot!(print("sh"), @r"
    export AWS_ACCESS_KEY_ID='ASIAMOCK77778888'
    export AWS_SECRET_ACCESS_KEY='[secret]'
    export AWS_SESSION_TOKEN='[secret]'
    export AWS_CREDENTIAL_EXPIRATION='[expiration]'
    unset AWS_PROFILE
    unset AWS_DEFAULT_PROFILE
    unset AWS_SECURITY_TOKEN
    export AWS_REGION='eu-west-1'
    export AWS_DEFAULT_REGION='eu-west-1'
    ");
    insta::assert_snapshot!(print("fish"), @r"
    set -gx AWS_ACCESS_KEY_ID 'ASIAMOCK77778888'
    set -gx AWS_SECRET_ACCESS_KEY '[secret]'
    set -gx AWS_SESSION_TOKEN '[secret]'
    set -gx AWS_CREDENTIAL_EXPIRATION '[expiration]'
    set -e AWS_PROFILE
    set -e AWS_DEFAULT_PROFILE
    set -e AWS_SECURITY_TOKEN
    set -gx AWS_REGION 'eu-west-1'
    set -gx AWS_DEFAULT_REGION 'eu-west-1'
    ");
    insta::assert_snapshot!(print("powershell"), @r"
    $env:AWS_ACCESS_KEY_ID = 'ASIAMOCK77778888'
    $env:AWS_SECRET_ACCESS_KEY = '[secret]'
    $env:AWS_SESSION_TOKEN = '[secret]'
    $env:AWS_CREDENTIAL_EXPIRATION = '[expiration]'
    Remove-Item -Path Env:AWS_PROFILE -ErrorAction SilentlyContinue
    Remove-Item -Path Env:AWS_DEFAULT_PROFILE -ErrorAction SilentlyContinue
    Remove-Item -Path Env:AWS_SECURITY_TOKEN -ErrorAction SilentlyContinue
    $env:AWS_REGION = 'eu-west-1'
    $env:AWS_DEFAULT_REGION = 'eu-west-1'
    ");
    insta::assert_snapshot!(print("json"), @r#"
    {
      "AWS_ACCESS_KEY_ID": "ASIAMOCK77778888",
      "AWS_CREDENTIAL_EXPIRATION": "[expiration]",
      "AWS_DEFAULT_PROFILE": null,
      "AWS_DEFAULT_REGION": "eu-west-1",
      "AWS_PROFILE": null,
      "AWS_REGION": "eu-west-1",
      "AWS_SECRET_ACCESS_KEY": "[secret]",
      "AWS_SECURITY_TOKEN": null,
      "AWS_SESSION_TOKEN": "[secret]"
    }
    "#);
    assert_eq!(
        sandbox.mock.counter("credentials"),
        1,
        "every format after the first used the cache"
    );
}

#[cfg(unix)]
#[test]
fn eval_of_env_sets_and_unset_clears_the_credentials_in_a_shell() {
    let sandbox = Sandbox::with_session();
    login_device(&sandbox);
    let set = stdout(
        sandbox
            .gac()
            .args(["env", "sandbox/ReadOnly"])
            .assert()
            .success()
            .get_output(),
    );
    let unset = stdout(
        sandbox
            .gac()
            .args(["env", "--unset"])
            .assert()
            .success()
            .get_output(),
    );
    let script = sandbox.home().join("eval.sh");
    std::fs::write(
        &script,
        "eval \"$1\"\nprintf '%s\\n' \"$AWS_ACCESS_KEY_ID\" \"$AWS_SECRET_ACCESS_KEY\" \"${AWS_PROFILE-unset}\"\neval \"$2\"\nprintf '%s\\n' \"${AWS_ACCESS_KEY_ID-cleared}\"\n",
    )
    .unwrap();
    let output = std::process::Command::new("sh")
        .arg(&script)
        .arg(&set)
        .arg(&unset)
        .env("AWS_PROFILE", "dev")
        .output()
        .unwrap();
    assert!(output.status.success(), "{}", stderr(&output));
    let lines: Vec<String> = stdout(&output).lines().map(str::to_owned).collect();
    assert_eq!(lines[0], "ASIAMOCK77778888");
    assert!(sandbox.mock.secrets().contains(&lines[1]));
    assert_eq!(lines[2], "unset");
    assert_eq!(lines[3], "cleared");
}

#[test]
fn env_unset_needs_no_login_and_conflicts_with_a_role() {
    let sandbox = Sandbox::new();
    sandbox
        .gac()
        .args(["env", "--unset", "--format", "fish"])
        .assert()
        .success()
        .stdout(
            "set -e AWS_ACCESS_KEY_ID\nset -e AWS_SECRET_ACCESS_KEY\nset -e AWS_SESSION_TOKEN\nset -e AWS_CREDENTIAL_EXPIRATION\n",
        );
    sandbox
        .gac()
        .args(["env", "--unset", "sandbox/ReadOnly"])
        .assert()
        .code(2);
}

/// Where PowerShell is installed (as on the CI runners), its output loads in PowerShell.
#[test]
fn env_powershell_output_loads_in_powershell() {
    let sandbox = Sandbox::with_session();
    login_device(&sandbox);
    let set = stdout(
        sandbox
            .gac()
            .args(["env", "sandbox/ReadOnly", "--format", "powershell"])
            .assert()
            .success()
            .get_output(),
    );
    let script = sandbox.home().join("load.ps1");
    std::fs::write(
        &script,
        format!(
            "{set}Write-Output $env:AWS_ACCESS_KEY_ID\nWrite-Output \"profile=$env:AWS_PROFILE\"\n"
        ),
    )
    .unwrap();
    let Ok(output) = std::process::Command::new("pwsh")
        .args(["-NoProfile", "-NonInteractive", "-File"])
        .arg(&script)
        .env("AWS_PROFILE", "dev")
        .output()
    else {
        return; // PowerShell is not installed
    };
    assert!(output.status.success(), "{}", stderr(&output));
    assert_eq!(
        stdout(&output).replace('\r', ""),
        "ASIAMOCK77778888\nprofile=\n"
    );
}

#[test]
fn credential_process_prints_the_json_credential_process_expects() {
    let sandbox = Sandbox::with_session();
    let args = [
        "credential-process",
        "--session",
        "corp",
        "--account-id",
        "111122223333",
        "--role-name",
        "ReadOnly",
    ];
    // Without a login it fails as a credential_process must: nonzero, the reason on stderr.
    sandbox
        .gac()
        .args(args)
        .assert()
        .code(3)
        .stdout("")
        .stderr(predicate::str::contains("gac login --session corp"));

    login_device(&sandbox);
    let output = sandbox.gac().args(args).assert().success();
    let json: Value = serde_json::from_slice(&output.get_output().stdout).unwrap();
    assert_eq!(json["Version"], 1);
    assert_eq!(json["AccessKeyId"], "ASIAMOCK11112222");
    assert!(
        sandbox
            .mock
            .secrets()
            .contains(&json["SecretAccessKey"].as_str().unwrap().to_owned())
    );
    assert!(json["SessionToken"].is_string());
    assert!(json["Expiration"].as_str().unwrap().ends_with('Z'));
    sandbox.gac().args(args).assert().success();
    assert_eq!(
        sandbox.mock.counter("credentials"),
        1,
        "the second call used the cache"
    );

    sandbox
        .gac()
        .args([
            "credential-process",
            "--account-id",
            "111122223333",
            "--role-name",
            "ReadOnly",
        ])
        .assert()
        .code(2)
        .stderr(predicate::str::contains("needs --session NAME"));
}
