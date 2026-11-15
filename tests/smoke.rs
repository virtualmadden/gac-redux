//! [docs/smoke-test.md](../docs/smoke-test.md) against a real IAM Identity Center. A person
//! approves the logins, picks a role in `gac select` and checks the console; this runs and checks
//! everything else, then prints the row for the release pull request. It never runs in CI:
//!
//! ```sh
//! GAC_SMOKE_START_URL=https://<portal>.awsapps.com/start GAC_SMOKE_REGION=<region> \
//!     cargo test --release --test smoke -- --ignored --nocapture
//! ```
//!
//! `GAC_SMOKE_PROFILE` picks the synced profile the AWS calls use; the first one otherwise.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus, Output, Stdio};

use serde_json::Value;

const SESSION: &str = "smoke";

/// Variables that would point gac or the AWS CLI somewhere other than the throwaway HOME and the
/// real service, or change which flow a login takes.
const CLEARED: &[&str] = &[
    "AWS_PROFILE",
    "AWS_DEFAULT_PROFILE",
    "AWS_CONFIG_FILE",
    "AWS_SHARED_CREDENTIALS_FILE",
    "AWS_ACCESS_KEY_ID",
    "AWS_SECRET_ACCESS_KEY",
    "AWS_SESSION_TOKEN",
    "AWS_REGION",
    "AWS_DEFAULT_REGION",
    "AWS_ENDPOINT_URL",
    "AWS_ENDPOINT_URL_SSO",
    "AWS_ENDPOINT_URL_SSO_OIDC",
    "AWS_ENDPOINT_URL_STS",
    "GAC_REDUX_SESSION",
    "GAC_REDUX_EXEC",
    "GAC_REDUX_FEDERATION_ENDPOINT",
    "SSH_CONNECTION",
    "SSH_TTY",
];

type Step = Result<(), String>;
type StepFn = fn(&mut Smoke) -> Step;

#[test]
#[ignore = "needs a real Identity Center and a person; see docs/smoke-test.md"]
fn smoke_test_against_a_real_identity_center() {
    let var = |name: &str| std::env::var(name).ok().filter(|v| !v.is_empty());
    let (Some(start_url), Some(region)) = (var("GAC_SMOKE_START_URL"), var("GAC_SMOKE_REGION"))
    else {
        panic!("set GAC_SMOKE_START_URL and GAC_SMOKE_REGION; see docs/smoke-test.md");
    };
    let home = tempfile::tempdir().unwrap();
    let mut smoke = Smoke {
        home: home.path().to_owned(),
        start_url,
        region,
        wanted_profile: var("GAC_SMOKE_PROFILE"),
        role: None,
    };
    // Check the AWS CLI before any login, so a missing one leaves no session to revoke.
    let aws = text(&smoke.aws(&["--version"]));
    let Some(aws) = aws
        .split_whitespace()
        .next()
        .filter(|v| v.starts_with("aws-cli/2."))
    else {
        panic!("the smoke test needs the AWS CLI v2 on PATH, but `aws --version` printed:\n{aws}");
    };

    let steps: [(&str, StepFn); 13] = [
        ("Setup", Smoke::setup),
        ("PKCE", Smoke::pkce),
        ("Select", Smoke::select),
        ("Device code", Smoke::device_code),
        ("List", Smoke::list),
        ("Sync", Smoke::sync),
        ("AWS call", Smoke::aws_call),
        ("Exec", Smoke::exec),
        ("Process mode", Smoke::process_mode),
        ("Console", Smoke::console),
        ("Doctor", Smoke::doctor),
        ("Logout", Smoke::logout),
        ("Remove", Smoke::remove),
    ];
    let mut results = Vec::new();
    for (number, (name, step)) in (1..).zip(steps) {
        // Each step builds on the one before, so the first failure ends the run.
        if results.iter().any(Result::is_err) {
            println!("{number}. {name}: not run");
            continue;
        }
        println!("\n== {number}. {name}");
        let result = step(&mut smoke);
        match &result {
            Ok(()) => println!("{number}. {name}: pass"),
            Err(reason) => println!("{number}. {name}: FAIL\n{reason}"),
        }
        results.push(result);
    }
    // A failure can leave the session logged in: revoke it rather than leave it to expire.
    if results.iter().any(Result::is_err) {
        let _ = smoke.gac(&["logout"]);
    }

    let passed = results.iter().filter(|r| r.is_ok()).count();
    let result = if passed == steps.len() {
        format!("Passed all {} steps", steps.len())
    } else {
        format!("Failed at step {} of {}", passed + 1, steps.len())
    };
    let version = smoke.gac(&["--version"]);
    println!("\nFor the release pull request:\n");
    println!(
        "| {} {} | `{}` | {result}, with {aws} |",
        std::env::consts::OS,
        std::env::consts::ARCH,
        text(&version).trim(),
    );
    assert_eq!(passed, steps.len(), "{result}");
}

struct Smoke {
    home: PathBuf,
    start_url: String,
    region: String,
    wanted_profile: Option<String>,
    /// The synced profile the AWS calls use, once `sync` wrote it.
    role: Option<Role>,
}

struct Role {
    profile: String,
    account_id: String,
    name: String,
}

impl Smoke {
    fn setup(&mut self) -> Step {
        let out = self.gac(&[
            "setup",
            "--session",
            SESSION,
            "--start-url",
            &self.start_url,
            "--region",
            &self.region,
        ]);
        expect_success(&out, "Added [sso-session smoke]")
    }

    fn pkce(&mut self) -> Step {
        println!("Approve the login in the browser that opens.");
        self.interactive(&["login"])?;
        self.expect_logged_in()
    }

    fn select(&mut self) -> Step {
        println!("Pick any role with the arrow keys and press Enter.");
        self.interactive(&["select"])?;
        let whoami = json(&self.gac(&["whoami", "--json"]))?;
        if whoami["source"] != "[default]" {
            return Err(format!("whoami did not pick [default]: {whoami}"));
        }
        let (account_id, role_name) = (
            str_field(&whoami, "accountId")?,
            str_field(&whoami, "roleName")?,
        );
        expect_identity(
            &self.aws(&["sts", "get-caller-identity"]),
            account_id,
            role_name,
        )?;
        expect_success(&self.gac(&["select", "--clear"]), "")?;
        let out = self.aws(&["sts", "get-caller-identity"]);
        if out.status.success() || !text(&out).contains("Unable to locate credentials") {
            return Err(format!(
                "the AWS CLI still found credentials:\n{}",
                tail(&out)
            ));
        }
        Ok(())
    }

    fn device_code(&mut self) -> Step {
        println!("Open the link, check the code matches, and approve.");
        self.interactive(&["login", "--device-code"])?;
        self.expect_logged_in()
    }

    fn list(&mut self) -> Step {
        let listing = json(&self.gac(&["list", "--json"]))?;
        let accounts = listing["accounts"].as_array().cloned().unwrap_or_default();
        let roles: usize = accounts
            .iter()
            .map(|a| a["roles"].as_array().map_or(0, Vec::len))
            .sum();
        if roles == 0 {
            return Err(format!("no roles listed: {listing}"));
        }
        println!("{} accounts, {roles} roles", accounts.len());
        Ok(())
    }

    fn sync(&mut self) -> Step {
        expect_success(
            &self.gac(&["sync", "--dry-run"]),
            "# BEGIN gac-redux sync session=smoke",
        )?;
        expect_success(&self.gac(&["sync"]), "Synced ")?;
        expect_success(&self.gac(&["sync"]), "Already up to date")?;
        let role = self.synced_role()?;
        println!("AWS calls use profile `{}`", role.profile);
        self.role = Some(role);
        Ok(())
    }

    fn aws_call(&mut self) -> Step {
        let role = self.role();
        let out = self.aws(&["sts", "get-caller-identity", "--profile", &role.profile]);
        expect_identity(&out, &role.account_id, &role.name)
    }

    fn exec(&mut self) -> Step {
        let role = self.role();
        let out = self.gac(&[
            "exec",
            "--profile",
            &role.profile,
            "--",
            "aws",
            "sts",
            "get-caller-identity",
            "--output",
            "json",
        ]);
        expect_identity(&out, &role.account_id, &role.name)
    }

    fn process_mode(&mut self) -> Step {
        expect_success(&self.gac(&["sync", "--mode", "process"]), "")?;
        if !self.config()?.contains("credential_process") {
            return Err("`sync --mode process` wrote no credential_process profiles".into());
        }
        self.aws_call()?;
        expect_success(&self.gac(&["sync", "--mode", "sso"]), "")?;
        if self.config()?.contains("credential_process") {
            return Err("`sync --mode sso` left credential_process profiles".into());
        }
        Ok(())
    }

    fn console(&mut self) -> Step {
        let profile = self.role().profile.clone();
        // The link holds a sign-in token, so it is checked here and never printed.
        let out = self.gac(&["console", "--print", "--profile", &profile]);
        if !out.status.success() {
            return Err(format!("`gac console --print` failed:\n{}", tail(&out)));
        }
        let link = String::from_utf8_lossy(&out.stdout);
        if !link.starts_with("https://signin.") || !link.contains("SigninToken=") {
            return Err("`gac console --print` printed no sign-in link".into());
        }
        self.interactive(&["console", "--profile", &profile])?;
        confirm(&format!(
            "Did the AWS console open, signed in as profile `{profile}`?"
        ))
    }

    fn doctor(&mut self) -> Step {
        let report = json(&self.gac(&["doctor", "--json"]))?;
        let failed: Vec<&Value> = report["findings"]
            .as_array()
            .into_iter()
            .flatten()
            .filter(|f| f["level"] == "fail")
            .collect();
        if failed.is_empty() {
            Ok(())
        } else {
            Err(format!("doctor failed checks: {failed:?}"))
        }
    }

    fn logout(&mut self) -> Step {
        expect_success(&self.gac(&["logout"]), "Logged out of session `smoke`.")?;
        expect_success(&self.gac(&["status"]), "not logged in")?;
        let out = self.gac(&["list", "--refresh", "--no-input"]);
        if out.status.code() != Some(3) {
            return Err(format!(
                "`gac list --refresh --no-input` did not exit with 3:\n{}",
                tail(&out)
            ));
        }
        // The role credentials the AWS CLI cached are gone too.
        let role = self.role();
        let out = self.aws(&["sts", "get-caller-identity", "--profile", &role.profile]);
        if out.status.success() {
            return Err("the AWS CLI still has role credentials after logout".into());
        }
        Ok(())
    }

    fn remove(&mut self) -> Step {
        expect_success(
            &self.gac(&["sync", "--remove"]),
            "Removed the `smoke` block",
        )?;
        if self.config()?.contains("# BEGIN gac-redux sync") {
            return Err("the sync block is still in the config file".into());
        }
        self.session().map(drop)
    }

    /// `gac status` has a valid token for the session that it can refresh.
    fn expect_logged_in(&self) -> Step {
        let session = self.session()?;
        let token = &session["token"];
        if token["state"] == "valid" && token["refreshable"] == true {
            Ok(())
        } else {
            Err(format!("the token is not valid and refreshable: {token}"))
        }
    }

    fn session(&self) -> Result<Value, String> {
        let status = json(&self.gac(&["status", "--json"]))?;
        status["sessions"]
            .as_array()
            .into_iter()
            .flatten()
            .find(|s| s["name"] == SESSION)
            .cloned()
            .ok_or_else(|| format!("`gac status` lists no session `{SESSION}`: {status}"))
    }

    /// `GAC_SMOKE_PROFILE`, or the first profile in the sync block, with its account and role.
    fn synced_role(&self) -> Result<Role, String> {
        let config = self.config()?;
        let block = config
            .split("# BEGIN gac-redux sync session=smoke")
            .nth(1)
            .and_then(|rest| rest.split("# END gac-redux sync").next())
            .ok_or("the config file has no sync block")?;
        let mut roles = Vec::new();
        for section in block.split("\n[profile ").skip(1) {
            let (name, body) = section.split_once(']').unwrap_or_default();
            let key = |key: &str| {
                body.lines().find_map(|line| {
                    let (k, v) = line.split_once('=')?;
                    (k.trim() == key).then(|| v.trim().to_owned())
                })
            };
            if let (Some(account_id), Some(role_name)) =
                (key("sso_account_id"), key("sso_role_name"))
            {
                roles.push(Role {
                    profile: name.trim().to_owned(),
                    account_id,
                    name: role_name,
                });
            }
        }
        match &self.wanted_profile {
            Some(wanted) => roles
                .into_iter()
                .find(|r| &r.profile == wanted)
                .ok_or_else(|| format!("no synced profile `{wanted}` (GAC_SMOKE_PROFILE)")),
            None => roles
                .into_iter()
                .next()
                .ok_or_else(|| "sync wrote no profiles".into()),
        }
    }

    fn role(&self) -> &Role {
        self.role.as_ref().expect("sync picked a role")
    }

    fn config(&self) -> Result<String, String> {
        std::fs::read_to_string(self.home.join(".aws").join("config"))
            .map_err(|err| format!("cannot read the config file: {err}"))
    }

    fn gac(&self, args: &[&str]) -> Output {
        self.command(env!("CARGO_BIN_EXE_gac"), args)
            .output()
            .expect("run gac")
    }

    fn aws(&self, args: &[&str]) -> Output {
        self.command("aws", args)
            .output()
            .expect("run the AWS CLI v2, which the smoke test needs on PATH")
    }

    /// `gac` at the terminal, for the steps a person takes part in.
    fn interactive(&self, args: &[&str]) -> Step {
        let status: ExitStatus = self
            .command(env!("CARGO_BIN_EXE_gac"), args)
            .stdin(Stdio::inherit())
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit())
            .status()
            .expect("run gac");
        if status.success() {
            Ok(())
        } else {
            Err(format!("`gac {}` failed: {status}", args.join(" ")))
        }
    }

    /// A command in the throwaway HOME, with the built `gac` first on PATH so process-mode
    /// profiles run it.
    fn command(&self, program: &str, args: &[&str]) -> Command {
        let mut cmd = Command::new(program);
        let gac_dir = Path::new(env!("CARGO_BIN_EXE_gac")).parent().unwrap();
        let path = std::env::var_os("PATH").unwrap_or_default();
        let dirs = std::iter::once(gac_dir.to_owned()).chain(std::env::split_paths(&path));
        for name in CLEARED {
            cmd.env_remove(name);
        }
        cmd.args(args)
            .env("PATH", std::env::join_paths(dirs).unwrap())
            .env("HOME", &self.home)
            .env("USERPROFILE", &self.home)
            .env("NO_COLOR", "1")
            .env("AWS_PAGER", "")
            .stdin(Stdio::null());
        cmd
    }
}

/// The command succeeded and said `expected`, on stdout or stderr.
fn expect_success(out: &Output, expected: &str) -> Step {
    if out.status.success() && text(out).contains(expected) {
        Ok(())
    } else {
        Err(format!("expected success and `{expected}`:\n{}", tail(out)))
    }
}

/// `aws sts get-caller-identity` answered as the Identity Center role for `role_name`, whose
/// IAM role is `AWSReservedSSO_<role_name>_<suffix>`.
fn expect_identity(out: &Output, account_id: &str, role_name: &str) -> Step {
    let identity = json(out)?;
    let arn = str_field(&identity, "Arn")?;
    let role = format!(":assumed-role/AWSReservedSSO_{role_name}_");
    if identity["Account"] == account_id && arn.contains(&role) {
        println!("{arn}");
        Ok(())
    } else {
        Err(format!(
            "expected account {account_id} and role {role_name}, got {arn}"
        ))
    }
}

fn json(out: &Output) -> Result<Value, String> {
    if !out.status.success() {
        return Err(format!("the command failed:\n{}", tail(out)));
    }
    serde_json::from_slice(&out.stdout)
        .map_err(|err| format!("unreadable JSON ({err}):\n{}", tail(out)))
}

fn str_field<'v>(value: &'v Value, key: &str) -> Result<&'v str, String> {
    value[key]
        .as_str()
        .ok_or_else(|| format!("no `{key}` in {value}"))
}

fn confirm(question: &str) -> Step {
    print!("{question} [y/N] ");
    std::io::stdout().flush().unwrap();
    let mut answer = String::new();
    std::io::stdin().read_line(&mut answer).unwrap();
    if answer.trim().eq_ignore_ascii_case("y") {
        Ok(())
    } else {
        Err("not confirmed".into())
    }
}

fn text(out: &Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    )
}

/// The exit status and the last lines of output, for a failed step.
fn tail(out: &Output) -> String {
    let text = text(out);
    let lines: Vec<&str> = text.lines().collect();
    let start = lines.len().saturating_sub(15);
    format!("{}\n{}", out.status, lines[start..].join("\n"))
}
