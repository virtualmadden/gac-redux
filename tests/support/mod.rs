//! The sandbox-HOME harness. Each test gets a temporary HOME with its own `~/.aws`, a private
//! mock Identity Center, and commands (`gac`, the AWS CLI) whose environment is cleared down to
//! that sandbox, so nothing ever reads or writes the real `~/.aws` or talks to AWS.

#![allow(dead_code)] // each test binary uses a different part of the harness

pub mod mock_idc;

use std::io::{BufRead, BufReader, Read};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::OnceLock;
use std::sync::mpsc;
use std::time::Duration;

use serde_json::Value;
use sha1::Digest;

pub use mock_idc::{MockAccount, MockIdc, default_accounts};

pub const START_URL: &str = "https://mock-example.awsapps.com/start";

/// An `[sso-session corp]` pointing at the mock's start URL, with a refresh-token scope.
pub const SESSION: &str = "\
[sso-session corp]
sso_start_url = https://mock-example.awsapps.com/start
sso_region = us-west-2
sso_registration_scopes = sso:account:access
";

/// Variables a child process needs to run at all; everything else is cleared. (Windows
/// variable names are case-insensitive.)
const PASSTHROUGH: &[&str] = &[
    "PATH",
    "PATHEXT",
    "SYSTEMROOT",
    "SYSTEMDRIVE",
    "WINDIR",
    "COMSPEC",
    "TEMP",
    "TMP",
    "TMPDIR",
];

#[derive(Debug)]
pub struct Sandbox {
    dir: tempfile::TempDir,
    pub mock: MockIdc,
}

impl Sandbox {
    pub fn new() -> Self {
        Self::with_accounts(default_accounts())
    }

    pub fn with_accounts(accounts: Vec<MockAccount>) -> Self {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join(".aws")).unwrap();
        Self {
            dir,
            mock: MockIdc::start(accounts),
        }
    }

    /// A sandbox whose config already has the `corp` session.
    pub fn with_session() -> Self {
        let sandbox = Self::new();
        sandbox.write_config(SESSION);
        sandbox
    }

    pub fn home(&self) -> &Path {
        self.dir.path()
    }

    pub fn config_path(&self) -> PathBuf {
        self.home().join(".aws/config")
    }

    pub fn credentials_path(&self) -> PathBuf {
        self.home().join(".aws/credentials")
    }

    pub fn write_config(&self, text: &str) {
        std::fs::write(self.config_path(), text).unwrap();
    }

    pub fn config(&self) -> String {
        std::fs::read_to_string(self.config_path()).unwrap_or_default()
    }

    pub fn write_credentials(&self, text: &str) {
        std::fs::write(self.credentials_path(), text).unwrap();
    }

    /// `~/.aws/sso/cache/<sha1(key)>.json`.
    pub fn token_path(&self, key: &str) -> PathBuf {
        let stem = hex::encode(sha1::Sha1::digest(key.as_bytes()));
        self.home()
            .join(".aws/sso/cache")
            .join(format!("{stem}.json"))
    }

    pub fn token_text(&self, key: &str) -> String {
        std::fs::read_to_string(self.token_path(key)).unwrap()
    }

    pub fn token(&self, key: &str) -> Value {
        serde_json::from_str(&self.token_text(key)).unwrap()
    }

    pub fn write_token(&self, key: &str, token: &Value) {
        let path = self.token_path(key);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, token.to_string()).unwrap();
    }

    /// Clears `cmd`'s environment down to the sandbox HOME and the mock endpoints.
    pub fn confine(&self, cmd: &mut Command) {
        cmd.env_clear();
        for name in PASSTHROUGH {
            if let Some(value) = std::env::var_os(name) {
                cmd.env(name, value);
            }
        }
        cmd.env("HOME", self.home())
            .env("USERPROFILE", self.home())
            .env("AWS_ENDPOINT_URL_SSO", &self.mock.url)
            .env("AWS_ENDPOINT_URL_SSO_OIDC", &self.mock.url)
            .env("AWS_EC2_METADATA_DISABLED", "true")
            .env("NO_COLOR", "1")
            .stdin(Stdio::null());
    }

    /// A `gac` command confined to the sandbox.
    pub fn gac(&self) -> assert_cmd::Command {
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_gac"));
        self.confine(&mut cmd);
        assert_cmd::Command::from_std(cmd)
    }

    /// A `gac` process with piped output, for flows the test has to drive.
    pub fn spawn_gac(&self, args: &[&str]) -> Child {
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_gac"));
        self.confine(&mut cmd);
        cmd.args(args)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap()
    }

    /// An `aws` command confined to the sandbox, or `None` when the AWS CLI is not installed.
    /// With `GAC_REQUIRE_AWS_CLI` set (as in CI), a missing CLI fails the test instead.
    pub fn aws(&self) -> Option<Command> {
        aws_cli_available().then(|| {
            let mut cmd = Command::new("aws");
            self.confine(&mut cmd);
            cmd.env("AWS_PAGER", "").env("AWS_CLI_AUTO_PROMPT", "off");
            cmd
        })
    }
}

fn aws_cli_available() -> bool {
    static AVAILABLE: OnceLock<bool> = OnceLock::new();
    *AVAILABLE.get_or_init(|| {
        let found = Command::new("aws")
            .arg("--version")
            .output()
            .is_ok_and(|o| o.status.success());
        assert!(
            found || std::env::var_os("GAC_REQUIRE_AWS_CLI").is_none(),
            "GAC_REQUIRE_AWS_CLI is set but the AWS CLI is not on PATH"
        );
        if !found {
            eprintln!("skipping AWS CLI interop: `aws` is not on PATH");
        }
        found
    })
}

/// Runs a login by acting as the browser: reads the authorize URL from the process output,
/// follows it through the mock (which approves at once), and waits for the process to exit.
pub fn drive_browser(mut child: Child) -> std::process::Output {
    let (tx, rx) = mpsc::channel::<String>();
    let readers: Vec<_> = [
        Box::new(child.stdout.take().unwrap()) as Box<dyn Read + Send>,
        Box::new(child.stderr.take().unwrap()) as Box<dyn Read + Send>,
    ]
    .into_iter()
    .map(|stream| {
        let tx = tx.clone();
        std::thread::spawn(move || {
            let mut collected = Vec::new();
            for line in BufReader::new(stream).lines().map_while(Result::ok) {
                let _ = tx.send(line.clone());
                collected.push(line);
            }
            collected.join("\n")
        })
    })
    .collect();
    drop(tx);

    let url = loop {
        let Ok(line) = rx.recv_timeout(Duration::from_secs(60)) else {
            let _ = child.kill();
            panic!("no authorize URL appeared in the output");
        };
        if let Some(url) = line
            .split_whitespace()
            .find(|word| word.starts_with("http") && word.contains("/authorize?"))
        {
            break url.to_owned();
        }
    };
    // The mock approves at once and redirects to the loopback listener, which the agent follows.
    let response = ureq::get(&url)
        .call()
        .expect("the browser request succeeds");
    assert_eq!(response.status(), 200, "the loopback page loads");

    let status = child.wait().unwrap();
    let mut outputs = readers.into_iter().map(|r| r.join().unwrap());
    std::process::Output {
        status,
        stdout: outputs.next().unwrap().into_bytes(),
        stderr: outputs.next().unwrap().into_bytes(),
    }
}

/// Every key of a JSON object, in file order.
pub fn key_order(text: &str) -> Vec<String> {
    let value: serde_json::Map<String, Value> = serde_json::from_str(text).unwrap();
    let mut keys: Vec<(usize, String)> = value
        .keys()
        .map(|k| (text.find(&format!("\"{k}\":")).unwrap(), k.clone()))
        .collect();
    keys.sort();
    keys.into_iter().map(|(_, k)| k).collect()
}

/// Asserts that none of `secrets` appears in `text`.
pub fn assert_no_secrets(text: &str, secrets: &[String], context: &str) {
    assert!(!secrets.is_empty(), "the mock issued secrets to look for");
    for secret in secrets {
        assert!(
            !text.contains(secret.as_str()),
            "{context}: secret `{secret}` leaked into:\n{text}"
        );
    }
}

pub fn stdout(output: &std::process::Output) -> String {
    String::from_utf8_lossy(&output.stdout).into_owned()
}

pub fn stderr(output: &std::process::Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}
