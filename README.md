# gimme-aws-creds

Short-lived AWS credentials through IAM Identity Center, as a single Rust binary that stays
byte-compatible with the AWS CLI and SDKs. AWS only.

> **Status: pre-release.** The binary and crate are called `gac`, a placeholder: the project
> will be renamed before its first publish. The native path described below works today;
> on-demand credentials (`env`, `exec`, `credential-process`, `console`) come next.

## How it works

`gac` sets up the SDKs' own Identity Center support and then gets out of the way:

1. `gac login` signs you in (PKCE in the browser, or a device code over SSH; legacy inline-SSO
   profiles always use a device code, as the AWS CLI does) and writes the token to
   `~/.aws/sso/cache` in exactly the format the AWS CLI writes, so `aws sso login`, the AWS CLI
   and every SDK share it.
2. `gac sync` writes one native `sso-session` profile per account and role into a managed block
   in `~/.aws/config`.
3. Your tools use those profiles directly. The SDK reads the token, refreshes it, and fetches
   role credentials itself; no role keys are written anywhere.

```ini
# BEGIN gac sync session=corp mode=sso name={account}/{role}
# Managed by gac: edits inside this block are replaced on the next sync.
[profile payments-prod/ReadOnly]
sso_session = corp
sso_account_id = 111122223333
sso_role_name = ReadOnly
# END gac sync session=corp
```

`gac` never edits a line outside its own blocks, and it skips any profile name that already has a
section in `~/.aws/credentials`: an SSO profile there would make the SDKs silently ignore its keys.

## Quick start

```console
$ gac setup                      # start URL, region, session name -> [sso-session corp]
$ gac login                      # PKCE in the browser (device code over SSH)
$ gac sync --dry-run             # diff of the managed block
$ gac sync
$ aws s3 ls --profile payments-prod/ReadOnly
```

## Commands

| Command | What it does |
|---|---|
| `gac setup` | Creates an `[sso-session]` in the session's managed block, or reuses one `aws configure sso` already wrote |
| `gac login` | Signs in and writes the shared token cache. `--device-code`, `--pkce`, `--no-browser`, `--port N`, `-p PROFILE` |
| `gac logout` | Revokes the session (`sso:Logout`), deletes its token and, as `aws sso logout` does, every role credential the AWS CLI cached from SSO tokens. `--all` |
| `gac status` | Sessions, token and registration expiry, sync blocks. No secrets. `--json` |
| `gac sync` | Writes and prunes the managed block. `--name TEMPLATE`, `--include`/`--exclude GLOB`, `--region`, `--reset`, `--refresh`, `--dry-run` |
| `gac list` | Accounts and roles, from a one-hour inventory cache. `--json`, `--refresh` |
| `gac doctor` | Read-only checks of the AWS files and caches, each with a suggested fix. `--json` |

`--session NAME` (or `GAC_SESSION`) picks the session when more than one is configured. Data goes
to stdout; prompts, links and progress go to stderr. Exit codes: `0` ok, `1` error, `2` usage,
`3` login required, `130` interrupted. `-v`/`-vv` log to stderr and never print a secret.

`gac` honors `AWS_CONFIG_FILE`, `AWS_SHARED_CREDENTIALS_FILE`, `AWS_ENDPOINT_URL_SSO`,
`AWS_ENDPOINT_URL_SSO_OIDC` and `NO_COLOR`. Its own state lives in `~/.aws/gac/` (mode 0700).

## Development

```console
$ cargo nextest run              # or: cargo test
$ cargo clippy --all-targets -- -D warnings
```

The tests run every command against a mock Identity Center (`tests/support/mock_idc.rs`) in a
throwaway HOME, so they never touch your `~/.aws` or call AWS. `tests/interop.rs` also checks
interop with the real AWS CLI v2 (it must be on `PATH`; set `GAC_REQUIRE_AWS_CLI=1` to fail
instead of skipping when it is missing) and with the Rust SDK's `aws-config`.

Requires Rust 1.94.1 or newer.
