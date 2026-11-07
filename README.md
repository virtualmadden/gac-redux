# gac-redux

Short-lived AWS credentials through IAM Identity Center (AWS SSO), as a single Rust binary that
stays byte-compatible with the AWS CLI and SDKs. One login gives you a profile for every account
and role you can use, and a list to pick the default from. AWS only.

> **Status: beta.** The package is `gac-redux`; the command it installs is `gac`. The native
> path described below is ready to use; on-demand credentials (`env`, `exec`,
> `credential-process`, `console`) come next. Please report problems in
> [issues](https://github.com/virtualmadden/gac-redux/issues).

## Install

```console
$ brew install virtualmadden/tap/gac-redux
```

Or download the archive for your platform from
[releases](https://github.com/virtualmadden/gac-redux/releases) (macOS and Linux on arm64 and
x86_64, Windows on x86_64), check it against `SHA256SUMS`, and put `gac` on your `PATH`. To build
from source instead: `cargo install --locked --git https://github.com/virtualmadden/gac-redux`.

Each archive also has `man/` with a page per command (`man gac`, `man gac-sync`) and
`completions/` with scripts for bash, zsh, fish, PowerShell and Elvish. Without them, load
completions straight from the binary, e.g. in `~/.zshrc` after `compinit`:

```sh
source <(gac completions zsh)
```

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
# BEGIN gac-redux sync session=corp mode=sso name={account}/{role}
# Managed by gac-redux: edits inside this block are replaced on the next sync.
[profile payments-prod/ReadOnly]
sso_session = corp
sso_account_id = 111122223333
sso_role_name = ReadOnly
# END gac-redux sync session=corp
```

`gac select` writes `[default]` into a block of its own, so the AWS CLI and SDKs use that account
and role when no profile is named. It takes over a `[default]` you wrote only when you agree, keeps
its lines, and `gac select --clear` removes the account and role again.

For a tool that reads only access keys, `gac exec` fetches the role's credentials and runs the
tool with them in its environment, and `gac env` prints them for the current shell. For tools
and older SDKs that support `credential_process` but not SSO, `gac sync --mode process` writes
profiles that run `gac credential-process` instead (so `gac` must be on their `PATH`). They are cached in `~/.aws/cli/cache` exactly as the AWS CLI
caches them, so `gac` and `aws` reuse each other's, and `gac logout` deletes them.

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
| `gac select` | Picks the account and role of the `[default]` profile from a list of every session's accounts and roles. `ACCOUNT/ROLE` picks without the list, `--clear` takes them out again, `--adopt` takes over a `[default]` you wrote, `--print` prints the chosen role's profile name instead of writing anything |
| `gac logout` | Revokes the session (`sso:Logout`), deletes its token and, as `aws sso logout` does, every role credential the AWS CLI cached from SSO tokens. `--all` |
| `gac status` | Sessions, token and registration expiry, sync blocks. No secrets. `--json` |
| `gac sync` | Writes and prunes the managed block. `--mode sso\|process`, `--name TEMPLATE`, `--include`/`--exclude GLOB`, `--chain SOURCE=ROLE_ARN`, `--region`, `--reset`, `--refresh`, `--dry-run` |
| `gac list` | Accounts and roles, from a one-hour inventory cache. `--json`, `--refresh` |
| `gac whoami` | The account, role and region AWS tools use right now, which rule picked them (`--profile`, `AWS_PROFILE`, `[default]`), and how long the token and role credentials last. Reads only local files, so it suits a shell prompt. `-p PROFILE`, `--json` |
| `gac exec -- CMD` | Runs a command with a role's keys in `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY` and `AWS_SESSION_TOKEN`, for tools that cannot use SSO profiles. The role is `ACCOUNT/ROLE`, else that of `--profile`, `AWS_PROFILE` or `[default]`. Exits with the command's code. `--region`, `--force` |
| `gac credential-process` | Prints a role's credentials as `credential_process` JSON. The profiles `gac sync --mode process` writes run it. `--session`, `--account-id`, `--role-name` |
| `gac env` | Prints the variables `gac exec` sets as shell commands: `eval "$(gac env)"`. `--format sh\|fish\|powershell\|json`, `--unset` prints the commands that clear them, `--region` |
| `gac console` | Opens the AWS console signed in as a role, through the AWS federation endpoint, without the access portal. Picks the role like `gac exec`. `--region`, `--destination s3/home` (or a console URL), `--print` prints the one-time sign-in link instead; over SSH it is printed |
| `gac doctor` | Checks the AWS files and caches, each problem with a suggested fix. `--fix` applies the mechanical ones; a fix to lines you wrote shows its diff and asks first (`--yes` skips asking). `--json` |
| `gac completions SHELL` | Prints a completion script for `bash`, `zsh`, `fish`, `powershell` or `elvish` |

With more than one session configured, a command uses `--session NAME`, else the session of
`--profile`, else `GAC_REDUX_SESSION`, else the session of the `[default]` profile. Data goes to stdout; prompts, links and progress go to stderr. A command that needs a login
asks to sign in first when run in a terminal; with `--no-input`, without a terminal, and always
in `gac credential-process`, it exits with code `3` instead. Exit codes: `0` ok, `1` error,
`2` usage, `3` login required, `130` interrupted. `-v`/`-vv` log to stderr and never print a secret.

`gac` honors `AWS_CONFIG_FILE`, `AWS_SHARED_CREDENTIALS_FILE`, `AWS_ENDPOINT_URL_SSO`,
`AWS_ENDPOINT_URL_SSO_OIDC` and `NO_COLOR`. Its own state lives in `~/.aws/gac-redux/` (mode 0700).

Upgrading from the `gac` pre-release: `~/.aws/gac/` is moved to `~/.aws/gac-redux/` on the first
run, and blocks with `# BEGIN gac sync` markers keep working and get the new markers on the next
`gac sync`. Rename `GAC_SESSION` and `GAC_LOG` to `GAC_REDUX_SESSION` and `GAC_REDUX_LOG`.

## Questions

### How do I get an AWS CLI profile for every account and role?

`gac sync`. `aws configure sso` writes one profile per run; `gac sync` asks Identity Center for
every account and role you can use and writes a profile for each, then prunes the ones you lost
access to on the next run. `--name` sets the profile names (default `{account}/{role}`), and
`--include`/`--exclude` filter by glob.

### How do I set the default AWS SSO profile?

`gac select` lists every account and role; pick one with the arrow keys and Enter, and the AWS CLI
and SDKs use it whenever no profile is named. `gac select payments-prod/ReadOnly` does the same
without the list, and `gac select --clear` goes back to no default, so a command without
`--profile` cannot land in the wrong account.

For a choice that lasts only as long as one shell, `export AWS_PROFILE=$(gac select --print)`
picks from the same list and prints the profile name (one `gac sync` wrote, if there is one)
without touching `[default]`.

### Does it work with `aws sso login` and the AWS SDKs?

Yes. `gac` writes the same token cache and the same native `sso-session` profiles the AWS CLI
does, so `aws sso login`, `aws sso logout`, the AWS CLI and every SDK that supports Identity
Center share one login, and you can stop using `gac` at any time without breaking a profile.

### Can I assume another role from an SSO role?

Yes. `gac sync --chain '*/Admin=arn:aws:iam::{account_id}:role/Deploy'` adds, for every synced
profile matching the glob, a profile with `role_arn` and `source_profile` that the AWS CLI and
SDKs follow themselves; `{account_id}` is the source profile's account, and the profile is named
by the same template (`payments-prod/Deploy`). `gac exec`, `env`, `console` and `whoami` follow
any `role_arn`/`source_profile` chain, with `role_session_name`, `external_id` and
`duration_seconds`, and share the AWS CLI's cache of assumed-role credentials. Profiles with
`mfa_serial` or `credential_source` are left to the AWS CLI.

### Does it write access keys to disk?

No long-lived ones. The profiles name an account and role, and the SDKs fetch short-lived role
credentials and refresh them themselves. `gac exec`, `env` and `console` cache short-lived role
credentials in `~/.aws/cli/cache`, as the AWS CLI does, and `~/.aws/credentials` is never
written.

### Can I log in over SSH or on a machine without a browser?

Yes. Over SSH, `gac login` uses a device code: it prints a link and a code to open on any other
device. `--device-code` forces that anywhere, and `--no-browser` prints the link instead of opening
it.

### Something is wrong with my AWS files. Where do I start?

`gac doctor` checks the AWS config, the credentials file and the caches without changing anything,
and suggests a fix for each problem it finds. `gac doctor --fix` applies the mechanical ones:
private file modes, removing a gac block whose `[sso-session]` is gone, adding the scope that
gets a session refresh tokens, and moving legacy profiles with an inline `sso_start_url` onto an
`[sso-session]`. A fix to lines you wrote shows its diff and asks first.

## Development

```console
$ cargo nextest run              # or: cargo test
$ cargo clippy --all-targets -- -D warnings
```

The tests run every command against a mock Identity Center (`tests/support/mock_idc.rs`) in a
throwaway HOME, so they never touch your `~/.aws` or call AWS. `tests/interop.rs` also checks
interop with the real AWS CLI v2 (it must be on `PATH`; set `GAC_REDUX_REQUIRE_AWS_CLI=1` to fail
instead of skipping when it is missing) and with the Rust SDK's `aws-config`.

Requires Rust 1.94.1 or newer.

## License

Licensed under either of [Apache License, Version 2.0](LICENSE-APACHE) or
[MIT license](LICENSE-MIT), at your option.
