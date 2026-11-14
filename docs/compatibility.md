# Compatibility

From 1.0.0, `gac` follows [Semantic Versioning](https://semver.org) for everything on this page.
Every 1.x release keeps what an earlier 1.x release promised here. Breaking a promise takes 2.0.
Until 1.0.0 ships, this page describes what 1.0 will promise, and a 0.x release may still change
any of it.

## What stays stable in 1.x

### Commands and flags

- The names of the commands, their flags (long and short), their positional arguments, and the
  values the enumerated flags take: `sync --mode`, `env --format` and the shells of
  `completions`.
- What a command or flag does, and the defaults that change what it does: `sso` mode and the
  `{account}/{role}` name template for `gac sync`, and `sh` for `gac env --format`.
- How a command picks its session: `--session`, then the session of `--profile`, then
  `GAC_REDUX_SESSION`, then the session of the `[default]` profile.
- How a command picks its role (`exec`, `env`, `console`): `ACCOUNT/ROLE`, then `--profile`,
  then `AWS_PROFILE`, then the `[default]` profile.

### Exit codes

| Code | Meaning |
|---|---|
| `0` | Success |
| `1` | Error, including `gac doctor` finding a problem it reports as `fail` |
| `2` | Usage error: a flag or argument that is wrong or missing, or a choice `--no-input` stops gac from asking for |
| `3` | Login required: no SSO token that works. `gac login` fixes it |
| `126` | `gac exec` found the command but could not run it |
| `127` | `gac exec` could not find the command |
| `130` | Interrupted |

Otherwise, `gac exec` exits with the command's exit code.

### Output for scripts

Data goes to stdout. Prompts, links, progress, warnings and logs go to stderr.

These outputs are stable:

- `--json` from `gac status`, `gac list`, `gac whoami` and `gac doctor`, and
  `gac env --format json`, as described in [JSON output](#json-output).
- `gac credential-process`: the `credential_process` format the AWS CLI and SDKs define,
  `Version` 1.
- `gac env` in every format: it sets `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`,
  `AWS_SESSION_TOKEN`, `AWS_CREDENTIAL_EXPIRATION` and, when the region is known, `AWS_REGION`
  and `AWS_DEFAULT_REGION`, and it unsets `AWS_PROFILE`, `AWS_DEFAULT_PROFILE` and
  `AWS_SECURITY_TOKEN`. `gac exec` gives the command the same environment. `--unset` prints the
  commands that unset the four credential variables.
- `gac select --print` prints one profile name, and `gac console --print` prints one sign-in
  URL, each on its own line.

### JSON output

- Field names, and what each field means, stay the same. New fields may appear in any release.
- A field without a value is left out, never `null`. The exception is `gac env --format json`,
  where `null` means "unset this variable".
- Timestamps are UTC, as `YYYY-MM-DDTHH:MM:SSZ`.
- A field with a listed set of values may gain new values in a minor release. Treat a value you
  don't know as "something else".
- The order of the fields in an object is not part of the promise.
- Free text is not part of it either: `message` and `fix` in `gac doctor`, `error` and
  `refreshError` in `gac status`. Use them to show a person, not to make a decision.

`gac status --json`:

| Field | |
|---|---|
| `configFile` | The config file gac read |
| `sessions[]` | Every session: `name`, `kind` (`sso-session` or `legacy-profile`), `startUrl`, `region`, `error` |
| `sessions[].token` | `state` (`valid`, `refresh-due`, `expired`, `missing` or `unreadable`), `expiresAt`, `refreshable`, `refreshError`, `registrationExpiresAt` |
| `sessions[].defaultProfile` | Present when the `[default]` profile uses this session: `accountId`, `roleName` |
| `sessions[].syncBlock` | Present when the session has a sync block: `profiles` (a count), `mode`, `name`, `region`, `include`, `exclude` |

`gac list --json`:

| Field | |
|---|---|
| `session` | The session the listing is from |
| `fetchedAt` | When gac fetched the listing from the portal |
| `accounts[]` | `accountId`, `accountName`, `email`, `roles` (role names) |

`gac whoami --json`:

| Field | |
|---|---|
| `profile` | The profile AWS tools use; `default` for `[default]` |
| `source` | What picked it: `--profile`, `AWS_PROFILE`, `AWS_DEFAULT_PROFILE` or `[default]` |
| `session`, `accountId`, `accountName`, `roleName` | The role the profile ends up as. `accountName` comes from the last listing |
| `ssoRole` | For a chained profile, the SSO role the chain starts from: `accountId`, `roleName` |
| `chain` | For a chained profile, the role ARNs it assumes in turn |
| `region`, `regionSource` | The region, and where it comes from: `AWS_REGION`, `AWS_DEFAULT_REGION` or `profile` |
| `token` | As in `gac status` |
| `credentials` | The cached role credentials: `state` (`valid`, `expiring`, `expired` or `missing`), `expiresAt` |
| `environmentCredentials` | `true` when `AWS_ACCESS_KEY_ID` is set, so AWS tools use those keys and not the profile |
| `execRole` | Inside `gac exec`, the role it runs as |

`gac doctor --json`:

| Field | |
|---|---|
| `findings[]` | `check`, `level` (`ok`, `warn` or `fail`), `message`, `fix`, `fixable` (present and `true` when `--fix` can apply the fix) |
| `fixed` | With `--fix`, what it changed |

A `check` names one area: `home`, `file-modes`, `config`, `mixed-credentials`, `sessions`,
`legacy-profiles`, `managed-blocks`, `default-profile` or `older-release`. New checks may appear.

`gac env --format json` is an object from each variable name to its value, or `null` to unset it.

### The files gac writes

`gac` writes `~/.aws/config` only inside its managed blocks and leaves every byte outside them as
it was. The exceptions are fixes from `gac doctor --fix` to lines you wrote, which show their diff
and ask first, and permission changes to files that are too open.

The blocks:

```text
# BEGIN gac-redux sync session=corp mode=sso name={account}/{role}
# Managed by gac-redux: edits inside this block are replaced on the next sync.
...
# END gac-redux sync session=corp
```

```text
# BEGIN gac-redux default
# Managed by gac-redux: `gac select` replaces this block.
[default]
...
# END gac-redux default
```

- The markers stay as shown. Every 1.x release reads the blocks an earlier release wrote,
  including 0.x blocks and those with the `# BEGIN gac sync` markers from before the rename.
- The BEGIN line of a sync block stores the settings that wrote it: `session`, `mode`, `name`,
  `region`, `include`, `exclude` and `chain`. In values, a space, `%`, `=` and control characters
  are percent-encoded. A minor release may add a setting. An older 1.x ignores a setting it does
  not know, and leaves it out when it writes the block again.
- `gac sync --remove` deletes a sync block. When `gac setup` wrote the session's
  `[sso-session]` into the block, it stays, as the same lines without the markers.
- The profiles in a sync block keep their keys: `sso_session`, `sso_account_id` and
  `sso_role_name` in `sso` mode, `credential_process` in `process` mode, and `role_arn` and
  `source_profile` for a chain, each with `region` when one is set. `gac credential-process
  --session SESSION --account-id ID --role-name ROLE`, the command a `process` profile runs, keeps
  working throughout 1.x.
- The SSO token cache in `~/.aws/sso/cache` is the AWS CLI's format, and gac follows the AWS CLI.
- `~/.aws/gac-redux/` holds gac's own caches. Their formats may change in any release, and gac
  starts over from a cache it cannot read. Don't read them from scripts.

### Environment variables

`gac` reads `GAC_REDUX_SESSION`, `GAC_REDUX_LOG`, `AWS_CONFIG_FILE`, `AWS_SHARED_CREDENTIALS_FILE`,
`AWS_ENDPOINT_URL_SSO`, `AWS_ENDPOINT_URL_SSO_OIDC`, `AWS_PROFILE`, `AWS_DEFAULT_PROFILE`,
`AWS_REGION`, `AWS_DEFAULT_REGION`, `AWS_ACCESS_KEY_ID` and `NO_COLOR`, and they keep their
meaning. `GAC_REDUX_LOG` takes the same filters as `RUST_LOG`; what the log says is not stable.

Besides the variables listed under `gac env`, `gac exec` sets `GAC_REDUX_EXEC` in the command's
environment, so a nested `gac exec` notices. Its value is not part of the promise.
`GAC_REDUX_FEDERATION_ENDPOINT` exists for gac's own tests and is not part of it either.

## What can change in any release

- Text meant for a person: messages, hints, tables, colors, the text form of `status`, `list`,
  `whoami` and `doctor`, the `--dry-run` diff, help, man pages and completion scripts.
- Additions: commands, flags, JSON fields and values, BEGIN-line settings and doctor checks.
- The minimum Rust version for building from source.
- Anything that contradicts this page or the documentation, which is a bug and gets fixed in a
  patch release, even when something relies on it. The release notes say so.
- What AWS changes: when the AWS CLI or Identity Center changes a format or an API, gac follows.
- The Rust library inside the crate, which is not a public API, and the hidden `gac man`
  command, which builds the release archives.

## Deprecations

A deprecated command, flag, value or field keeps working until 2.0. From the release that
deprecates it, the release notes list it, and using a deprecated command, flag or value prints a
warning on stderr. 2.0 removes them, and its upgrade guide lists each one with what to use
instead.

## How it is checked

- The command line is snapshotted in
  [`src/cli/snapshots/gac_redux__cli__tests__the_stable_command_line.snap`](../src/cli/snapshots/gac_redux__cli__tests__the_stable_command_line.snap).
- Every JSON shape above, the `credential_process` output and both blocks are snapshotted by
  [`tests/compatibility.rs`](../tests/compatibility.rs).
- Exit codes `0` to `3` and `127` are checked across [`tests/cli/`](../tests/cli/).

A pull request that changes one of these snapshots other than by adding to it breaks this
promise, and needs a deprecation instead.
