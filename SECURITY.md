# Security policy

gac handles SSO tokens and role credentials, so security problems get priority over everything
else.

## Supported versions

Security fixes go into the latest release. Before 1.0 that is the latest 0.x release; from 1.0,
the latest 1.x release. Upgrade to get a fix: there are no backports to older releases.

## Reporting a vulnerability

Please report privately, not in a public issue: open the
[Security tab](https://github.com/virtualmadden/gac-redux/security) and choose **Report a
vulnerability**. Include the gac version (`gac --version`), the platform, and the steps that show
the problem. Leave out real tokens and credentials; redacted output is enough.

What happens next:

1. You get an acknowledgement within a few days.
2. Once confirmed, the fix is developed in a private fork and released.
3. A GitHub security advisory is published with the release, crediting you unless you prefer
   otherwise.

## In scope

Anything that could expose or misuse credentials, for example: tokens or role credentials
written with loose file permissions or where other tools do not expect them, secrets in logs,
output or error messages, a sign-in flow that accepts a forged callback, or a `gac` command that
uses a different account or role than it reports.
