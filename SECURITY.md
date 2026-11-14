# Security Policy

## Responsible use

DualVerify-Sentinel is an authorization-gated security validation engine. It is
intended for use on systems you own or operate, or where you have explicit
written authorization from the system owner to test.

- Use only against in-scope targets with confirmed authorization.
- No destructive tests, no persistence, no payload building, no exfiltration of data found during a test.
- If you discover a 0-day or otherwise undisclosed vulnerability in a third-party product, follow that product's responsible disclosure process. Do not publish raw PoCs publicly without the vendor's consent.
- Never include real target data, credentials, private authorization records, unauthorized scan output or any other sensitive information in an issue, pull request or security report. Use fictional or self-owned lab data only.

## Reporting a vulnerability in this repository

Do **not** open a public issue for security problems.

1. Prefer GitHub's private security advisory (Security tab) for this repository.
2. Include: a brief description of the issue, minimal reproduction steps (against your own or authorized systems only), and the affected file or component.
3. Response target: 5 business days for acknowledgement, 30 days for a fix.
4. We coordinate disclosure with the reporter before any public release.

## Bug reports and community feedback

For non-security bugs, platform compatibility results or feature requests, open a
normal GitHub issue. Community testing is welcome — see
[CONTRIBUTING.md](CONTRIBUTING.md) for ways to help.

## Scope

This policy covers the code in this repository. External toolchains this tool may
invoke (nuclei, bandit, etc.) are maintained by their respective projects and
are out of scope here.
