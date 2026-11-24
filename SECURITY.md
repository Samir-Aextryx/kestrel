# Security policy

KESTREL is a self-hosted platform for authorized security research. Please only
use it against systems you own or have explicit written permission to test.

## Reporting a vulnerability

Do not open a public issue for security problems in KESTREL itself. Use GitHub's
private vulnerability reporting (Security → Advisories → Report a vulnerability)
on this repository, or contact the maintainers directly.

Please include:

- affected version or commit,
- a minimal reproduction,
- the impact you observed,
- any suggested fix.

## Supported versions

The latest release on `main` receives security fixes. Older snapshots are not
maintained.

## Scope

In scope: authentication and session handling, scope-gate bypasses, sandbox or
harness escapes, report signing, plugin isolation, data exposure.

Out of scope: findings produced by a scan against a third-party target, and
missed detections that do not create a security impact in KESTREL itself.
