# Security policy

django-mcp-oauth is an authorization server: it mints the tokens that let an
MCP client act as a user. A flaw that lets a client obtain a token it should
not have, extend a token's scope or lifetime, replay a rotated refresh token
outside the grace window, or bypass the product's authorization gate is a
security issue, not just a bug.

## Reporting

Report suspected vulnerabilities privately. Do not open a public issue: an
issue is visible to everyone the moment it is filed, before any fix exists.

1. **Preferred:** GitHub private vulnerability reporting —
   <https://github.com/BrandonLewis/django-mcp-oauth/security/advisories/new>
   ("Report a vulnerability" on the repository's Security tab). Only you and
   the maintainer can see the advisory; the fix is coordinated there and the
   advisory is published when it ships.
2. **Fallback**, if you cannot use GitHub: email
   <security@anvilrockroad.com>.

Include a minimal reproduction (the request sequence, or a failing test), the
package version (`pip show django-mcp-oauth`), and the Django and Authlib
versions in use.

You will get an acknowledgement within 5 business days. Fixes ship in the next
release with credit in the advisory and changelog unless you ask otherwise.

## Scope

- In scope: the `django_mcp_oauth` package — the authorization server, the
  resource-server helpers, the management commands.
- Out of scope: products built on it (report to their own repositories) and
  the libraries it builds on (Authlib, PyJWT, cryptography, Django) — report
  upstream, and tell us so we can raise the pinned minimum.

## Supported versions

Only the latest release on PyPI receives fixes.
