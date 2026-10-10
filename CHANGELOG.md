# Changelog

## 2.0.0 (unreleased)

Security release. It fixes every finding of the Keyless security audit of 7 October 2026
(2 critical, 5 high, 4 medium, 4 low, 1 informational) and the follow-ups from reviewing the
fixes. Several settings now do what they always claimed to, so **read
[Upgrading](docs/authentication-policy.md#8-upgrading-from-earlier-versions) before you
deploy**. The full rules are in [docs/authentication-policy.md](docs/authentication-policy.md);
the per-finding report is [docs/security-audit-2026-10-report.md](docs/security-audit-2026-10-report.md).

### Changes people will notice

- **Password settings are enforced for the first time.** Disable Password Login, the per-user
  Passwordless Only flag and Require a Passkey for System Users had no effect before (Frappe
  never ran the override that checked them). Check who they lock out before upgrading.
  Administrator break-glass is unchanged.
- **Frappe 2FA users** can no longer sign in with an email code or a magic link, which skipped
  Frappe's second factor. Passkeys and backup codes still work.
- **Magic links** open a "Sign in" page with a button instead of signing in at once, and only
  work in the browser that asked for them. People who read mail on another device should use
  an email code.
- **Adding a passkey or generating backup codes** asks people to confirm it's them (a passkey
  or an emailed code) unless they signed in within the **Step-up Window**. Every change to
  passkeys or backup codes emails the account owner.
- **Passkeys are only accepted from the configured site URL** and the new **Allowed Origins**.
  Behind a proxy that terminates TLS, set `host_name` to the https URL or add it there.
- **Fresh installs** leave Keyless and every factor switched off. Existing sites keep their
  settings.

### Security fixes

- Users could re-point their User Passkey records to another account and sign in as it (C-1).
- Password login ignored every Keyless policy (C-2), including through usernames, mobile
  numbers, the OAuth2 password grant, password-reset links and Frappe's email-link login.
- Reflected XSS on `/keyless/login` and an open redirect after magic-link sign-in (H-1, H-2).
- WebAuthn origin and RP ID were taken from request headers (H-5).
- Rate limits only counted per IP, codes could be guessed in parallel, and requesting a new
  code reset the guess budget (M-1). Limits now also count per account, are atomic, and a
  stranger cannot use them up from one machine.
- Responses showed which addresses have accounts (M-2).
- Backup-code race, low per-IP limits behind NAT, library error text returned to clients,
  audit log committing failed requests and storing a client-chosen IP (L-1 to L-4).
- Hardening: the code pepper never falls back to `secret_key` or an empty value; disabled
  users cannot update passkey state (I-1).

### Settings

- New: **Allowed Origins**, **Daily Code Limit per Account** (default 10), **Step-up Window
  (minutes)** (default 5).
- **Rate Limit per Hour** now sets per-account hourly limits; per-IP limits are 20× it for
  email and recovery endpoints and 200× for passkeys.
- Removed: **Allow Passwordless Signup**, which was never enforced.

### Other

- Sign-in codes and links are sent as soon as the request commits instead of waiting for the
  email queue. Notifications are still queued.
- A missing `encryption_key` is created the way Frappe creates it. Rotating it invalidates all
  backup codes.
- Frappe 15 is supported and tested in CI alongside Frappe 16.
- CI runs the server tests and a browser suite (`e2e/`, real Chromium with a virtual WebAuthn
  authenticator) on every pull request.
- Migrating reports User Passkey rows that look re-pointed and warns when no passkey origin is
  https (Error Log).

## 1.0.1

Earlier releases have no changelog.
