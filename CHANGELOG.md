# Changelog

## 2.0.1 (13 October 2026)

Security release. It fixes the follow-up audits of 10 October 2026 (F-1 to F-4, F-9) and
12 October 2026 (G-1 to G-6, G-8). **Read
[Upgrading](docs/authentication-policy.md#8-upgrading-from-earlier-versions) before you
deploy**, and run `bench setup requirements` before `bench migrate`, because the cbor2
requirement changed. The steps to stage it are in
[docs/staging-checklist-2.0.1.md](docs/staging-checklist-2.0.1.md).

### Changes people will notice

- **Backup codes that someone else created or moved stop working.** Each code now only
  works for the user who generated it. Codes users made themselves keep working. The
  migrate lists the affected codes in the Error Log ("Keyless: review Keyless Backup Code
  ownership").
- **Users can no longer change their own Passwordless Only setting.** The Keyless fields on
  User are now System Manager only, and every change is logged and emailed. The migrate
  lists anyone who turned it off for themselves ("Keyless: review Passwordless Only
  changes").
- **Removing your own passkey now asks you to confirm it's you**, as adding one already
  did.
- **System Managers can no longer create or edit passkeys or backup codes, or delete audit
  log entries.** They can still delete other users' passkeys and backup codes; each
  deletion is logged and emailed to the owner.
- **Keyless Settings numbers must be within fixed ranges.** For example, OTP Length must be
  6 to 8, Rate Limit per Hour 1 to 100, and Audit Retention 30 to 3650 days. The migrate
  moves stored values into range and reports each change ("Keyless: settings out of
  range").
- **Magic links work again on sites west of UTC.** The browser cookie had been expiring
  before the link did.
- **Codes and links go to the email address stored on the account**, not the address as
  typed.

### Security fixes

- A password login with an empty 2FA `tmp_id` skipped the policy check. On a blocked
  account, that showed whether a password was correct (F-1).
- System Managers could add a passkey to any account, Administrator included, and sign in
  as that user (F-2). The same was possible with backup codes: a System Manager could
  create a code for another user, or move one to them (G-1).
- Users could clear their own Passwordless Only (F-3).
- `redirect-to` targets such as `/.//evil.com` sent people to another site after they
  signed in (G-2).
- Removing a passkey needed no recent sign-in (G-4).
- The per-IP limits counted every IPv6 address separately, so one host could spread
  requests across its whole /64. They now count a /64 as one client (G-5). This corrects
  the 2.0.0 note below that said "a stranger cannot use them up from one machine". That
  was never true for wrong guesses at a code, which count per address only; see
  [section 3](docs/authentication-policy.md).
- cbor2 below 5.9.0 can be made to recurse without limit (CVE-2026-26209). Keyless now
  requires `cbor2>=5.9.0,<6` (G-6).
- System Managers could delete audit log entries (G-8).
- Keyless Settings accepted negative and out-of-range values, including an Audit Retention
  that let the daily purge empty the audit log (F-9). Every change to the retention setting
  is now itself logged (`audit_retention_changed`).
- Codes and links were sent to the address as typed. Limits now count each address the way
  the database compares it, so two spellings of one address share a limit (F-4).

### Other

- Sites on a `*.frappe.cloud` hostname get weaker protection for magic links than sites on
  their own domain (G-9). Their sign-in pages share a site with other tenants. See
  [Magic links](docs/authentication-policy.md).
- Maintainer decisions from 13 October 2026 (issue #29): changing a passkey or backup codes
  does not sign out other sessions, and the Rate Limit per Hour range is fixed in code.

## 2.0.0 (on main from 10 October 2026, never tagged)

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
  stranger cannot use the request limits up from one machine (corrected in 2.0.1: not
  wrong guesses at a code, and not across an IPv6 /64 before 2.0.1).
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
