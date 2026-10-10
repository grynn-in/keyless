# Staging checklist: Keyless 2.0.0

Run this on a **copy of a real production site** before tagging `v2.0.0` and before
upgrading any production site. Copy each section into the release issue and tick it off
there. Record failures with the Error Log or Keyless Audit Log entry next to them.

The rules behind each check are in [authentication-policy.md](authentication-policy.md),
and the upgrade table is [section 8](authentication-policy.md#8-upgrading-from-earlier-versions).

## 0. Environment

The staging site has to look like production, or the TLS and proxy checks prove nothing.

- [ ] Restored from a recent production backup, including `site_config.json`, with the
      **same `encryption_key`** as production (otherwise every backup code is invalid).
- [ ] Outgoing mail is redirected to a test mailbox, or real users are disabled or have
      their email changed, so staging does not mail real people.
- [ ] nginx terminates TLS with a valid certificate. Passkeys need a real https origin;
      a self-signed certificate is not enough on iOS.
- [ ] nginx **overwrites** the client IP: `proxy_set_header X-Forwarded-For $remote_addr;`,
      not `$proxy_add_x_forwarded_for`.
- [ ] nginx access logs do not record `key=` from magic-link URLs.
- [ ] gunicorn workers, not `bench serve`.
- [ ] Real SMTP, not `mute_emails`.
- [ ] Scheduler on: `bench --site <site> scheduler enable` and `bench doctor` shows workers.
- [ ] `host_name` in site_config is the https URL of the staging site, or that URL is in
      Keyless Settings → **Allowed Origins**.

## 1. Before the upgrade (still on 1.0.1)

Record these on the copy. They predict what happens to production.

- [ ] Note the Keyless Settings values for Disable Password Login, Require a Passkey for
      System Users, Rate Limit per Hour, Daily Code Limit per Account, Max OTP Attempts.
- [ ] List users who will lose password login. These settings are enforced for the first
      time in 2.0.0:
  - [ ] everyone, if **Disable Password Login** is on;
  - [ ] users with **Passwordless Only** set;
  - [ ] System Users **without Frappe 2FA** and without a passkey, if **Require a Passkey for
        System Users** is on.
- [ ] List Frappe 2FA users without a passkey or backup codes. They lose email codes and
      magic links.
- [ ] List OAuth clients that use the password grant for users who will lose password login.
- [ ] Check custom code and integrations for `/api/resource/User Passkey` writes,
      imports of `keyless.overrides.login`, and full URLs passed as `redirect-to`.

## 2. Upgrade

- [ ] `bench get-app` / checkout at `main` (2.0.0), then `bench --site <site> migrate`.
- [ ] `bench build --app keyless`, then restart gunicorn and workers.
- [ ] Migrate finished without errors.
- [ ] Error Log has no **"Keyless: check passkey origins"** entry, or it was fixed by setting
      `host_name` / Allowed Origins.
- [ ] Error Log **"Keyless: review User Passkey ownership"**: none, or each listed record
      was checked.
- [ ] The login page loads the Keyless bundle (no 404 for the bundle in the browser
      network tab, no console errors, not the plain fallback form).

## 3. Automated browser suite

The suite resets Keyless settings and creates test users. Run it on the **copy only**,
then put the settings noted in step 1 back.

- [ ] `KEYLESS_E2E_SITE=<site> KEYLESS_E2E_URL=https://<staging host> node run.js` from
      `apps/keyless/e2e` (see [e2e/README.md](../e2e/README.md)). The suite reads codes from
      the Email Queue, so it needs `mute_emails` for the run; set it, restart, run, then
      unset it and restart again.
- [ ] All 9 flows pass.
- [ ] Keyless Settings restored to the values from step 1.

## 4. Manual sign-in on real devices

For each device: register a passkey from Desk (step-up should be asked unless you just
signed in), sign out, sign in with the passkey, then sign in with an email code.

| Device | Register | Passkey sign-in | Email code | Magic link (same browser) |
|---|---|---|---|---|
| iOS Safari | [ ] | [ ] | [ ] | [ ] |
| Android Chrome | [ ] | [ ] | [ ] | [ ] |
| Windows Hello (Edge or Chrome) | [ ] | [ ] | [ ] | [ ] |
| Physical security key (e.g. YubiKey) | [ ] | [ ] | n/a | n/a |

Also check:

- [ ] A magic link opens a "Sign in" page with a button, and signs in only on the button.
- [ ] A magic link opened in **another browser or device** is refused, and the Audit Log
      shows `magic_link_failed` with `other_browser`.
- [ ] Adding a passkey and generating backup codes each send the owner an email.
- [ ] Step-up by emailed code works for a user with no passkey.
- [ ] A backup code signs in once and is refused the second time (`backup_failed`,
      `already_used`).

## 5. Policy checks

- [ ] A user from the lock-out list in step 1 gets the expected refusal on password login,
      and the Audit Log shows `password_blocked`.
- [ ] The same user cannot get in with a password-reset link.
- [ ] A Frappe 2FA user is refused email code and magic link (`factor_blocked`,
      `frappe_2fa`) and can still sign in with a passkey or a backup code.
- [ ] Administrator break-glass password login still works.
- [ ] Wrong codes: after **Max OTP Attempts** guesses the code stops working.
- [ ] Audit Log IP addresses are real client IPs, not the proxy's, and sending a forged
      `X-Forwarded-For` header does not change the logged IP.
- [ ] Notification emails go out through the queue (scheduler running).

## 6. Sign-off

- [ ] Error Log reviewed for the whole run: nothing new from Keyless that is unexplained.
- [ ] Results posted on the release issue.

Then release: in `CHANGELOG.md` change `## 2.0.0 (unreleased)` to `## 2.0.0 (<date>)`,
commit, and tag `v2.0.0` on that commit.
