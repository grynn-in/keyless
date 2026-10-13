# Staging checklist: Keyless 2.0.1

Run this on a **copy of a real production site** before you tag `v2.0.1` and before you
upgrade any production site. Copy each section into the release issue and tick it off
there. Note each failure with its Error Log or Keyless Audit Log entry.

2.0.1 changes less than 2.0.0, so this list reuses that one:

- Environment: [2.0.0 checklist, section 0](staging-checklist-2.0.0.md#0-environment). Use the same `encryption_key` as production; otherwise every backup code is invalid.
- Browser suite: [2.0.0 checklist, section 3](staging-checklist-2.0.0.md#3-automated-browser-suite). All 9 flows must pass, then clean up.
- Real devices: [2.0.0 checklist, section 4](staging-checklist-2.0.0.md#4-manual-sign-in-on-real-devices). Running one device is enough if 2.0.0 already passed on all of them.

Coming from a version before 2.0.0? Run the whole 2.0.0 checklist instead, then
sections 1 and 3 below.

## 1. Before the upgrade

Check these on the copy:

- [ ] Write down every number in Keyless Settings. Any value outside these ranges will be
      moved into range:

      | Setting | Range |
      |---|---|
      | OTP Length | 6–8 |
      | OTP Expiry | 60–3600 s |
      | Max OTP Attempts | 1–10 |
      | Rate Limit per Hour | 1–100 |
      | Daily Code Limit | 1–1000 |
      | Magic Link Expiry | 2–60 min |
      | Step-up Window | 1–60 min |
      | Audit Retention | 30–3650 days |

- [ ] Note the site time zone (System Settings). On sites west of UTC, magic links failed
      before this release. Check that they work afterwards.
- [ ] Look for custom code or integrations that do any of these. Each one is refused now:
  - create or edit Keyless Backup Code rows;
  - delete Keyless Audit Log rows as a System Manager;
  - set a user's Keyless fields as a non-System Manager;
  - call `revoke_passkey` without a recent sign-in.

## 2. Upgrade

- [ ] Check out the commit being staged and write its hash down; it is the commit to tag.
- [ ] `bench setup requirements`. Then check `bench pip show cbor2`: the version must be
      at least 5.9.0 and below 6.
- [ ] `bench --site <site> migrate`, then `bench build --app keyless`, then restart
      gunicorn and the workers.
- [ ] The migrate finished without errors.
- [ ] Review these Error Log entries. Each one only reports; act on what it lists:

| Error Log title | What to do |
|---|---|
| Keyless: review Keyless Backup Code ownership | The listed codes no longer sign anyone in. Ask the users to generate new codes. Check the Audit Log for any `backup_code` sign-in by a code that was used. |
| Keyless: review Passwordless Only changes | Turn the flag back on for anyone listed who should have it. |
| Keyless: settings out of range | Check that each value it moved is acceptable. |
| Keyless: settings bounds patch failed | Find the cause, fix it and migrate again. |
| Keyless: review User Passkey ownership | Check each listed record. |
| A traceback containing "cannot read the collation of tabUser.email" | Should not appear. If it does, email codes, magic links and backup codes fail with a server error; report it. |

## 3. 2.0.1 checks

- [ ] **Backup codes.** Generate codes, sign in with one, and confirm that the same code
      is refused the second time.
- [ ] **Backup codes, System Manager.** As a System Manager who is not Administrator, try to
      create a Keyless Backup Code, and to edit one, from Desk. Both are refused.
- [ ] **Backup codes, deleting.** Deleting another user's codes works. The user gets one
      email, and the Audit Log shows `backup_code_deleted`.
- [ ] **Passkeys.** Removing your own passkey asks you to confirm it's you, unless you signed
      in within the Step-up Window.
- [ ] **Audit Log.** A System Manager cannot delete an entry. Administrator can.
- [ ] **Passwordless Only.** A user who is not a System Manager cannot see or change the
      Keyless section on their own User record.
- [ ] **Redirects.** `/keyless/login?redirect-to=/.//example.com` stays on the site after
      sign-in.
- [ ] **Magic links.** A magic link signs in from the browser that asked for it. Repeat this
      with the site time zone west of UTC (for example America/New_York) if production
      uses one.
- [ ] **Email codes.** A code requested with a different case of the address (`USER@…`) is
      delivered to the address stored on the account.
- [ ] **Settings.** Saving Keyless Settings with OTP Length 4 is refused. Changing Audit
      Retention writes `audit_retention_changed` to the Audit Log.
- [ ] **Administrator break-glass.** Password login still works.

## 4. Sign-off

- [ ] Error Log reviewed for the whole run: nothing new from Keyless is unexplained.
- [ ] Results posted on the release issue.

Then release:

1. In `CHANGELOG.md`, change `## 2.0.1 (unreleased)` to `## 2.0.1 (<date>)` and commit.
2. Tag `v2.0.1` on that commit.

If `main` has moved past the staged commit with code changes, stage again first.
