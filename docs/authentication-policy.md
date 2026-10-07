# Authentication policy: how Keyless behaves

This page describes what Keyless does in each situation. It covers the
security fixes on branch `fix/security-audit-2026-10` (audit of 7 October 2026):
Phase 1 (C-1, C-2, H-4) and Phase 2 (H-1, H-2, H-3, H-5). Later phases will extend it.

Settings named here live in **Keyless Settings** unless stated otherwise.
"Blocked" means the request gets **HTTP 401** with the message
*"Password login is disabled. Use a passkey or email code."* and no session is created.

---

## 1. Password login

### Where the policy applies

Frappe signs a user in with a password on these paths, and Keyless enforces the policy on all of them:

| Path | Covered |
|---|---|
| `POST /api/method/login` (the standard `/login` page uses this) | yes |
| `cmd=login` sent to **any** URL, for example `POST /api/method/ping` | yes |
| Second step of Frappe's two-factor login (`tmp_id` + `otp`) | yes |
| OAuth2 token endpoint with `grant_type=password` (see section 2) | yes |

These do **not** go through the password policy, by design:

| Path | Why |
|---|---|
| Keyless factors (passkey, email OTP, magic link, backup code) | They are the replacement for passwords. See section 3. |
| LDAP login, social login (OAuth providers), Frappe's own email-link login, impersonation by Administrator | They sign in through `login_as`, not with a password. |
| API key / secret (`Authorization: token key:secret`) and existing OAuth bearer tokens | They are not logins. Disabling passwords does **not** revoke them. Revoke keys and tokens yourself if needed. |

### Decision rules

Keyless first works out **which user** the login name refers to, exactly as Frappe does:
the user name or email, any letter case, and also the **username** or **mobile number**
when System Settings allows login with those. The rules then apply to that user,
whatever was typed.

Rules are checked in this order; the first that matches wins.

| # | If… | Then… |
|---|---|---|
| 1 | Keyless is disabled (**Enable Keyless** off) | Keyless does nothing. Frappe's normal password login applies. |
| 2 | The user is **Administrator** and **Allow Administrator Password (Break-glass)** is on | Allowed, even when every other rule below would block. |
| 3 | **Disable Password Login** is on | Blocked, for every login name, including unknown names and Administrator without break-glass. |
| 4 | The login name matches no user | Not handled by Keyless. Frappe answers *"Invalid login credentials"*. |
| 5 | The user has **Passwordless Only** ticked (User form, Keyless section) | Blocked. |
| 6 | **Require a Passkey for System Users** is on, the user is a System User, and Frappe 2FA does **not** apply to them | Blocked. |
| 6a | Same, but Frappe 2FA **does** apply to them | Allowed. Frappe then asks for the second factor (authenticator code, SMS or email) before creating the session. |
| 7 | None of the above | Allowed. Frappe checks the password, 2FA, IP and login-hour restrictions as usual. |

### What the person signing in sees

- **If a login is blocked**, the response is the same whether the password was correct or wrong.
  A blocked attempt never confirms a password. The password is not even checked.
- **If Disable Password Login is on**, every login name, real or not, gets the same blocked response.
- **If only per-user rules apply** (rules 5 and 6), an unknown name gets Frappe's
  *"Invalid login credentials"* while a blocked account gets the Keyless message.
  This tells an outsider that the account exists and cannot use a password. It does not reveal
  the password. If that matters, turn on **Disable Password Login** site-wide.
- Blocked attempts do not count towards Frappe's failed-login lockout, because no password is checked.

### Frappe's own "Disable Username/Password Login"

Keyless does **not** switch on System Settings → **Disable Username/Password Login**
(`disable_user_pass_login`). Frappe applies that flag to everyone, Administrator included,
so it would remove the break-glass login. Frappe also refuses to save it unless social login,
LDAP or Frappe's email-link login is enabled.

- **If you want** to remove password login for Administrator too, turn it on yourself,
  and only once another way to sign in as Administrator exists.
- **If you keep break-glass**, also restrict Administrator by IP (**Restrict IP** on the
  Administrator user) and alert on Administrator password logins in the Keyless Audit Log.

---

## 2. OAuth2 password grant

Frappe's OAuth2 provider lets a client exchange a username and password for a token
(`POST /api/method/frappe.integrations.oauth2.get_token` with `grant_type=password`).

| If… | Then… |
|---|---|
| Rules 2–6 above would block a password login for that username | The token request is refused with HTTP 401 and **no token is issued**. |
| **Require a Passkey for System Users** is on and the username is a System User, even one with Frappe 2FA | Refused. Rule 6a does not apply here, because the password grant never runs Frappe's 2FA step. |
| Otherwise | The grant works as before. |

This applies on `/api/method/…`, `/api/v1/method/…`, `/api/v2/method/…` and the legacy
`cmd=frappe.integrations.oauth2.get_token` form. Authorization-code and refresh-token
grants are not affected.

---

## 3. Keyless factors

All Keyless factors create the session through `LoginManager.login_as`. They are never
mistaken for a password login. A factor only works when it is switched on in Keyless
Settings (see section 6 for the defaults on a fresh install).

Email OTP and magic links only prove that someone can read the user's mailbox, so two rules
refuse them. Both give HTTP 401, *"Sign in with a passkey."*, and the code or link is used
up by the attempt.

| If… | Then… |
|---|---|
| **Frappe 2FA applies to the user** (System Settings → Enable Two Factor Auth, and one of the user's roles has Two Factor Authentication ticked) and they use **email OTP** or a **magic link** | Refused. `login_as` skips Frappe's 2FA step, so these factors would otherwise get round it. Logged as `factor_blocked` / `frappe_2fa`. |
| **Require a Passkey for System Users** is on, the user is a **System User**, and they use **email OTP** or a **magic link** | Refused. Logged as `factor_blocked` / `passkey_required`. |
| Either rule applies and the user signs in with a **passkey** | Allowed. |
| Either rule applies and the user signs in with a **backup code** | Allowed. Backup codes remain the recovery path when a passkey is lost. |
| Neither rule applies | Every enabled factor works. |

Notes:
- Frappe never applies 2FA to Administrator, and its "bypass 2FA for users who log in from
  restricted IP addresses" setting is honoured. Keyless follows Frappe's own decision.
- Administrator is a System User, so with **Require a Passkey for System Users** on,
  Administrator cannot use email OTP or magic links either. The password break-glass
  (rule 2) still works.

---

## 4. Passkeys (User Passkey records)

### Who can change passkey records

| If… | Then… |
|---|---|
| A normal user calls `/api/resource/User Passkey` (create, read, update or delete) | Refused (HTTP 403). Only System Managers have permissions on the doctype. |
| A user registers a passkey through the Keyless sign-in or settings screens | Works as before. |
| A user lists or removes **their own** passkey through the Keyless screens | Works as before. |
| A user tries to remove **someone else's** passkey through the Keyless API | Refused (`PermissionError`). System Managers may remove any passkey. |
| Anyone, including a System Manager or server code, changes `user`, `credential_id`, `public_key` or `user_handle` on an existing passkey | Refused (*"Cannot change … of a registered passkey"*). Only the device name can be edited. To move a passkey to another account, delete it and register again. |

### Signing in with a passkey

| If… | Then… |
|---|---|
| The passkey's response carries a user handle that is not the bound user's WebAuthn handle | Refused, *"Passkey does not match this account"*. Logged as `passkey_failed` / `user_handle_mismatch`. |
| The response carries no user handle at all | Refused the same way. Keyless registers resident keys, and browsers always return the handle for those. |
| The handle matches and the signature verifies | Signed in. |

### Which websites a passkey works from

A passkey is bound to a website. Keyless decides which websites it trusts from
**configuration only**. Request headers such as `Origin` and `Host`, which the browser or an
attacker controls, are never used.

| If… | Then… |
|---|---|
| The passkey ceremony comes from the **configured site URL** (`host_name` in site_config, else the site name, plus the bench port in developer mode) | Accepted. |
| It comes from an origin listed in **Allowed Origins** (one per line, e.g. `https://erp.example.com:8001`) | Accepted. |
| It comes from any other origin, even if the request's `Origin` header claims it | Refused, *"Could not verify this passkey"*. |
| **RP ID** is set | That RP ID is used for registration and sign-in. |
| **RP ID** is blank | The hostname of the configured site URL is used. A spoofed `Host` header cannot change it. |
| An Allowed Origins line is not of the form `scheme://host[:port]` | Keyless Settings refuses to save. |

**If people reach the site on a different domain or port than the configured URL** (for
example behind a reverse proxy while `host_name` is not set), passkey sign-in fails until you
set `host_name` in site_config or add that origin to **Allowed Origins**. Each allowed origin's
host must be the RP ID or a subdomain of it; browsers enforce that.

### Checking existing data after upgrading

Before this fix, any user could re-point their own passkey at another account. To find
records that may have been tampered with:

```bash
bench --site <site> execute keyless.security.report_repointed_passkeys
```

It lists passkeys whose creator is not the bound user, or whose stored user handle is not
that user's handle. It also runs once automatically during `bench migrate`, and writes its
findings to the **Error Log** ("Keyless: review User Passkey ownership").
It **only reports**; it never changes or deletes anything. A System Manager who registered
a passkey on someone's behalf also shows up, so review each row before deleting it.

---

## 5. Where people land after signing in

Both the Keyless login page (`/keyless/login?redirect-to=…`) and magic links can send the
person to a page after sign-in.

| If the requested target is… | Then… |
|---|---|
| A path on this site starting with a single `/`, e.g. `/app/todo?x=1` | Used as given. |
| Another site (`https://evil.com`, `//evil.com`), a backslash form (`/\evil.com`), a scheme (`javascript:`), a bare name (`app/todo`) or anything with control characters | Ignored. The person lands on the default page: Desk for System Users, the website home page for Website Users. |

Magic links:

| If… | Then… |
|---|---|
| Someone requests a link with a target | The target is checked as above and stored on the server with the link. The emailed URL contains only the key, so editing the URL cannot change where the link leads. |
| An older link (sent before this change) carries `redirect_to` in its URL | That target is used only if it passes the same check. |

Everything the login page writes into its HTML (the target, logo, app name, titles and link
labels) is escaped, so a crafted link cannot inject script into the page.

---

## 6. Fresh installs

| If… | Then… |
|---|---|
| Keyless is installed on a new site | **Enable Keyless** and every factor (passkeys, magic link, email OTP, backup codes) are **off**. Nothing changes for users until an administrator opts in. |
| Keyless is upgraded on a site that already has Keyless Settings | Existing settings are kept. Nothing is switched off by the upgrade. |

The defaults that stay on, but have no effect until Keyless is enabled: Allow Administrator
Password (break-glass), Hide User Enumeration, and User Verification = required.

---

## 7. Audit log entries

New or changed events in **Keyless Audit Log**:

| Event | When | Notes |
|---|---|---|
| `password_blocked` | A password login or OAuth password grant was blocked | `method` is `password` or `oauth_password`. For an unknown login name, `user` is `Guest` and the typed name is in `detail`. |
| `factor_blocked` | Email OTP or magic link refused | `detail` is `passkey_required` (System User rule) or `frappe_2fa` (Frappe 2FA applies). |
| `passkey_failed` | Passkey sign-in refused | New `detail` value: `user_handle_mismatch`. |

---

## 8. Upgrading from earlier versions

Run `bench --site <site> migrate` after updating. Then check:

| Change | What to do |
|---|---|
| Users can no longer create or edit User Passkey records through `/api/resource` | Nothing, unless a custom integration relied on it. Use the Keyless API instead. |
| Disable Password Login, Passwordless Only and Require a Passkey for System Users are now **actually enforced** | Before upgrading, check who would be locked out. In particular, Require a Passkey for System Users now blocks the passwords of System Users who do not have Frappe 2FA. |
| OAuth clients using the password grant stop working when password login is disabled for that user | Move them to the authorization-code grant or API keys. |
| The **Allow Passwordless Signup** setting is removed | Nothing. It was never enforced; Keyless has no signup flow. |
| The `login` method override (`keyless.overrides.login`) is removed | Nothing, unless other code imported it. The policy now runs from the `before_login`, `on_login` and `before_request` hooks. |
| `report_repointed_passkeys` runs during migrate | Check the Error Log for "Keyless: review User Passkey ownership". |
| Users with Frappe 2FA can no longer sign in with email OTP or magic links | Make sure they have a passkey (or backup codes) before upgrading, or they will need a password plus Frappe 2FA. |
| Passkeys only work from the configured site URL and **Allowed Origins** | If users reach the site on another domain or port, set `host_name` in site_config or add the origin to Allowed Origins. Otherwise passkey sign-in fails. |
| Login-page and magic-link targets must be same-site paths | Nothing for normal use. Links or integrations that pass full URLs as `redirect-to` now land on the default page. |

---

## 9. Decisions behind this behaviour

Maintainer decisions taken during the 2026-10 security remediation.

| # | Topic | Decision |
|---|---|---|
| D1 | Frappe's own *Disable Username/Password Login* | Keyless does not set it, because it would also remove the Administrator break-glass. |
| D2 | Fresh-install defaults | Keyless and every factor are off until an administrator opts in. |
| D3 | Users Frappe 2FA applies to | Email OTP and magic link are refused. |
| D4 | OAuth2 password grant when passwords are disabled | Blocked. |
| D5 | Factors refused for System Users when passkeys are required | Email OTP and magic link. Backup codes stay as recovery. |
| D6 | Passkey sign-in options for an email address | Pending (Phase 3, M-2): discoverable credentials only; the `email` parameter is dropped. |
| D7 | Recent re-authentication before adding a passkey or rotating backup codes | Pending (Phase 3, M-3): a setting, default 5 minutes. |
| D8 | Magic-link hardening | Pending (Phase 3, M-4): GET shows a confirmation page and only the POST signs in. Binding the link to the requesting browser is a later follow-up. |
| D9 | Passwords for System Users when passkeys are required | Allowed only when Frappe 2FA applies to the user. Never through the OAuth2 password grant, which skips 2FA. |
| D10 | Backup codes for users with Frappe 2FA | Allowed, as the recovery path. |
