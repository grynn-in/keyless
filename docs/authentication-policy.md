# Authentication policy: how Keyless behaves

This page describes what Keyless does in each situation. It covers the
security fixes on branch `fix/security-audit-2026-10` (audit of 7 October 2026):
Phase 1 (C-1, C-2, H-4), Phase 2 (H-1, H-2, H-3, H-5), Phase 3 (M-1 to M-4) and Phase 4 (L-1 to L-4, I-1).

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

Frappe's **password reset link** (from "Forgot password", or from an expired password) signs the
person in once the new password is set, on every route Frappe accepts it. A signed-in user changing
their own password with the old one is not affected. That session follows the password rules: if password login
is blocked for the user, or the user is a System User under **Require a Passkey for System Users**,
the reset is refused with *"Sign in with a passkey."* and nothing changes. It is **not** refused for
users Frappe 2FA applies to, so they can still recover a forgotten password, even though Frappe's
reset skips 2FA (open decision: refusing it would close that gap but lock them out of recovery). Frappe's own **email-link login** follows the email-factor rules
(section 3) the same way. Both are logged as `factor_blocked`.

These do **not** go through the password policy, by design:

| Path | Why |
|---|---|
| Keyless factors (passkey, email OTP, magic link, backup code) | They are the replacement for passwords. See section 3. |
| LDAP login, social login (OAuth providers), impersonation by Administrator | They sign in through `login_as`, not with a password. |
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

**On Frappe 15**, which has no `before_login` trigger, Keyless adds the one call Frappe 16 makes
at the start of `LoginManager.login()` (`keyless/compat.py`), so the rules above hold there too:
the policy runs before the password is checked. The patch is in place once a worker process has
imported Keyless, which its first Keyless hook does; on most workers that is the first request.
Until then, `on_login` checks the password login instead, after the password check: a blocked login
then gets Frappe's *"Invalid login credentials"*, the same response as a wrong password. One gap
remains for that first request only: a correct but **expired** password gets Frappe's "Password
Reset" answer, which shows the password was right. The reset link it carries is still refused.

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

### Email sign-in codes: limits

Limits count per account (the email address, ignoring case and spaces). Addresses with no
account are counted the same way, so the limits reveal nothing. Hitting a limit gives
HTTP 429, *"Too many attempts. Try again later."*

Anyone who knows an address could use up a limit on it, so limits on requests and on
recovery codes count per address **and client IP**: a stranger hitting the limit from their
machine does not stop the owner signing in from theirs. The same address may make **10
times** the limit in total, from all IPs together, before it is refused everywhere; that
backstop is what bounds an attacker who has many IPs. Wrong guesses at a sign-in code are
the exception: they count per address only, because that limit is what keeps a 6-digit code
from being guessed, and it must not grow with the number of IPs an attacker has. Someone
refused there can still sign in with a magic link or a passkey.

Every attempt is counted before it is checked, so parallel requests cannot together get
past a limit. Correct codes are given back, so signing in does not use up the budget for
wrong guesses.

| If… | Then… |
|---|---|
| An address has asked for more than **Rate Limit per Hour** codes in the last hour from one IP | Refused from that IP until the hour is up. Other IPs can still ask, up to 10 times the limit in total. |
| An address has asked for more than **Daily Code Limit per Account** codes (default 10) in a day from one IP | Refused from that IP until the day is up. Other IPs can still ask, up to 10 times the limit in total. |
| A code gets more than **Max OTP Attempts** wrong guesses | That code is deleted; request a new one. |
| An account makes twice **Max OTP Attempts** wrong guesses in an hour, across all its codes and from any IP | Every code for it is refused until the hour is up. Requesting a new code does not reset this. Magic links and passkeys still work. |
| Someone guesses wrong | The code keeps its original expiry (**OTP Expiry**); guessing never extends it. |
| Two requests send the right code at the same moment | Only one gets a session. |
| An address has asked for too many **magic links** | The same hourly and daily limits apply to links as to codes, counted separately. |
| An address gets 10 wrong **recovery codes** in an hour from one IP | Recovery codes for it are refused from that IP until the hour is up; other IPs can still try, up to 100 in total. Recovery codes are 10 characters from 32 (50 bits), so 100 guesses an hour do not make them guessable. |
| A counter is found without an expiry (left by an earlier version) | It gets one on its next use, so no limit can last for ever. |
| Two requests use the same recovery code at the same moment | Only one gets a session; the code is then used. |

Limits per client IP only stop floods from one address, so that a whole office behind one
IP is not locked out: 20 times **Rate Limit per Hour** for code, link and recovery-code
requests (100 by default), and 200 times for passkey sign-in (1000 by default).

### What people see when they request a code or link

| If… | Then… |
|---|---|
| The address has an account, has none, or the mail server fails | The same response: *"ok"*, in the same time. The code or link is created and mailed after the response has gone, and sent at once rather than left for the next run of the email queue, so it does not depend on the scheduler. A sending failure is only written to the Error Log; check it, and the Email Queue, if people report missing codes. |
| **Hide User Enumeration** is off | Unknown addresses get *"No active user found"*, as before. |

### Magic links: confirm before signing in

| If… | Then… |
|---|---|
| Someone opens the emailed link | A "Sign in" page with one button. Nothing is used up and nobody is signed in yet. Mail scanners and link previews, which only open links, can no longer burn them. |
| They press **Sign in** | The link is used up and they are signed in. |
| The link is used again, has expired, or is not real | *"This sign-in link is invalid or has expired."* (HTTP 403). |
| Two requests confirm the same link at the same moment | Only one gets a session. |

Not covered yet (D8 follow-up): a page on another site could still submit the confirmation
form with an attacker's own link, signing the victim into the attacker's account, and a
leaked link still works from any device until it expires.

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

Passkey sign-in never asks for, or uses, an email address: the browser offers the passkeys
it holds for this site. The sign-in options are the same for everyone, so they cannot reveal
which accounts have passkeys. Passkeys registered as non-discoverable credentials cannot be
used to sign in (Keyless has always registered discoverable ones).

| If… | Then… |
|---|---|
| The passkey's response carries a user handle that is not the bound user's WebAuthn handle | Refused, *"Passkey does not match this account"*. Logged as `passkey_failed` / `user_handle_mismatch`. |
| The response carries no user handle at all | Refused the same way. Keyless registers resident keys, and browsers always return the handle for those. |
| The handle matches and the signature verifies, but the user is disabled | Refused, *"User is disabled"*. Nothing about the attempt is stored on the passkey. |
| The handle matches and the signature verifies | Signed in. |
| Verification fails for any reason | *"Could not verify this passkey."* The technical reason is only in the audit log (`detail`). |

### Adding a passkey or generating new backup codes

These changes need **recent re-authentication**: within the **Step-up Window** (default 5
minutes).

| If… | Then… |
|---|---|
| The person signed in within the window (any method) | Allowed. |
| They confirmed with one of **their own** passkeys within the window | Allowed. |
| They confirmed with a code emailed to them within the window | Allowed. Offered only when **Email OTP** is on and email factors are allowed for them (section 3). The code is sent at once. The same hourly and daily limits apply as to sign-in codes, and twice **Max OTP Attempts** wrong guesses an hour. |
| None of these | Refused (*"Confirm it's you before changing how you sign in."*). In Desk, Keyless asks them to confirm with a passkey, or else an emailed code, and then continues. With neither available, they must sign out and in again. |
| They try to confirm with someone else's passkey | Refused. |

Removing a passkey does not need re-authentication, but it is notified like the changes below.

### Notifications

| If… | Then… |
|---|---|
| A passkey is added or removed, or new backup codes are generated | An email goes to the account owner saying what changed and listing the passkeys now on the account, with a prompt to act if it was not them. It is queued, so a mail failure does not block the change. |

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

How entries are written:

| If… | Then… |
|---|---|
| Something is logged during a web request | The entry is written after the response, in its own transaction. Logging never saves the request's other changes early. |
| The request then fails | Its other changes are rolled back, but the audit entry is still written. |
| The IP address is recorded | It is Frappe's resolved client IP. The raw `X-Forwarded-For` header is never stored. See the README's "Reverse proxy" section. |

New or changed events in **Keyless Audit Log**:

| Event | When | Notes |
|---|---|---|
| `password_blocked` | A password login or OAuth password grant was blocked | `method` is `password` or `oauth_password`. For an unknown login name, `user` is `Guest` and the typed name is in `detail`. |
| `factor_blocked` | Email OTP or magic link refused | `detail` is `passkey_required` (System User rule) or `frappe_2fa` (Frappe 2FA applies). |
| `passkey_failed` | Passkey sign-in refused | New `detail` values: `user_handle_mismatch`, `user_disabled`, and the verification library's message. |
| `passkey_register_failed` | Passkey registration refused | Was never recorded before this release; the event name was missing from the log's list. |
| `step_up` / `step_up_failed` | Someone confirmed it was them (or failed to) before changing sign-in methods | `method` is `passkey` or `email_otp`. |
| `backup_failed` | Recovery code refused | Now also logged for addresses with no account (`user` is `Guest`). `detail` is `already_used` when another request used the code first. |

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
| Password reset links no longer sign in users whose password login is blocked, or System Users who need a passkey | Those users sign in with a passkey (or a recovery code). |
| Passkeys are only accepted from configured origins, and the migrate warns (Error Log "Keyless: check passkey origins") when none is https | Behind a proxy that terminates TLS, set `host_name` to the https URL or add it to Allowed Origins. |
| `report_repointed_passkeys` runs during migrate | Check the Error Log for "Keyless: review User Passkey ownership". |
| Users with Frappe 2FA can no longer sign in with email OTP or magic links | Make sure they have a passkey (or backup codes) before upgrading, or they will need a password plus Frappe 2FA. |
| Passkeys only work from the configured site URL and **Allowed Origins** | If users reach the site on another domain or port, set `host_name` in site_config or add the origin to Allowed Origins. Otherwise passkey sign-in fails. |
| Login-page and magic-link targets must be same-site paths | Nothing for normal use. Links or integrations that pass full URLs as `redirect-to` now land on the default page. |
| Magic links need one extra click | Tell users the link opens a "Sign in" page with a button. |
| Codes and links are mailed after the response, and sent at once | Nothing; they no longer wait for the email queue. Notifications about sign-in method changes are still queued, so keep the scheduler running. Mail failures are no longer shown to users. |
| New limits on sign-in codes per account (hourly, daily, wrong guesses) | Review **Rate Limit per Hour**, **Daily Code Limit per Account** and **Max OTP Attempts**. |
| Adding a passkey or generating backup codes asks people to confirm it's them | Nothing; set **Step-up Window** if 5 minutes does not suit. |
| Passkey sign-in no longer uses the email field | Nothing for passkeys registered by Keyless. |
| The reverse proxy must overwrite `X-Forwarded-For` | See the README's "Reverse proxy" section. |
| Codes are peppered with `encryption_key` from site_config | A new site may not have one yet; Keyless then creates and saves it, as Frappe does for encrypted passwords. It never falls back to `secret_key` or an empty value. **Rotating `encryption_key` invalidates every stored backup code**, so ask users to generate new codes afterwards. |
| Per-IP limits are much higher; per-account limits now also cover magic links and recovery codes, and count per address and IP with an account-wide backstop of 10 times the limit | Review **Rate Limit per Hour** and **Daily Code Limit per Account**. |
| The hourly `purge_expired_challenges` job is removed | Nothing; it never did anything. |

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
| D6 | Passkey sign-in options for an email address | Discoverable credentials only; the `email` parameter is dropped. |
| D7 | Recent re-authentication before adding a passkey or rotating backup codes | Required, within a Step-up Window setting (default 5 minutes). |
| D8 | Magic-link hardening | Opening the link shows a confirmation page; only its POST signs in. Binding the link to the requesting browser is a later follow-up. |
| D9 | Passwords for System Users when passkeys are required | Allowed only when Frappe 2FA applies to the user. Never through the OAuth2 password grant, which skips 2FA. |
| D10 | Backup codes for users with Frappe 2FA | Allowed, as the recovery path. |
