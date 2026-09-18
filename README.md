# Keyless

Passwordless accounts for the Frappe Framework. Passkeys (WebAuthn/FIDO2), email OTP, magic links, and hashed backup codes — issued through `LoginManager.login_as`, not a parallel session stack.

Frappe already ships email-link login (`frappe.www.login.send_login_link`) and TOTP as a second factor. It does not ship passkeys ([frappe#37486](https://github.com/frappe/frappe/issues/37486)), does not hide user enumeration on the email-link path, and cannot disable password login. Keyless is a custom app that fills that gap without forking core.

## What it is

A standard Frappe app (`hooks.py`, DocTypes, whitelisted methods, website page, desk workspace) targeting **Frappe v15 and v16**.

| Factor | Assurance | Stored |
| --- | --- | --- |
| Passkey | AAL2 when user verification is `required` | Public key + credential id on **User Passkey** |
| Email OTP | AAL1 | HMAC digest in Redis, 5 min TTL |
| Magic link | AAL1 | Unguessable key in Redis, 10 min TTL, one-shot |
| Backup codes | Recovery | HMAC digest on **Keyless Backup Code** |
| Password | Optional / break-glass | Unchanged Frappe `User.password` |

Sessions are normal Frappe `sid` cookies. Desk, CSRF, IP restrictions, login hours, and `on_login` hooks keep working.

## Install

```bash
cd ~/frappe-bench
bench get-app https://github.com/grynn-in/keyless
bench pip install webauthn
bench --site site.local install-app keyless
bench --site site.local migrate
bench --site site.local clear-cache
```

Open **Keyless Settings**. Enable the factors you want. Optionally **Disable Password Login** (Administrator can remain as break-glass).

Login URL: `/keyless/login`. Set **Replace Standard Login Page** to send `/login` there from the website bundle.

## Architecture (short)

1. Guest POSTs to `keyless.api.*` (rate-limited, `allow_guest=True`).
2. Challenge or OTP lives in Redis, peppered with `encryption_key`.
3. On success the API calls `LoginManager.login_as(user)` — the same passwordless path Frappe uses for impersonation and email-link login.
4. `override_whitelisted_methods["login"]` blocks password POSTs when the policy says so.
5. `auth_hooks` is reserved for future signed API assertions; browser login does **not** `frappe.set_user()` from a header.

Do not fork `frappe/auth.py`. Do not store OTPs in MariaDB. Do not use SMS OTP (SIM swap). Do not make Administrator passwordless-only without an out-of-band recovery story.

## Multi-site benches

WebAuthn **RP ID** is the hostname of the site. Leave `rp_id` blank to use the current host. A passkey registered on `erp.company.ch` will not work on `staging.company.ch`. That is the spec, not a bug.

HTTPS is required in production (localhost is the WebAuthn exception).

## Tests

```bash
bench --site site.local run-tests --app keyless
```

## License

MIT
