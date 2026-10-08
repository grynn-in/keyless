# Keyless security remediation report (audit of 7 October 2026)

Branch `fix/security-audit-2026-10`, starting from `2818e78`. Every finding was first
reproduced with a failing test on the unfixed code, then fixed in its own commit. The suite
(133 tests: 20 existing, 113 new) passes on Frappe v16.22.0 (MariaDB 10.11, Redis, Python 3.14).

Behaviour after the fixes, as "if this, then that" rules, is in
[authentication-policy.md](authentication-policy.md). Maintainer decisions D1–D10 are recorded
in its last section.

## Findings

| ID | Finding | Reproduced | Fix commit | Test file | Deviation from the brief, and why |
|---|---|---|---|---|---|
| C-1 | User Passkey re-pointing | Yes: low-privilege REST create and re-point both succeeded; another user's `userHandle` signed in | `94d2bb5` | `test_security_c1.py` | Report script also runs once as a post-sync patch (report only). `revoke_passkey` now deletes with `ignore_permissions` after its own ownership check; without it, removing the `All` role would have stopped users removing their own passkeys. `userHandle` is not covered by the WebAuthn signature, so that check is a second line of defence; the permission and locked-field changes are the real fix. |
| C-2 | Password login bypass via `cmd=login` | Yes, worse than reported: the `login` override never ran at all (Frappe never dispatches `cmd == "login"`), so the policy had no effect anywhere | `305014b` | `test_security_c2.py` | Blocks in `before_login` (before the password is checked, so right and wrong passwords look identical) plus an authoritative `on_login` check, rather than only `on_login`. Refuses only password logins, not "any session not minted by Keyless", so LDAP, social login and impersonation keep working. Per D1, System Settings `disable_user_pass_login` is not set; documented. |
| H-4 | Password-policy gaps | Yes: username/mobile logins, OAuth password grant (token issued on every route), dead settings | `305014b` (a, d), `d9deb5c`, `9533f00` (D9) | `test_security_h4.py` | The `find_by_credentials(..., validate_password=False)` lookup is kept, because `before_login` only sees the typed name; the old name-only lookup was deleted with the override. Removed the unenforced `allow_passwordless_signup` setting. Per D9, System Users may use a password when Frappe 2FA applies to them; the OAuth password grant stays refused for them because it skips 2FA. |
| H-1 | Reflected XSS on `/keyless/login` | Yes: script payload and hostile app name rendered unescaped | `3925b6d` | `test_security_h1.py` | Explicit `\| e` on every variable instead of an `{% autoescape %}` block, which would double-escape the page's macros. |
| H-2 | Open redirect after magic link | Yes: emailed link carried and followed `https://evil.com` | `094e910` | `test_security_h2.py` | None. The target is stored with the key in Redis; a safe target in an older link's URL is still honoured. |
| H-3 | 2FA bypass; all factors on by default | Yes: 2FA user signed in by email code alone; fresh install had everything on | `6f127a3` | `test_security_h3.py` | `install._ensure_settings` never ran (`frappe.db.exists` is always true for a Single); the real defaults were the JSON field defaults, which were changed and the dead function removed. |
| H-5 | WebAuthn origin / RP ID from headers | Yes: spoofed `Host` changed the RP ID; foreign origin accepted | `5ecd741` | `test_security_h5.py` | New **Allowed Origins** setting is the allow-list. |
| M-1 | Rate limits and OTP brute force | Yes: 8 of 12 parallel guesses evaluated (limit 3); rotating IPs never limited; re-issue reset the budget; wrong guess reset TTL to 300 s | `75e7f96` | `test_security_m1.py` | Per-account limits are Keyless's own counters on the normalised email, not `rate_limit(key="email")`, which reads the raw form value (so case variants would count separately). Kept 6-digit codes: an account gets at most 2 × Max OTP Attempts guesses per hour. |
| M-2 | User enumeration | Yes: passkey options listed credentials; mail failure and backup-code work differed | `2098570` | `test_security_m2.py` | Removed the fixed 150 ms sleep for unknown addresses; with mail queued it would have made them the slow path. Also fixed `generate_codes` shadowing `_`, which broke its error message. |
| M-3 | No step-up or notification | Yes: any session could add a passkey or replace codes silently | `5b43f85` | `test_security_m3.py` | A fresh sign-in counts as recent re-authentication. The email-code step-up is offered only where email factors are allowed for the user (D3/D5). An upgraded site loads the new Step-up Window as 0; treated as the default instead of blocking saves. |
| M-4 | Magic link bearer GET | Yes: GET signed in and burned the link | `54d2f45` | `test_security_m4.py` | Per D8, GET→POST only; browser binding is a follow-up. Also made magic-link keys and WebAuthn challenges atomically one-shot (3 of 8 parallel requests used one link before). |
| L-1 | Backup-code race | Yes: 6 of 6 parallel redemptions signed in | `e9d6f96` | `test_security_l1.py` | None (`SELECT … FOR UPDATE`). |
| L-2 | Per-IP limit and NAT | Yes: sixth sign-in from one IP refused | `05ea93b` | `test_security_l2.py` | Limits per IP derived from the setting (20× for email/recovery, 200× for passkeys) rather than new settings. Added per-account limits for magic links and wrong recovery codes. |
| L-3 | WebAuthn error text | Yes: library text returned to clients | `419b59c` | `test_security_l3.py` | Also fixed: the audit log's event list lacked four event names, so those events (including `passkey_register_failed`, which predates this work) were silently never recorded. |
| L-4 | Audit log commit and IPs | Yes: orphan passkey committed by a failing request; raw `X-Forwarded-For` stored | `f438833` | `test_security_l4.py` | Uses Frappe's `after_response` callback (own transaction) rather than `frappe.enqueue`, so entries do not depend on a worker. |
| I-1 | Hardening notes | Yes: empty-pepper fallback, sign count stored for disabled users, no-op code | `ece05dc` | `test_security_i1.py` | Proxy-log note added in M-1; break-glass restrict-IP advice in the policy doc. |

## I-1 checklist

- [x] Document scrubbing `key=` from reverse-proxy access logs (README, "Reverse proxy").
- [x] HMAC pepper fails closed without `encryption_key`; rotation invalidates backup codes (documented).
- [x] `verify_authentication` checks the user is enabled before storing the sign count.
- [x] Document pairing `allow_administrator_password` with `restrict_ip` and alerting.
- [x] Remove the no-op `_sync_login_redirect` and `purge_expired_challenges`.
- [x] Negative-path tests: blocked password login (C-2), cross-user passkey use (C-1, M-3), replayed challenges (I-1, M-4), OTP lockout (M-1).

## Do not regress

All verified unchanged: secrets from `secrets`; codes stored as HMAC-SHA256 digests and
compared in constant time; one-time values in Redis with TTLs, deleted on use (now atomically);
challenges random, one-shot and bound to ceremony and user; sessions only through `login_as`;
login page script uses `textContent` and same-origin redirect checks.

## Open items

- **D8 follow-up:** bind magic links to the requesting browser. Until then a page on another
  site can submit the confirmation form with an attacker's own link, and a leaked link works
  from any device until it expires.
- **Front-end assets untested in a browser:** the test bench was built without assets (Frappe
  16 needs Node 24). The Desk step-up dialog and login-page changes are syntax-checked only.
