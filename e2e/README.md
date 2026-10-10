# Browser tests

Drives the Keyless login page and Desk flows in real Chromium. A virtual WebAuthn
authenticator (Chrome DevTools Protocol) gives passkeys real cryptography, and nothing on
the server is mocked. CI runs it on every pull request (Frappe 16 job).

What it checks:

- the login page loads its bundle with no script errors;
- email-code sign-in lands in Desk;
- registering a passkey from Desk (a fresh sign-in counts as step-up);
- step-up by passkey after the window expires, then backup codes are shown;
- passkey sign-in;
- step-up by emailed code for a user with no passkey, and cancelling it;
- a magic link shows a confirmation page, signs in only on the button, and is then used up;
- a `redirect-to` XSS payload stays inert text.

## Running it locally

The suite resets the site's Keyless settings and creates its own test users, so use a
throwaway site. The server-side helpers (`keyless/tests/e2e_support.py`) refuse to run
unless the site has `allow_tests` set.

```sh
bench new-site e2e.localhost
bench --site e2e.localhost install-app keyless
bench --site e2e.localhost set-config allow_tests true
bench build --app keyless
bench serve --port 8000          # in another terminal

cd apps/keyless/e2e
npm ci
npx playwright install chromium
node run.js
```

A `*.localhost` site name resolves to your machine in Chromium, so no hosts-file entry is
needed. Mail is not sent: the suite sets `mute_emails` and reads codes and links from the
Email Queue.

Settings, all optional:

| Variable | Default | Meaning |
|---|---|---|
| `KEYLESS_E2E_SITE` | `e2e.localhost` | Site to test |
| `KEYLESS_E2E_URL` | `http://<site>:8000` | Where the site is served |
| `KEYLESS_E2E_BENCH` | `~/frappe-bench` | Bench directory, for `bench execute` |
| `KEYLESS_E2E_BENCH_CMD` | `bench` | Command used to run bench |
| `KEYLESS_E2E_SCREENSHOTS` | `e2e/screenshots` | A screenshot is saved after every step |

The script exits non-zero if any step fails. In CI, the screenshots and server log are
uploaded as an artifact when it does.
