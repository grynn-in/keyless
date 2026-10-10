// Browser check of the Keyless front end: real Chromium with a virtual WebAuthn
// authenticator (Chrome DevTools Protocol), so passkeys use real cryptography and
// nothing on the server is mocked. See e2e/README.md for how to run it.
const { chromium } = require("playwright");
const { execFileSync } = require("child_process");
const os = require("os");
const path = require("path");
const fs = require("fs");

const SITE = process.env.KEYLESS_E2E_SITE || "e2e.localhost";
const BASE = process.env.KEYLESS_E2E_URL || `http://${SITE}:8000`;
const BENCH_DIR = process.env.KEYLESS_E2E_BENCH || path.join(os.homedir(), "frappe-bench");
const BENCH_CMD = process.env.KEYLESS_E2E_BENCH_CMD || "bench";
const SHOTS = process.env.KEYLESS_E2E_SCREENSHOTS || path.join(__dirname, "screenshots");
const results = [];

// Server-side helpers in keyless/tests/e2e_support.py, run through `bench execute`.
function server(fn, kwargs = {}) {
	const out = execFileSync(
		BENCH_CMD,
		["--site", SITE, "execute", `keyless.tests.e2e_support.${fn}`, "--kwargs", JSON.stringify(kwargs)],
		{ cwd: BENCH_DIR, encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] }
	);
	const last = out.trim().split("\n").pop();
	return last ? JSON.parse(last) : null;
}
const mail = (to) => (server("last_mail", { recipient: to }) || {}).text || "";
const clearStepUp = () => server("clear_step_up");
const count = (doctype, user) => server("count", { doctype, user });
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
let SYS, SYS2;

async function waitForMail(to, pattern, since) {
	// Each poll is a `bench execute`, which takes a second or two on a CI runner.
	const deadline = Date.now() + 45000;
	while (Date.now() < deadline) {
		const text = mail(to);
		const m = text.match(pattern);
		if (m && m[0] !== since) return m;
		await sleep(500);
	}
	const errors = server("recent_errors") || [];
	throw new Error(`no mail matching ${pattern} for ${to}; recent Error Log: ${errors.join(" | ") || "none"}`);
}

async function step(name, page, fn) {
	try {
		await fn();
		results.push({ name, ok: true });
		console.log(`PASS  ${name}`);
	} catch (e) {
		results.push({ name, ok: false, error: e.message.split("\n")[0] });
		console.log(`FAIL  ${name}: ${e.message.split("\n")[0]}`);
	}
	await page.screenshot({ path: `${SHOTS}/${String(results.length).padStart(2, "0")}-${name.replace(/\W+/g, "-")}.png` });
}

async function newPage(browser) {
	const context = await browser.newContext({ baseURL: BASE, viewport: { width: 1200, height: 900 }, locale: "en-US" });
	const page = await context.newPage();
	page.errors = [];
	page.dialogs = [];
	page.failedAssets = [];
	page.on("response", (r) => r.status() >= 400 && r.url().includes("/assets/") && page.failedAssets.push(`${r.status()} ${r.url()}`));
	page.on("pageerror", (e) => page.errors.push(e.message));
	// No realtime (socket.io) server runs on the test bench; its connection errors are expected.
	page.on("console", (m) => m.type() === "error" && !/socket\.io|status of 404/.test(m.text()) && page.errors.push(m.text()));
	page.on("dialog", async (d) => {
		page.dialogs.push(`${d.type()}: ${d.message()}`);
		await (d.type() === "prompt" ? d.accept("E2E laptop") : d.dismiss());
	});
	const cdp = await context.newCDPSession(page);
	await cdp.send("WebAuthn.enable");
	await cdp.send("WebAuthn.addVirtualAuthenticator", {
		options: {
			protocol: "ctap2",
			transport: "internal",
			hasResidentKey: true,
			hasUserVerification: true,
			isUserVerified: true,
			automaticPresenceSimulation: true,
		},
	});
	return page;
}

const whoAmI = (page) =>
	page.evaluate(async () => (await (await fetch("/api/method/frappe.auth.get_logged_user")).json()).message || "Guest");

async function otpSignIn(page, email) {
	const before = (mail(email).match(/\b\d{6}\b/) || [])[0];
	await page.goto("/keyless/login");
	await page.fill("#keyless-email", email);
	await page.click("#keyless-email-form button[type=submit]");
	await page.waitForSelector("#keyless-otp-input", { state: "visible" });
	const [code] = await waitForMail(email, /\b\d{6}\b/, before);
	await page.fill("#keyless-otp-input", code);
	await page.click("#keyless-otp-form button[type=submit]");
	await page.waitForURL(/\/(app|desk)/, { timeout: 15000 });
}

async function openKeylessMenu(page, user, item) {
	await page.goto(`/app/user/${encodeURIComponent(user)}`);
	const group = page.getByRole("button", { name: "Keyless" });
	await group.waitFor({ timeout: 20000 });
	await group.click();
	await page.getByRole("link", { name: item }).or(page.getByRole("menuitem", { name: item })).first().click();
}

(async () => {
	fs.mkdirSync(SHOTS, { recursive: true });
	[SYS, SYS2] = server("setup", { url: BASE });
	console.log(`Keyless browser suite against ${BASE} (site ${SITE})\n`);
	const browser = await chromium.launch();

	// --- A System User who registers a passkey ---
	const page = await newPage(browser);

	await step("login page loads its bundle with no script errors", page, async () => {
		await page.goto("/keyless/login");
		await page.waitForSelector("#keyless-email");
		const scripts = await page.$$eval("script[src]", (s) => s.map((x) => x.src));
		if (!scripts.some((s) => s.includes("keyless_web.bundle"))) throw new Error("bundle not referenced");
		// A referenced but unbuilt bundle 404s, and the page silently falls back to plain form posts.
		if (page.failedAssets.length) throw new Error(`assets failed to load: ${page.failedAssets.join(", ")}`);
		if (page.errors.length) throw new Error(page.errors.join(" | "));
	});

	await step("email code sign-in lands in Desk", page, async () => {
		await otpSignIn(page, SYS);
		if ((await whoAmI(page)) !== SYS) throw new Error("not signed in");
	});

	await step("register a passkey from Desk (fresh sign-in counts as step-up)", page, async () => {
		await openKeylessMenu(page, SYS, "Register Passkey");
		await page.getByText("Passkey registered").waitFor({ timeout: 20000 });
		if (count("User Passkey", SYS) !== 1) throw new Error("no User Passkey row");
		if (!/E2E laptop/.test(mail(SYS))) throw new Error("no 'passkey added' notification queued");
	});

	await step("expired step-up is confirmed with the passkey, then codes are shown", page, async () => {
		clearStepUp();
		await openKeylessMenu(page, SYS, "New Backup Codes");
		const dialog = page.locator(".modal:visible").filter({ hasText: "Backup codes" });
		await dialog.waitFor({ timeout: 20000 });
		const codes = await dialog.locator("code").count();
		if (codes !== 10) throw new Error(`expected 10 codes, saw ${codes}`);
		if (page.errors.length) throw new Error(page.errors.join(" | "));
	});

	await step("passkey sign-in after logging out", page, async () => {
		await page.evaluate(() => fetch("/api/method/logout", { method: "POST", headers: { "X-Frappe-CSRF-Token": frappe.csrf_token } }));
		await page.goto("/keyless/login");
		if ((await whoAmI(page)) !== "Guest") throw new Error("still signed in");
		await page.click("#keyless-passkey");
		await page.waitForURL(/\/(app|desk)/, { timeout: 15000 });
		if ((await whoAmI(page)) !== SYS) throw new Error("passkey sign-in did not sign in");
	});

	// --- System user without a passkey: step-up falls back to an emailed code ---
	const page2 = await newPage(browser);
	await step("step-up by emailed code when the user has no passkey", page2, async () => {
		await otpSignIn(page2, SYS2);
		clearStepUp();
		const before = (mail(SYS2).match(/\b\d{6}\b/) || [])[0];
		await openKeylessMenu(page2, SYS2, "New Backup Codes");
		const prompt = page2.locator(".modal:visible").filter({ hasText: "Confirm it's you" });
		await prompt.waitFor({ timeout: 20000 });
		const [code] = await waitForMail(SYS2, /\b\d{6}\b/, before);
		await prompt.locator('input[data-fieldname="otp"]').fill(code);
		await prompt.getByRole("button", { name: "Confirm" }).click();
		const codes = page2.locator(".modal:visible").filter({ hasText: "Backup codes" });
		await codes.waitFor({ timeout: 20000 });
		if ((await codes.locator("code").count()) !== 10) throw new Error("codes not shown");
	});

	await step("closing the confirm dialog cancels without generating codes", page2, async () => {
		await page2.locator(".modal:visible .btn-modal-close, .modal:visible [data-dismiss=modal]").first().click().catch(() => {});
		clearStepUp();
		const before = count("Keyless Backup Code", SYS2);
		await openKeylessMenu(page2, SYS2, "New Backup Codes");
		const prompt = page2.locator(".modal:visible").filter({ hasText: "Confirm it's you" });
		await prompt.waitFor({ timeout: 20000 });
		await prompt.locator(".btn-modal-close").click();
		await page2.locator(".modal:visible").filter({ hasText: "Cancelled" }).waitFor({ timeout: 10000 });
		const after = count("Keyless Backup Code", SYS2);
		if (before !== after) throw new Error(`codes changed: ${before} -> ${after}`);
	});

	// --- Magic link: opening it only shows a confirmation page ---
	const page3 = await newPage(browser);
	await step("magic link shows a confirmation page, then signs in on click", page3, async () => {
		await page3.goto("/keyless/login?redirect-to=/app/todo");
		await page3.fill("#keyless-email", SYS2);
		await page3.click("#keyless-link");
		await page3.getByText(/Link sent/).waitFor({ timeout: 15000 });
		const [link] = await waitForMail(SYS2, /https?:\/\/[^\s"<>]+login_via_link\?key=[\w-]+/);
		await page3.goto(link);
		await page3.getByRole("button", { name: "Sign in" }).waitFor();
		if ((await whoAmI(page3)) !== "Guest") throw new Error("opening the link signed in");
		await page3.getByRole("button", { name: "Sign in" }).click();
		await page3.waitForURL(/\/(app|desk)\/todo/, { timeout: 15000 });
		if ((await whoAmI(page3)) !== SYS2) throw new Error("not signed in after confirming");
		await page3.goto(link);
		await page3.getByText("invalid or has expired").waitFor();
	});

	// --- XSS payload in redirect-to ---
	const page4 = await newPage(browser);
	await step("redirect-to XSS payload does not run", page4, async () => {
		await page4.goto("/keyless/login?redirect-to=" + encodeURIComponent('/x"><script>alert(1)</script>'));
		await page4.waitForSelector("#keyless-email");
		await sleep(500);
		if (page4.dialogs.length) throw new Error(`dialog opened: ${page4.dialogs.join(", ")}`);
		// The payload is a same-site path, so it is kept, but must arrive as plain attribute text.
		const attr = await page4.$eval(".keyless-login", (el) => el.getAttribute("data-redirect-to"));
		if (attr !== '/x"><script>alert(1)</script>') throw new Error(`attribute was not escaped intact: ${attr}`);
		const injected = await page4.$$eval("script", (s) => s.filter((x) => x.textContent.includes("alert(1)")).length);
		if (injected) throw new Error("payload became a <script> element");
	});

	await browser.close();
	const failed = results.filter((r) => !r.ok);
	console.log(`\n${results.length - failed.length}/${results.length} passed`);
	process.exit(failed.length ? 1 : 0);
})();
