/**
 * Website login: passkey, email OTP, magic link and recovery codes.
 * Loaded via web_include_js on every website page; binds only on /keyless/login
 * (anything rendering `.keyless-login`) and, to add a "Login with Passkey"
 * option, on Frappe's standard /login.
 *
 * The page markup mirrors Frappe's login.html, so behaviour follows Frappe's
 * login.js where it can: hash steps (#login, #otp, #recovery), the
 * `invalid-login` wiggle on errors, and `redirect-to` after sign-in.
 *
 * Static import (not import()) so Frappe's esbuild IIFE bundle can inline the helper.
 */
import { startAuthentication } from "./webauthn_client.js";

(function () {
	const t = (msg, args) => (typeof window.__ === "function" ? window.__(msg, args) : msg);

	function $(sel, root) {
		return (root || document).querySelector(sel);
	}

	let root = null;

	function frappeMajor() {
		return parseInt((root && root.dataset.frappeMajor) || "15", 10);
	}

	function visibleStep() {
		return root.querySelector(".keyless-step:not([hidden])");
	}

	function statusEl() {
		const step = visibleStep();
		return (step && step.querySelector(".keyless-status")) || $("#keyless-status");
	}

	/** kind: "" (progress), "success" or "error". */
	function status(msg, kind) {
		const el = statusEl();
		if (!el) return;
		el.textContent = msg || "";
		el.dataset.kind = kind || "";
		el.classList.remove(
			"text-muted",
			"text-danger",
			"text-success",
			"login-error-banner",
			"login-success-banner"
		);
		if (frappeMajor() >= 16 && kind) {
			// v16 ships banner styles for exactly these two cases.
			el.classList.add(kind === "error" ? "login-error-banner" : "login-success-banner");
		} else {
			el.classList.add(
				kind === "error" ? "text-danger" : kind === "success" ? "text-success" : "text-muted"
			);
		}
		if (kind === "error") wiggle();
	}

	function clearStatus() {
		root.querySelectorAll(".keyless-status").forEach((el) => {
			el.textContent = "";
			el.dataset.kind = "";
			el.className = "keyless-status text-muted";
		});
		root.querySelectorAll(".form-group.invalid").forEach((g) => g.classList.remove("invalid"));
	}

	/** Frappe's login.set_invalid: shake the visible card. */
	function wiggle() {
		const step = visibleStep();
		const card = step && step.querySelector(".login-content.page-card");
		if (!card) return;
		card.classList.add("invalid-login");
		setTimeout(() => card.classList.remove("invalid-login"), 500);
	}

	function markInvalid(input, msg) {
		const group = input && input.closest(".form-group");
		if (group) {
			group.classList.add("invalid");
			const fieldError = group.querySelector(".field-error");
			if (fieldError) fieldError.textContent = msg;
		}
		status(msg, "error");
		if (input) input.focus();
	}

	function busy(form, on) {
		if (!form) return;
		form.querySelectorAll("button").forEach((b) => (b.disabled = on));
	}

	function csrfToken() {
		return window.csrf_token || (window.frappe && window.frappe.csrf_token) || "";
	}

	async function call(method, args) {
		const res = await fetch("/api/method/" + method, {
			method: "POST",
			headers: {
				"Content-Type": "application/json",
				Accept: "application/json",
				"X-Frappe-CSRF-Token": csrfToken(),
			},
			body: JSON.stringify(args || {}),
			credentials: "same-origin",
		});
		let data = {};
		try {
			data = await res.json();
		} catch (e) {
			throw new Error(
				res.status === 429
					? t("Too many requests. Please wait and try again.")
					: t("Request failed")
			);
		}
		if (data.exc || data._server_messages || !res.ok) {
			let msg = (typeof data.message === "string" && data.message) || t("Request failed");
			try {
				const parsed = JSON.parse(data._server_messages || "[]");
				if (parsed[0]) msg = JSON.parse(parsed[0]).message || msg;
			} catch (e) {
				/* keep msg */
			}
			throw new Error(msg);
		}
		return data.message;
	}

	/** Same-origin path from ?redirect-to=, else null (Frappe's sanitise_redirect). */
	function redirectTo() {
		const raw =
			new URLSearchParams(window.location.search).get("redirect-to") ||
			(root && root.dataset.redirectTo) ||
			"";
		if (!raw) return null;
		try {
			const url = new URL(raw, window.location.origin);
			if (url.origin !== window.location.origin) return null;
			return url.pathname + url.search + url.hash;
		} catch (e) {
			return null;
		}
	}

	function goHome(result) {
		window.location.href = redirectTo() || (result && result.home) || "/app";
	}

	function emailValue(input) {
		return ((input && input.value) || "").trim();
	}

	function requireEmail(input) {
		const email = emailValue(input);
		if (!email || (input.checkValidity && !input.checkValidity())) {
			markInvalid(input, t("Enter a valid email address"));
			return null;
		}
		return email;
	}

	// ---- steps (#login, #otp, #recovery), like Frappe's hash-driven sections ----

	function showStep(name) {
		const steps = root.querySelectorAll(".keyless-step");
		let target = root.querySelector(`.keyless-step[data-keyless-step="${name}"]`);
		if (!target) target = root.querySelector('.keyless-step[data-keyless-step="login"]');
		steps.forEach((s) => (s.hidden = s !== target));
		clearStatus();
		const mainEmail = $("#keyless-email");
		const backupEmail = $("#keyless-backup-email");
		if (backupEmail && mainEmail && !backupEmail.value) backupEmail.value = mainEmail.value;
		const first = target && target.querySelector("input:not([type=hidden])");
		if (first) {
			// Recovery: jump to the code if the email is already filled.
			const next = name === "recovery" && first.value ? $("#keyless-backup-code") : first;
			if (next) next.focus();
		}
	}

	function route() {
		let hash = (window.location.hash || "#login").slice(1);
		// The code step needs the email from step 1 (e.g. after a reload).
		if (hash === "otp" && !emailValue($("#keyless-email"))) hash = "login";
		showStep(hash);
	}

	// ---- factors ----

	const actions = {
		async passkey(form) {
			status(t("Waiting for your device…"));
			try {
				const options = await call("keyless.api.passkey.authentication_options", {});
				const credential = await startAuthentication(options);
				const result = await call("keyless.api.passkey.verify_authentication", {
					credential: JSON.stringify(credential),
					challenge_id: options.challenge_id,
				});
				goHome(result);
			} catch (e) {
				status(e.message || t("Passkey failed"), "error");
			}
		},

		async otp(form) {
			const emailInput = $("#keyless-email");
			const email = requireEmail(emailInput);
			if (!email) return;
			status(t("Sending a code…"));
			await call("keyless.api.otp.request_otp", { email });
			// pushState (not location.hash) so the hashchange handler does not wipe the status.
			window.history.pushState(null, "", "#otp");
			showStep("otp");
			status(t("Check your inbox for a short code."), "success");
		},

		async link(form) {
			const email = requireEmail($("#keyless-email"));
			if (!email) return;
			status(t("Sending a sign-in link…"));
			const args = { email };
			const target = redirectTo();
			if (target) args.redirect_to = target;
			await call("keyless.api.magic_link.send_link", args);
			status(t("Link sent. It expires in a few minutes."), "success");
		},
	};

	async function run(name, form) {
		busy(form, true);
		try {
			await actions[name](form);
		} catch (e) {
			status(e.message, "error");
		} finally {
			busy(form, false);
		}
	}

	function bind() {
		root = document.querySelector(".keyless-login");
		if (!root) return;

		root.addEventListener("input", (ev) => {
			const group = ev.target.closest(".form-group");
			if (group) group.classList.remove("invalid");
		});

		// Option buttons (type=button) run their own factor.
		root.querySelectorAll('button[type="button"][data-keyless-action]').forEach((btn) => {
			btn.addEventListener("click", () => run(btn.dataset.keylessAction, btn.form));
		});

		// Enter / main button runs the primary factor.
		const emailForm = $("#keyless-email-form");
		if (emailForm) {
			emailForm.addEventListener("submit", (ev) => {
				ev.preventDefault();
				const primary = emailForm.querySelector('button[type="submit"][data-keyless-action]');
				if (primary) run(primary.dataset.keylessAction, emailForm);
			});
		}

		const otpForm = $("#keyless-otp-form");
		if (otpForm) {
			otpForm.addEventListener("submit", async (ev) => {
				ev.preventDefault();
				const otpInput = $("#keyless-otp-input");
				const otp = (otpInput.value || "").trim();
				if (!otp) return markInvalid(otpInput, t("Enter the code from your email"));
				const email = emailValue($("#keyless-email"));
				if (!email) {
					window.location.hash = "#login";
					return;
				}
				busy(otpForm, true);
				try {
					status(t("Verifying..."));
					goHome(await call("keyless.api.otp.verify_otp", { email, otp }));
				} catch (e) {
					status(e.message, "error");
				} finally {
					busy(otpForm, false);
				}
			});

			const resend = otpForm.querySelector('[data-keyless-action="otp-resend"]');
			if (resend) {
				resend.addEventListener("click", async (ev) => {
					ev.preventDefault();
					const email = emailValue($("#keyless-email"));
					if (!email) {
						window.location.hash = "#login";
						return;
					}
					try {
						status(t("Sending a code…"));
						await call("keyless.api.otp.request_otp", { email });
						status(t("Check your inbox for a short code."), "success");
					} catch (e) {
						status(e.message, "error");
					}
				});
			}
		}

		const backupForm = $("#keyless-backup-form");
		if (backupForm) {
			backupForm.addEventListener("submit", async (ev) => {
				ev.preventDefault();
				const email = requireEmail($("#keyless-backup-email"));
				if (!email) return;
				const codeInput = $("#keyless-backup-code");
				const code = (codeInput.value || "").trim();
				if (!code) return markInvalid(codeInput, t("Enter a recovery code"));
				busy(backupForm, true);
				try {
					status(t("Verifying..."));
					goHome(await call("keyless.api.backup.redeem", { email, code }));
				} catch (e) {
					status(e.message, "error");
				} finally {
					busy(backupForm, false);
				}
			});
		}

		window.addEventListener("hashchange", route);
		route();
	}

	// ---- Frappe's standard /login: add a "Login with Passkey" option ----
	//
	// Frappe's login.html has no extension point for extra login methods, so we
	// add one button where Frappe renders its own alternatives ("Login with Email
	// Link", social logins). Anything unexpected in the markup: do nothing.

	function keylessLoginUrl() {
		const target = redirectTo();
		return "/keyless/login" + (target ? "?redirect-to=" + encodeURIComponent(target) : "");
	}

	function optionButton(label) {
		const a = document.createElement("a");
		a.href = keylessLoginUrl();
		a.className = "btn btn-block btn-default btn-sm btn-login-option btn-login-with-keyless";
		a.textContent = label;
		return a;
	}

	function addStandardLoginOption(config) {
		if (!config || !config.enabled) return;
		if (!(config.enable_passkeys || config.enable_email_otp || config.enable_magic_link)) return;
		const card = document.querySelector("section.for-login .login-content.page-card");
		const form = card && card.querySelector("form.form-login");
		if (!form || card.querySelector(".btn-login-with-keyless")) return;

		const label = config.enable_passkeys ? t("Login with Passkey") : t("Passwordless Login");
		const v16 = !!card.querySelector(".page-card-head");

		if (v16) {
			// v16: alternatives are .btn-login-option links inside .page-card-actions.
			const actions = form.querySelector(".page-card-actions");
			if (!actions) return;
			const social = actions.querySelector(".social-logins");
			actions.insertBefore(optionButton(label), social || null);
			return;
		}

		// v15: alternatives live in .social-logins (with the "or" divider) inside
		// an outer .page-card-body; create that block when Frappe did not render one.
		const wrapper = document.createElement("div");
		wrapper.className = "login-button-wrapper";
		wrapper.appendChild(optionButton(label));
		let buttons = form.querySelector(".social-logins .social-login-buttons");
		if (buttons) {
			const group = document.createElement("div");
			group.className = "social-login-buttons";
			group.appendChild(wrapper);
			buttons.parentNode.appendChild(group);
			return;
		}
		const body = document.createElement("div");
		body.className = "page-card-body";
		const social = document.createElement("div");
		social.className = "social-logins text-center";
		const divider = document.createElement("p");
		divider.className = "text-muted login-divider";
		divider.textContent = t("or");
		buttons = document.createElement("div");
		buttons.className = "social-login-buttons";
		buttons.appendChild(wrapper);
		social.appendChild(divider);
		social.appendChild(buttons);
		body.appendChild(social);
		form.appendChild(body);
	}

	async function bindStandardLogin() {
		if (!/^\/login\/?$/.test(window.location.pathname)) return;
		if (!document.querySelector("section.for-login")) return;
		try {
			const res = await fetch("/api/method/keyless.api.settings.public_config", {
				headers: { Accept: "application/json" },
				credentials: "same-origin",
			});
			if (!res.ok) return;
			const data = await res.json();
			addStandardLoginOption(data.message);
		} catch (e) {
			/* Keyless missing or unreachable: leave Frappe's page alone. */
		}
	}

	function init() {
		bind();
		bindStandardLogin();
	}

	if (document.readyState === "loading") {
		document.addEventListener("DOMContentLoaded", init);
	} else {
		init();
	}
})();
