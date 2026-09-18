/**
 * Website login: passkey + email OTP + magic link.
 * Loaded via web_include_js on every website page; binds only on /login and /keyless/login.
 */

(function () {
	function $(sel, root) {
		return (root || document).querySelector(sel);
	}

	function status(msg, kind) {
		const el = $("#keyless-status");
		if (!el) return;
		el.textContent = msg || "";
		el.dataset.kind = kind || "";
	}

	async function call(method, args) {
		const res = await fetch("/api/method/" + method, {
			method: "POST",
			headers: {
				"Content-Type": "application/json",
				Accept: "application/json",
				"X-Frappe-CSRF-Token": window.csrf_token || "",
			},
			body: JSON.stringify(args || {}),
			credentials: "same-origin",
		});
		const data = await res.json();
		if (data.exc || data._server_messages) {
			let msg = data.message || "Request failed";
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

	async function withPasskey(email) {
		const { startAuthentication } = await import("/assets/keyless/js/webauthn_client.js");
		const options = await call("keyless.api.passkey.authentication_options", { email: email || null });
		const credential = await startAuthentication(options);
		const result = await call("keyless.api.passkey.verify_authentication", {
			credential: JSON.stringify(credential),
			challenge_id: options.challenge_id,
		});
		window.location.href = result.home || "/app";
	}

	function bind() {
		const root = document.querySelector(".keyless-login");
		if (!root) return;

		const emailInput = $("#keyless-email");
		const otpForm = $("#keyless-otp-form");

		$("#keyless-passkey")?.addEventListener("click", async () => {
			try {
				status("Waiting for your device…");
				await withPasskey(emailInput?.value || null);
			} catch (e) {
				status(e.message || "Passkey failed", "error");
			}
		});

		$("#keyless-email-form")?.addEventListener("submit", async (ev) => {
			ev.preventDefault();
			const email = emailInput.value;
			try {
				status("Sending a code…");
				await call("keyless.api.otp.request_otp", { email });
				otpForm.hidden = false;
				status("Check your inbox for a short code.");
				$("#keyless-otp-input")?.focus();
			} catch (e) {
				status(e.message, "error");
			}
		});

		otpForm?.addEventListener("submit", async (ev) => {
			ev.preventDefault();
			try {
				const result = await call("keyless.api.otp.verify_otp", {
					email: emailInput.value,
					otp: $("#keyless-otp-input").value,
				});
				window.location.href = result.home || "/app";
			} catch (e) {
				status(e.message, "error");
			}
		});

		$("#keyless-link")?.addEventListener("click", async () => {
			try {
				status("Sending a sign-in link…");
				await call("keyless.api.magic_link.send_link", { email: emailInput.value });
				status("Link sent. It expires in a few minutes.");
			} catch (e) {
				status(e.message, "error");
			}
		});
	}

	if (document.readyState === "loading") {
		document.addEventListener("DOMContentLoaded", bind);
	} else {
		bind();
	}
})();
