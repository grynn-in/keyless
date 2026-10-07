import { startAuthentication, startRegistration } from "./webauthn_client.js";

frappe.provide("keyless");

keyless.boot = () => frappe.boot.keyless || { enabled: false };

frappe.ui.form.on("User", {
	refresh(frm) {
		if (!keyless.boot().enabled || !keyless.boot().enable_passkeys) return;
		if (frm.is_new()) return;
		const is_self = frm.doc.name === frappe.session.user;
		const is_manager = frappe.user_roles.includes("System Manager");
		if (!is_self && !is_manager) return;

		frm.add_custom_button(__("Register Passkey"), () => keyless.register_passkey(frm), __("Keyless"));
		frm.add_custom_button(__("New Backup Codes"), () => keyless.rotate_backup_codes(), __("Keyless"));
	},
});

/**
 * Adding a passkey or regenerating backup codes needs a recent sign-in or
 * confirmation (step-up). Resolves when the server will accept the change.
 */
keyless.ensure_recent_auth = async function () {
	const state = await frappe.xcall("keyless.api.stepup.status");
	if (state.recent) return;

	if (state.methods.includes("passkey") && window.PublicKeyCredential) {
		try {
			const options = await frappe.xcall("keyless.api.stepup.passkey_options");
			const credential = await startAuthentication(options);
			await frappe.xcall("keyless.api.stepup.verify_passkey", {
				credential: JSON.stringify(credential),
				challenge_id: options.challenge_id,
			});
			return;
		} catch (e) {
			if (!state.methods.includes("email")) throw e;
		}
	}

	if (state.methods.includes("email")) {
		await frappe.xcall("keyless.api.stepup.request_email_code");
		const code = await new Promise((resolve, reject) => {
			const dialog = frappe.prompt(
				{ fieldname: "otp", fieldtype: "Data", label: __("Code"), reqd: 1 },
				(values) => resolve(values.otp),
				__("Confirm it's you"),
				__("Confirm")
			);
			dialog.set_message(__("We emailed you a code."));
			dialog.onhide = () => reject(new Error(__("Cancelled")));
		});
		await frappe.xcall("keyless.api.stepup.verify_email_code", { otp: code });
		return;
	}

	throw new Error(__("Sign out and sign in again to continue."));
};

keyless.register_passkey = async function (frm) {
	if (!window.PublicKeyCredential) {
		frappe.msgprint(__("This browser does not support passkeys."));
		return;
	}
	try {
		await keyless.ensure_recent_auth();
		const options = await frappe.xcall("keyless.api.passkey.registration_options");
		const credential = await startRegistration(options);
		const name = prompt(__("Device name"), __("This device"));
		await frappe.xcall("keyless.api.passkey.verify_registration", {
			credential: JSON.stringify(credential),
			challenge_id: options.challenge_id,
			friendly_name: name,
		});
		frappe.show_alert({ message: __("Passkey registered"), indicator: "green" });
		frm && frm.reload_doc();
	} catch (e) {
		frappe.msgprint(e.message || __("Could not register passkey"));
	}
};

keyless.rotate_backup_codes = async function () {
	try {
		await keyless.ensure_recent_auth();
	} catch (e) {
		frappe.msgprint(e.message || __("Could not confirm it's you"));
		return;
	}
	const r = await frappe.xcall("keyless.api.backup.generate_codes");
	const html = (r.codes || []).map((c) => `<code>${frappe.utils.escape_html(c)}</code>`).join("<br>");
	frappe.msgprint({
		title: __("Backup codes — copy them now"),
		message: `<p>${__("These codes will not be shown again.")}</p><p>${html}</p>`,
	});
};
