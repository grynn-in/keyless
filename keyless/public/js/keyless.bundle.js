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

keyless.register_passkey = async function (frm) {
	if (!window.PublicKeyCredential) {
		frappe.msgprint(__("This browser does not support passkeys."));
		return;
	}
	try {
		const options = await frappe.xcall("keyless.api.passkey.registration_options");
		const { startRegistration } = await import("./webauthn_client.js");
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
	const r = await frappe.xcall("keyless.api.backup.generate_codes");
	const html = (r.codes || []).map((c) => `<code>${frappe.utils.escape_html(c)}</code>`).join("<br>");
	frappe.msgprint({
		title: __("Backup codes — copy them now"),
		message: `<p>${__("These codes will not be shown again.")}</p><p>${html}</p>`,
	});
};
