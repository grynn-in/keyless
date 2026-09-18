/**
 * Minimal WebAuthn client. Talks the PublicKeyCredential JSON that
 * @simplewebauthn and py_webauthn agree on (base64url, not ArrayBuffer over the wire).
 */

function b64urlToBuf(value) {
	const pad = "=".repeat((4 - (value.length % 4)) % 4);
	const str = (value + pad).replace(/-/g, "+").replace(/_/g, "/");
	const raw = atob(str);
	const buf = new ArrayBuffer(raw.length);
	const view = new Uint8Array(buf);
	for (let i = 0; i < raw.length; i++) view[i] = raw.charCodeAt(i);
	return buf;
}

function bufToB64url(buf) {
	const bytes = new Uint8Array(buf);
	let str = "";
	for (let i = 0; i < bytes.length; i++) str += String.fromCharCode(bytes[i]);
	return btoa(str).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

function reviveCreateOptions(options) {
	const pub = { ...options };
	pub.challenge = b64urlToBuf(options.challenge);
	pub.user = { ...options.user, id: b64urlToBuf(options.user.id) };
	if (pub.excludeCredentials) {
		pub.excludeCredentials = pub.excludeCredentials.map((c) => ({
			...c,
			id: b64urlToBuf(c.id),
		}));
	}
	return pub;
}

function reviveRequestOptions(options) {
	const pub = { ...options };
	pub.challenge = b64urlToBuf(options.challenge);
	if (pub.allowCredentials) {
		pub.allowCredentials = pub.allowCredentials.map((c) => ({
			...c,
			id: b64urlToBuf(c.id),
		}));
	}
	return pub;
}

function credentialToJSON(cred) {
	return {
		id: cred.id,
		rawId: bufToB64url(cred.rawId),
		type: cred.type,
		authenticatorAttachment: cred.authenticatorAttachment,
		response: {
			clientDataJSON: bufToB64url(cred.response.clientDataJSON),
			attestationObject: cred.response.attestationObject
				? bufToB64url(cred.response.attestationObject)
				: undefined,
			authenticatorData: cred.response.authenticatorData
				? bufToB64url(cred.response.authenticatorData)
				: undefined,
			signature: cred.response.signature ? bufToB64url(cred.response.signature) : undefined,
			userHandle: cred.response.userHandle ? bufToB64url(cred.response.userHandle) : undefined,
		},
		clientExtensionResults: cred.getClientExtensionResults(),
	};
}

export async function startRegistration(options) {
	const cred = await navigator.credentials.create({ publicKey: reviveCreateOptions(options) });
	return credentialToJSON(cred);
}

export async function startAuthentication(options) {
	const cred = await navigator.credentials.get({ publicKey: reviveRequestOptions(options) });
	return credentialToJSON(cred);
}
