app_name = "keyless"
app_title = "Keyless"
app_publisher = "Grynn GmbH"
app_description = "Passwordless accounts for the Frappe Framework — passkeys, magic links, and email OTP."
app_email = "deepak.pai@grynn.in"
app_license = "mit"

required_apps = ["frappe"]

export_python_type_annotations = True

add_to_apps_screen = [
	{
		"name": "keyless",
		"logo": "/assets/keyless/images/keyless-mark.svg",
		"title": "Keyless",
		"route": "/app/keyless-settings",
		"has_permission": "keyless.api.settings.can_show_app",
	}
]

after_install = "keyless.install.after_install"
after_migrate = "keyless.install.after_migrate"
before_uninstall = "keyless.install.before_uninstall"

app_include_js = ["keyless.bundle.js"]
app_include_css = ["keyless.bundle.css"]
web_include_js = ["keyless_web.bundle.js"]
web_include_css = ["keyless_web.bundle.css"]

website_route_rules = [
	{"from_route": "/keyless/login", "to_route": "keyless_login"},
]

override_whitelisted_methods = {
	"login": "keyless.overrides.login.login",
}

auth_hooks = ["keyless.auth.request_auth"]

on_login = "keyless.auth.on_login"
on_logout = "keyless.auth.on_logout"
on_session_creation = "keyless.auth.on_session_creation"

extend_bootinfo = "keyless.boot.extend_bootinfo"

doc_events = {
	"User": {
		"after_insert": "keyless.user.after_user_insert",
		"on_trash": "keyless.user.on_user_trash",
		"on_update": "keyless.user.on_user_update",
	}
}

scheduler_events = {
	"hourly": ["keyless.tasks.purge_expired_challenges"],
	"daily": ["keyless.tasks.purge_old_audit_logs"],
}

# Translation
translated_languages_for_setup = ["en", "de", "fr"]
