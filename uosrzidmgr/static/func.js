function validateLogin() {
	const login = document.querySelector('input[name=login]')
	if (login.value.length < 4) {
		login.setCustomValidity('Login too short')
		return;
	}
	fetch('/api/exists/' + login.value)
	.then(response => response.json())
	.then(exists => {
		console.debug(`Login already exists: ${exists}`)
		login.setCustomValidity(exists ? 'User already exists' : '')
	})
}


function verifyAndSetSuggestion(given, family, len) {
	given += Math.random().toString(36).substr(10);
	const suggestion = given.substr(0, len) + family;
	console.debug(`Generated login suggestion: ${suggestion}`)
	fetch('/api/exists/' + suggestion)
	.then(response => response.json())
	.then(exists => {
		if (exists) {
			verifyAndSetSuggestion(given, family, len + 1)
		} else {
			const login = document.querySelector('input[name=login]')
			console.debug(`Suggesting login ${suggestion}`)
			login.value = suggestion
		}
	})
}


function suggestLogin() {
	const given = document.querySelector('input[name=name_given]').value.toLowerCase()
	const family = document.querySelector('input[name=name_family]').value.toLowerCase()
	if (given && family) {
		verifyAndSetSuggestion(given, family, 1)
	}
}


function validatePassword() {
	const password = document.querySelector('input[name=password]')
	const password_confirm = document.querySelector('input[name=password_confirm]')
	password_confirm.setCustomValidity(
		password.value != password_confirm.value
		? "Passwords Don't Match"
		: '');
}

addEventListener("DOMContentLoaded", (event) => {
	// Verify passwords match
	const password = document.querySelector('input[name=password]')
	const password_confirm = document.querySelector('input[name=password_confirm]')
	if (password && password_confirm) {
		password.onchange = validatePassword;
		password_confirm.onkeyup = validatePassword;
	}

	// Check that login does not already exist
	const login = document.querySelector('input[name=login]')
	login?.addEventListener('keyup', validateLogin)

	// Suggest login name
	const given = document.querySelector('input[name=name_given]')
	const family = document.querySelector('input[name=name_family]')
	if (given && family) {
		given.onchange = suggestLogin;
		family.onchange = suggestLogin;
	}
});
