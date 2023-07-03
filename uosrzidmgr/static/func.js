function validateLogin() {
	const login = document.querySelector('input[name=login]')
	if (login.value.length < 4) {
		login.setCustomValidity('Login too short')
		return;
	}
	fetch('/api/exists/' + login.value)
	.then(response => response.json())
	.then(exists => {
		login.setCustomValidity(exists ? 'User already exists' : '')
	})
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
	const password = document.querySelector('input[name=password]')
	const password_confirm = document.querySelector('input[name=password_confirm]')
	if (password && password_confirm) {
		password.onchange = validatePassword;
		password_confirm.onkeyup = validatePassword;
	}

	const login = document.querySelector('input[name=login]')
	login?.addEventListener('keyup', validateLogin)
});
