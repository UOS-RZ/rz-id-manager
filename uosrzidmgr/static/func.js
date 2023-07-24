function validateLogin() {
  const login = document.querySelector("input[name=login]");
  if (login.value.length < 4) {
    login.setCustomValidity("Login too short");
    return;
  }
  fetch("/api/exists/" + login.value)
    .then((response) => response.json())
    .then((exists) => {
      console.debug(`Login already exists: ${exists}`);
      login.setCustomValidity(exists ? "User already exists" : "");
    });
}

function validateManagementLogin() {
  const management_login = document.querySelector(
    "input[name=management_login]",
  );
  if (management_login.value.length < 2) {
    management_login.setCustomValidity("Login too short");
    return;
  }
  fetch("/api/exists/" + management_login.value)
    .then((response) => response.json())
    .then((exists) => {
      console.debug(`Login does exists: ${exists}`);
      management_login.setCustomValidity(exists ? "" : "User does not exists");
    });
}

function verifyAndSetSuggestion(given, family, len) {
  given += Math.random().toString(36).substr(10);
  const suggestion = given.substr(0, len) + family;
  console.debug(`Generated login suggestion: ${suggestion}`);
  fetch("/api/exists/" + suggestion)
    .then((response) => response.json())
    .then((exists) => {
      if (exists) {
        verifyAndSetSuggestion(given, family, len + 1);
      } else {
        const login = document.querySelector("input[name=login]");
        console.debug(`Suggesting login ${suggestion}`);
        login.value = suggestion;
        validateLogin();
      }
    });
}

function suggestLogin() {
  const given = document
    .querySelector("input[name=name_given]")
    .value.toLowerCase()
    .replace(/[^a-z]/g, "");
  const family = document
    .querySelector("input[name=name_family]")
    .value.toLowerCase()
    .replace(/[^a-z]/g, "");
  if (given && family) {
    verifyAndSetSuggestion(given, family, 1);
  }
}

function validatePassword() {
  const password = document.querySelector("input[name=password]");
  const password_confirm = document.querySelector(
    "input[name=password_confirm]",
  );
  password_confirm.setCustomValidity(
    password.value != password_confirm.value ? "Passwords Don't Match" : "",
  );
}

function updateCity(post_code_field, ciry_field) {
  const post_code = document.querySelector(`input[name=${post_code_field}]`);
  const city = document.querySelector(`input[name=${ciry_field}]`);
  const name = zipcodes[post_code.value];
  if (name && city) {
    city.value = name;
  }
}

function updateWorkCity() {
  updateCity('work_post_code', 'work_city')
}

function updatePrivateCity() {
  updateCity('private_post_code', 'private_city')
}

addEventListener("DOMContentLoaded", () => {
  // Verify passwords match
  const password = document.querySelector("input[name=password]");
  const password_confirm = document.querySelector(
    "input[name=password_confirm]",
  );
  if (password && password_confirm) {
    password.onchange = validatePassword;
    password_confirm.onkeyup = validatePassword;
  }

  // Check that login does not already exist
  const login = document.querySelector("input[name=login]");
  login?.addEventListener("keyup", validateLogin);
  login?.addEventListener("change", validateLogin);

  // Check that the management login exists
  const management_login = document.querySelector(
    "input[name=management_login]",
  );
  management_login?.addEventListener("keyup", validateManagementLogin);
  management_login?.addEventListener("change", validateManagementLogin);

  // Suggest login name
  const given = document.querySelector("input[name=name_given]");
  const family = document.querySelector("input[name=name_family]");
  if (given && family) {
    given.onchange = suggestLogin;
    family.onchange = suggestLogin;
  }

  // Complete invite URL
  const invite_link = document.getElementById("invite_link");
  if (invite_link) {
    invite_link.innerText =
      window.location.origin + invite_link.getAttribute("data-link");
  }

  // Mark required fields
  for (let elem of document.querySelectorAll("*[required]")) {
    elem.previousElementSibling.innerText += " *";
  }

  // Turn postal code into city
  const work_post_code = document.querySelector( "input[name=work_post_code]");
  work_post_code?.addEventListener("change", updateWorkCity);
  const private_post_code = document.querySelector( "input[name=private_post_code]");
  private_post_code?.addEventListener("change", updatePrivateCity);
});
