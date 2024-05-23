const SEND_BUTTON = 'send-button';
const DISABLED = 'disabled';
const HIDDEN = 'hidden';
const EMAIL = 'email';
const PHONE = 'phone';
const VERIFICATION_METHOD = 'verification-method';
const VERIFICATION_STEP = 'verification-step';
const VERIFICATION_CODE = 'verification-code';
const INPUT_FIELD = 'input-field';
const INITIAL_STEP = 'initial-step';
const ERROR = 'error';
const RESULT = 'result';

const EMAIL_REGEX = new RegExp(/.+@.+/);

let verificationData = {};
let verificationCodeLength = 6;

function isValidPhoneNumber(tel) {
  const value = tel.replace(/\D/g, '');
  return value.length >= 10;
}

function isValidEmail(email) {
  return EMAIL_REGEX.test(email);
}

function isValidInput(type, value) {
  if (type == PHONE && isValidPhoneNumber(value)) {
    return true;
  } else if (type == EMAIL && isValidEmail(value)) {
    return true;
  }

  return false;
}

function toggleSendButtonState(event) {
  const id = event.target.id;
  if (id == EMAIL || id == PHONE) {
    const value = event.target.value;

    const button = document.getElementById(SEND_BUTTON);
    if (isValidInput(id, value)) {
      button.disabled = false;
      button.classList.remove(DISABLED);
    } else {
      button.disabled = true;
      button.classList.add(DISABLED);
    }
  }
}

function showInputField() {
  const method = document.getElementById(VERIFICATION_METHOD).value;
  const inputFieldDiv = document.getElementById(INPUT_FIELD);
  inputFieldDiv.innerHTML = '';

  if (method === EMAIL) {
    inputFieldDiv.innerHTML = `<input type="email" id="${EMAIL}" placeholder="Enter your email">`;
  } else if (method === PHONE) {
    inputFieldDiv.innerHTML = `<input type="tel" id="${PHONE}" placeholder="Enter your phone number" oninput="formatPhoneNumber(event)" maxlength="16">`;
  }

  const button = document.getElementById(SEND_BUTTON);
  button.disabled = true;
  button.classList.add(DISABLED);

  document.getElementById(RESULT).classList.add(HIDDEN);
}

function formatPhoneNumber(event) {
  const input = event.target;
  const value = input.value.replace(/\D/g, '');
  let formattedValue = '';

  if (value.length > 0) {
    formattedValue += '(' + value.substring(0, 3);
  }
  if (value.length > 3) {
    formattedValue += ') ' + value.substring(3, 6);
  }
  if (value.length > 6) {
    formattedValue += '-' + value.substring(6, 10);
  }

  input.value = formattedValue;
}

function formatVerificationCode(event) {
  const input = event.target;
  const value = input.value.replace(/\D/g, '').substring(0, verificationCodeLength);
  input.value = value;
}

function sendVerification() {
  const method = document.getElementById(VERIFICATION_METHOD).value;
  let value;
  if (method === EMAIL) {
    value = document.getElementById(EMAIL).value;
  } else if (method === PHONE) {
    value = document.getElementById(PHONE).value;
  }

  if (!value) {
    displayMessage('Please enter a valid ' + method, true);
    return;
  }

  toggleLoading(true);

  verificationData.method = method;
  verificationData.value = value;
  verificationData.csrf = document.getElementById('csrf').value;

  fetch('/verify', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json'
    },
    body: JSON.stringify(verificationData)
  })
    .then(response => response.json().then(data => ({
      status: response.status,
      body: data
    })))
    .then(({ status, body }) => {
      if (status === 201) {
        verificationCodeLength = body.code_length || 6;
        verificationData.csrf = body.csrf;

        document.getElementById(INITIAL_STEP).classList.add(HIDDEN);
        document.getElementById(VERIFICATION_STEP).classList.remove(HIDDEN);
        document.getElementById('verification-message').innerText =
          `A verification code has been sent to your ${method}. Please enter the ${verificationCodeLength}-digit code below.`;
        displayMessage(body.message, false);

        // Add input listener for verification code
        const codeInput = document.getElementById(VERIFICATION_CODE);
        codeInput.addEventListener('input', formatVerificationCode);
      } else {
        displayMessage(body.message, true);
      }
      toggleLoading(false);
    })
    .catch(error => {
      console.log(error);
      displayMessage('Error sending verification. Please try again.', true);
      toggleLoading(false);
    });
}

function verifyCode() {
  toggleLoading(true);

  const code = document.getElementById(VERIFICATION_CODE).value;

  if (code.length !== verificationCodeLength) {
    displayMessage(`Please enter the ${verificationCodeLength}-digit code.`, true);
    toggleLoading(false);
    return;
  }

  const payload = {
    ...verificationData,
    code: code
  };

  fetch('/verify', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json'
    },
    body: JSON.stringify(payload)
  })
    .then(response => response.json().then(data => ({
      status: response.status,
      body: data
    })))
    .then(({ status, body }) => {
      if (status === 200) {
        displayMessage(body.message, false);
        document.getElementsByTagName('h1')[0].innerText = 'Access granted';
        document.title = 'Access granted';
        document.querySelector('.container').innerHTML = '<h1>Access granted</h1>';
      } else {
        displayMessage(body.message, true);
      }
      toggleLoading(false);
    })
    .catch(error => {
      console.log(error);
      displayMessage('Error verifying code. Please try again.', true);
      toggleLoading(false);
    });
}

function displayMessage(message, isError) {
  const resultDiv = document.getElementById(RESULT);
  resultDiv.innerText = message;
  if (isError) {
    resultDiv.classList.add(ERROR);
  } else {
    resultDiv.classList.remove(ERROR);
  }
  resultDiv.classList.remove(HIDDEN);
}

function toggleLoading(isLoading) {
  const formElements = document.querySelectorAll('select, input, button');
  formElements.forEach(element => {
    element.disabled = isLoading;
    element.classList.toggle(DISABLED, isLoading);
  });
  document.getElementById('spinner').classList.toggle(HIDDEN, !isLoading);
}

document.addEventListener("DOMContentLoaded", function() {
  const method = document.getElementById(VERIFICATION_METHOD).value;
  if (method) {
    showInputField();
  }

  document.addEventListener('keydown', function(event) {
    if (event.key === 'Enter') {
      if (!document.getElementById(INITIAL_STEP).classList.contains(HIDDEN)) {
        sendVerification();
      } else if (!document.getElementById(VERIFICATION_STEP).classList.contains(HIDDEN)) {
        verifyCode();
      }
    }
  });

  document.addEventListener('input', toggleSendButtonState);
  document.addEventListener('change', toggleSendButtonState);

  const codeInput = document.getElementById(VERIFICATION_CODE);
  if (codeInput) {
    codeInput.addEventListener('input', formatVerificationCode);
  }
});
