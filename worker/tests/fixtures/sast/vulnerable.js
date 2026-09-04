// Hardcoded secret
const apiKey = "supersecret123";
const awsKey = "AKIAIOSFODNN7EXAMPLE";

// Dangerous eval with user input
const userInput = process.argv[2];
eval(userInput);

// Function constructor
const f = new Function("a", "b", "return a + b");

// Child process with user input — semgrep javascript.lang.security.audit.dangerous-subprocess
const { exec } = require('child_process');
exec(userInput, (err, stdout) => {});

// SQL injection
const query = "SELECT * FROM users WHERE id = " + userInput;

// XSS via innerHTML with user input
document.body.innerHTML = userInput;
