import os
import subprocess
import pickle

# Hardcoded secret — semgrep p/secrets should flag
password = "supersecret123"
api_key = "AKIAIOSFODNN7EXAMPLE"

# Dangerous eval with user input — semgrep p/security-audit
user_input = input("cmd: ")
x = eval(user_input)

# Subprocess with shell and user input — semgrep python.lang.security.audit.dangerous-subprocess
subprocess.run(user_input, shell=True)

# SQL injection with string concat — semgrep
query = "SELECT * FROM users WHERE id = " + user_input

# Unsafe deserialization
data = pickle.loads(b"test")

# Additional file for multi-file proof
