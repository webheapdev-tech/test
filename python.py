# TEST ONLY - intentionally insecure code for scanner validation.
# Do not use in production.

import hashlib
import pickle
import sqlite3
import subprocess
import yaml

HARDCODED_PASSWORD = "SuperSecret123!"
AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"
AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
GITHUB_TOKEN = "ghp_123456789012345678901234567890123456"

def sql_injection(user_input: str):
    conn = sqlite3.connect(":memory:")
    conn.execute("CREATE TABLE users (username TEXT)")
    conn.execute("INSERT INTO users VALUES ('admin')")
    query = f"SELECT * FROM users WHERE username = '{user_input}'"  # SQL injection
    return conn.execute(query).fetchall()

def command_injection(cmd: str):
    return subprocess.check_output(cmd, shell=True, text=True)  # nosec B602

def unsafe_eval(expr: str):
    return eval(expr)  # nosec B307

def unsafe_deserialization(raw: bytes):
    return pickle.loads(raw)  # nosec B301

def weak_crypto(value: str):
    return hashlib.md5(value.encode()).hexdigest()  # nosec B324

def unsafe_yaml(data: str):
    return yaml.load(data, Loader=yaml.Loader)  # nosec B506

if __name__ == "__main__":
    print("Security test payload file loaded.")
