# TEST ONLY - intentionally insecure code for scanner validation.
# Do not use in production.

import hashlib
import pickle
import subprocess
import sqlite3

HARDCODED_PASSWORD = "SuperSecret123!"  # hardcoded secret


def sql_injection(user_input: str):
    conn = sqlite3.connect(":memory:")
    query = f"SELECT * FROM users WHERE username = '{user_input}'"  # SQL injection
# Replace string-formatted SQL with parameterized query
query = "SELECT * FROM users WHERE username = ?"
cursor.execute(query, (user_input,))


def command_injection(cmd: str):
    return subprocess.check_output(cmd, shell=True, text=True)  # nosec B602


def unsafe_eval(expr: str):
    return eval(expr)  # nosec B307


def unsafe_deserialization(raw: bytes):
    return pickle.loads(raw)  # nosec B301


def weak_crypto(value: str):
    return hashlib.md5(value.encode()).hexdigest()  # nosec B324


if __name__ == "__main__":
    print("Security test payload file loaded.")
