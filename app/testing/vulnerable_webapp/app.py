from __future__ import annotations

import logging
import os
from pathlib import Path

from flask import Flask, jsonify, redirect, render_template_string, request


LOG_PATH = Path(os.getenv("AEGISAI_WEBAPP_LOG", "/home/legesya/test-project/logs/vulnerable_webapp.log"))
LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
logging.basicConfig(
    filename=str(LOG_PATH),
    level=logging.INFO,
    format="%(asctime)s | %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S",
)

app = Flask(__name__)

USERS = {"admin": "admin123", "demo": "demo123", "soc": "soc123"}

TEMPLATE = """
<!doctype html>
<html>
  <head><title>AegisAI Vulnerable Login</title></head>
  <body>
    <h1>Vulnerable Demo Login</h1>
    <form method="post" action="/login">
      <input type="text" name="username" placeholder="username">
      <input type="password" name="password" placeholder="password">
      <button type="submit">Login</button>
    </form>
  </body>
</html>
"""


def log_attempt(ip: str, method: str, path: str, username: str, status: int) -> None:
    logging.info("%s | %s | %s | username=%s | status=%s", ip, method, path, username, status)


@app.get("/")
def index():
    return render_template_string(TEMPLATE)


@app.post("/login")
def login():
    username = request.form.get("username", "")
    password = request.form.get("password", "")
    expected = USERS.get(username)
    status = 200 if expected and expected == password else 401
    log_attempt(request.remote_addr or "unknown", request.method, request.path, username, status)
    if status == 200:
        return jsonify({"status": "ok", "message": f"Welcome {username}"})
    return jsonify({"status": "error", "message": "Invalid credentials"})


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False)
