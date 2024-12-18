from flask import Flask, request, redirect, url_for, render_template, jsonify, make_response
import requests
import os
import json
import secrets
from redis import Redis
from urllib.parse import urlparse

app = Flask(__name__)

# Google OAuth 2.0 credentials
CLIENT_ID = os.environ.get("CLIENT_ID")
CLIENT_SECRET = os.environ.get("CLIENT_SECRET")
REDIRECT_URI = os.environ.get("REDIRECT_URI")

# Vercel KV setup
REDIS_URL = os.environ.get("REDIS_URL")
if REDIS_URL:
    url = urlparse(REDIS_URL)
    redis_client = Redis(host=url.hostname, port=url.port, password=url.password, ssl=True)
else:
    print("REDIS_URL not found in environment variables")
    redis_client = None

# Helper functions for key management
def save_key(email, key):
    if redis_client:
        redis_client.set(email, key)

def load_key(email):
    if redis_client:
        return redis_client.get(email)
    return None

def delete_key(email):
    if redis_client:
        redis_client.delete(email)

@app.route("/")
def index():
    if request.cookies.get("user"):
        return redirect(url_for("dashboard"))
    return render_template("index.html")

@app.route("/signin")
def signin():
    google_auth_url = (
        f"https://accounts.google.com/o/oauth2/v2/auth"
        f"?response_type=code"
        f"&client_id={CLIENT_ID}"
        f"&redirect_uri={REDIRECT_URI}"
        f"&scope=openid%20email"
        f"&access_type=offline"
    )
    return redirect(google_auth_url)

@app.route("/dashboard")
def dashboard():
    email = request.cookies.get("user")
    user_key = load_key(email)

    if user_key:
        return render_template("dashboard.html", key=user_key.decode('utf-8'))
    else:
        return redirect(url_for("error"))

@app.route("/regenerate_key", methods=["POST"])
def regenerate_key():
    email = request.cookies.get("user")
    new_key = secrets.token_hex(16)
    save_key(email, new_key)
    return redirect("/dashboard?key_regenerated=true")

@app.route("/oauth2callback")
def oauth2callback():
    # Exchange the authorization code for tokens
    code = request.args.get("code")
    token_url = "https://oauth2.googleapis.com/token"
    token_data = {
        "code": code,
        "client_id": CLIENT_ID,
        "client_secret": CLIENT_SECRET,
        "redirect_uri": REDIRECT_URI,
        "grant_type": "authorization_code",
    }
    token_response = requests.post(token_url, data=token_data).json()

    # Get user info
    user_info_url = "https://www.googleapis.com/oauth2/v1/userinfo"
    headers = {"Authorization": f"Bearer {token_response['access_token']}"}
    user_info = requests.get(user_info_url, headers=headers).json()

    email = user_info.get("email")
    domain = email.split("@")[1] if email else None

    if domain == "pinewood.edu":
        user_key = load_key(email)

        if not user_key:
            new_key = secrets.token_hex(16)
            save_key(email, new_key)

        response = make_response(redirect(url_for("dashboard")))
        response.set_cookie("user", email, httponly=True, secure=True)
        return response

    else:
        return redirect(url_for("error"))

@app.route("/error")
def error():
    return render_template("error.html"), 403

@app.route('/logout')
def logout():
    response = make_response(redirect(url_for("index")))
    response.set_cookie("user", "", expires=0)
    return response

if __name__ == "__main__":
    app.run(debug=True, port=8080)
