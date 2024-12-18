from flask import Flask, request, redirect, url_for, render_template, jsonify, make_response
import requests
import os
import json
import secrets

app = Flask(__name__)

# Google OAuth 2.0 credentials
CLIENT_ID = os.environ.get("CLIENT_ID")
CLIENT_SECRET = os.environ.get("CLIENT_SECRET")
REDIRECT_URI = os.environ.get("REDIRECT_URI")

# Check if keys.json exists, create it if not
if not os.path.exists("keys.json"):
  with open("keys.json", "w") as f:
    f.write("[]")

# Helper to save keys
def save_keys(data):
  with open("keys.json", "w") as f:
    json.dump(data, f)

def load_keys():
  with open("keys.json", "r") as f:
    return json.load(f)

@app.route("/")
def index():
  # Placeholder homepage, add your sign-in button here
  if request.cookies.get("user"):
    return redirect(url_for("dashboard"))
  return render_template("index.html")  # Add a Google Sign-In button in index.html

@app.route("/signin")
def signin():
  # Redirect to Google's OAuth 2.0 authorization endpoint
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
  # Check if the user has a valid key
  keys = load_keys()
  user_key = next((k for k in keys if k["email"] == request.cookies.get("user")), None)

  if user_key:
    return render_template("dashboard.html", key=user_key["key"])
  else:
    return redirect(url_for("error"))
  
@app.route("/regenerate_key", methods=["POST"])
def regenerate_key():
  # Regenerate the user's key
  keys = load_keys()
  user_key = next((k for k in keys if k["email"] == request.cookies.get("user")), None)
  if user_key:
    user_key["key"] = secrets.token_hex(16)
    save_keys(keys)
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
    # Check if the user already has a key
    keys = load_keys()
    user_key = next((k for k in keys if k["email"] == email), None)

    if not user_key:
      # Generate a new key
      new_key = secrets.token_hex(16)
      keys.append({"email": email, "key": new_key})
      save_keys(keys)
      user_key = {"key": new_key}

    # Set a cookie with some secure value
    response = make_response(redirect(url_for("dashboard")))
    response.set_cookie("user", email, httponly=True, secure=True)
    return response

  else:
    return redirect(url_for("error"))

@app.route("/error")
def error():
  # Render an error page
  return render_template("error.html"), 403

@app.route('/logout')
def logout():
  # Clear the user cookie
  response = make_response(redirect(url_for("index")))
  response.set_cookie("user", "", expires=0)
  return response

if __name__ == "__main__":
  app.run(debug=True, port=8080)
