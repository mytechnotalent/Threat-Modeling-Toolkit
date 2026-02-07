"""Vulnerable API fixture for testing TMT scanner detection capabilities.

This file intentionally contains security vulnerabilities across all
categories: replay attacks, race conditions, token abuse, auth/session
issues, and API route problems. Used exclusively for testing.

WARNING: This code is intentionally insecure. Never deploy in production.
"""

import hashlib
import random
import uuid

from flask import Flask, request, jsonify, session

app = Flask(__name__)
app.secret_key = "hardcoded-secret-key"

# ──────────────────────────────────────────────────────────────────────────────
# Global mutable state without synchronization (race condition + shared state)
# ──────────────────────────────────────────────────────────────────────────────

user_balances = {}
active_coupons = {}


# ──────────────────────────────────────────────────────────────────────────────
# Insecure session configuration
# ──────────────────────────────────────────────────────────────────────────────

app.config["SESSION_COOKIE_SECURE"] = False
app.config["SESSION_COOKIE_HTTPONLY"] = False


# ──────────────────────────────────────────────────────────────────────────────
# Overly permissive CORS
# ──────────────────────────────────────────────────────────────────────────────


@app.after_request
def add_cors(response):
    """Add wildcard CORS headers to every response."""
    response.headers["Access-Control-Allow-Origin"] = "*"
    return response


# ──────────────────────────────────────────────────────────────────────────────
# Login without session regeneration, weak password hash, no brute force protection
# ──────────────────────────────────────────────────────────────────────────────


@app.post("/api/login")
def login():
    """Authenticate a user with email and password."""
    data = request.json
    email = data["email"]
    password_hash = hashlib.md5(data["password"].encode()).hexdigest()
    user = db.users.find_one({"email": email, "password": password_hash})
    if user:
        session["user_id"] = str(user["_id"])
        return jsonify({"status": "ok"})
    return jsonify({"error": str("Invalid credentials")}), 401


# ──────────────────────────────────────────────────────────────────────────────
# Token generation: predictable, no expiry, no rate limit
# ──────────────────────────────────────────────────────────────────────────────


@app.post("/api/invite")
def generate_invite():
    """Generate an invitation token for a new user."""
    token = str(uuid.uuid1())
    db.invites.insert_one(
        {
            "token": token,
            "created_by": session.get("user_id"),
        }
    )
    return jsonify({"invite_token": token})


# ──────────────────────────────────────────────────────────────────────────────
# Invite acceptance without single-use enforcement (token reuse + replay)
# ──────────────────────────────────────────────────────────────────────────────


@app.post("/api/accept-invite")
def accept_invite():
    """Accept an invitation using a token."""
    token = request.json["token"]
    invite = db.invites.find_one({"token": token})
    if not invite:
        return jsonify({"error": "Invalid invite"}), 400
    new_user = {"email": request.json["email"], "role": "member"}
    db.users.insert_one(new_user)
    return jsonify({"status": "account created"})


# ──────────────────────────────────────────────────────────────────────────────
# Balance transfer with race condition (non-atomic read-modify-write)
# ──────────────────────────────────────────────────────────────────────────────


@app.post("/api/transfer")
def transfer():
    """Transfer balance between user accounts."""
    data = request.json
    sender = db.accounts.find_one({"user_id": data["from"]})
    if sender["balance"] >= data["amount"]:
        db.accounts.update(
            {"user_id": data["from"]},
            {"$set": {"balance": sender["balance"] - data["amount"]}},
        )
        db.accounts.update(
            {"user_id": data["to"]},
            {"$set": {"balance": sender["balance"] + data["amount"]}},
        )
    return jsonify({"status": "transferred"})


# ──────────────────────────────────────────────────────────────────────────────
# Coupon redemption with race condition (TOCTOU)
# ──────────────────────────────────────────────────────────────────────────────


@app.post("/api/redeem-coupon")
def redeem_coupon():
    """Redeem a promotional coupon code."""
    code = request.json["code"]
    coupon = db.coupons.find_one({"code": code, "is_used": False})
    if coupon:
        apply_discount(coupon["discount"])
        db.coupons.update({"code": code}, {"$set": {"is_used": True}})
        return jsonify({"status": "redeemed"})
    return jsonify({"error": "Invalid coupon"}), 400


# ──────────────────────────────────────────────────────────────────────────────
# Admin endpoint without role check
# ──────────────────────────────────────────────────────────────────────────────


@app.get("/api/admin/users")
def admin_list_users():
    """List all users in the system."""
    users = list(db.users.find())
    return jsonify(users)


# ──────────────────────────────────────────────────────────────────────────────
# Mass assignment vulnerability
# ──────────────────────────────────────────────────────────────────────────────


@app.put("/api/profile")
def update_profile():
    """Update the current user's profile."""
    db.users.update({"_id": session["user_id"]}, {"$set": request.json})
    return jsonify({"status": "updated"})


# ──────────────────────────────────────────────────────────────────────────────
# IDOR: object access without ownership check
# ──────────────────────────────────────────────────────────────────────────────


@app.get("/api/documents/<doc_id>")
def get_document(doc_id):
    """Retrieve a document by its ID."""
    doc = db.documents.find_one({"_id": doc_id})
    return jsonify(doc)


# ──────────────────────────────────────────────────────────────────────────────
# Verbose error exposure
# ──────────────────────────────────────────────────────────────────────────────


@app.post("/api/process")
def process_data():
    """Process submitted data."""
    try:
        result = complex_operation(request.json)
        return jsonify(result)
    except Exception as e:
        return jsonify({"error": str(e), "trace": traceback.format_exc()}), 500


# ──────────────────────────────────────────────────────────────────────────────
# Logout that doesn't actually invalidate anything
# ──────────────────────────────────────────────────────────────────────────────


@app.post("/api/logout")
def logout():
    """Log the user out."""
    return jsonify({"status": "logged out"})


# ──────────────────────────────────────────────────────────────────────────────
# Password reset with token but no invalidation after use
# ──────────────────────────────────────────────────────────────────────────────


@app.post("/api/reset-password")
def reset_password():
    """Reset a user's password using a reset token."""
    token = request.json["token"]
    result = verify_token(token)
    if result:
        new_hash = hashlib.sha1(request.json["new_password"].encode()).hexdigest()
        db.users.update({"_id": result["user_id"]}, {"$set": {"password": new_hash}})
        return jsonify({"status": "password reset"})
    return jsonify({"error": "Invalid token"}), 400
