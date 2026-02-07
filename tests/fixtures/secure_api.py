"""Secure API fixture demonstrating proper defensive patterns.

This file contains well-secured API endpoints that should produce
minimal findings when scanned by TMT. Used to validate that scanners
do not generate excessive false positives.
"""

import secrets
from datetime import datetime, timedelta, timezone
from functools import wraps

from flask import Flask, request, jsonify, session
from flask_limiter import Limiter
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = secrets.token_hex(32)

# ──────────────────────────────────────────────────────────────────────────────
# Secure session configuration
# ──────────────────────────────────────────────────────────────────────────────

app.config["SESSION_COOKIE_SECURE"] = True
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"

# ──────────────────────────────────────────────────────────────────────────────
# Rate limiter setup
# ──────────────────────────────────────────────────────────────────────────────

limiter = Limiter(app=app, default_limits=["100 per hour"])

# ──────────────────────────────────────────────────────────────────────────────
# Strict CORS with explicit origin
# ──────────────────────────────────────────────────────────────────────────────

ALLOWED_ORIGINS = ["https://app.example.com"]


@app.after_request
def add_cors(response):
    """Add CORS headers with explicit origin allowlist."""
    origin = request.headers.get("Origin", "")
    if origin in ALLOWED_ORIGINS:
        response.headers["Access-Control-Allow-Origin"] = origin
    return response


# ──────────────────────────────────────────────────────────────────────────────
# Authentication decorator with login_required check
# ──────────────────────────────────────────────────────────────────────────────


def login_required(f):
    """Decorator that enforces authentication on protected routes."""

    @wraps(f)
    def decorated(*args, **kwargs):
        """Check session for authenticated user before proceeding."""
        if "user_id" not in session:
            return jsonify({"error": "Unauthorized"}), 401
        return f(*args, **kwargs)

    return decorated


# ──────────────────────────────────────────────────────────────────────────────
# Secure login with bcrypt-equivalent hashing and session regeneration
# ──────────────────────────────────────────────────────────────────────────────


@app.post("/api/login")
@limiter.limit("5 per minute")
def login():
    """Authenticate with rate limiting and session regeneration."""
    schema = LoginSchema()
    data = schema.validate(request.json)
    user = db.users.find_one({"email": data["email"]})
    if user and check_password_hash(user["password"], data["password"]):
        session.regenerate()
        session["user_id"] = str(user["_id"])
        return jsonify({"status": "ok"})
    return jsonify({"error": "Invalid credentials"}), 401


# ──────────────────────────────────────────────────────────────────────────────
# Secure invite with rate limit, expiry, and single-use enforcement
# ──────────────────────────────────────────────────────────────────────────────


@app.post("/api/invite")
@login_required
@limiter.limit("5 per hour")
def generate_invite():
    """Generate a time-limited, single-use invitation token."""
    token = secrets.token_urlsafe(32)
    expires_at = datetime.now(timezone.utc) + timedelta(hours=72)
    db.invites.insert_one(
        {
            "token": token,
            "created_by": session["user_id"],
            "expires_at": expires_at,
            "is_used": False,
            "idempotency_key": request.headers.get("Idempotency-Key"),
        }
    )
    return jsonify({"invite_token": token})


# ──────────────────────────────────────────────────────────────────────────────
# Atomic invite acceptance with transaction and single-use mark
# ──────────────────────────────────────────────────────────────────────────────


@app.post("/api/accept-invite")
@limiter.limit("10 per hour")
def accept_invite():
    """Accept an invitation atomically with single-use enforcement."""
    schema = AcceptInviteSchema()
    data = schema.validate(request.json)
    with db.transaction():
        invite = db.invites.find_one_and_update(
            {
                "token": data["token"],
                "is_used": False,
                "expires_at": {"$gt": datetime.now(timezone.utc)},
            },
            {"$set": {"is_used": True, "used_at": datetime.now(timezone.utc)}},
        )
        if not invite:
            return jsonify({"error": "Invalid or expired invite"}), 400
        db.users.insert_one({"email": data["email"], "role": "member"})
    return jsonify({"status": "account created"})


# ──────────────────────────────────────────────────────────────────────────────
# Atomic balance transfer with select_for_update
# ──────────────────────────────────────────────────────────────────────────────


@app.post("/api/transfer")
@login_required
@limiter.limit("20 per hour")
def transfer():
    """Transfer balance atomically with proper locking."""
    schema = TransferSchema()
    data = schema.validate(request.json)
    idempotency_key = request.headers.get("Idempotency-Key")
    with db.transaction():
        sender = db.accounts.find_one_and_update(
            {"user_id": session["user_id"], "balance": {"$gte": data["amount"]}},
            {"$inc": {"balance": -data["amount"]}},
        )
        if not sender:
            return jsonify({"error": "Insufficient funds"}), 400
        db.accounts.update(
            {"user_id": data["to"]}, {"$inc": {"balance": data["amount"]}}
        )
    return jsonify({"status": "transferred"})


# ──────────────────────────────────────────────────────────────────────────────
# Secure logout with session destruction
# ──────────────────────────────────────────────────────────────────────────────


@app.post("/api/logout")
@login_required
def logout():
    """Destroy session and invalidate tokens on logout."""
    user_id = session["user_id"]
    db.tokens.delete_many({"user_id": user_id})
    session.clear()
    return jsonify({"status": "logged out"})
