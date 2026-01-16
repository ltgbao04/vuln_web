#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Small vulnerable demo app that maps directly to the KB testing cases:
- Access_Level_Role_Coverage
- Business_Logic_Tampering
- Forced_Browsing_Auth_Bypass
- IDOR_Parameter_Manipulation
- Session_Fixation
- Session_ID_Predictability

Run locally for manual / automated scanner validation:
    pip install flask
    python temp/vuln_demo_app.py
"""

import base64
import time
from datetime import datetime
from typing import Dict, Optional

from flask import Flask, jsonify, make_response, redirect, render_template_string, request, url_for

app = Flask(__name__)

# Simple in-memory stores
USERS: Dict[str, Dict[str, str]] = {
    "admin": {"password": "admin123", "role": "admin"},
    "moderator": {"password": "mod123", "role": "moderator"},
    "user": {"password": "user123", "role": "user"},
    "alice": {"password": "alice123", "role": "user"},
    "bob": {"password": "bob123", "role": "user"},
}

# session_id -> username (value is intentionally predictable and unrotated)
SESSIONS: Dict[str, str] = {}

# Sample orders for IDOR testing
ORDERS: Dict[str, Dict[str, str]] = {
    "1001": {"owner": "alice", "item": "Basic Plan", "price": "49.99"},
    "1002": {"owner": "bob", "item": "Pro Plan", "price": "99.99"},
    "1003": {"owner": "user", "item": "VIP Ticket", "price": "199.99"},
}


def _new_session_id() -> str:
    """Predictable session value: base64(timestamp)."""

    ts = str(int(time.time()))
    return base64.urlsafe_b64encode(ts.encode()).decode().rstrip("=")


def _current_user() -> Optional[str]:
    """Return username tied to the session cookie."""

    sid = request.cookies.get("sessionid")
    if sid and sid in SESSIONS:
        return SESSIONS[sid]
    return None


@app.route("/", methods=["GET"])
def index():
    """Simple landing page with links to interactive UI and raw API."""

    return render_template_string(
        """
        <html>
        <head>
          <title>RedSwarm Demo App</title>
          <style>
            body { font-family: Arial, sans-serif; margin: 32px; }
            a { display: block; margin: 6px 0; }
            .card { border: 1px solid #ccc; padding: 16px; border-radius: 6px; margin-bottom: 14px; }
          </style>
        </head>
        <body>
          <h1>RedSwarm Test Site</h1>
          <div class="card">
            <h3>Interactive UI</h3>
            <a href="/ui">UI Home</a>
            <a href="/ui/login">Login (sets predictable session cookie)</a>
            <a href="/ui/dashboard">Dashboard (needs login)</a>
            <a href="/ui/admin">Admin Reports (forced browsing target)</a>
            <a href="/ui/order">Order Viewer (IDOR target)</a>
            <a href="/ui/checkout">Checkout (business logic tampering)</a>
            <a href="/ui/role-check">Role Check (access level coverage)</a>
          </div>
          <div class="card">
            <h3>Raw API Endpoints</h3>
            <code>/login</code> (GET sets cookie, POST authenticates)<br/>
            <code>/dashboard</code> (requires login cookie)<br/>
            <code>/admin/reports</code> (forced browsing, no auth check)<br/>
            <code>/api/order/&lt;order_id&gt;</code> (IDOR target)<br/>
            <code>/checkout</code> (business logic tampering)<br/>
            <code>/role-check</code> (role probe)<br/>
          </div>
          <div class="card">
            <h3>Sample Credentials</h3>
            <ul>
              <li>admin / admin123</li>
              <li>moderator / mod123</li>
              <li>user / user123</li>
              <li>alice / alice123</li>
              <li>bob / bob123</li>
            </ul>
          </div>
        </body>
        </html>
        """
    )


@app.route("/login", methods=["GET"])
def login_form():
    """
    GET sets a predictable pre-auth cookie and returns a minimal form.
    Scanner uses this as the baseline for Session Fixation and Session ID Predictability.
    """

    sid = request.cookies.get("sessionid") or _new_session_id()
    resp = make_response(
        """
        <html>
          <body>
            <h2>Demo Login</h2>
            <form action="/login" method="POST">
              <input name="username" value="alice" />
              <input name="password" value="alice123" type="password" />
              <input type="hidden" name="hidden_total" value="100" />
              <input type="hidden" name="price" value="100" />
              <input type="hidden" name="quantity" value="1" />
              <input type="hidden" name="discount" value="0" />
              <button type="submit">Login</button>
            </form>
          </body>
        </html>
        """
    )
    # Deliberately predictable and not rotated
    resp.set_cookie("sessionid", sid, httponly=False)
    return resp


@app.route("/ui/login", methods=["GET", "POST"])
def ui_login():
    """UI login page that mirrors /login behavior and shows the current session id."""

    message = ""
    role = None
    session_id = request.cookies.get("sessionid") or ""

    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        # Reuse API logic
        sid = request.cookies.get("sessionid") or _new_session_id()
        user = USERS.get(username or "", {})
        if not user or user.get("password") != (password or ""):
            message = "❌ Invalid credentials"
            resp = make_response(
                render_template_string(UI_LOGIN_TEMPLATE, message=message, session_id=sid, role=None)
            )
            resp.set_cookie("sessionid", sid, httponly=False)
            return resp

        SESSIONS[sid] = username
        role = user.get("role")
        message = f"✅ Logged in as {username} (role: {role}) – session not rotated"
        resp = make_response(
            render_template_string(UI_LOGIN_TEMPLATE, message=message, session_id=sid, role=role)
        )
        resp.set_cookie("sessionid", sid, httponly=False)
        return resp

    return render_template_string(UI_LOGIN_TEMPLATE, message=message, session_id=session_id, role=role)


@app.route("/login", methods=["POST"])
def login():
    """
    Authenticates user but intentionally reuses the pre-auth session cookie value (session fixation)
    and keeps the predictable format (timestamp base64).
    """

    username = request.form.get("username") or request.json.get("username") if request.is_json else None
    password = request.form.get("password") or request.json.get("password") if request.is_json else None

    sid = request.cookies.get("sessionid") or _new_session_id()
    user = USERS.get(username or "", {})
    if not user or user.get("password") != (password or ""):
        resp = make_response(jsonify({"ok": False, "message": "invalid credentials"}), 401)
        resp.set_cookie("sessionid", sid, httponly=False)
        return resp

    # Do NOT rotate session ID after auth -> session fixation + predictable ID
    SESSIONS[sid] = username  # session id persists
    resp = make_response(
        jsonify(
            {
                "ok": True,
                "message": "logged in without rotating session",
                "sessionid": sid,
                "role": user.get("role"),
            }
        )
    )
    resp.set_cookie("sessionid", sid, httponly=False)
    return resp


@app.route("/dashboard", methods=["GET"])
def dashboard():
    user = _current_user()
    if not user:
        return jsonify({"ok": False, "message": "login required"}), 401
    return jsonify({"ok": True, "message": f"welcome {user}", "time": datetime.utcnow().isoformat()})


@app.route("/ui/dashboard", methods=["GET"])
def ui_dashboard():
    user = _current_user()
    if not user:
        return redirect(url_for("ui_login"))
    return render_template_string(
        """
        <h2>Dashboard</h2>
        <p>Welcome {{ user }}! Time: {{ ts }}</p>
        <a href="/ui">Back</a>
        """,
        user=user,
        ts=datetime.utcnow().isoformat(),
    )


@app.route("/admin/reports", methods=["GET"])
def admin_reports():
    """
    Forced browsing target: intentionally does NOT check authentication.
    Baseline request should include the session cookie; variant without cookie still returns the report.
    """

    report = {
        "title": "Monthly Revenue",
        "generated_at": datetime.utcnow().isoformat(),
        "data": {"total": 123456, "currency": "USD"},
        "note": "No auth enforced - forced browsing vulnerable",
    }
    return jsonify(report)


@app.route("/ui/admin", methods=["GET"])
def ui_admin():
    """UI view for the forced browsing target."""

    report = {
        "title": "Monthly Revenue",
        "generated_at": datetime.utcnow().isoformat(),
        "data": {"total": 123456, "currency": "USD"},
        "note": "No auth enforced - forced browsing vulnerable",
    }
    return render_template_string(
        """
        <h2>Admin Reports (Forced Browsing)</h2>
        <pre>{{ report }}</pre>
        <p><strong>Note:</strong> This page is intentionally exposed without auth.</p>
        <a href="/ui">Back</a>
        """,
        report=report,
    )


@app.route("/api/order/<order_id>", methods=["GET"])
def get_order(order_id: str):
    """
    IDOR target: returns order details without checking ownership.
    Changing the ID reveals other users' orders while authenticated.
    """

    user = _current_user() or "guest"
    order = ORDERS.get(order_id)
    if not order:
        return jsonify({"ok": False, "message": "order not found", "requested_by": user}), 404

    return jsonify(
        {
            "ok": True,
            "order_id": order_id,
            "owner": order.get("owner"),
            "item": order.get("item"),
            "price": order.get("price"),
            "requested_by": user,
            "note": "Ownership not enforced (IDOR)",
        }
    )


@app.route("/ui/order", methods=["GET", "POST"])
def ui_order():
    """UI for IDOR testing."""

    order_data = None
    message = ""
    selected_id = request.form.get("order_id") if request.method == "POST" else "1001"

    if selected_id:
        order = ORDERS.get(selected_id)
        user = _current_user() or "guest"
        if order:
            order_data = {
                "order_id": selected_id,
                "owner": order.get("owner"),
                "item": order.get("item"),
                "price": order.get("price"),
                "requested_by": user,
                "note": "Ownership not enforced (IDOR)",
            }
        else:
            message = f"Order {selected_id} not found (requested by {user})"

    return render_template_string(
        """
        <h2>IDOR Order Viewer</h2>
        <form method="POST">
          <label>Order ID:</label>
          <input name="order_id" value="{{ selected_id }}" />
          <button type="submit">Fetch</button>
        </form>
        {% if message %}<p>{{ message }}</p>{% endif %}
        {% if order_data %}
        <pre>{{ order_data }}</pre>
        {% endif %}
        <p>Try IDs 1001, 1002, 1003 while logged in as one user to view others' data.</p>
        <a href="/ui">Back</a>
        """,
        order_data=order_data,
        selected_id=selected_id,
        message=message,
    )


@app.route("/checkout", methods=["POST"])
def checkout():
    """
    Business logic tampering target:
    - Accepts client-supplied price/quantity/discount/total with no server validation.
    - Hidden fields (from /login form) can be modified by the scanner.
    """

    price = float(request.form.get("price", request.json.get("price", 0)) if request.form or request.is_json else 0)
    qty = float(request.form.get("quantity", request.json.get("quantity", 1)) if request.form or request.is_json else 1)
    discount = float(request.form.get("discount", request.json.get("discount", 0)) if request.form or request.is_json else 0)
    client_total = request.form.get("total") or (request.json.get("total") if request.is_json else None)
    hidden_total = request.form.get("hidden_total")

    # Vulnerable: trust client-side totals/discounts
    if client_total:
        final_total = float(client_total)
    else:
        final_total = max(0, price * qty * (1 - (discount / 100)))

    response = {
        "ok": True,
        "message": "order confirmed",
        "price": price,
        "quantity": qty,
        "discount": discount,
        "final_total": final_total,
        "hidden_total": hidden_total,
        "note": "Server accepted client totals without validation",
    }
    return jsonify(response)


@app.route("/ui/checkout", methods=["GET", "POST"])
def ui_checkout():
    """UI for business logic tampering with price/quantity/discount/total."""

    result = None
    if request.method == "POST":
        # Submit to the same vulnerable logic
        with app.test_request_context():
            # Build a fake request to reuse checkout logic directly is complex; instead call endpoint.
            pass

    return render_template_string(
        """
        <h2>Checkout (Business Logic Tampering)</h2>
        <form method="POST" action="/checkout">
          <label>Price:</label><input name="price" value="100" /><br/>
          <label>Quantity:</label><input name="quantity" value="1" /><br/>
          <label>Discount (%):</label><input name="discount" value="0" /><br/>
          <label>Total (override):</label><input name="total" value="100" /><br/>
          <label>Hidden Total:</label><input name="hidden_total" value="100" /><br/>
          <button type="submit">Submit (POST /checkout)</button>
        </form>
        <p>Tip: Change price=0.01, quantity=-1, discount=100, or total=1 to observe acceptance.</p>
        <a href="/ui">Back</a>
        """,
        result=result,
    )


@app.route("/role-check", methods=["GET"])
def role_check():
    """
    Simple endpoint to exercise credentials of different privilege levels.
    The endpoint itself is permissive; the scanner uses provided credentials to probe coverage.
    """

    user = _current_user()
    role = USERS.get(user or "", {}).get("role", "guest")
    return jsonify({"ok": True, "user": user, "role": role, "timestamp": int(time.time())})


@app.route("/ui/role-check", methods=["GET"])
def ui_role_check():
    """UI for access level role coverage probing."""

    user = _current_user()
    role = USERS.get(user or "", {}).get("role", "guest")
    return render_template_string(
        """
        <h2>Role Check</h2>
        <p>User: {{ user }}</p>
        <p>Role: {{ role }}</p>
        <p>Timestamp: {{ ts }}</p>
        <p>Login with different users to see role changes (admin/moderator/user/...)</p>
        <a href="/ui">Back</a>
        """,
        user=user,
        role=role,
        ts=int(time.time()),
    )


# Simple UI home
@app.route("/ui", methods=["GET"])
def ui_home():
    return redirect(url_for("index"))


# Template for login UI (kept small and inline)
UI_LOGIN_TEMPLATE = """
<h2>Login (Session Fixation / Predictable ID)</h2>
<p>{{ message }}</p>
<form method="POST">
  <label>Username:</label><input name="username" value="alice" /><br/>
  <label>Password:</label><input name="password" value="alice123" type="password" /><br/>
  <button type="submit">Login</button>
</form>
<p>Current sessionid (predictable, not rotated): <code>{{ session_id }}</code></p>
{% if role %}<p>Role: {{ role }}</p>{% endif %}
<a href="/ui">Back</a>
"""


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8000, debug=False)

