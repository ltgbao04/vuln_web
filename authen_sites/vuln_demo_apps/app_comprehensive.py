#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Comprehensive Vulnerable Demo Application
==========================================
This Flask app demonstrates vulnerabilities for all testing testcases:

1. Session Fixation (SESS-FIX-001) - Session ID not rotated after login
2. Predictable Session ID (SESS-PRED-001) - Weak session identifiers  
3. IDOR Parameter Manipulation (IDOR-001) - Access other users' data
4. Forced Browsing Auth Bypass (FB-001) - No server-side auth check
5. Business Logic Tampering (BL-*) - Price/quantity/discount manipulation
6. Access Level Role Coverage (AC-ROLE-001) - Multi-role system

Run: python app_comprehensive.py
Access: http://localhost:5000

Test users:
- admin:admin123 (privilege_priority: 1)
- moderator:mod123 (privilege_priority: 2)
- user1:user123 (privilege_priority: 3)
- user2:pass456 (privilege_priority: 3)
"""

import base64
import hashlib
import json
import os
import time
from functools import wraps
from flask import Flask, request, jsonify, render_template_string, redirect, url_for, make_response, session, g

app = Flask(__name__)
app.secret_key = 'vulnerable_secret_key_for_demo'

# ============================================================================
# DATABASE SIMULATION
# ============================================================================

# Users database with roles
USERS = {
    'admin': {
        'password': 'admin123',
        'role': 'admin',
        'privilege_priority': 1,
        'email': 'admin@company.com',
        'balance': 10000.00
    },
    'moderator': {
        'password': 'mod123', 
        'role': 'moderator',
        'privilege_priority': 2,
        'email': 'mod@company.com',
        'balance': 5000.00
    },
    'user1': {
        'password': 'user123',
        'role': 'user',
        'privilege_priority': 3,
        'email': 'user1@example.com',
        'balance': 1000.00
    },
    'user2': {
        'password': 'pass456',
        'role': 'user', 
        'privilege_priority': 3,
        'email': 'user2@example.com',
        'balance': 500.00
    }
}

# Orders database for IDOR testing
ORDERS = {
    '1001': {'user': 'user1', 'product': 'Laptop', 'amount': 999.99, 'status': 'completed'},
    '1002': {'user': 'user1', 'product': 'Mouse', 'amount': 49.99, 'status': 'pending'},
    '1003': {'user': 'user2', 'product': 'Keyboard', 'amount': 79.99, 'status': 'completed'},
    '1004': {'user': 'admin', 'product': 'Server', 'amount': 5000.00, 'status': 'processing'},
}

# Profile database for IDOR
PROFILES = {
    '1': {'username': 'admin', 'ssn': '123-45-6789', 'phone': '555-0001', 'address': 'Admin Tower'},
    '2': {'username': 'moderator', 'ssn': '234-56-7890', 'phone': '555-0002', 'address': 'Mod Street'},
    '3': {'username': 'user1', 'ssn': '345-67-8901', 'phone': '555-0003', 'address': '123 User Lane'},
    '4': {'username': 'user2', 'ssn': '456-78-9012', 'phone': '555-0004', 'address': '456 User Ave'},
}

# Products for business logic testing
PRODUCTS = {
    'PROD001': {'name': 'Premium Headphones', 'price': 299.99, 'stock': 50},
    'PROD002': {'name': 'Wireless Mouse', 'price': 49.99, 'stock': 100},
    'PROD003': {'name': 'Mechanical Keyboard', 'price': 149.99, 'stock': 30},
}

# Valid promo codes
VALID_PROMOS = {
    'SAVE10': 10,
    'SAVE20': 20,
    'VIP50': 50,
}

# Session storage (simulating vulnerable session management)
SESSIONS = {}
SESSION_COUNTER = 1000  # Predictable counter for session IDs

# ============================================================================
# VULNERABILITY 1: SESSION FIXATION
# Session ID is NOT rotated after login - same session persists
# ============================================================================

def generate_weak_session_id():
    """Generate predictable session ID (VULN: SESS-PRED-001)"""
    global SESSION_COUNTER
    SESSION_COUNTER += 1
    # Weak: base64 of timestamp + counter
    weak_data = f"{int(time.time())}:{SESSION_COUNTER}"
    return base64.b64encode(weak_data.encode()).decode()

def get_current_user():
    """Get current user from session cookie"""
    session_id = request.cookies.get('session_id')
    if session_id and session_id in SESSIONS:
        return SESSIONS[session_id]
    return None

# ============================================================================
# HTML TEMPLATES
# ============================================================================

BASE_TEMPLATE = '''
<!DOCTYPE html>
<html>
<head>
    <title>VulnDemo - {{ title }}</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 40px; background: #f5f5f5; }
        .container { max-width: 800px; margin: 0 auto; background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
        h1 { color: #333; }
        .nav { background: #333; padding: 10px; margin-bottom: 20px; border-radius: 4px; }
        .nav a { color: white; margin-right: 15px; text-decoration: none; }
        .nav a:hover { text-decoration: underline; }
        .alert { padding: 10px; margin: 10px 0; border-radius: 4px; }
        .alert-success { background: #d4edda; color: #155724; }
        .alert-error { background: #f8d7da; color: #721c24; }
        .alert-info { background: #d1ecf1; color: #0c5460; }
        form { margin: 20px 0; }
        input, button { padding: 10px; margin: 5px 0; }
        input[type="text"], input[type="password"], input[type="number"] { width: 200px; }
        button { background: #007bff; color: white; border: none; cursor: pointer; border-radius: 4px; }
        button:hover { background: #0056b3; }
        table { width: 100%; border-collapse: collapse; margin: 20px 0; }
        th, td { padding: 10px; border: 1px solid #ddd; text-align: left; }
        th { background: #f8f9fa; }
        .card { border: 1px solid #ddd; padding: 15px; margin: 10px 0; border-radius: 4px; }
        pre { background: #f4f4f4; padding: 10px; overflow-x: auto; }
        .debug { background: #fff3cd; padding: 10px; margin: 10px 0; font-size: 12px; }
    </style>
</head>
<body>
    <div class="container">
        <div class="nav">
            <a href="/">Home</a>
            <a href="/dashboard">Dashboard</a>
            <a href="/profile">Profile</a>
            <a href="/orders">Orders</a>
            <a href="/shop">Shop</a>
            <a href="/admin">Admin</a>
            {% if user %}
            <a href="/logout" style="float:right;">Logout ({{ user.username }})</a>
            {% else %}
            <a href="/login" style="float:right;">Login</a>
            {% endif %}
        </div>
        {{ content | safe }}
    </div>
</body>
</html>
'''

LOGIN_TEMPLATE = '''
<h1>Login</h1>
<div class="alert alert-info">
    <strong>Test Credentials:</strong><br>
    admin:admin123 | moderator:mod123 | user1:user123 | user2:pass456
</div>
{% if error %}
<div class="alert alert-error">{{ error }}</div>
{% endif %}
<form method="POST" action="/login">
    <div>
        <label>Username:</label><br>
        <input type="text" name="username" required>
    </div>
    <div>
        <label>Password:</label><br>
        <input type="password" name="password" required>
    </div>
    <div>
        <button type="submit">Login</button>
    </div>
</form>
<div class="debug">
    <strong>Session Fixation Test:</strong> Current session_id cookie: {{ session_id }}
</div>
'''

DASHBOARD_TEMPLATE = '''
<h1>Dashboard</h1>
<div class="alert alert-success">Welcome, {{ user.username }}! (Role: {{ user.role }})</div>
<div class="card">
    <h3>Your Account</h3>
    <p>Email: {{ user.email }}</p>
    <p>Balance: ${{ user.balance }}</p>
    <p>Privilege Level: {{ user.privilege_priority }}</p>
</div>
<div class="debug">
    <strong>Debug Info:</strong><br>
    Session ID: {{ session_id }}<br>
    User Role: {{ user.role }}
</div>
'''

# ============================================================================
# ROUTES
# ============================================================================

@app.route('/')
def index():
    user = get_current_user()
    content = '''
    <h1>Vulnerable Demo Application</h1>
    <p>This application contains intentional security vulnerabilities for testing:</p>
    <div class="card">
        <h3>1. Session Fixation (SESS-FIX-001)</h3>
        <p>Session ID is NOT rotated after login. Pre-auth session persists.</p>
        <p><strong>Test:</strong> Note session_id cookie before login, verify it stays same after login.</p>
    </div>
    <div class="card">
        <h3>2. Predictable Session ID (SESS-PRED-001)</h3>
        <p>Session IDs are base64(timestamp:counter) - easily guessable.</p>
        <p><strong>Test:</strong> Decode session_id, predict next values.</p>
    </div>
    <div class="card">
        <h3>3. IDOR - Insecure Direct Object Reference (IDOR-001)</h3>
        <p>Change user_id, order_id, profile_id to access other users' data.</p>
        <p><strong>Test:</strong> <code>/api/profile?id=1</code>, <code>/api/order/1003</code></p>
    </div>
    <div class="card">
        <h3>4. Forced Browsing Auth Bypass (FB-001)</h3>
        <p>Some endpoints don't check authentication properly.</p>
        <p><strong>Test:</strong> Access <code>/admin/users</code> or <code>/api/reports</code> without login.</p>
    </div>
    <div class="card">
        <h3>5. Business Logic Tampering (BL-*)</h3>
        <p>Price, quantity, discount can be manipulated in checkout.</p>
        <p><strong>Test:</strong> POST to <code>/api/checkout</code> with modified price/quantity.</p>
    </div>
    <div class="card">
        <h3>6. Access Level Role Coverage (AC-ROLE-001)</h3>
        <p>Multi-role system: admin (1), moderator (2), user (3).</p>
        <p><strong>Test:</strong> Different endpoints have different role requirements.</p>
    </div>
    '''
    return render_template_string(BASE_TEMPLATE, title='Home', content=content, user=user)


@app.route('/login', methods=['GET', 'POST'])
def login():
    session_id = request.cookies.get('session_id')
    
    # VULN: If no session exists, create one BEFORE login (Session Fixation setup)
    if not session_id:
        session_id = generate_weak_session_id()
    
    if request.method == 'POST':
        username = request.form.get('username', '')
        password = request.form.get('password', '')
        
        if username in USERS and USERS[username]['password'] == password:
            # VULN: Session Fixation - NOT rotating session ID after login!
            # The pre-auth session_id is reused for the authenticated session
            user_data = {
                'username': username,
                'role': USERS[username]['role'],
                'privilege_priority': USERS[username]['privilege_priority'],
                'email': USERS[username]['email'],
                'balance': USERS[username]['balance']
            }
            SESSIONS[session_id] = user_data
            
            response = make_response(redirect('/dashboard'))
            # VULN: Same session_id cookie, not regenerated
            response.set_cookie('session_id', session_id, httponly=True)
            return response
        else:
            content = render_template_string(LOGIN_TEMPLATE, error='Invalid credentials', session_id=session_id)
            response = make_response(render_template_string(BASE_TEMPLATE, title='Login', content=content, user=None))
            response.set_cookie('session_id', session_id)
            return response
    
    content = render_template_string(LOGIN_TEMPLATE, error=None, session_id=session_id)
    response = make_response(render_template_string(BASE_TEMPLATE, title='Login', content=content, user=None))
    response.set_cookie('session_id', session_id)
    return response


@app.route('/logout')
def logout():
    session_id = request.cookies.get('session_id')
    if session_id and session_id in SESSIONS:
        del SESSIONS[session_id]
    response = make_response(redirect('/'))
    response.delete_cookie('session_id')
    return response


@app.route('/dashboard')
def dashboard():
    user = get_current_user()
    if not user:
        return redirect('/login')
    
    session_id = request.cookies.get('session_id', 'N/A')
    content = render_template_string(DASHBOARD_TEMPLATE, user=user, session_id=session_id)
    return render_template_string(BASE_TEMPLATE, title='Dashboard', content=content, user=user)


# ============================================================================
# VULNERABILITY 3: IDOR - Profile Access
# ============================================================================

@app.route('/profile')
def profile_page():
    user = get_current_user()
    if not user:
        return redirect('/login')
    
    # Find user's profile ID
    profile_id = None
    for pid, profile in PROFILES.items():
        if profile['username'] == user['username']:
            profile_id = pid
            break
    
    content = f'''
    <h1>My Profile</h1>
    <div class="card">
        <p><strong>Profile ID:</strong> {profile_id}</p>
        <p><strong>Username:</strong> {user['username']}</p>
        <p><strong>Email:</strong> {user['email']}</p>
        <p><strong>Role:</strong> {user['role']}</p>
    </div>
    <div class="alert alert-info">
        <strong>IDOR Test:</strong> Try accessing <code>/api/profile?id=1</code> through <code>id=4</code>
    </div>
    '''
    return render_template_string(BASE_TEMPLATE, title='Profile', content=content, user=user)


@app.route('/api/profile')
def api_profile():
    """VULN: IDOR - No authorization check on profile_id parameter"""
    user = get_current_user()
    if not user:
        return jsonify({'error': 'Unauthorized'}), 401
    
    profile_id = request.args.get('id', '1')
    
    # VULN: No check if user owns this profile!
    if profile_id in PROFILES:
        return jsonify({
            'profile_id': profile_id,
            'data': PROFILES[profile_id]
        })
    return jsonify({'error': 'Profile not found'}), 404


@app.route('/api/user/<user_id>')
def api_user(user_id):
    """VULN: IDOR - Access any user by ID"""
    user = get_current_user()
    if not user:
        return jsonify({'error': 'Unauthorized'}), 401
    
    # Map user_id to username
    user_map = {'1': 'admin', '2': 'moderator', '3': 'user1', '4': 'user2'}
    
    # VULN: No authorization check!
    if user_id in user_map:
        username = user_map[user_id]
        return jsonify({
            'user_id': user_id,
            'username': username,
            'email': USERS[username]['email'],
            'role': USERS[username]['role'],
            'balance': USERS[username]['balance']
        })
    return jsonify({'error': 'User not found'}), 404


# ============================================================================
# VULNERABILITY 3: IDOR - Order Access
# ============================================================================

@app.route('/orders')
def orders_page():
    user = get_current_user()
    if not user:
        return redirect('/login')
    
    # Get user's orders
    user_orders = {oid: order for oid, order in ORDERS.items() if order['user'] == user['username']}
    
    rows = ''
    for oid, order in user_orders.items():
        rows += f'''<tr>
            <td>{oid}</td>
            <td>{order['product']}</td>
            <td>${order['amount']}</td>
            <td>{order['status']}</td>
            <td><a href="/api/order/{oid}">View API</a></td>
        </tr>'''
    
    content = f'''
    <h1>My Orders</h1>
    <table>
        <tr><th>Order ID</th><th>Product</th><th>Amount</th><th>Status</th><th>API</th></tr>
        {rows}
    </table>
    <div class="alert alert-info">
        <strong>IDOR Test:</strong> Try accessing other order IDs: /api/order/1001, /api/order/1003, /api/order/1004
    </div>
    '''
    return render_template_string(BASE_TEMPLATE, title='Orders', content=content, user=user)


@app.route('/api/order/<order_id>')
def api_order(order_id):
    """VULN: IDOR - No authorization check on order access"""
    user = get_current_user()
    if not user:
        return jsonify({'error': 'Unauthorized'}), 401
    
    # VULN: No check if user owns this order!
    if order_id in ORDERS:
        return jsonify({
            'order_id': order_id,
            'order': ORDERS[order_id]
        })
    return jsonify({'error': 'Order not found'}), 404


# ============================================================================
# VULNERABILITY 4: FORCED BROWSING AUTH BYPASS
# ============================================================================

@app.route('/admin')
def admin_page():
    user = get_current_user()
    content = '''
    <h1>Admin Panel</h1>
    <div class="card">
        <h3>Admin Functions</h3>
        <ul>
            <li><a href="/admin/users">User Management</a> (Should require auth)</li>
            <li><a href="/admin/settings">System Settings</a> (Should require auth)</li>
            <li><a href="/api/reports">Reports API</a> (VULN: No auth check!)</li>
            <li><a href="/api/admin/stats">Admin Stats</a> (VULN: No auth check!)</li>
        </ul>
    </div>
    '''
    return render_template_string(BASE_TEMPLATE, title='Admin', content=content, user=user)


@app.route('/admin/users')
def admin_users():
    """VULN: Forced Browsing - Can access without proper auth check"""
    # VULN: No authentication check! Anyone can access this.
    users_html = ''
    for username, data in USERS.items():
        users_html += f'''<tr>
            <td>{username}</td>
            <td>{data['email']}</td>
            <td>{data['role']}</td>
            <td>${data['balance']}</td>
        </tr>'''
    
    content = f'''
    <h1>User Management</h1>
    <div class="alert alert-error">
        <strong>VULN:</strong> This page has NO authentication check - forced browsing possible!
    </div>
    <table>
        <tr><th>Username</th><th>Email</th><th>Role</th><th>Balance</th></tr>
        {users_html}
    </table>
    '''
    user = get_current_user()
    return render_template_string(BASE_TEMPLATE, title='User Management', content=content, user=user)


@app.route('/admin/settings')
def admin_settings():
    """VULN: Forced Browsing - sensitive settings without auth"""
    # VULN: No authentication check!
    content = '''
    <h1>System Settings</h1>
    <div class="alert alert-error">
        <strong>VULN:</strong> Sensitive configuration exposed without authentication!
    </div>
    <div class="card">
        <pre>
DATABASE_URL = postgresql://admin:supersecret@db.internal:5432/production
API_KEY = sk_live_abcdef123456789
AWS_SECRET = AKIAIOSFODNN7EXAMPLE
SMTP_PASSWORD = email_p@ssw0rd!
        </pre>
    </div>
    '''
    user = get_current_user()
    return render_template_string(BASE_TEMPLATE, title='Settings', content=content, user=user)


@app.route('/api/reports')
def api_reports():
    """VULN: Forced Browsing - API returns sensitive data without auth"""
    # VULN: No authentication check!
    return jsonify({
        'reports': [
            {'id': 1, 'title': 'Financial Report Q4', 'revenue': 1250000, 'profit': 340000},
            {'id': 2, 'title': 'User Analytics', 'total_users': 50000, 'active': 12000},
            {'id': 3, 'title': 'Security Audit', 'vulnerabilities': 15, 'critical': 3},
        ],
        'generated_at': '2026-01-05',
        'confidential': True
    })


@app.route('/api/admin/stats')
def api_admin_stats():
    """VULN: Forced Browsing - Admin stats without auth"""
    # VULN: No authentication check!
    return jsonify({
        'total_revenue': 5000000,
        'total_users': len(USERS),
        'admin_password_hash': hashlib.md5(b'admin123').hexdigest(),
        'database_connection_string': 'postgresql://admin:secret@localhost/prod'
    })


# ============================================================================
# VULNERABILITY 5: BUSINESS LOGIC TAMPERING
# ============================================================================

@app.route('/shop')
def shop():
    user = get_current_user()
    
    products_html = ''
    for pid, prod in PRODUCTS.items():
        products_html += f'''
        <div class="card">
            <h3>{prod['name']}</h3>
            <p>Price: ${prod['price']}</p>
            <p>Stock: {prod['stock']} units</p>
            <form method="POST" action="/cart/add">
                <input type="hidden" name="product_id" value="{pid}">
                <input type="hidden" name="price" value="{prod['price']}">
                <input type="number" name="quantity" value="1" min="1" max="10">
                <button type="submit">Add to Cart</button>
            </form>
        </div>
        '''
    
    content = f'''
    <h1>Shop</h1>
    <div class="alert alert-info">
        <strong>Business Logic Tests:</strong>
        <ul>
            <li>Hidden field tampering: Modify the hidden "price" field</li>
            <li>Quantity manipulation: Try negative or zero quantities</li>
            <li>Use API: POST to /api/checkout with modified values</li>
        </ul>
    </div>
    {products_html}
    '''
    return render_template_string(BASE_TEMPLATE, title='Shop', content=content, user=user)


@app.route('/cart/add', methods=['POST'])
def add_to_cart():
    """Process cart addition - vulnerable to hidden field tampering"""
    user = get_current_user()
    
    product_id = request.form.get('product_id')
    # VULN: Trusting client-provided price instead of server-side lookup!
    price = float(request.form.get('price', 0))
    quantity = int(request.form.get('quantity', 1))
    
    # VULN: No validation of negative quantity!
    total = price * quantity
    
    content = f'''
    <h1>Cart Updated</h1>
    <div class="alert alert-success">
        Added {quantity} x {product_id} at ${price} each = ${total} total
    </div>
    <div class="alert alert-error">
        <strong>VULN:</strong> Price was taken from hidden form field (tamperable)!
        <br>Quantity was not validated (negative accepted)!
    </div>
    <a href="/shop">Continue Shopping</a> | <a href="/checkout">Checkout</a>
    '''
    return render_template_string(BASE_TEMPLATE, title='Cart', content=content, user=user)


@app.route('/checkout')
def checkout_page():
    user = get_current_user()
    if not user:
        return redirect('/login')
    
    content = '''
    <h1>Checkout</h1>
    <form method="POST" action="/api/checkout">
        <div class="card">
            <h3>Order Summary</h3>
            <input type="hidden" name="product_id" value="PROD001">
            <input type="hidden" name="original_price" value="299.99">
            
            <p>Product: Premium Headphones</p>
            <p>
                <label>Price: $</label>
                <input type="number" name="price" value="299.99" step="0.01">
                <small>(VULN: editable!)</small>
            </p>
            <p>
                <label>Quantity:</label>
                <input type="number" name="quantity" value="1">
                <small>(VULN: try -1 or 0)</small>
            </p>
            <p>
                <label>Discount %:</label>
                <input type="number" name="discount" value="0" min="0" max="100">
                <small>(VULN: try 100 or 150)</small>
            </p>
            <p>
                <label>Promo Code:</label>
                <input type="text" name="promo_code" placeholder="Enter code">
                <small>(Valid: SAVE10, SAVE20, VIP50)</small>
            </p>
            <input type="hidden" name="is_eligible" value="false">
            <input type="hidden" name="total" value="299.99">
        </div>
        <button type="submit">Complete Purchase</button>
    </form>
    '''
    return render_template_string(BASE_TEMPLATE, title='Checkout', content=content, user=user)


@app.route('/api/checkout', methods=['POST'])
def api_checkout():
    """VULN: Business Logic Tampering - Multiple vulnerabilities"""
    user = get_current_user()
    if not user:
        return jsonify({'error': 'Unauthorized'}), 401
    
    # Get form data or JSON
    if request.is_json:
        data = request.get_json()
    else:
        data = request.form.to_dict()
    
    product_id = data.get('product_id', 'PROD001')
    
    # VULN BL-PRICE-001: Trusting client-provided price!
    price = float(data.get('price', 0))
    
    # VULN BL-QTY-001: No validation of quantity!
    quantity = int(data.get('quantity', 1))
    
    # VULN BL-PROMO-001: Direct discount manipulation!
    discount = float(data.get('discount', 0))
    
    # VULN BL-HIDDEN-001: Trusting hidden eligibility field!
    is_eligible = data.get('is_eligible', 'false')
    if is_eligible == 'true':
        discount += 20  # Extra discount for "eligible" users
    
    # Promo code processing
    promo_code = data.get('promo_code', '')
    if promo_code and promo_code.upper() in VALID_PROMOS:
        discount += VALID_PROMOS[promo_code.upper()]
    
    # Calculate total (with vulnerabilities)
    subtotal = price * quantity
    discount_amount = subtotal * (discount / 100)
    total = subtotal - discount_amount
    
    # VULN: Accepting negative totals!
    result = {
        'status': 'success',
        'message': 'Order processed successfully',
        'order': {
            'product_id': product_id,
            'price_used': price,
            'quantity': quantity,
            'discount_percent': discount,
            'subtotal': round(subtotal, 2),
            'discount_amount': round(discount_amount, 2),
            'total': round(total, 2),
            'charged_to': user['username']
        },
        'vulnerabilities_exploited': []
    }
    
    # Check what was exploited
    if product_id in PRODUCTS and price != PRODUCTS[product_id]['price']:
        result['vulnerabilities_exploited'].append('BL-PRICE-001: Price tampering detected')
    if quantity <= 0:
        result['vulnerabilities_exploited'].append('BL-QTY-001: Invalid quantity accepted')
    if discount > 100 or discount < 0:
        result['vulnerabilities_exploited'].append('BL-PROMO-001: Invalid discount accepted')
    if is_eligible == 'true':
        result['vulnerabilities_exploited'].append('BL-HIDDEN-001: Hidden field tampering detected')
    
    return jsonify(result)


# ============================================================================
# VULNERABILITY 6: ACCESS LEVEL ROLE COVERAGE
# ============================================================================

@app.route('/api/admin-only')
def admin_only():
    """Endpoint requiring admin role"""
    user = get_current_user()
    if not user:
        return jsonify({'error': 'Authentication required'}), 401
    if user['role'] != 'admin':
        return jsonify({'error': 'Admin access required'}), 403
    return jsonify({'message': 'Admin data', 'secret': 'admin-secret-123'})


@app.route('/api/moderator-only')
def moderator_only():
    """Endpoint requiring moderator or higher role"""
    user = get_current_user()
    if not user:
        return jsonify({'error': 'Authentication required'}), 401
    if user['role'] not in ['admin', 'moderator']:
        return jsonify({'error': 'Moderator access required'}), 403
    return jsonify({'message': 'Moderator data', 'reports': [1, 2, 3]})


@app.route('/api/user-data')
def user_data():
    """Endpoint for any authenticated user"""
    user = get_current_user()
    if not user:
        return jsonify({'error': 'Authentication required'}), 401
    return jsonify({
        'message': 'User data',
        'username': user['username'],
        'role': user['role']
    })


# ============================================================================
# CREDENTIAL CONFIG ENDPOINT (for scanner integration)
# ============================================================================

@app.route('/api/test-auth')
def test_auth():
    """Test endpoint to verify authentication works"""
    user = get_current_user()
    if user:
        return jsonify({
            'authenticated': True,
            'user': user
        })
    return jsonify({'authenticated': False}), 401


# ============================================================================
# MAIN
# ============================================================================

if __name__ == '__main__':
    print("=" * 60)
    print("Vulnerable Demo Application")
    print("=" * 60)
    print("\nTest Vulnerabilities:")
    print("1. Session Fixation - Login and check session_id stays same")
    print("2. Predictable Session - Decode base64 session to see pattern")
    print("3. IDOR - /api/profile?id=X, /api/order/X, /api/user/X")
    print("4. Forced Browsing - /admin/users, /api/reports (no auth needed)")
    print("5. Business Logic - /api/checkout with tampered values")
    print("6. Role Coverage - /api/admin-only, /api/moderator-only")
    print("\nTest Credentials:")
    print("  admin:admin123 (privilege: 1)")
    print("  moderator:mod123 (privilege: 2)")
    print("  user1:user123 (privilege: 3)")
    print("  user2:pass456 (privilege: 3)")
    print("\n" + "=" * 60)
    
    app.run(host='0.0.0.0', port=5000, debug=True)
