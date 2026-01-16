/**
 * Comprehensive Vulnerable Demo Application (Node.js/Express)
 * ===========================================================
 * 
 * Alternative to Python version - same vulnerabilities:
 * 1. Session Fixation (SESS-FIX-001)
 * 2. Predictable Session ID (SESS-PRED-001)
 * 3. IDOR Parameter Manipulation (IDOR-001)
 * 4. Forced Browsing Auth Bypass (FB-001)
 * 5. Business Logic Tampering (BL-*)
 * 6. Access Level Role Coverage (AC-ROLE-001)
 * 
 * Run: npm install express cookie-parser && node app_comprehensive.js
 * Access: http://localhost:5001
 */

const express = require('express');
const cookieParser = require('cookie-parser');
const crypto = require('crypto');

const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());

// ============================================================================
// DATABASE SIMULATION
// ============================================================================

const USERS = {
    admin: { password: 'admin123', role: 'admin', privilege_priority: 1, email: 'admin@company.com', balance: 10000 },
    moderator: { password: 'mod123', role: 'moderator', privilege_priority: 2, email: 'mod@company.com', balance: 5000 },
    user1: { password: 'user123', role: 'user', privilege_priority: 3, email: 'user1@example.com', balance: 1000 },
    user2: { password: 'pass456', role: 'user', privilege_priority: 3, email: 'user2@example.com', balance: 500 }
};

const ORDERS = {
    '1001': { user: 'user1', product: 'Laptop', amount: 999.99, status: 'completed' },
    '1002': { user: 'user1', product: 'Mouse', amount: 49.99, status: 'pending' },
    '1003': { user: 'user2', product: 'Keyboard', amount: 79.99, status: 'completed' },
    '1004': { user: 'admin', product: 'Server', amount: 5000.00, status: 'processing' }
};

const PROFILES = {
    '1': { username: 'admin', ssn: '123-45-6789', phone: '555-0001', address: 'Admin Tower' },
    '2': { username: 'moderator', ssn: '234-56-7890', phone: '555-0002', address: 'Mod Street' },
    '3': { username: 'user1', ssn: '345-67-8901', phone: '555-0003', address: '123 User Lane' },
    '4': { username: 'user2', ssn: '456-78-9012', phone: '555-0004', address: '456 User Ave' }
};

const PRODUCTS = {
    'PROD001': { name: 'Premium Headphones', price: 299.99, stock: 50 },
    'PROD002': { name: 'Wireless Mouse', price: 49.99, stock: 100 },
    'PROD003': { name: 'Mechanical Keyboard', price: 149.99, stock: 30 }
};

const VALID_PROMOS = { 'SAVE10': 10, 'SAVE20': 20, 'VIP50': 50 };

// Session storage
const SESSIONS = {};
let SESSION_COUNTER = 1000;

// ============================================================================
// VULNERABLE SESSION MANAGEMENT
// ============================================================================

function generateWeakSessionId() {
    SESSION_COUNTER++;
    // VULN: Predictable - base64 of timestamp:counter
    const weakData = `${Date.now()}:${SESSION_COUNTER}`;
    return Buffer.from(weakData).toString('base64');
}

function getCurrentUser(req) {
    const sessionId = req.cookies.session_id;
    if (sessionId && SESSIONS[sessionId]) {
        return SESSIONS[sessionId];
    }
    return null;
}

// ============================================================================
// HTML TEMPLATE HELPER
// ============================================================================

function renderPage(title, content, user) {
    const userNav = user 
        ? `<a href="/logout" style="float:right;">Logout (${user.username})</a>`
        : `<a href="/login" style="float:right;">Login</a>`;
    
    return `
<!DOCTYPE html>
<html>
<head>
    <title>VulnDemo - ${title}</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 40px; background: #f5f5f5; }
        .container { max-width: 800px; margin: 0 auto; background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
        h1 { color: #333; }
        .nav { background: #2c5aa0; padding: 10px; margin-bottom: 20px; border-radius: 4px; }
        .nav a { color: white; margin-right: 15px; text-decoration: none; }
        .nav a:hover { text-decoration: underline; }
        .alert { padding: 10px; margin: 10px 0; border-radius: 4px; }
        .alert-success { background: #d4edda; color: #155724; }
        .alert-error { background: #f8d7da; color: #721c24; }
        .alert-info { background: #d1ecf1; color: #0c5460; }
        form { margin: 20px 0; }
        input, button { padding: 10px; margin: 5px 0; }
        input[type="text"], input[type="password"], input[type="number"] { width: 200px; }
        button { background: #2c5aa0; color: white; border: none; cursor: pointer; border-radius: 4px; }
        button:hover { background: #1e3d6f; }
        table { width: 100%; border-collapse: collapse; margin: 20px 0; }
        th, td { padding: 10px; border: 1px solid #ddd; text-align: left; }
        th { background: #f8f9fa; }
        .card { border: 1px solid #ddd; padding: 15px; margin: 10px 0; border-radius: 4px; }
        pre { background: #f4f4f4; padding: 10px; overflow-x: auto; }
        .debug { background: #fff3cd; padding: 10px; margin: 10px 0; font-size: 12px; }
        .badge { display: inline-block; padding: 2px 8px; border-radius: 3px; font-size: 12px; }
        .badge-node { background: #68a063; color: white; }
    </style>
</head>
<body>
    <div class="container">
        <div class="nav">
            <span class="badge badge-node">Node.js</span>
            <a href="/">Home</a>
            <a href="/dashboard">Dashboard</a>
            <a href="/profile">Profile</a>
            <a href="/orders">Orders</a>
            <a href="/shop">Shop</a>
            <a href="/admin">Admin</a>
            ${userNav}
        </div>
        ${content}
    </div>
</body>
</html>`;
}

// ============================================================================
// ROUTES
// ============================================================================

app.get('/', (req, res) => {
    const user = getCurrentUser(req);
    const content = `
        <h1>Vulnerable Demo Application (Node.js)</h1>
        <p>This is the Node.js version running on port 5001.</p>
        <p>Same vulnerabilities as Python version on port 5000.</p>
        <div class="card">
            <h3>Vulnerabilities Available:</h3>
            <ul>
                <li>Session Fixation & Predictable Session ID</li>
                <li>IDOR Parameter Manipulation</li>
                <li>Forced Browsing Auth Bypass</li>
                <li>Business Logic Tampering</li>
                <li>Access Level Role Coverage</li>
            </ul>
        </div>
    `;
    res.send(renderPage('Home', content, user));
});

// ============================================================================
// LOGIN - VULNERABLE TO SESSION FIXATION
// ============================================================================

app.get('/login', (req, res) => {
    let sessionId = req.cookies.session_id;
    
    // VULN: Create session BEFORE login
    if (!sessionId) {
        sessionId = generateWeakSessionId();
        res.cookie('session_id', sessionId, { httpOnly: true });
    }
    
    const content = `
        <h1>Login</h1>
        <div class="alert alert-info">
            <strong>Test Credentials:</strong><br>
            admin:admin123 | moderator:mod123 | user1:user123 | user2:pass456
        </div>
        <form method="POST" action="/login">
            <div><label>Username:</label><br><input type="text" name="username" required></div>
            <div><label>Password:</label><br><input type="password" name="password" required></div>
            <div><button type="submit">Login</button></div>
        </form>
        <div class="debug">
            <strong>Session Fixation Test:</strong> Current session_id: ${sessionId}
        </div>
    `;
    res.send(renderPage('Login', content, null));
});

app.post('/login', (req, res) => {
    const { username, password } = req.body;
    let sessionId = req.cookies.session_id;
    
    if (!sessionId) {
        sessionId = generateWeakSessionId();
    }
    
    if (USERS[username] && USERS[username].password === password) {
        // VULN: NOT rotating session ID after login!
        SESSIONS[sessionId] = {
            username,
            role: USERS[username].role,
            privilege_priority: USERS[username].privilege_priority,
            email: USERS[username].email,
            balance: USERS[username].balance
        };
        res.cookie('session_id', sessionId, { httpOnly: true });
        return res.redirect('/dashboard');
    }
    
    res.cookie('session_id', sessionId);
    const content = `
        <h1>Login</h1>
        <div class="alert alert-error">Invalid credentials</div>
        <form method="POST" action="/login">
            <div><label>Username:</label><br><input type="text" name="username" required></div>
            <div><label>Password:</label><br><input type="password" name="password" required></div>
            <div><button type="submit">Login</button></div>
        </form>
    `;
    res.send(renderPage('Login', content, null));
});

app.get('/logout', (req, res) => {
    const sessionId = req.cookies.session_id;
    if (sessionId && SESSIONS[sessionId]) {
        delete SESSIONS[sessionId];
    }
    res.clearCookie('session_id');
    res.redirect('/');
});

app.get('/dashboard', (req, res) => {
    const user = getCurrentUser(req);
    if (!user) return res.redirect('/login');
    
    const content = `
        <h1>Dashboard</h1>
        <div class="alert alert-success">Welcome, ${user.username}! (Role: ${user.role})</div>
        <div class="card">
            <h3>Your Account</h3>
            <p>Email: ${user.email}</p>
            <p>Balance: $${user.balance}</p>
            <p>Privilege Level: ${user.privilege_priority}</p>
        </div>
        <div class="debug">
            <strong>Debug:</strong> Session ID: ${req.cookies.session_id}
        </div>
    `;
    res.send(renderPage('Dashboard', content, user));
});

// ============================================================================
// IDOR VULNERABILITIES
// ============================================================================

app.get('/profile', (req, res) => {
    const user = getCurrentUser(req);
    if (!user) return res.redirect('/login');
    
    let profileId = '1';
    for (const [pid, profile] of Object.entries(PROFILES)) {
        if (profile.username === user.username) {
            profileId = pid;
            break;
        }
    }
    
    const content = `
        <h1>My Profile</h1>
        <div class="card">
            <p><strong>Profile ID:</strong> ${profileId}</p>
            <p><strong>Username:</strong> ${user.username}</p>
            <p><strong>Email:</strong> ${user.email}</p>
        </div>
        <div class="alert alert-info">
            <strong>IDOR Test:</strong> Try /api/profile?id=1 through id=4
        </div>
    `;
    res.send(renderPage('Profile', content, user));
});

// VULN: IDOR - No authorization check
app.get('/api/profile', (req, res) => {
    const user = getCurrentUser(req);
    if (!user) return res.status(401).json({ error: 'Unauthorized' });
    
    const profileId = req.query.id || '1';
    
    // VULN: No check if user owns this profile!
    if (PROFILES[profileId]) {
        return res.json({ profile_id: profileId, data: PROFILES[profileId] });
    }
    res.status(404).json({ error: 'Profile not found' });
});

// VULN: IDOR - Access any user
app.get('/api/user/:userId', (req, res) => {
    const user = getCurrentUser(req);
    if (!user) return res.status(401).json({ error: 'Unauthorized' });
    
    const userMap = { '1': 'admin', '2': 'moderator', '3': 'user1', '4': 'user2' };
    const userId = req.params.userId;
    
    // VULN: No authorization check!
    if (userMap[userId]) {
        const username = userMap[userId];
        return res.json({
            user_id: userId,
            username,
            email: USERS[username].email,
            role: USERS[username].role,
            balance: USERS[username].balance
        });
    }
    res.status(404).json({ error: 'User not found' });
});

app.get('/orders', (req, res) => {
    const user = getCurrentUser(req);
    if (!user) return res.redirect('/login');
    
    const userOrders = Object.entries(ORDERS)
        .filter(([_, order]) => order.user === user.username)
        .map(([oid, order]) => `
            <tr>
                <td>${oid}</td>
                <td>${order.product}</td>
                <td>$${order.amount}</td>
                <td>${order.status}</td>
                <td><a href="/api/order/${oid}">View API</a></td>
            </tr>
        `).join('');
    
    const content = `
        <h1>My Orders</h1>
        <table>
            <tr><th>Order ID</th><th>Product</th><th>Amount</th><th>Status</th><th>API</th></tr>
            ${userOrders}
        </table>
        <div class="alert alert-info">
            <strong>IDOR Test:</strong> Try /api/order/1001, /api/order/1003, /api/order/1004
        </div>
    `;
    res.send(renderPage('Orders', content, user));
});

// VULN: IDOR - No order ownership check
app.get('/api/order/:orderId', (req, res) => {
    const user = getCurrentUser(req);
    if (!user) return res.status(401).json({ error: 'Unauthorized' });
    
    const orderId = req.params.orderId;
    
    // VULN: No check if user owns this order!
    if (ORDERS[orderId]) {
        return res.json({ order_id: orderId, order: ORDERS[orderId] });
    }
    res.status(404).json({ error: 'Order not found' });
});

// ============================================================================
// FORCED BROWSING VULNERABILITIES
// ============================================================================

app.get('/admin', (req, res) => {
    const user = getCurrentUser(req);
    const content = `
        <h1>Admin Panel</h1>
        <div class="card">
            <h3>Admin Functions</h3>
            <ul>
                <li><a href="/admin/users">User Management</a> (VULN: No auth!)</li>
                <li><a href="/admin/settings">System Settings</a> (VULN: No auth!)</li>
                <li><a href="/api/reports">Reports API</a></li>
                <li><a href="/api/admin/stats">Admin Stats</a></li>
            </ul>
        </div>
    `;
    res.send(renderPage('Admin', content, user));
});

// VULN: Forced Browsing - No auth check!
app.get('/admin/users', (req, res) => {
    const user = getCurrentUser(req);
    
    const usersHtml = Object.entries(USERS)
        .map(([username, data]) => `
            <tr>
                <td>${username}</td>
                <td>${data.email}</td>
                <td>${data.role}</td>
                <td>$${data.balance}</td>
            </tr>
        `).join('');
    
    const content = `
        <h1>User Management</h1>
        <div class="alert alert-error">
            <strong>VULN:</strong> No authentication check - forced browsing possible!
        </div>
        <table>
            <tr><th>Username</th><th>Email</th><th>Role</th><th>Balance</th></tr>
            ${usersHtml}
        </table>
    `;
    res.send(renderPage('User Management', content, user));
});

// VULN: Forced Browsing - Sensitive settings exposed
app.get('/admin/settings', (req, res) => {
    const user = getCurrentUser(req);
    const content = `
        <h1>System Settings</h1>
        <div class="alert alert-error">
            <strong>VULN:</strong> Sensitive configuration exposed without authentication!
        </div>
        <div class="card">
            <pre>
DATABASE_URL = postgresql://admin:supersecret@db.internal:5432/production
API_KEY = sk_live_abcdef123456789
AWS_SECRET = AKIAIOSFODNN7EXAMPLE
JWT_SECRET = jwt_secret_do_not_expose
            </pre>
        </div>
    `;
    res.send(renderPage('Settings', content, user));
});

// VULN: Forced Browsing - API returns data without auth
app.get('/api/reports', (req, res) => {
    // VULN: No authentication check!
    res.json({
        reports: [
            { id: 1, title: 'Financial Report Q4', revenue: 1250000, profit: 340000 },
            { id: 2, title: 'User Analytics', total_users: 50000, active: 12000 },
            { id: 3, title: 'Security Audit', vulnerabilities: 15, critical: 3 }
        ],
        generated_at: new Date().toISOString(),
        confidential: true
    });
});

app.get('/api/admin/stats', (req, res) => {
    // VULN: No authentication check!
    res.json({
        total_revenue: 5000000,
        total_users: Object.keys(USERS).length,
        admin_password_hash: crypto.createHash('md5').update('admin123').digest('hex'),
        database_connection_string: 'postgresql://admin:secret@localhost/prod'
    });
});

// ============================================================================
// BUSINESS LOGIC VULNERABILITIES
// ============================================================================

app.get('/shop', (req, res) => {
    const user = getCurrentUser(req);
    
    const productsHtml = Object.entries(PRODUCTS)
        .map(([pid, prod]) => `
            <div class="card">
                <h3>${prod.name}</h3>
                <p>Price: $${prod.price}</p>
                <p>Stock: ${prod.stock} units</p>
                <form method="POST" action="/cart/add">
                    <input type="hidden" name="product_id" value="${pid}">
                    <input type="hidden" name="price" value="${prod.price}">
                    <input type="number" name="quantity" value="1" min="1" max="10">
                    <button type="submit">Add to Cart</button>
                </form>
            </div>
        `).join('');
    
    const content = `
        <h1>Shop</h1>
        <div class="alert alert-info">
            <strong>Business Logic Tests:</strong>
            <ul>
                <li>Modify hidden "price" field</li>
                <li>Try negative/zero quantities</li>
                <li>POST to /api/checkout with tampered values</li>
            </ul>
        </div>
        ${productsHtml}
    `;
    res.send(renderPage('Shop', content, user));
});

app.post('/cart/add', (req, res) => {
    const user = getCurrentUser(req);
    const { product_id, price, quantity } = req.body;
    
    // VULN: Trusting client price, not validating quantity
    const total = parseFloat(price) * parseInt(quantity);
    
    const content = `
        <h1>Cart Updated</h1>
        <div class="alert alert-success">
            Added ${quantity} x ${product_id} at $${price} each = $${total} total
        </div>
        <div class="alert alert-error">
            <strong>VULN:</strong> Price from hidden field (tamperable)! Quantity not validated!
        </div>
        <a href="/shop">Continue Shopping</a> | <a href="/checkout">Checkout</a>
    `;
    res.send(renderPage('Cart', content, user));
});

app.get('/checkout', (req, res) => {
    const user = getCurrentUser(req);
    if (!user) return res.redirect('/login');
    
    const content = `
        <h1>Checkout</h1>
        <form method="POST" action="/api/checkout">
            <div class="card">
                <h3>Order Summary</h3>
                <input type="hidden" name="product_id" value="PROD001">
                <input type="hidden" name="original_price" value="299.99">
                
                <p>Product: Premium Headphones</p>
                <p><label>Price: $</label>
                    <input type="number" name="price" value="299.99" step="0.01">
                    <small>(VULN: editable!)</small>
                </p>
                <p><label>Quantity:</label>
                    <input type="number" name="quantity" value="1">
                    <small>(VULN: try -1 or 0)</small>
                </p>
                <p><label>Discount %:</label>
                    <input type="number" name="discount" value="0">
                    <small>(VULN: try 100 or 150)</small>
                </p>
                <p><label>Promo Code:</label>
                    <input type="text" name="promo_code" placeholder="SAVE10, SAVE20, VIP50">
                </p>
                <input type="hidden" name="is_eligible" value="false">
            </div>
            <button type="submit">Complete Purchase</button>
        </form>
    `;
    res.send(renderPage('Checkout', content, user));
});

// VULN: Business Logic Tampering endpoint
app.post('/api/checkout', (req, res) => {
    const user = getCurrentUser(req);
    if (!user) return res.status(401).json({ error: 'Unauthorized' });
    
    const data = req.body;
    const productId = data.product_id || 'PROD001';
    
    // VULN: Trusting all client values!
    const price = parseFloat(data.price || 0);
    const quantity = parseInt(data.quantity || 1);
    const discount = parseFloat(data.discount || 0);
    const isEligible = data.is_eligible === 'true';
    const promoCode = (data.promo_code || '').toUpperCase();
    
    let totalDiscount = discount;
    if (isEligible) totalDiscount += 20;
    if (VALID_PROMOS[promoCode]) totalDiscount += VALID_PROMOS[promoCode];
    
    const subtotal = price * quantity;
    const discountAmount = subtotal * (totalDiscount / 100);
    const total = subtotal - discountAmount;
    
    const vulnerabilitiesExploited = [];
    if (PRODUCTS[productId] && price !== PRODUCTS[productId].price) {
        vulnerabilitiesExploited.push('BL-PRICE-001: Price tampering');
    }
    if (quantity <= 0) {
        vulnerabilitiesExploited.push('BL-QTY-001: Invalid quantity');
    }
    if (discount > 100 || discount < 0) {
        vulnerabilitiesExploited.push('BL-PROMO-001: Invalid discount');
    }
    if (isEligible) {
        vulnerabilitiesExploited.push('BL-HIDDEN-001: Hidden field tampering');
    }
    
    res.json({
        status: 'success',
        message: 'Order processed successfully',
        order: {
            product_id: productId,
            price_used: price,
            quantity,
            discount_percent: totalDiscount,
            subtotal: subtotal.toFixed(2),
            discount_amount: discountAmount.toFixed(2),
            total: total.toFixed(2),
            charged_to: user.username
        },
        vulnerabilities_exploited: vulnerabilitiesExploited
    });
});

// ============================================================================
// ACCESS LEVEL ROLE COVERAGE
// ============================================================================

app.get('/api/admin-only', (req, res) => {
    const user = getCurrentUser(req);
    if (!user) return res.status(401).json({ error: 'Authentication required' });
    if (user.role !== 'admin') return res.status(403).json({ error: 'Admin access required' });
    res.json({ message: 'Admin data', secret: 'admin-secret-123' });
});

app.get('/api/moderator-only', (req, res) => {
    const user = getCurrentUser(req);
    if (!user) return res.status(401).json({ error: 'Authentication required' });
    if (!['admin', 'moderator'].includes(user.role)) {
        return res.status(403).json({ error: 'Moderator access required' });
    }
    res.json({ message: 'Moderator data', reports: [1, 2, 3] });
});

app.get('/api/user-data', (req, res) => {
    const user = getCurrentUser(req);
    if (!user) return res.status(401).json({ error: 'Authentication required' });
    res.json({ message: 'User data', username: user.username, role: user.role });
});

app.get('/api/test-auth', (req, res) => {
    const user = getCurrentUser(req);
    if (user) {
        return res.json({ authenticated: true, user });
    }
    res.status(401).json({ authenticated: false });
});

// ============================================================================
// START SERVER
// ============================================================================

const PORT = 5001;
app.listen(PORT, () => {
    console.log('='.repeat(60));
    console.log('Vulnerable Demo Application (Node.js)');
    console.log('='.repeat(60));
    console.log(`\nServer running at http://localhost:${PORT}`);
    console.log('\nTest Credentials:');
    console.log('  admin:admin123 | moderator:mod123 | user1:user123 | user2:pass456');
    console.log('\n' + '='.repeat(60));
});
