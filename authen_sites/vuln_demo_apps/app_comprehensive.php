<?php
/**
 * Comprehensive Vulnerable Demo Application (PHP)
 * ================================================
 * 
 * Single-file PHP application with all vulnerabilities:
 * 1. Session Fixation (SESS-FIX-001)
 * 2. Predictable Session ID (SESS-PRED-001)
 * 3. IDOR Parameter Manipulation (IDOR-001)
 * 4. Forced Browsing Auth Bypass (FB-001)
 * 5. Business Logic Tampering (BL-*)
 * 6. Access Level Role Coverage (AC-ROLE-001)
 * 
 * Run: php -S localhost:5002 app_comprehensive.php
 * Access: http://localhost:5002
 */

// VULN: Weak session configuration
ini_set('session.use_strict_mode', '0');
ini_set('session.use_only_cookies', '1');

// ============================================================================
// DATABASE SIMULATION
// ============================================================================

$USERS = [
    'admin' => ['password' => 'admin123', 'role' => 'admin', 'privilege_priority' => 1, 'email' => 'admin@company.com', 'balance' => 10000],
    'moderator' => ['password' => 'mod123', 'role' => 'moderator', 'privilege_priority' => 2, 'email' => 'mod@company.com', 'balance' => 5000],
    'user1' => ['password' => 'user123', 'role' => 'user', 'privilege_priority' => 3, 'email' => 'user1@example.com', 'balance' => 1000],
    'user2' => ['password' => 'pass456', 'role' => 'user', 'privilege_priority' => 3, 'email' => 'user2@example.com', 'balance' => 500]
];

$ORDERS = [
    '1001' => ['user' => 'user1', 'product' => 'Laptop', 'amount' => 999.99, 'status' => 'completed'],
    '1002' => ['user' => 'user1', 'product' => 'Mouse', 'amount' => 49.99, 'status' => 'pending'],
    '1003' => ['user' => 'user2', 'product' => 'Keyboard', 'amount' => 79.99, 'status' => 'completed'],
    '1004' => ['user' => 'admin', 'product' => 'Server', 'amount' => 5000.00, 'status' => 'processing']
];

$PROFILES = [
    '1' => ['username' => 'admin', 'ssn' => '123-45-6789', 'phone' => '555-0001', 'address' => 'Admin Tower'],
    '2' => ['username' => 'moderator', 'ssn' => '234-56-7890', 'phone' => '555-0002', 'address' => 'Mod Street'],
    '3' => ['username' => 'user1', 'ssn' => '345-67-8901', 'phone' => '555-0003', 'address' => '123 User Lane'],
    '4' => ['username' => 'user2', 'ssn' => '456-78-9012', 'phone' => '555-0004', 'address' => '456 User Ave']
];

$PRODUCTS = [
    'PROD001' => ['name' => 'Premium Headphones', 'price' => 299.99, 'stock' => 50],
    'PROD002' => ['name' => 'Wireless Mouse', 'price' => 49.99, 'stock' => 100],
    'PROD003' => ['name' => 'Mechanical Keyboard', 'price' => 149.99, 'stock' => 30]
];

$VALID_PROMOS = ['SAVE10' => 10, 'SAVE20' => 20, 'VIP50' => 50];

// ============================================================================
// ROUTING
// ============================================================================

$request_uri = $_SERVER['REQUEST_URI'];
$request_method = $_SERVER['REQUEST_METHOD'];
$path = parse_url($request_uri, PHP_URL_PATH);

// Start session
session_start();

// API Routes (JSON responses)
if (strpos($path, '/api/') === 0) {
    header('Content-Type: application/json');
    
    if ($path === '/api/profile') {
        handleApiProfile();
    } elseif (preg_match('/^\/api\/user\/(\d+)$/', $path, $matches)) {
        handleApiUser($matches[1]);
    } elseif (preg_match('/^\/api\/order\/(\d+)$/', $path, $matches)) {
        handleApiOrder($matches[1]);
    } elseif ($path === '/api/reports') {
        handleApiReports();
    } elseif ($path === '/api/admin/stats') {
        handleApiAdminStats();
    } elseif ($path === '/api/checkout' && $request_method === 'POST') {
        handleApiCheckout();
    } elseif ($path === '/api/admin-only') {
        handleApiAdminOnly();
    } elseif ($path === '/api/moderator-only') {
        handleApiModeratorOnly();
    } elseif ($path === '/api/user-data') {
        handleApiUserData();
    } elseif ($path === '/api/test-auth') {
        handleApiTestAuth();
    } else {
        http_response_code(404);
        echo json_encode(['error' => 'Not found']);
    }
    exit;
}

// Page Routes (HTML responses)
switch ($path) {
    case '/':
    case '/index.php':
        showHomePage();
        break;
    case '/login':
        handleLogin();
        break;
    case '/logout':
        handleLogout();
        break;
    case '/dashboard':
        showDashboard();
        break;
    case '/profile':
        showProfile();
        break;
    case '/orders':
        showOrders();
        break;
    case '/shop':
        showShop();
        break;
    case '/checkout':
        showCheckout();
        break;
    case '/cart/add':
        handleCartAdd();
        break;
    case '/admin':
        showAdmin();
        break;
    case '/admin/users':
        showAdminUsers();
        break;
    case '/admin/settings':
        showAdminSettings();
        break;
    default:
        http_response_code(404);
        echo "Page not found";
}

// ============================================================================
// HELPER FUNCTIONS
// ============================================================================

function getCurrentUser() {
    return isset($_SESSION['user']) ? $_SESSION['user'] : null;
}

function generateWeakSessionId() {
    // VULN: Predictable session ID
    static $counter = 1000;
    $counter++;
    return base64_encode(time() . ':' . $counter);
}

function renderPage($title, $content) {
    global $USERS;
    $user = getCurrentUser();
    $userNav = $user 
        ? '<a href="/logout" style="float:right;">Logout (' . htmlspecialchars($user['username']) . ')</a>'
        : '<a href="/login" style="float:right;">Login</a>';
    
    echo <<<HTML
<!DOCTYPE html>
<html>
<head>
    <title>VulnDemo - {$title}</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 40px; background: #f5f5f5; }
        .container { max-width: 800px; margin: 0 auto; background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
        h1 { color: #333; }
        .nav { background: #8b0000; padding: 10px; margin-bottom: 20px; border-radius: 4px; }
        .nav a { color: white; margin-right: 15px; text-decoration: none; }
        .nav a:hover { text-decoration: underline; }
        .alert { padding: 10px; margin: 10px 0; border-radius: 4px; }
        .alert-success { background: #d4edda; color: #155724; }
        .alert-error { background: #f8d7da; color: #721c24; }
        .alert-info { background: #d1ecf1; color: #0c5460; }
        form { margin: 20px 0; }
        input, button { padding: 10px; margin: 5px 0; }
        input[type="text"], input[type="password"], input[type="number"] { width: 200px; }
        button { background: #8b0000; color: white; border: none; cursor: pointer; border-radius: 4px; }
        button:hover { background: #5c0000; }
        table { width: 100%; border-collapse: collapse; margin: 20px 0; }
        th, td { padding: 10px; border: 1px solid #ddd; text-align: left; }
        th { background: #f8f9fa; }
        .card { border: 1px solid #ddd; padding: 15px; margin: 10px 0; border-radius: 4px; }
        pre { background: #f4f4f4; padding: 10px; overflow-x: auto; }
        .debug { background: #fff3cd; padding: 10px; margin: 10px 0; font-size: 12px; }
        .badge { display: inline-block; padding: 2px 8px; border-radius: 3px; font-size: 12px; }
        .badge-php { background: #777bb4; color: white; }
    </style>
</head>
<body>
    <div class="container">
        <div class="nav">
            <span class="badge badge-php">PHP</span>
            <a href="/">Home</a>
            <a href="/dashboard">Dashboard</a>
            <a href="/profile">Profile</a>
            <a href="/orders">Orders</a>
            <a href="/shop">Shop</a>
            <a href="/admin">Admin</a>
            {$userNav}
        </div>
        {$content}
    </div>
</body>
</html>
HTML;
}

// ============================================================================
// PAGE HANDLERS
// ============================================================================

function showHomePage() {
    $content = <<<HTML
    <h1>Vulnerable Demo Application (PHP)</h1>
    <p>This is the PHP version running on port 5002.</p>
    <p>Same vulnerabilities as Python (5000) and Node.js (5001) versions.</p>
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
HTML;
    renderPage('Home', $content);
}

function handleLogin() {
    global $USERS;
    
    // VULN: Session Fixation - NOT regenerating session ID
    $sessionId = session_id();
    
    if ($_SERVER['REQUEST_METHOD'] === 'POST') {
        $username = $_POST['username'] ?? '';
        $password = $_POST['password'] ?? '';
        
        if (isset($USERS[$username]) && $USERS[$username]['password'] === $password) {
            // VULN: NOT calling session_regenerate_id()!
            $_SESSION['user'] = [
                'username' => $username,
                'role' => $USERS[$username]['role'],
                'privilege_priority' => $USERS[$username]['privilege_priority'],
                'email' => $USERS[$username]['email'],
                'balance' => $USERS[$username]['balance']
            ];
            header('Location: /dashboard');
            exit;
        }
        
        $error = '<div class="alert alert-error">Invalid credentials</div>';
    } else {
        $error = '';
    }
    
    $content = <<<HTML
    <h1>Login</h1>
    <div class="alert alert-info">
        <strong>Test Credentials:</strong><br>
        admin:admin123 | moderator:mod123 | user1:user123 | user2:pass456
    </div>
    {$error}
    <form method="POST" action="/login">
        <div><label>Username:</label><br><input type="text" name="username" required></div>
        <div><label>Password:</label><br><input type="password" name="password" required></div>
        <div><button type="submit">Login</button></div>
    </form>
    <div class="debug">
        <strong>Session Fixation Test:</strong> PHPSESSID: {$sessionId}
    </div>
HTML;
    renderPage('Login', $content);
}

function handleLogout() {
    session_destroy();
    header('Location: /');
    exit;
}

function showDashboard() {
    $user = getCurrentUser();
    if (!$user) {
        header('Location: /login');
        exit;
    }
    
    $sessionId = session_id();
    $content = <<<HTML
    <h1>Dashboard</h1>
    <div class="alert alert-success">Welcome, {$user['username']}! (Role: {$user['role']})</div>
    <div class="card">
        <h3>Your Account</h3>
        <p>Email: {$user['email']}</p>
        <p>Balance: \${$user['balance']}</p>
        <p>Privilege Level: {$user['privilege_priority']}</p>
    </div>
    <div class="debug">
        <strong>Debug:</strong> PHPSESSID: {$sessionId}
    </div>
HTML;
    renderPage('Dashboard', $content);
}

function showProfile() {
    global $PROFILES;
    $user = getCurrentUser();
    if (!$user) {
        header('Location: /login');
        exit;
    }
    
    $profileId = 1;
    foreach ($PROFILES as $pid => $profile) {
        if ($profile['username'] === $user['username']) {
            $profileId = $pid;
            break;
        }
    }
    
    $content = <<<HTML
    <h1>My Profile</h1>
    <div class="card">
        <p><strong>Profile ID:</strong> {$profileId}</p>
        <p><strong>Username:</strong> {$user['username']}</p>
        <p><strong>Email:</strong> {$user['email']}</p>
    </div>
    <div class="alert alert-info">
        <strong>IDOR Test:</strong> Try /api/profile?id=1 through id=4
    </div>
HTML;
    renderPage('Profile', $content);
}

function showOrders() {
    global $ORDERS;
    $user = getCurrentUser();
    if (!$user) {
        header('Location: /login');
        exit;
    }
    
    $rows = '';
    foreach ($ORDERS as $oid => $order) {
        if ($order['user'] === $user['username']) {
            $rows .= "<tr><td>{$oid}</td><td>{$order['product']}</td><td>\${$order['amount']}</td><td>{$order['status']}</td><td><a href='/api/order/{$oid}'>View API</a></td></tr>";
        }
    }
    
    $content = <<<HTML
    <h1>My Orders</h1>
    <table>
        <tr><th>Order ID</th><th>Product</th><th>Amount</th><th>Status</th><th>API</th></tr>
        {$rows}
    </table>
    <div class="alert alert-info">
        <strong>IDOR Test:</strong> Try /api/order/1001, /api/order/1003, /api/order/1004
    </div>
HTML;
    renderPage('Orders', $content);
}

function showShop() {
    global $PRODUCTS;
    $user = getCurrentUser();
    
    $productsHtml = '';
    foreach ($PRODUCTS as $pid => $prod) {
        $productsHtml .= <<<HTML
        <div class="card">
            <h3>{$prod['name']}</h3>
            <p>Price: \${$prod['price']}</p>
            <p>Stock: {$prod['stock']} units</p>
            <form method="POST" action="/cart/add">
                <input type="hidden" name="product_id" value="{$pid}">
                <input type="hidden" name="price" value="{$prod['price']}">
                <input type="number" name="quantity" value="1" min="1" max="10">
                <button type="submit">Add to Cart</button>
            </form>
        </div>
HTML;
    }
    
    $content = <<<HTML
    <h1>Shop</h1>
    <div class="alert alert-info">
        <strong>Business Logic Tests:</strong>
        <ul>
            <li>Modify hidden "price" field</li>
            <li>Try negative/zero quantities</li>
            <li>POST to /api/checkout with tampered values</li>
        </ul>
    </div>
    {$productsHtml}
HTML;
    renderPage('Shop', $content);
}

function handleCartAdd() {
    $product_id = $_POST['product_id'] ?? '';
    $price = floatval($_POST['price'] ?? 0);
    $quantity = intval($_POST['quantity'] ?? 1);
    $total = $price * $quantity;
    
    $content = <<<HTML
    <h1>Cart Updated</h1>
    <div class="alert alert-success">
        Added {$quantity} x {$product_id} at \${$price} each = \${$total} total
    </div>
    <div class="alert alert-error">
        <strong>VULN:</strong> Price from hidden field (tamperable)! Quantity not validated!
    </div>
    <a href="/shop">Continue Shopping</a> | <a href="/checkout">Checkout</a>
HTML;
    renderPage('Cart', $content);
}

function showCheckout() {
    $user = getCurrentUser();
    if (!$user) {
        header('Location: /login');
        exit;
    }
    
    $content = <<<HTML
    <h1>Checkout</h1>
    <form method="POST" action="/api/checkout">
        <div class="card">
            <h3>Order Summary</h3>
            <input type="hidden" name="product_id" value="PROD001">
            <input type="hidden" name="original_price" value="299.99">
            
            <p>Product: Premium Headphones</p>
            <p><label>Price: \$</label>
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
HTML;
    renderPage('Checkout', $content);
}

function showAdmin() {
    $content = <<<HTML
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
HTML;
    renderPage('Admin', $content);
}

function showAdminUsers() {
    global $USERS;
    // VULN: No authentication check!
    
    $rows = '';
    foreach ($USERS as $username => $data) {
        $rows .= "<tr><td>{$username}</td><td>{$data['email']}</td><td>{$data['role']}</td><td>\${$data['balance']}</td></tr>";
    }
    
    $content = <<<HTML
    <h1>User Management</h1>
    <div class="alert alert-error">
        <strong>VULN:</strong> No authentication check - forced browsing possible!
    </div>
    <table>
        <tr><th>Username</th><th>Email</th><th>Role</th><th>Balance</th></tr>
        {$rows}
    </table>
HTML;
    renderPage('User Management', $content);
}

function showAdminSettings() {
    // VULN: No authentication check!
    $content = <<<HTML
    <h1>System Settings</h1>
    <div class="alert alert-error">
        <strong>VULN:</strong> Sensitive configuration exposed without authentication!
    </div>
    <div class="card">
        <pre>
DATABASE_URL = mysql://root:password123@localhost/production
API_KEY = sk_live_php_abcdef123456789
AWS_SECRET = AKIAIOSFODNN7EXAMPLE
SMTP_PASSWORD = email_p@ssw0rd!
        </pre>
    </div>
HTML;
    renderPage('Settings', $content);
}

// ============================================================================
// API HANDLERS
// ============================================================================

function handleApiProfile() {
    global $PROFILES;
    $user = getCurrentUser();
    if (!$user) {
        http_response_code(401);
        echo json_encode(['error' => 'Unauthorized']);
        return;
    }
    
    $profileId = $_GET['id'] ?? '1';
    
    // VULN: No authorization check!
    if (isset($PROFILES[$profileId])) {
        echo json_encode(['profile_id' => $profileId, 'data' => $PROFILES[$profileId]]);
    } else {
        http_response_code(404);
        echo json_encode(['error' => 'Profile not found']);
    }
}

function handleApiUser($userId) {
    global $USERS;
    $user = getCurrentUser();
    if (!$user) {
        http_response_code(401);
        echo json_encode(['error' => 'Unauthorized']);
        return;
    }
    
    $userMap = ['1' => 'admin', '2' => 'moderator', '3' => 'user1', '4' => 'user2'];
    
    // VULN: No authorization check!
    if (isset($userMap[$userId])) {
        $username = $userMap[$userId];
        echo json_encode([
            'user_id' => $userId,
            'username' => $username,
            'email' => $USERS[$username]['email'],
            'role' => $USERS[$username]['role'],
            'balance' => $USERS[$username]['balance']
        ]);
    } else {
        http_response_code(404);
        echo json_encode(['error' => 'User not found']);
    }
}

function handleApiOrder($orderId) {
    global $ORDERS;
    $user = getCurrentUser();
    if (!$user) {
        http_response_code(401);
        echo json_encode(['error' => 'Unauthorized']);
        return;
    }
    
    // VULN: No authorization check!
    if (isset($ORDERS[$orderId])) {
        echo json_encode(['order_id' => $orderId, 'order' => $ORDERS[$orderId]]);
    } else {
        http_response_code(404);
        echo json_encode(['error' => 'Order not found']);
    }
}

function handleApiReports() {
    // VULN: No authentication check!
    echo json_encode([
        'reports' => [
            ['id' => 1, 'title' => 'Financial Report Q4', 'revenue' => 1250000, 'profit' => 340000],
            ['id' => 2, 'title' => 'User Analytics', 'total_users' => 50000, 'active' => 12000],
            ['id' => 3, 'title' => 'Security Audit', 'vulnerabilities' => 15, 'critical' => 3]
        ],
        'generated_at' => date('Y-m-d'),
        'confidential' => true
    ]);
}

function handleApiAdminStats() {
    global $USERS;
    // VULN: No authentication check!
    echo json_encode([
        'total_revenue' => 5000000,
        'total_users' => count($USERS),
        'admin_password_hash' => md5('admin123'),
        'database_connection_string' => 'mysql://admin:secret@localhost/prod'
    ]);
}

function handleApiCheckout() {
    global $PRODUCTS, $VALID_PROMOS;
    $user = getCurrentUser();
    if (!$user) {
        http_response_code(401);
        echo json_encode(['error' => 'Unauthorized']);
        return;
    }
    
    $productId = $_POST['product_id'] ?? 'PROD001';
    $price = floatval($_POST['price'] ?? 0);
    $quantity = intval($_POST['quantity'] ?? 1);
    $discount = floatval($_POST['discount'] ?? 0);
    $isEligible = ($_POST['is_eligible'] ?? 'false') === 'true';
    $promoCode = strtoupper($_POST['promo_code'] ?? '');
    
    $totalDiscount = $discount;
    if ($isEligible) $totalDiscount += 20;
    if (isset($VALID_PROMOS[$promoCode])) $totalDiscount += $VALID_PROMOS[$promoCode];
    
    $subtotal = $price * $quantity;
    $discountAmount = $subtotal * ($totalDiscount / 100);
    $total = $subtotal - $discountAmount;
    
    $vulns = [];
    if (isset($PRODUCTS[$productId]) && $price != $PRODUCTS[$productId]['price']) {
        $vulns[] = 'BL-PRICE-001: Price tampering';
    }
    if ($quantity <= 0) $vulns[] = 'BL-QTY-001: Invalid quantity';
    if ($discount > 100 || $discount < 0) $vulns[] = 'BL-PROMO-001: Invalid discount';
    if ($isEligible) $vulns[] = 'BL-HIDDEN-001: Hidden field tampering';
    
    echo json_encode([
        'status' => 'success',
        'message' => 'Order processed successfully',
        'order' => [
            'product_id' => $productId,
            'price_used' => $price,
            'quantity' => $quantity,
            'discount_percent' => $totalDiscount,
            'subtotal' => round($subtotal, 2),
            'discount_amount' => round($discountAmount, 2),
            'total' => round($total, 2),
            'charged_to' => $user['username']
        ],
        'vulnerabilities_exploited' => $vulns
    ]);
}

function handleApiAdminOnly() {
    $user = getCurrentUser();
    if (!$user) {
        http_response_code(401);
        echo json_encode(['error' => 'Authentication required']);
        return;
    }
    if ($user['role'] !== 'admin') {
        http_response_code(403);
        echo json_encode(['error' => 'Admin access required']);
        return;
    }
    echo json_encode(['message' => 'Admin data', 'secret' => 'admin-secret-123']);
}

function handleApiModeratorOnly() {
    $user = getCurrentUser();
    if (!$user) {
        http_response_code(401);
        echo json_encode(['error' => 'Authentication required']);
        return;
    }
    if (!in_array($user['role'], ['admin', 'moderator'])) {
        http_response_code(403);
        echo json_encode(['error' => 'Moderator access required']);
        return;
    }
    echo json_encode(['message' => 'Moderator data', 'reports' => [1, 2, 3]]);
}

function handleApiUserData() {
    $user = getCurrentUser();
    if (!$user) {
        http_response_code(401);
        echo json_encode(['error' => 'Authentication required']);
        return;
    }
    echo json_encode(['message' => 'User data', 'username' => $user['username'], 'role' => $user['role']]);
}

function handleApiTestAuth() {
    $user = getCurrentUser();
    if ($user) {
        echo json_encode(['authenticated' => true, 'user' => $user]);
    } else {
        http_response_code(401);
        echo json_encode(['authenticated' => false]);
    }
}
?>
