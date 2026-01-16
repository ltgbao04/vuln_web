# Vulnerable Demo Applications

This directory contains intentionally vulnerable web applications for testing the RedSwarm security scanner's detection modules.

## Overview

Each application implements the **same vulnerabilities** in different languages, allowing you to test with your preferred stack:

| Application | Language | Port | Command |
|------------|----------|------|---------|
| `app_comprehensive.py` | Python/Flask | 5000 | `python app_comprehensive.py` |
| `app_comprehensive.js` | Node.js/Express | 5001 | `node app_comprehensive.js` |
| `app_comprehensive.php` | PHP | 5002 | `php -S localhost:5002 app_comprehensive.php` |

## Implemented Vulnerabilities

### 1. Session Fixation (SESS-FIX-001)
- **WSTG:** WSTG-SESS-04
- **Description:** Session ID is NOT rotated after successful login
- **Test:** Note session_id cookie before login, verify it stays the same after login
- **Affected endpoints:** `/login` → `/dashboard`

### 2. Predictable Session ID (SESS-PRED-001)
- **WSTG:** WSTG-SESS-03
- **Description:** Session IDs are `base64(timestamp:counter)` - easily predictable
- **Test:** Decode session_id, predict next values, forge sessions

### 3. IDOR - Insecure Direct Object Reference (IDOR-001)
- **WSTG:** WSTG-ATHZ-04
- **Description:** Access other users' data by changing ID parameters
- **Test endpoints:**
  - `/api/profile?id=1` through `id=4`
  - `/api/user/1` through `/api/user/4`
  - `/api/order/1001` through `/api/order/1004`

### 4. Forced Browsing Auth Bypass (FB-001)
- **WSTG:** WSTG-ATHZ-01
- **Description:** Protected resources accessible without authentication
- **Test endpoints (no auth required):**
  - `/admin/users` - Lists all users with sensitive data
  - `/admin/settings` - Exposes database credentials
  - `/api/reports` - Confidential financial reports
  - `/api/admin/stats` - Admin statistics with password hash

### 5. Business Logic Tampering (BL-*)
- **WSTG:** WSTG-BUSL-*
- **Description:** Multiple business logic flaws in checkout process

| ID | Vulnerability | Test |
|----|--------------|------|
| BL-PRICE-001 | Price Tampering | Change `price` field to `0.01` |
| BL-QTY-001 | Quantity Manipulation | Set `quantity=-1` or `quantity=0` |
| BL-PROMO-001 | Discount Bypass | Set `discount=100` or `discount=150` |
| BL-HIDDEN-001 | Hidden Field Tampering | Set `is_eligible=true` |

- **Test endpoint:** POST `/api/checkout`
- **Test via UI:** `/checkout` page

### 6. Access Level Role Coverage (AC-ROLE-001)
- **WSTG:** WSTG-ATHZ-02
- **Description:** Multi-role system for testing authorization coverage
- **Roles:**
  - `admin` (privilege_priority: 1)
  - `moderator` (privilege_priority: 2)
  - `user` (privilege_priority: 3)
- **Test endpoints:**
  - `/api/admin-only` - Requires admin role
  - `/api/moderator-only` - Requires moderator or admin role
  - `/api/user-data` - Requires any authenticated user

## Test Credentials

| Username | Password | Role | Privilege |
|----------|----------|------|-----------|
| admin | admin123 | admin | 1 |
| moderator | mod123 | moderator | 2 |
| user1 | user123 | user | 3 |
| user2 | pass456 | user | 3 |

## Quick Start

### Python (Flask)
```bash
cd temp/vuln_demo_apps
pip install flask
python app_comprehensive.py
# Open http://localhost:5000
```

### Node.js (Express)
```bash
cd temp/vuln_demo_apps
npm install express cookie-parser
node app_comprehensive.js
# Open http://localhost:5001
```

### PHP
```bash
cd temp/vuln_demo_apps
php -S localhost:5002 app_comprehensive.php
# Open http://localhost:5002
```

## Running the Scanner

Use the provided `auth_config_demo.json` for scanner integration:

```bash
python pentester.py http://localhost:5000 --credential temp/vuln_demo_apps/auth_config_demo.json
```

## Mapping to Test Cases

| Test Case File | Vulnerability ID | Demo Endpoint |
|---------------|-----------------|---------------|
| Session_Fixation.yaml | SESS-FIX-001 | `/login` |
| Session_ID_Predictability.yaml | SESS-PRED-001 | Session cookie |
| IDOR_Parameter_Manipulation.yaml | IDOR-001 | `/api/profile`, `/api/order/*`, `/api/user/*` |
| Forced_Browsing_Auth_Bypass.yaml | FB-001 | `/admin/*`, `/api/reports`, `/api/admin/stats` |
| Business_Logic_Tampering.yaml | BL-* | `/api/checkout`, `/shop`, `/checkout` |
| Access_Level_Role_Coverage.yaml | AC-ROLE-001 | All endpoints with role checks |

## API Examples

### IDOR Test
```bash
# Login as user1
curl -c cookies.txt -b cookies.txt -X POST http://localhost:5000/login \
  -d "username=user1&password=user123"

# Access own profile (id=3)
curl -b cookies.txt http://localhost:5000/api/profile?id=3

# IDOR: Access admin profile (id=1)
curl -b cookies.txt http://localhost:5000/api/profile?id=1
```

### Forced Browsing Test
```bash
# No login required - direct access to sensitive data
curl http://localhost:5000/admin/users
curl http://localhost:5000/api/reports
curl http://localhost:5000/api/admin/stats
```

### Business Logic Test
```bash
# Login first
curl -c cookies.txt -b cookies.txt -X POST http://localhost:5000/login \
  -d "username=user1&password=user123"

# Price tampering - pay $0.01 for $299.99 product
curl -b cookies.txt -X POST http://localhost:5000/api/checkout \
  -d "product_id=PROD001&price=0.01&quantity=1&discount=0"

# Negative quantity
curl -b cookies.txt -X POST http://localhost:5000/api/checkout \
  -d "product_id=PROD001&price=299.99&quantity=-1&discount=0"

# 100% discount
curl -b cookies.txt -X POST http://localhost:5000/api/checkout \
  -d "product_id=PROD001&price=299.99&quantity=1&discount=100"
```

## Notes

- All applications contain **intentional security vulnerabilities** for testing purposes
- **DO NOT** deploy these applications in production or expose them to untrusted networks
- The vulnerabilities are designed to match the detection patterns in RedSwarm's detection modules
