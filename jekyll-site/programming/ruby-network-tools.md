---
layout: training-page
title: "Ruby Network Tools — Red Team Academy"
module: "Programming"
tags:
  - ruby
  - network-tools
  - red-team
  - reconnaissance
page_key: "prog-ruby-network-tools"
render_with_liquid: false
---

# Ruby Network Tools

Three complete network reconnaissance tools written in pure Ruby stdlib. No external gem dependencies — only `socket`, `resolv`, `net/http`, `openssl`, `uri`, `json`, and `optparse`, which all ship with Ruby 3.3+.

---

## Tool 1: HTTP Recon & Fingerprinting Tool

Accepts one or more target URLs (or a file), performs HEAD and GET requests, extracts security headers, detects WAF signatures, and checks for common sensitive paths.

```ruby
#!/usr/bin/env ruby
# http_recon.rb
#
# Usage:
#   ruby http_recon.rb https://target.local
#   ruby http_recon.rb --file targets.txt --output report.json
#   ruby http_recon.rb https://target.local https://target2.local
#
# Produces: formatted terminal output + JSON file

require 'net/http'
require 'openssl'
require 'uri'
require 'json'
require 'optparse'

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

INTERESTING_PATHS = %w[
  /robots.txt /sitemap.xml /.git/HEAD /.git/config /.env /.env.local
  /wp-admin /wp-login.php /phpinfo.php /server-status /server-info
  /.htaccess /admin /admin.php /administrator /backup /api /api/v1
  /swagger /swagger-ui.html /openapi.json /actuator /actuator/env
  /console /phpmyadmin /adminer.php /.DS_Store /.svn/entries
  /web.config /crossdomain.xml /clientaccesspolicy.xml
  /readme.html /readme.md /CHANGELOG.txt /CHANGELOG.md
].freeze

SECURITY_HEADERS = %w[
  Strict-Transport-Security
  Content-Security-Policy
  X-Frame-Options
  X-Content-Type-Options
  X-XSS-Protection
  Referrer-Policy
  Permissions-Policy
  Access-Control-Allow-Origin
  X-Permitted-Cross-Domain-Policies
].freeze

WAF_SIGNATURES = {
  'Cloudflare'         => [/cf-ray|cloudflare/i, /__cfduid|cf_clearance/i],
  'AWS WAF'            => [/x-amzn-requestid|awswaf/i, nil],
  'Akamai'             => [/akamai|x-akamai-transformed/i, /ak_bmsc/i],
  'F5 BIG-IP'          => [/BIGipServer/i, /F5-TrafficShield/i],
  'Imperva / Incapsula' => [/incapsula|x-iinfo/i, /visid_incap|incap_ses/i],
  'ModSecurity'        => [/mod_security|modsecurity/i, nil],
  'Sucuri'             => [/sucuri|x-sucuri-id/i, nil],
  'Barracuda'          => [/barracuda/i, /barra_counter_session/i],
  'Nginx + Naxsi'      => [/naxsi/i, nil],
  'Wordfence'          => [nil, /wordfence/i]
}.freeze

# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------

options = { urls: [], output: 'http_recon.json', timeout: 10, verbose: false }

OptionParser.new do |opts|
  opts.banner = "Usage: #{$0} [--file FILE] [--output FILE] [--timeout N] [URL ...]"
  opts.on('--file FILE',    'File containing target URLs (one per line)') { |f| options[:file] = f }
  opts.on('--output FILE',  'JSON output filename', "Default: #{options[:output]}") { |f| options[:output] = f }
  opts.on('--timeout N',    Integer, "HTTP timeout in seconds (default: #{options[:timeout]})") { |n| options[:timeout] = n }
  opts.on('-v', '--verbose', 'Verbose output') { options[:verbose] = true }
end.parse!

options[:urls] = ARGV.dup
options[:urls] += File.readlines(options[:file], chomp: true).reject(&:empty?) if options[:file]

if options[:urls].empty?
  abort "No targets specified. Use URL arguments or --file FILE."
end

TIMEOUT = options[:timeout]
VERBOSE = options[:verbose]

# ---------------------------------------------------------------------------
# HTTP helpers
# ---------------------------------------------------------------------------

def make_http(uri, timeout)
  http = Net::HTTP.new(uri.host, uri.port)
  http.use_ssl      = (uri.scheme == 'https')
  http.verify_mode  = OpenSSL::SSL::VERIFY_NONE
  http.open_timeout = timeout
  http.read_timeout = timeout
  http
end

def safe_head(url, timeout)
  uri = URI(url)
  make_http(uri, timeout).start do |h|
    req = Net::HTTP::Head.new(uri.request_uri)
    req['User-Agent'] = 'Mozilla/5.0 (compatible; SecurityScanner/1.0)'
    res = h.request(req)
    [res.code.to_i, res.to_hash]
  end
rescue => e
  STDERR.puts "  HEAD #{url} — #{e.class}: #{e.message}" if VERBOSE
  [0, {}]
end

def safe_get(url, timeout)
  uri = URI(url)
  make_http(uri, timeout).start do |h|
    req = Net::HTTP::Get.new(uri.request_uri)
    req['User-Agent'] = 'Mozilla/5.0 (compatible; SecurityScanner/1.0)'
    res = h.request(req)
    [res.code.to_i, res.body.to_s, res.to_hash]
  end
rescue => e
  STDERR.puts "  GET #{url} — #{e.class}: #{e.message}" if VERBOSE
  [0, '', {}]
end

def extract_title(body)
  m = body.match(/<title[^>]*>([^<]*)<\/title>/i)
  m ? m[1].strip[0, 100] : nil
end

def detect_waf(headers_hash, cookies_str)
  detected = []
  headers_str = headers_hash.to_s.downcase
  WAF_SIGNATURES.each do |name, (header_pat, cookie_pat)|
    if (header_pat && headers_str.match?(header_pat)) ||
       (cookie_pat && cookies_str.match?(cookie_pat))
      detected << name
    end
  end
  detected
end

def extract_cookies_info(headers_hash)
  cookies = []
  Array(headers_hash['set-cookie']).each do |sc|
    parts  = sc.split(';').map(&:strip)
    pair   = parts.first.split('=', 2)
    name   = pair[0].strip
    flags  = {
      httponly: parts.any? { |p| p.casecmp?('httponly') },
      secure:   parts.any? { |p| p.casecmp?('secure') },
      samesite: parts.find { |p| p.downcase.start_with?('samesite') }&.split('=', 2)&.last
    }.compact
    cookies << { name: name, flags: flags }
  end
  cookies
end

# ---------------------------------------------------------------------------
# Analyze a single target
# ---------------------------------------------------------------------------

def analyze_target(url, timeout)
  puts "\n[*] Analyzing: #{url}"
  result = { url: url, timestamp: Time.now.utc.iso8601 }

  # --- HEAD request ---
  head_code, head_headers = safe_head(url, timeout)
  result[:head_status] = head_code

  # --- GET request ---
  get_code, body, get_headers = safe_get(url, timeout)
  result[:get_status] = get_code

  # Use whichever headers we got
  headers = head_headers.merge(get_headers)

  # Key headers
  result[:server]           = headers['server']&.first
  result[:x_powered_by]     = headers['x-powered-by']&.first
  result[:content_type]     = headers['content-type']&.first
  result[:title]            = extract_title(body)

  # Security headers
  result[:security_headers] = {}
  SECURITY_HEADERS.each do |h|
    val = headers[h.downcase]&.first
    result[:security_headers][h] = val || 'MISSING'
  end

  # HSTS
  hsts = headers['strict-transport-security']&.first
  result[:hsts] = hsts ? { present: true, value: hsts } : { present: false }

  # Cookies
  cookies_str = headers['set-cookie'].to_a.join(' ')
  result[:cookies] = extract_cookies_info(headers)

  # WAF detection
  result[:waf] = detect_waf(headers, cookies_str)

  # Print header summary
  fmt = "  %-35s %s"
  puts format(fmt, 'Server:',       result[:server] || '(not disclosed)')
  puts format(fmt, 'X-Powered-By:', result[:x_powered_by] || '(not disclosed)')
  puts format(fmt, 'Title:',        result[:title] || '(none)')
  puts format(fmt, 'WAF:',          result[:waf].empty? ? 'Not detected' : result[:waf].join(', '))
  puts format(fmt, 'HSTS:',         result[:hsts][:present] ? result[:hsts][:value] : 'NOT SET')

  # Security headers summary
  missing = SECURITY_HEADERS.reject { |h| headers[h.downcase] }
  puts "  Missing security headers (#{missing.size}): #{missing.join(', ')}" unless missing.empty?

  # Cookie flags
  result[:cookies].each do |ck|
    issues = []
    issues << 'no HttpOnly' unless ck[:flags][:httponly]
    issues << 'no Secure'   unless ck[:flags][:secure]
    puts "  Cookie '#{ck[:name]}': #{issues.join(', ')}" unless issues.empty?
  end

  # --- Check interesting paths ---
  result[:interesting_paths] = []
  base_uri = URI(url)
  base     = "#{base_uri.scheme}://#{base_uri.host}:#{base_uri.port}"

  print "  Checking #{INTERESTING_PATHS.size} paths"
  INTERESTING_PATHS.each do |path|
    check_url = base + path
    code, h   = safe_head(check_url, [timeout, 3].min)
    print '.'
    $stdout.flush
    next if [0, 400, 404, 410].include?(code)

    ct = h['content-type']&.first.to_s.split(';').first.strip
    result[:interesting_paths] << { path: path, code: code, content_type: ct }
    print "\n  [!] #{code} #{path} [#{ct}]"
    print '.'
  end
  puts

  result
end

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

puts "=" * 60
puts "HTTP Recon & Fingerprinting Tool"
puts "Targets : #{options[:urls].size}"
puts "Timeout : #{TIMEOUT}s"
puts "=" * 60

all_results = options[:urls].map { |url| analyze_target(url, TIMEOUT) }

# Write JSON report
File.write(options[:output], JSON.pretty_generate(all_results))
puts "\n[+] JSON report written to: #{options[:output]}"

# Summary table
puts "\n" + "=" * 60
puts "SUMMARY"
puts format("%-40s %-6s %-20s %s", 'URL', 'Code', 'Server', 'WAF')
puts "-" * 80
all_results.each do |r|
  puts format("%-40s %-6s %-20s %s",
    r[:url][0, 38],
    r[:get_status],
    r[:server].to_s[0, 18],
    r[:waf].empty? ? '-' : r[:waf].join(',')
  )
end
```

---

## Tool 2: DNS Enumeration Tool

Enumerates all standard DNS record types for a domain, attempts zone transfers, and brute-forces subdomains using a thread pool. Outputs a JSON report.

```ruby
#!/usr/bin/env ruby
# dns_enum.rb
#
# Usage:
#   ruby dns_enum.rb --domain target.com
#   ruby dns_enum.rb --domain target.com --wordlist /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt
#   ruby dns_enum.rb --domain target.com --wordlist subs.txt --threads 50 --resolver 8.8.8.8 --output results.json
#
# Requires: Ruby 3.3+ stdlib only (resolv)

require 'resolv'
require 'optparse'
require 'json'
require 'thread'

# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------

options = {
  threads:  25,
  resolver: '8.8.8.8',
  output:   nil,
  wordlist: nil,
  timeout:  3
}

OptionParser.new do |opts|
  opts.banner = "Usage: #{$0} --domain DOMAIN [options]"
  opts.on('--domain DOMAIN',    'Target domain (required)')        { |d| options[:domain]   = d }
  opts.on('--wordlist FILE',    'Wordlist for brute-force')        { |f| options[:wordlist] = f }
  opts.on('--resolver IP',      'DNS resolver IP (default: 8.8.8.8)') { |r| options[:resolver] = r }
  opts.on('--threads N',        Integer, 'Thread count (default: 25)') { |n| options[:threads]  = n }
  opts.on('--timeout N',        Integer, 'DNS timeout seconds (default: 3)') { |n| options[:timeout]  = n }
  opts.on('--output FILE',      'JSON output file')                { |f| options[:output]   = f }
end.parse!

abort "Error: --domain is required" unless options[:domain]

DOMAIN   = options[:domain].downcase.chomp('.')
RESOLVER = options[:resolver]
THREADS  = options[:threads]
TIMEOUT  = options[:timeout]
OUTPUT   = options[:output] || "#{DOMAIN}_dns.json"

# ---------------------------------------------------------------------------
# DNS resolver factory — always use the specified resolver
# ---------------------------------------------------------------------------

def make_resolver(server, timeout)
  Resolv::DNS.new(nameserver: [server], search: [], ndots: 1).tap do |r|
    r.timeouts = timeout
  end
end

# ---------------------------------------------------------------------------
# Standard record type enumeration
# ---------------------------------------------------------------------------

RECORD_TYPES = {
  'A'     => Resolv::DNS::Resource::IN::A,
  'AAAA'  => Resolv::DNS::Resource::IN::AAAA,
  'MX'    => Resolv::DNS::Resource::IN::MX,
  'NS'    => Resolv::DNS::Resource::IN::NS,
  'TXT'   => Resolv::DNS::Resource::IN::TXT,
  'CNAME' => Resolv::DNS::Resource::IN::CNAME,
  'SOA'   => Resolv::DNS::Resource::IN::SOA,
  'SRV'   => Resolv::DNS::Resource::IN::SRV,
  'PTR'   => Resolv::DNS::Resource::IN::PTR,
  'CAA'   => Resolv::DNS::Resource::IN::CAA
}.freeze

def query_records(domain, type_class, resolver)
  resolver.getresources(domain, type_class).map do |rr|
    case rr
    when Resolv::DNS::Resource::IN::A, Resolv::DNS::Resource::IN::AAAA
      rr.address.to_s
    when Resolv::DNS::Resource::IN::MX
      "#{rr.preference} #{rr.exchange}"
    when Resolv::DNS::Resource::IN::NS
      rr.name.to_s
    when Resolv::DNS::Resource::IN::TXT
      rr.strings.join(' ')
    when Resolv::DNS::Resource::IN::CNAME
      rr.name.to_s
    when Resolv::DNS::Resource::IN::SOA
      "mname=#{rr.mname} rname=#{rr.rname} serial=#{rr.serial}"
    when Resolv::DNS::Resource::IN::SRV
      "priority=#{rr.priority} weight=#{rr.weight} port=#{rr.port} target=#{rr.target}"
    when Resolv::DNS::Resource::IN::CAA
      "#{rr.flags} #{rr.tag} #{rr.value}"
    else
      rr.to_s
    end
  end
rescue Resolv::ResolvError, Resolv::ResolvTimeout
  []
rescue => e
  []
end

def enumerate_records(domain, resolver)
  puts "[*] Enumerating standard records for #{domain}"
  results = {}
  RECORD_TYPES.each do |type_name, type_class|
    records = query_records(domain, type_class, resolver)
    unless records.empty?
      results[type_name] = records
      records.each { |r| puts "  #{type_name.ljust(6)} #{r}" }
    end
  end
  results
end

# ---------------------------------------------------------------------------
# Zone transfer attempt (AXFR)
# ---------------------------------------------------------------------------

def attempt_axfr(domain, ns_servers)
  puts "\n[*] Attempting zone transfer (AXFR) against #{ns_servers.size} nameserver(s)"
  axfr_results = {}

  ns_servers.each do |ns|
    ns_host = ns.split.last.chomp('.')
    ns_ip   = Resolv.getaddress(ns_host) rescue ns_host

    begin
      # Raw AXFR via TCP using Resolv::DNS
      # Build AXFR query message
      msg = Resolv::DNS::Message.new
      msg.add_question(domain, Resolv::DNS::Resource::IN::ANY)
      # Note: True AXFR requires TCP and specific query type 252
      # Most Ruby stdlib implementations don't support AXFR natively
      # We use a raw TCP socket approach instead

      socket = TCPSocket.new(ns_ip, 53)
      require 'socket'

      # Build DNS AXFR query manually
      qname  = domain.split('.').map { |l| [l.length].pack('C') + l }.join + "\x00"
      query  = "\x00\x01"        # ID: 1
      query += "\x00\x00"        # Flags: standard query
      query += "\x00\x01"        # QDCOUNT: 1
      query += "\x00\x00" * 3   # AN/NS/AR count: 0
      query += qname
      query += "\x00\xFC"        # QTYPE: 252 = AXFR
      query += "\x00\x01"        # QCLASS: IN
      # Prepend 2-byte length for TCP DNS
      tcp_query = [query.bytesize].pack('n') + query

      socket.write(tcp_query)
      socket.flush

      # Read response length
      len_bytes = socket.read(2)
      if len_bytes && len_bytes.bytesize == 2
        length = len_bytes.unpack1('n')
        response = socket.read(length)
        if response && response.bytesize > 0
          # AXFR response detected — parse what we can
          axfr_results[ns_host] = {
            status:   'success',
            raw_size: response.bytesize,
            note:     'AXFR allowed — use dig or dnsrecon for full parse'
          }
          puts "  [+] AXFR success against #{ns_host}! Use: dig axfr #{domain} @#{ns_ip}"
        else
          axfr_results[ns_host] = { status: 'refused' }
          puts "  [-] AXFR refused by #{ns_host}"
        end
      end

      socket.close
    rescue Errno::ECONNREFUSED, Errno::ETIMEDOUT, SocketError => e
      axfr_results[ns_host] = { status: 'unreachable', error: e.message }
      puts "  [-] Cannot reach #{ns_host}: #{e.message}"
    rescue => e
      axfr_results[ns_host] = { status: 'error', error: e.message }
      puts "  [-] AXFR error against #{ns_host}: #{e.message}"
    end
  end

  axfr_results
end

# ---------------------------------------------------------------------------
# DNSSEC NSEC walking (zone enumeration via NSEC chain)
# ---------------------------------------------------------------------------

def nsec_walk(domain, resolver)
  puts "\n[*] Attempting DNSSEC NSEC zone walking..."
  discovered  = []
  current     = domain
  max_iters   = 500

  max_iters.times do
    begin
      # Query NSEC record for current name
      # Resolv doesn't support NSEC natively — we look for Type 47 (NSEC)
      # in additional records from ANY query
      resources = resolver.getresources(current, Resolv::DNS::Resource::IN::ANY)
      nsec = resources.find { |r| r.class.to_s.include?('NSEC') }

      break unless nsec

      # The NSEC next name tells us the next existing name in the zone
      next_name = nsec.respond_to?(:next_name) ? nsec.next_name.to_s : nil
      break if next_name.nil? || next_name == current || next_name == domain

      if next_name.end_with?(domain)
        discovered << next_name
        puts "  [NSEC] Found: #{next_name}"
      end

      current = next_name
      break if current == domain  # Wrapped around
    rescue => e
      break
    end
  end

  if discovered.empty?
    puts "  [-] NSEC walking unsuccessful (zone may not be DNSSEC-signed or NSEC3 used)"
  end

  discovered
end

# ---------------------------------------------------------------------------
# Brute-force subdomains with thread pool
# ---------------------------------------------------------------------------

def brute_force(domain, wordlist_path, threads, resolver_ip, timeout)
  unless File.exist?(wordlist_path)
    puts "[-] Wordlist not found: #{wordlist_path}"
    return []
  end

  words    = File.readlines(wordlist_path, chomp: true).reject(&:empty?)
  queue    = Queue.new
  results  = Queue.new
  workers  = []
  checked  = Mutex.new.tap { |m| @count = 0; @mutex = m }

  words.each    { |w| queue << w }
  threads.times { queue << :stop }

  puts "\n[*] Brute-forcing #{words.size} subdomains with #{threads} threads"

  workers = threads.times.map do
    Thread.new do
      thread_resolver = make_resolver(resolver_ip, timeout)
      loop do
        word = queue.pop
        break if word == :stop

        subdomain = "#{word}.#{domain}"
        begin
          addrs = query_records(subdomain, Resolv::DNS::Resource::IN::A, thread_resolver)
          unless addrs.empty?
            results << { subdomain: subdomain, addrs: addrs, type: 'A' }
            print "\n[+] #{subdomain} => #{addrs.join(', ')}"
          else
            # Check for CNAME
            cnames = query_records(subdomain, Resolv::DNS::Resource::IN::CNAME, thread_resolver)
            unless cnames.empty?
              results << { subdomain: subdomain, cname: cnames.first, type: 'CNAME' }
              print "\n[+] #{subdomain} => CNAME #{cnames.first}"
            end
          end
        rescue
        ensure
          @mutex.synchronize { @count += 1 }
          print "\r[*] Progress: #{@count}/#{words.size}" if @count % 100 == 0
        end
      end
    end
  end

  workers.each(&:join)
  puts "\n[*] Brute-force complete"

  found = []
  results.size.times { found << results.pop }
  found
end

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

resolver = make_resolver(RESOLVER, TIMEOUT)
report   = {
  domain:    DOMAIN,
  resolver:  RESOLVER,
  timestamp: Time.now.utc.iso8601,
  records:   {},
  axfr:      {},
  nsec:      [],
  brute:     []
}

puts "=" * 60
puts "DNS Enumeration Tool"
puts "Domain   : #{DOMAIN}"
puts "Resolver : #{RESOLVER}"
puts "=" * 60

# Standard record enumeration
report[:records] = enumerate_records(DOMAIN, resolver)

# Zone transfer attempt using found nameservers
ns_servers = report[:records]['NS'] || []
report[:axfr] = attempt_axfr(DOMAIN, ns_servers) unless ns_servers.empty?

# NSEC walking
report[:nsec] = nsec_walk(DOMAIN, resolver)

# Subdomain brute force
if options[:wordlist]
  report[:brute] = brute_force(DOMAIN, options[:wordlist], THREADS, RESOLVER, TIMEOUT)
else
  puts "\n[*] No wordlist specified — skipping brute-force"
  puts "    Use: --wordlist /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt"
end

# Write JSON
File.write(OUTPUT, JSON.pretty_generate(report))
puts "\n[+] Results written to: #{OUTPUT}"
puts "[+] Total subdomains found: #{report[:brute].size}"
puts "[+] Standard records found: #{report[:records].map { |t,r| "#{t}(#{r.size})" }.join(', ')}"
```

---

## Tool 3: Subdomain Brute-Forcer with Wildcard Detection

A dedicated subdomain brute-forcer with wildcard filtering, CNAME-based wildcard detection, and a thread pool. Separate from the DNS enum tool for use as a fast standalone scanner.

```ruby
#!/usr/bin/env ruby
# subdomain_brute.rb
#
# Usage:
#   ruby subdomain_brute.rb --domain target.com --wordlist subs.txt
#   ruby subdomain_brute.rb --domain target.com --wordlist subs.txt \
#                           --threads 100 --resolver 1.1.1.1 --output results.json
#
# Features:
#   - Wildcard IP detection and filtering
#   - CNAME-based wildcard detection
#   - Custom resolver (bypasses system /etc/resolv.conf)
#   - Thread pool with Queue
#   - JSON + plain text output

require 'resolv'
require 'optparse'
require 'json'
require 'thread'
require 'securerandom'

# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------

options = {
  threads:  50,
  resolver: '8.8.8.8',
  output:   nil,
  timeout:  3
}

OptionParser.new do |opts|
  opts.banner = "Usage: #{$0} --domain DOMAIN --wordlist FILE [options]"
  opts.on('--domain DOMAIN',   'Target domain (required)')           { |d| options[:domain]   = d }
  opts.on('--wordlist FILE',   'Wordlist file (required)')           { |f| options[:wordlist] = f }
  opts.on('--resolver IP',     'Custom DNS resolver (default: 8.8.8.8)') { |r| options[:resolver] = r }
  opts.on('--threads N',       Integer, 'Thread count (default: 50)')    { |n| options[:threads]  = n }
  opts.on('--timeout N',       Integer, 'DNS timeout in seconds (default: 3)') { |n| options[:timeout]  = n }
  opts.on('--output FILE',     'Output file prefix (default: domain name)') { |f| options[:output]   = f }
end.parse!

abort "Error: --domain is required"   unless options[:domain]
abort "Error: --wordlist is required" unless options[:wordlist]
abort "Error: wordlist not found: #{options[:wordlist]}" unless File.exist?(options[:wordlist])

DOMAIN    = options[:domain].downcase.chomp('.')
WORDLIST  = options[:wordlist]
RESOLVER  = options[:resolver]
THREADS   = options[:threads]
TIMEOUT   = options[:timeout]
OUT_BASE  = options[:output] || DOMAIN

# ---------------------------------------------------------------------------
# Resolver factory
# ---------------------------------------------------------------------------

def make_resolver(server, timeout)
  Resolv::DNS.new(nameserver: [server], search: [], ndots: 1).tap do |r|
    r.timeouts = timeout
  end
end

# ---------------------------------------------------------------------------
# DNS lookup helpers
# ---------------------------------------------------------------------------

def resolve_a(hostname, resolver)
  resolver.getresources(hostname, Resolv::DNS::Resource::IN::A)
          .map { |r| r.address.to_s }
rescue Resolv::ResolvError, Resolv::ResolvTimeout
  []
rescue
  []
end

def resolve_cname(hostname, resolver)
  resolver.getresources(hostname, Resolv::DNS::Resource::IN::CNAME)
          .map { |r| r.name.to_s }
rescue Resolv::ResolvError, Resolv::ResolvTimeout
  []
rescue
  []
end

def resolve_aaaa(hostname, resolver)
  resolver.getresources(hostname, Resolv::DNS::Resource::IN::AAAA)
          .map { |r| r.address.to_s }
rescue Resolv::ResolvError, Resolv::ResolvTimeout
  []
rescue
  []
end

# ---------------------------------------------------------------------------
# Wildcard detection
# ---------------------------------------------------------------------------

# Test N random subdomains — if any resolve, we have a wildcard
WILDCARD_TEST_COUNT = 5

def detect_wildcard_ips(domain, resolver)
  wildcard_ips  = []
  wildcard_cnames = []

  WILDCARD_TEST_COUNT.times do
    random_sub = "#{SecureRandom.hex(12)}.#{domain}"
    addrs  = resolve_a(random_sub, resolver)
    cnames = resolve_cname(random_sub, resolver)
    wildcard_ips   += addrs   unless addrs.empty?
    wildcard_cnames += cnames unless cnames.empty?
  end

  wildcard_ips   = wildcard_ips.uniq
  wildcard_cnames = wildcard_cnames.uniq

  if wildcard_ips.any? || wildcard_cnames.any?
    puts "[!] WILDCARD DETECTED for *.#{domain}"
    puts "    Wildcard IPs   : #{wildcard_ips.join(', ')}"   unless wildcard_ips.empty?
    puts "    Wildcard CNAMEs: #{wildcard_cnames.join(', ')}" unless wildcard_cnames.empty?
  else
    puts "[*] No wildcard detected for *.#{domain}"
  end

  { ips: wildcard_ips, cnames: wildcard_cnames }
end

def wildcard_match?(addrs, cnames, wildcard)
  # Check if any resolved address matches a known wildcard IP
  return true if addrs.any? { |ip| wildcard[:ips].include?(ip) }

  # Check CNAME wildcard (e.g. random.target.com CNAME -> wildcard.fastly.net)
  return true if cnames.any? { |cn|
    wildcard[:cnames].any? { |wc|
      # If the wildcard CNAME is the same root, it's a wildcard hit
      cn == wc || (wildcard[:cnames].include?(cn))
    }
  }

  false
end

# ---------------------------------------------------------------------------
# Thread pool brute-forcer
# ---------------------------------------------------------------------------

def brute_force(domain, wordlist_path, threads, resolver_ip, timeout, wildcard)
  words     = File.readlines(wordlist_path, chomp: true)
                  .map(&:strip).reject(&:empty?).uniq
  queue     = Queue.new
  results   = Queue.new
  lock      = Mutex.new
  count     = 0
  total     = words.size

  words.each    { |w| queue << w }
  threads.times { queue << :stop }

  puts "[*] Starting brute-force: #{total} words, #{threads} threads"
  start_time = Time.now

  workers = threads.times.map do
    Thread.new do
      r = make_resolver(resolver_ip, timeout)

      loop do
        word = queue.pop
        break if word == :stop

        sub  = "#{word}.#{domain}"
        addrs  = resolve_a(sub, r)
        cnames = resolve_cname(sub, r)
        aaaa   = resolve_aaaa(sub, r)

        lock.synchronize { count += 1 }

        # Update progress every 500 checks
        if lock.synchronize { count } % 500 == 0
          elapsed = (Time.now - start_time).round(1)
          rate    = (count / elapsed).round(0) rescue 0
          print "\r[*] #{count}/#{total} | #{rate} req/s | found: #{results.size}          "
          $stdout.flush
        end

        next if addrs.empty? && cnames.empty? && aaaa.empty?

        # Filter wildcards
        if wildcard[:ips].any? || wildcard[:cnames].any?
          next if wildcard_match?(addrs, cnames, wildcard)
        end

        entry = {
          subdomain: sub,
          a:         addrs,
          aaaa:      aaaa,
          cname:     cnames
        }.reject { |_, v| v.empty? }

        results << entry
        print "\n[+] #{sub}"
        print " A=#{addrs.join(',')}"         unless addrs.empty?
        print " AAAA=#{aaaa.join(',')}"       unless aaaa.empty?
        print " CNAME=#{cnames.join(',')}"    unless cnames.empty?
        print "\r[*] #{count}/#{total}          "
      end
    end
  end

  workers.each(&:join)
  elapsed = (Time.now - start_time).round(2)
  puts "\n[*] Brute-force complete in #{elapsed}s | #{total} words checked"

  found = []
  results.size.times { found << results.pop }
  found.sort_by { |r| r[:subdomain] }
end

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

puts "=" * 60
puts "Subdomain Brute-Forcer with Wildcard Detection"
puts "Domain   : #{DOMAIN}"
puts "Resolver : #{RESOLVER}"
puts "Threads  : #{THREADS}"
puts "Wordlist : #{WORDLIST}"
puts "=" * 60

resolver = make_resolver(RESOLVER, TIMEOUT)

# Wildcard detection phase
puts "\n[*] Phase 1: Wildcard detection"
wildcard = detect_wildcard_ips(DOMAIN, resolver)

# Brute-force phase
puts "\n[*] Phase 2: Subdomain brute-force"
found = brute_force(DOMAIN, WORDLIST, THREADS, RESOLVER, TIMEOUT, wildcard)

# Output
puts "\n" + "=" * 60
puts "[+] RESULTS: #{found.size} live subdomains found"

# JSON report
json_out = "#{OUT_BASE}_subdomains.json"
report   = {
  domain:          DOMAIN,
  resolver:        RESOLVER,
  timestamp:       Time.now.utc.iso8601,
  wildcard:        wildcard,
  total_checked:   File.readlines(WORDLIST).size,
  found_count:     found.size,
  subdomains:      found
}
File.write(json_out, JSON.pretty_generate(report))
puts "[+] JSON report: #{json_out}"

# Plain text list
txt_out = "#{OUT_BASE}_subdomains.txt"
File.write(txt_out, found.map { |r| r[:subdomain] }.join("\n") + "\n")
puts "[+] Plain text : #{txt_out}"

# Terminal table
if found.any?
  puts "\n" + format("%-45s %-20s %s", 'SUBDOMAIN', 'A RECORD(S)', 'CNAME')
  puts "-" * 80
  found.each do |r|
    puts format("%-45s %-20s %s",
      r[:subdomain][0, 43],
      Array(r[:a]).first(2).join(',').to_s[0, 18],
      Array(r[:cname]).first.to_s[0, 15]
    )
  end
end
```

---

## Resources

- [Ruby Resolv stdlib documentation](https://ruby-doc.org/stdlib/libdoc/resolv/rdoc/Resolv.html)
- [Metasploit Rex core library](https://github.com/rapid7/rex-core)
- [ruby-dns gem (async DNS)](https://github.com/ioquatix/ruby-dns)
- [dnsruby gem (full DNS protocol support)](https://github.com/alexdalitz/dnsruby)
- [SecLists DNS wordlists](https://github.com/danielmiessler/SecLists/tree/master/Discovery/DNS)
- [Net::HTTP docs](https://ruby-doc.org/stdlib/libdoc/net-http/rdoc/Net/HTTP.html)
- [Resolv::DNS source](https://github.com/ruby/resolv)
- [IANA DNS record types](https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml)
