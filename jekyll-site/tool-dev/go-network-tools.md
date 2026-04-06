---
layout: training-page
title: "Go Network Tools — Red Team Academy"
module: "Tool Development"
tags:
  - go
  - golang
  - port-scanning
  - network
  - recon
  - concurrency
page_key: "tooldev-go-network-tools"
render_with_liquid: false
---

# Go Network Tools & Scanners

## Overview

Go is uniquely suited for red team network tooling because it compiles to a single, statically linked binary with no runtime dependencies — drop it on any Linux, Windows, or macOS target and it runs immediately. Go's goroutine model makes concurrent network probes trivial: a pool of goroutines can scan thousands of hosts simultaneously. This module builds a full scanner suite: CIDR expansion, concurrent TCP scanning, banner grabbing, service detection, and HTTP endpoint discovery.

Go version: 1.22+. No external packages required for the core tools.

## CIDR Expander & Target Generator

```
// cidr.go — expand CIDR blocks to a flat list of IPs.
// Build: go build -o cidr cidr.go
// Usage: ./cidr 10.10.10.0/24 192.168.1.1 172.16.0.0/22 > targets.txt

package main

import (
	"encoding/binary"
	"fmt"
	"net"
	"os"
)

// expandCIDR converts a CIDR string to a slice of individual IP strings.
// It skips the network address and broadcast address for non-/31 and /32 prefixes.
func expandCIDR(cidr string) ([]string, error) {
	// Try to parse as CIDR; if it fails, treat as a single IP
	ip, network, err := net.ParseCIDR(cidr)
	if err != nil {
		// Not a CIDR — try as a raw IP address
		if parsed := net.ParseIP(cidr); parsed != nil {
			return []string{parsed.String()}, nil
		}
		return nil, fmt.Errorf("invalid target: %s", cidr)
	}

	_ = ip // ip is the address before masking; network.IP is the masked network address

	// Convert network address to uint32 for arithmetic
	networkIP := binary.BigEndian.Uint32(network.IP.To4())
	ones, bits := network.Mask.Size()
	numHosts   := uint32(1) << uint(bits-ones)  // 2^(host bits)

	ips := make([]string, 0, numHosts)
	for i := uint32(1); i < numHosts-1; i++ {  // skip network (i=0) and broadcast (i=last)
		hostIP := make(net.IP, 4)
		binary.BigEndian.PutUint32(hostIP, networkIP+i)
		ips = append(ips, hostIP.String())
	}
	return ips, nil
}

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "Usage: cidr <cidr/ip> [...]")
		os.Exit(1)
	}
	for _, spec := range os.Args[1:] {
		ips, err := expandCIDR(spec)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[!] %v\n", err)
			continue
		}
		for _, ip := range ips {
			fmt.Println(ip)
		}
	}
}
```

## Concurrent TCP Port Scanner

Uses goroutines with a semaphore channel to limit concurrency. Each goroutine probes one IP:port combination with a configurable timeout. Results are sent over a results channel and consumed by a writer goroutine to avoid lock contention on the output file.

```
// scanner.go — high-speed concurrent TCP port scanner.
// Build: go build -ldflags="-s -w" -o scanner scanner.go
// Usage: ./scanner -targets targets.txt -ports 22,80,443,445,3389,5985 -workers 500

package main

import (
	"bufio"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"math/rand"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

// PortResult holds the result of a single TCP probe.
type PortResult struct {
	IP    string `json:"ip"`
	Port  int    `json:"port"`
	State string `json:"state"`
}

// probe attempts a TCP connect to addr with the given timeout.
// Returns true if the connection succeeds (port is open).
func probe(addr string, timeout time.Duration) bool {
	conn, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil {
		return false
	}
	conn.Close()
	return true
}

// scanHost probes all ports on a single IP, sending open results to the results channel.
// sem is a buffered channel used as a semaphore to cap concurrent goroutines.
func scanHost(ip string, ports []int, sem chan struct{}, results chan<- PortResult,
	timeout time.Duration, jitterMs int) {
	for _, port := range ports {
		sem <- struct{}{} // acquire semaphore slot (blocks if at capacity)
		go func(p int) {
			defer func() { <-sem }() // release slot when done

			addr := net.JoinHostPort(ip, strconv.Itoa(p))
			if probe(addr, timeout) {
				results <- PortResult{IP: ip, Port: p, State: "open"}
			}
			// Jitter: random sleep up to jitterMs milliseconds (reduces scan burst patterns)
			if jitterMs > 0 {
				time.Sleep(time.Duration(rand.Intn(jitterMs)) * time.Millisecond)
			}
		}(port)
	}
}

func main() {
	targetsFile := flag.String("targets", "targets.txt", "File with one IP per line")
	portsFlag   := flag.String("ports",   "22,80,443,445,3389,5985,8080,8443", "Comma-separated ports")
	workers     := flag.Int("workers",    500,  "Max concurrent goroutines")
	timeoutMs   := flag.Int("timeout",    1500, "Per-probe timeout in milliseconds")
	jitterMs    := flag.Int("jitter",     20,   "Max per-probe jitter in milliseconds")
	outputFile  := flag.String("output",  "open_ports.ndjson", "Output NDJSON file")
	flag.Parse()

	// Parse ports
	ports := []int{}
	for _, ps := range strings.Split(*portsFlag, ",") {
		if p, err := strconv.Atoi(strings.TrimSpace(ps)); err == nil {
			ports = append(ports, p)
		}
	}

	// Read target IPs from file
	f, _ := os.Open(*targetsFile)
	scanner := bufio.NewScanner(f)
	var targets []string
	for scanner.Scan() {
		if ip := strings.TrimSpace(scanner.Text()); ip != "" {
			targets = append(targets, ip)
		}
	}
	f.Close()

	fmt.Printf("[*] Scanning %d hosts, %d ports, %d workers\n", len(targets), len(ports), *workers)
	start := time.Now()

	// Semaphore channel: buffer size = max concurrent workers
	sem     := make(chan struct{}, *workers)
	results := make(chan PortResult, 1000)
	var wg sync.WaitGroup

	// Writer goroutine: consumes results and writes to output file
	out, _ := os.Create(*outputFile)
	enc    := json.NewEncoder(out)
	wg.Add(1)
	go func() {
		defer wg.Done()
		for r := range results {
			enc.Encode(r)
			fmt.Printf("  [OPEN] %s:%d\n", r.IP, r.Port)
		}
	}()

	// Launch a goroutine per host; scanHost itself uses the semaphore for port-level concurrency
	var scanWg sync.WaitGroup
	timeout := time.Duration(*timeoutMs) * time.Millisecond
	for _, ip := range targets {
		scanWg.Add(1)
		go func(h string) {
			defer scanWg.Done()
			scanHost(h, ports, sem, results, timeout, *jitterMs)
		}(ip)
	}

	// Wait for all scans to finish, then close results channel to signal the writer
	scanWg.Wait()
	close(results)
	wg.Wait()
	out.Close()

	fmt.Printf("[+] Done in %.1fs — results in %s\n", time.Since(start).Seconds(), *outputFile)
}
```

## TCP Banner Grabber

Connects to open ports, sends protocol-appropriate probes, and reads the server's initial response. Classifies services using byte-pattern matching. Feeds into the scanner pipeline as a second-pass enrichment step.

```
// banner.go — concurrent TCP banner grabber.
// Build: go build -o banner banner.go
// Usage: ./banner -input open_ports.ndjson -output banners.ndjson -workers 50

package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

// probeBytes maps port numbers to initial probe payloads.
// Ports where the server sends first get an empty probe (we just read).
var probeBytes = map[int][]byte{
	80:   []byte("HEAD / HTTP/1.0\r\n\r\n"),
	443:  []byte("HEAD / HTTP/1.0\r\n\r\n"),
	8080: []byte("HEAD / HTTP/1.0\r\n\r\n"),
	8443: []byte("HEAD / HTTP/1.0\r\n\r\n"),
	5985: []byte("GET /wsman HTTP/1.1\r\nHost: localhost\r\n\r\n"),
}

// servicePatterns maps byte sequences to service names.
var servicePatterns = []struct {
	pattern []byte
	service string
}{
	{[]byte("SSH-"), "SSH"},
	{[]byte("220 "), "SMTP/FTP"},
	{[]byte("HTTP/"), "HTTP"},
	{[]byte("* OK"), "IMAP"},
	{[]byte("+OK"), "POP3"},
	{[]byte("\x00\x00\x00\x85\xffSMB"), "SMBv1"},
	{[]byte("\xfeSMB"), "SMBv2/3"},
	{[]byte("NTLMSSP"), "NTLM"},
	{[]byte("\x03\x00\x00"), "RDP"},
}

// BannerResult holds the result of one banner grab attempt.
type BannerResult struct {
	IP          string `json:"ip"`
	Port        int    `json:"port"`
	Banner      string `json:"banner,omitempty"`
	Service     string `json:"service"`
	Error       string `json:"error,omitempty"`
}

func grabBanner(ip string, port int, timeout time.Duration) BannerResult {
	result := BannerResult{IP: ip, Port: port, Service: "unknown"}
	addr   := net.JoinHostPort(ip, strconv.Itoa(port))

	conn, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil {
		result.Error = err.Error()
		return result
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(timeout))

	// Send probe if we have one; otherwise just read (server sends first)
	if probe, ok := probeBytes[port]; ok && len(probe) > 0 {
		conn.Write(probe)
	}

	// Read first 1024 bytes of response
	buf := make([]byte, 1024)
	n, _ := conn.Read(buf)
	if n == 0 {
		result.Error = "no data"
		return result
	}
	data := buf[:n]

	// Store as printable string (replace non-printable bytes)
	var sb strings.Builder
	for _, b := range data {
		if b >= 32 && b < 127 {
			sb.WriteByte(b)
		} else {
			sb.WriteRune('.')
		}
	}
	result.Banner = strings.TrimSpace(sb.String())

	// Fingerprint the service
	for _, sp := range servicePatterns {
		if strings.Contains(string(data), string(sp.pattern)) {
			result.Service = sp.service
			break
		}
	}
	return result
}

func main() {
	input   := flag.String("input",   "open_ports.ndjson", "Scanner output file")
	output  := flag.String("output",  "banners.ndjson",    "Banner output file")
	workers := flag.Int("workers",    50,                  "Concurrent grabbers")
	timeout := flag.Int("timeout",    3000,                "Timeout in ms")
	flag.Parse()

	// Read input records
	f, _ := os.Open(*input)
	scanner := bufio.NewScanner(f)
	type PortRecord struct { IP string `json:"ip"`; Port int `json:"port"` }
	var records []PortRecord
	for scanner.Scan() {
		var r PortRecord
		if json.Unmarshal([]byte(scanner.Text()), &r) == nil {
			records = append(records, r)
		}
	}
	f.Close()

	sem  := make(chan struct{}, *workers)
	var wg sync.WaitGroup
	out, _ := os.Create(*output)
	enc    := json.NewEncoder(out)
	var mu sync.Mutex
	dur    := time.Duration(*timeout) * time.Millisecond

	for _, rec := range records {
		wg.Add(1)
		sem <- struct{}{}
		go func(r PortRecord) {
			defer wg.Done()
			defer func() { <-sem }()
			result := grabBanner(r.IP, r.Port, dur)
			mu.Lock()
			enc.Encode(result)
			mu.Unlock()
		}(rec)
	}
	wg.Wait()
	out.Close()
	fmt.Printf("[+] Banner grab complete — results in %s\n", *output)
}
```
