package main

import (
	"crypto/tls"
	"net"
	"net/http"
	"time"
)

// ── JA3 Fingerprint Spoofing ────────────────────────────────────────────────
//
// JA3 is a TLS fingerprinting method that hashes the ClientHello message
// (cipher suites, extensions, elliptic curves, etc.) to identify the TLS
// client. Go's standard crypto/tls produces a recognizable JA3 hash that
// differs from browsers. EDR/NDR products use JA3 to flag non-browser
// HTTPS traffic.
//
// Approach: Configure Go's TLS client to mimic Chrome's cipher suite
// ordering and extension set. This changes the JA3 hash to closely match
// a real Chrome browser.
//
// For full JA3 spoofing fidelity, use the uTLS library:
//   go get github.com/refraction-networking/utls
// and replace crypto/tls.Dial with utls.Dial + utls.HelloChrome_Auto.
//
// This module provides a "good enough" approach using Go's standard library
// by setting specific cipher suites and TLS parameters to produce a less
// recognizable JA3 hash. Zero external dependencies.

// chromeCipherSuites mimics Chrome's cipher suite preferences.
// Ordering matters — JA3 hashes the exact order.
var chromeCipherSuites = []uint16{
	// TLS 1.3 cipher suites (these are added automatically by Go but
	// we declare them to document the fingerprint)
	tls.TLS_AES_128_GCM_SHA256,
	tls.TLS_AES_256_GCM_SHA384,
	tls.TLS_CHACHA20_POLY1305_SHA256,

	// TLS 1.2 cipher suites (Chrome order)
	tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
	tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
	tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
	tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
	tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
	tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
	tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
	tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
	tls.TLS_RSA_WITH_AES_128_GCM_SHA256,
	tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
	tls.TLS_RSA_WITH_AES_128_CBC_SHA,
	tls.TLS_RSA_WITH_AES_256_CBC_SHA,
}

// chromeCurves mimics Chrome's elliptic curve preferences.
var chromeCurves = []tls.CurveID{
	tls.X25519,
	tls.CurveP256,
	tls.CurveP384,
}

// newSpoofedTLSConfig creates a TLS config that mimics Chrome's fingerprint.
func newSpoofedTLSConfig() *tls.Config {
	return &tls.Config{
		InsecureSkipVerify: true,
		MinVersion:         tls.VersionTLS12,
		MaxVersion:         tls.VersionTLS13,
		CipherSuites:       chromeCipherSuites,
		CurvePreferences:   chromeCurves,

		// Renegotiation support (Chrome enables this)
		Renegotiation: tls.RenegotiateOnceAsClient,
	}
}

// newSpoofedHTTPClient creates an HTTP client with a Chrome-like TLS fingerprint.
func newSpoofedHTTPClient() *http.Client {
	return &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: newSpoofedTLSConfig(),
			DialTLS: func(network, addr string) (net.Conn, error) {
				// Custom dialer with Chrome-like TLS config
				conn, err := tls.DialWithDialer(
					&net.Dialer{Timeout: 15 * time.Second},
					network,
					addr,
					newSpoofedTLSConfig(),
				)
				if err != nil {
					return nil, err
				}
				return conn, nil
			},
			MaxIdleConns:        10,
			IdleConnTimeout:     90 * time.Second,
			DisableCompression:  false,
			ForceAttemptHTTP2:   true, // Chrome uses HTTP/2
		},
		Timeout: 30 * time.Second,
	}
}

// newSpoofedTLSConn creates a raw TLS connection with the spoofed fingerprint.
func newSpoofedTLSConn(addr string) (*tls.Conn, error) {
	return tls.DialWithDialer(
		&net.Dialer{Timeout: 15 * time.Second},
		"tcp",
		addr,
		newSpoofedTLSConfig(),
	)
}
