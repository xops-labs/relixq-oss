// Copyright (c) 2026 Yasvanth Udayakumar
// SPDX-License-Identifier: Apache-2.0
// See LICENSE in the repository root for full terms.
package tlsscanner

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/relix-q/relix-q/finding"
)

func TestScan_LocalServer_FlagsClassicalKey(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer srv.Close()

	target, err := ParseTarget(strings.TrimPrefix(srv.URL, "https://"))
	if err != nil {
		t.Fatal(err)
	}

	findings, err := Scan(context.Background(), target)
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}

	var sawKey bool
	for _, f := range findings {
		if f.FilePath != target.Endpoint() {
			t.Errorf("finding %s missing endpoint location: %q", f.RuleID, f.FilePath)
		}
		if f.RuleID == "TLS_CERT_CLASSICAL_KEY" {
			sawKey = true
			if f.QuantumSafety != finding.QuantumVulnerable {
				t.Errorf("classical cert key not flagged quantum-vulnerable: %+v", f)
			}
		}
	}
	if !sawKey {
		t.Fatalf("expected a TLS_CERT_CLASSICAL_KEY finding; got %d: %+v", len(findings), findings)
	}
}

func TestScan_UnreachableErrors(t *testing.T) {
	// Port 1 on localhost should refuse quickly.
	_, err := Scan(context.Background(), Target{Host: "127.0.0.1", Port: 1})
	if err == nil {
		t.Fatal("expected an error scanning an unreachable endpoint")
	}
}

func TestParseTarget(t *testing.T) {
	cases := []struct {
		in   string
		host string
		port int
	}{
		{"example.com", "example.com", 443},
		{"example.com:8443", "example.com", 8443},
		{"https://example.com/path", "example.com", 443},
		{"127.0.0.1:443", "127.0.0.1", 443},
	}
	for _, c := range cases {
		got, err := ParseTarget(c.in)
		if err != nil {
			t.Fatalf("%s: %v", c.in, err)
		}
		if got.Host != c.host || got.Port != c.port {
			t.Errorf("ParseTarget(%q) = %s:%d, want %s:%d", c.in, got.Host, got.Port, c.host, c.port)
		}
	}
}
