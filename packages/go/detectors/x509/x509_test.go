// Copyright (c) 2026 Yasvanth Udayakumar
// SPDX-License-Identifier: Apache-2.0
// See LICENSE in the repository root for full terms.
package x509_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	stdx509 "crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	x509det "github.com/relix-q/relix-q/detectors/x509"
	"github.com/relix-q/relix-q/finding"
	"github.com/relix-q/relix-q/rules"
	"github.com/relix-q/relix-q/scanner"
)

// --- programmatic fixtures ---------------------------------------------------

var (
	rsaKeyOnce sync.Once
	rsaKeyVal  *rsa.PrivateKey
)

// testRSAKey returns a process-cached RSA-2048 key (generation is the slow
// part of this suite; one key is plenty for every test).
func testRSAKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	rsaKeyOnce.Do(func() {
		k, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			panic(err)
		}
		rsaKeyVal = k
	})
	return rsaKeyVal
}

// selfSignedDER builds a self-signed certificate and returns its DER bytes.
func selfSignedDER(t *testing.T, cn string, pub, priv any) []byte {
	t.Helper()
	tmpl := &stdx509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		NotAfter:     time.Date(2031, 1, 1, 0, 0, 0, 0, time.UTC),
	}
	der, err := stdx509.CreateCertificate(rand.Reader, tmpl, tmpl, pub, priv)
	if err != nil {
		t.Fatalf("CreateCertificate(%s): %v", cn, err)
	}
	return der
}

func pemBytes(t *testing.T, blockType string, der []byte) []byte {
	t.Helper()
	return pem.EncodeToMemory(&pem.Block{Type: blockType, Bytes: der})
}

// beginLines returns the 1-based line numbers of every "-----BEGIN" marker.
func beginLines(content []byte) []int {
	var out []int
	for i, line := range strings.Split(string(content), "\n") {
		if strings.HasPrefix(line, "-----BEGIN ") {
			out = append(out, i+1)
		}
	}
	return out
}

// byRuleID indexes matches by rule id, failing on duplicates.
func byRuleID(t *testing.T, matches []x509det.Match) map[string]x509det.Match {
	t.Helper()
	out := map[string]x509det.Match{}
	for _, m := range matches {
		if _, dup := out[m.RuleID]; dup {
			t.Fatalf("duplicate rule id %s in matches", m.RuleID)
		}
		out[m.RuleID] = m
	}
	return out
}

// assertCleanSnippet enforces the sensitivity contract: the snippet is exactly
// the BEGIN marker line (or the synthetic DER placeholder) and never carries
// base64 body bytes.
func assertCleanSnippet(t *testing.T, m x509det.Match, body []byte) {
	t.Helper()
	if strings.Contains(m.Snippet, "\n") {
		t.Errorf("%s: snippet spans multiple lines: %q", m.RuleID, m.Snippet)
	}
	if !strings.HasPrefix(m.Snippet, "-----BEGIN ") && m.Snippet != "(binary DER certificate)" {
		t.Errorf("%s: snippet is not a BEGIN marker: %q", m.RuleID, m.Snippet)
	}
	// No line of the PEM body may appear in the snippet.
	for _, line := range strings.Split(string(body), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "-----") {
			continue
		}
		if strings.Contains(m.Snippet, line) {
			t.Errorf("%s: snippet leaks body bytes", m.RuleID)
		}
	}
}

// --- certificates ------------------------------------------------------------

func TestRSACertificate(t *testing.T) {
	key := testRSAKey(t)
	content := pemBytes(t, "CERTIFICATE", selfSignedDER(t, "rsa.test.relixq", &key.PublicKey, key))

	matches := x509det.Detect(content)
	if len(matches) != 2 {
		t.Fatalf("want 2 matches (pubkey+sig), got %d: %+v", len(matches), matches)
	}
	byID := byRuleID(t, matches)

	pub, ok := byID["X509_CERT_PUBKEY_RSA"]
	if !ok {
		t.Fatal("missing X509_CERT_PUBKEY_RSA")
	}
	if pub.Algorithm != "RSA" || pub.KeySize == nil || *pub.KeySize != 2048 {
		t.Errorf("pubkey: want RSA/2048, got %s/%v", pub.Algorithm, pub.KeySize)
	}
	if !strings.Contains(pub.Message, "RSA-2048") ||
		!strings.Contains(pub.Message, "CN=rsa.test.relixq") ||
		!strings.Contains(pub.Message, "2031-01-01") {
		t.Errorf("pubkey message missing bits/CN/expiry: %q", pub.Message)
	}
	if pub.Line != 1 || pub.UsageType != "certificate" {
		t.Errorf("pubkey: want line 1 / usage certificate, got %d / %s", pub.Line, pub.UsageType)
	}

	sig, ok := byID["X509_CERT_SIG_RSA"]
	if !ok {
		t.Fatal("missing X509_CERT_SIG_RSA")
	}
	if sig.Algorithm != "RSA" || !strings.Contains(sig.Message, "sha256WithRSAEncryption") {
		t.Errorf("sig: want RSA sha256WithRSAEncryption, got %s %q", sig.Algorithm, sig.Message)
	}

	for _, m := range matches {
		assertCleanSnippet(t, m, content)
	}
}

func TestECDSACertificate(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	content := pemBytes(t, "CERTIFICATE", selfSignedDER(t, "ec.test.relixq", &key.PublicKey, key))

	matches := x509det.Detect(content)
	if len(matches) != 2 {
		t.Fatalf("want 2 matches, got %d", len(matches))
	}
	byID := byRuleID(t, matches)

	pub, ok := byID["X509_CERT_PUBKEY_ECDSA"]
	if !ok {
		t.Fatal("missing X509_CERT_PUBKEY_ECDSA")
	}
	if pub.Algorithm != "ECDSA" || !strings.Contains(pub.Message, "P-256") {
		t.Errorf("pubkey: want ECDSA P-256, got %s %q", pub.Algorithm, pub.Message)
	}

	sig, ok := byID["X509_CERT_SIG_ECDSA"]
	if !ok {
		t.Fatal("missing X509_CERT_SIG_ECDSA")
	}
	if !strings.Contains(sig.Message, "ecdsa-with-SHA256") {
		t.Errorf("sig: want ecdsa-with-SHA256, got %q", sig.Message)
	}
}

func TestEd25519Certificate(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	content := pemBytes(t, "CERTIFICATE", selfSignedDER(t, "ed.test.relixq", pub, priv))

	matches := x509det.Detect(content)
	if len(matches) != 2 {
		t.Fatalf("want 2 matches, got %d", len(matches))
	}
	byID := byRuleID(t, matches)
	if _, ok := byID["X509_CERT_PUBKEY_ED25519"]; !ok {
		t.Error("missing X509_CERT_PUBKEY_ED25519")
	}
	if _, ok := byID["X509_CERT_SIG_ED25519"]; !ok {
		t.Error("missing X509_CERT_SIG_ED25519")
	}
}

// --- private keys -------------------------------------------------------------

func TestRSAPrivateKeyPKCS1(t *testing.T) {
	key := testRSAKey(t)
	content := pemBytes(t, "RSA PRIVATE KEY", stdx509.MarshalPKCS1PrivateKey(key))

	matches := x509det.Detect(content)
	if len(matches) != 1 {
		t.Fatalf("want 1 match, got %d", len(matches))
	}
	m := matches[0]
	if m.RuleID != "X509_PRIVATE_KEY_RSA" || m.Algorithm != "RSA" {
		t.Errorf("want X509_PRIVATE_KEY_RSA/RSA, got %s/%s", m.RuleID, m.Algorithm)
	}
	if m.KeySize == nil || *m.KeySize != 2048 {
		t.Errorf("want key size 2048, got %v", m.KeySize)
	}
	if m.UsageType != "key_storage" {
		t.Errorf("want usage_type key_storage, got %s", m.UsageType)
	}
	wantCWE := map[int]bool{327: false, 798: false}
	for _, c := range m.CWE {
		wantCWE[c] = true
	}
	if !wantCWE[327] || !wantCWE[798] {
		t.Errorf("want CWE [327 798], got %v", m.CWE)
	}
	assertCleanSnippet(t, m, content)
}

func TestPKCS8ECPrivateKey(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := stdx509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	content := pemBytes(t, "PRIVATE KEY", der)

	matches := x509det.Detect(content)
	if len(matches) != 1 {
		t.Fatalf("want 1 match, got %d", len(matches))
	}
	m := matches[0]
	if m.RuleID != "X509_PRIVATE_KEY_ECDSA" || m.Algorithm != "ECDSA" {
		t.Errorf("want X509_PRIVATE_KEY_ECDSA/ECDSA, got %s/%s", m.RuleID, m.Algorithm)
	}
	if !strings.Contains(m.Message, "P-256") {
		t.Errorf("message should name the curve, got %q", m.Message)
	}
}

func TestPKCS8UnknownAlgorithmNotFlagged(t *testing.T) {
	// A "PRIVATE KEY" block whose DER does not parse stands in for future PQC
	// (ML-DSA / ML-KEM) PKCS#8 OIDs: the algorithm cannot be positively
	// identified, so nothing may be flagged.
	content := pemBytes(t, "PRIVATE KEY", []byte{0x30, 0x03, 0x02, 0x01, 0x00})
	if matches := x509det.Detect(content); len(matches) != 0 {
		t.Fatalf("unidentifiable PKCS#8 must not be flagged, got %+v", matches)
	}
}

func TestOpenSSHEd25519PrivateKey(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	block, err := ssh.MarshalPrivateKey(priv, "test key")
	if err != nil {
		t.Fatal(err)
	}
	content := pem.EncodeToMemory(block)

	matches := x509det.Detect(content)
	if len(matches) != 1 {
		t.Fatalf("want 1 match, got %d", len(matches))
	}
	m := matches[0]
	if m.RuleID != "X509_PRIVATE_KEY_ED25519" || m.Algorithm != "Ed25519" {
		t.Errorf("want X509_PRIVATE_KEY_ED25519/Ed25519, got %s/%s", m.RuleID, m.Algorithm)
	}
}

// --- CSR -----------------------------------------------------------------------

func TestCertificateRequest(t *testing.T) {
	key := testRSAKey(t)
	der, err := stdx509.CreateCertificateRequest(rand.Reader, &stdx509.CertificateRequest{
		Subject: pkix.Name{CommonName: "csr.test.relixq"},
	}, key)
	if err != nil {
		t.Fatal(err)
	}
	content := pemBytes(t, "CERTIFICATE REQUEST", der)

	matches := x509det.Detect(content)
	if len(matches) != 2 {
		t.Fatalf("want 2 matches, got %d", len(matches))
	}
	byID := byRuleID(t, matches)
	if _, ok := byID["X509_CSR_PUBKEY_RSA"]; !ok {
		t.Error("missing X509_CSR_PUBKEY_RSA")
	}
	if _, ok := byID["X509_CSR_SIG_RSA"]; !ok {
		t.Error("missing X509_CSR_SIG_RSA")
	}
}

// --- public keys -----------------------------------------------------------------

func TestPKIXPublicKey(t *testing.T) {
	key := testRSAKey(t)
	der, err := stdx509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	matches := x509det.Detect(pemBytes(t, "PUBLIC KEY", der))
	if len(matches) != 1 {
		t.Fatalf("want 1 match, got %d", len(matches))
	}
	if matches[0].RuleID != "X509_PUBLIC_KEY_RSA" {
		t.Errorf("want X509_PUBLIC_KEY_RSA, got %s", matches[0].RuleID)
	}
}

// --- multi-block / lines ----------------------------------------------------------

func TestMultiBlockChainAndKey(t *testing.T) {
	rsaK := testRSAKey(t)
	ecK, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	var buf []byte
	buf = append(buf, []byte("# leaf + intermediate + key bundle\n\n")...)
	buf = append(buf, pemBytes(t, "CERTIFICATE", selfSignedDER(t, "leaf.test.relixq", &rsaK.PublicKey, rsaK))...)
	buf = append(buf, pemBytes(t, "CERTIFICATE", selfSignedDER(t, "intermediate.test.relixq", &ecK.PublicKey, ecK))...)
	buf = append(buf, pemBytes(t, "RSA PRIVATE KEY", stdx509.MarshalPKCS1PrivateKey(rsaK))...)

	lines := beginLines(buf)
	if len(lines) != 3 {
		t.Fatalf("fixture should have 3 BEGIN markers, found %d", len(lines))
	}

	matches := x509det.Detect(buf)
	if len(matches) != 5 {
		t.Fatalf("want 5 matches (2+2+1), got %d: %+v", len(matches), matches)
	}

	// Per-block line attribution: cert findings carry their own block's
	// BEGIN line; the key finding carries the third marker's line.
	wantLines := map[string]int{
		"X509_CERT_PUBKEY_RSA":   lines[0],
		"X509_CERT_SIG_RSA":      lines[0],
		"X509_CERT_PUBKEY_ECDSA": lines[1],
		"X509_CERT_SIG_ECDSA":    lines[1],
		"X509_PRIVATE_KEY_RSA":   lines[2],
	}
	byID := byRuleID(t, matches)
	for id, want := range wantLines {
		m, ok := byID[id]
		if !ok {
			t.Errorf("missing %s", id)
			continue
		}
		if m.Line != want {
			t.Errorf("%s: want line %d, got %d", id, want, m.Line)
		}
		assertCleanSnippet(t, m, buf)
	}
}

// --- robustness --------------------------------------------------------------------

func TestGarbageContentEmitsNothing(t *testing.T) {
	cases := map[string][]byte{
		"plain text":        []byte("this is not a certificate\njust some text\n"),
		"empty":             nil,
		"corrupt cert body": []byte("-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n"),
		"unknown block":     []byte("-----BEGIN FOO BAR-----\nAAAA\n-----END FOO BAR-----\n"),
		"binary junk":       {0x00, 0x01, 0x02, 0xff, 0xfe, 0x30, 0x82},
	}
	for name, content := range cases {
		if matches := x509det.Detect(content); len(matches) != 0 {
			t.Errorf("%s: want 0 matches, got %d", name, len(matches))
		}
	}
}

func TestRawDERCertificate(t *testing.T) {
	key := testRSAKey(t)
	der := selfSignedDER(t, "der.test.relixq", &key.PublicKey, key)

	matches := x509det.Detect(der)
	if len(matches) != 2 {
		t.Fatalf("want 2 matches from raw DER, got %d", len(matches))
	}
	byID := byRuleID(t, matches)
	for _, id := range []string{"X509_CERT_PUBKEY_RSA", "X509_CERT_SIG_RSA"} {
		m, ok := byID[id]
		if !ok {
			t.Fatalf("missing %s", id)
		}
		if m.Line != 1 {
			t.Errorf("%s: raw DER findings belong on line 1, got %d", id, m.Line)
		}
		if m.Snippet != "(binary DER certificate)" {
			t.Errorf("%s: unexpected DER snippet %q", id, m.Snippet)
		}
	}
}

// --- finding conversion ---------------------------------------------------------

func TestToFindingShape(t *testing.T) {
	key := testRSAKey(t)
	content := pemBytes(t, "CERTIFICATE", selfSignedDER(t, "shape.test.relixq", &key.PublicKey, key))
	matches := x509det.Detect(content)
	if len(matches) == 0 {
		t.Fatal("no matches")
	}
	f := x509det.ToFinding("job-1", "certs/server.pem", matches[0])
	if f.Language != "x509" || f.Severity != finding.SeverityCritical ||
		f.QuantumSafety != finding.QuantumVulnerable || f.Confidence != 0.99 ||
		f.Category != "certificate" || f.Column != 1 || f.FilePath != "certs/server.pem" {
		t.Errorf("finding metadata wrong: %+v", f)
	}
	if f.Recommendation == "" {
		t.Error("finding must carry a PQC recommendation")
	}
}

// --- pipeline integration ----------------------------------------------------------

// TestScannerPipelineIntegration proves LangX509 files flow through the normal
// scan orchestrator (walk → route → x509 detect → JSONL) with no rules loaded
// for the language.
func TestScannerPipelineIntegration(t *testing.T) {
	key := testRSAKey(t)
	repo := t.TempDir()
	certDir := filepath.Join(repo, "certs")
	if err := os.MkdirAll(certDir, 0o755); err != nil {
		t.Fatal(err)
	}
	content := pemBytes(t, "CERTIFICATE", selfSignedDER(t, "pipeline.test.relixq", &key.PublicKey, key))
	if err := os.WriteFile(filepath.Join(certDir, "server-rsa.pem"), content, 0o600); err != nil {
		t.Fatal(err)
	}
	// A garbage .pem must scan cleanly with zero findings.
	if err := os.WriteFile(filepath.Join(certDir, "broken.pem"), []byte("not pem\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	out := filepath.Join(t.TempDir(), "findings.jsonl")
	scn := scanner.New(scanner.Job{ScanJobID: "itest"}, nil)
	res, err := scn.Scan(context.Background(), scanner.ScanRequest{
		RepoPath: repo,
		Pack:     rules.NewPackForTest(nil),
		Output:   out,
	})
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if res.FilesScanned != 2 {
		t.Errorf("want 2 files scanned, got %d (skipped %d)", res.FilesScanned, res.FilesSkipped)
	}
	if res.FindingsCount != 2 {
		t.Errorf("want 2 findings, got %d", res.FindingsCount)
	}

	raw, err := os.Open(out)
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	findings, err := finding.ReadAll(raw)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]bool{}
	for _, f := range findings {
		got[f.RuleID] = true
		if f.Language != "x509" {
			t.Errorf("finding language: want x509, got %s", f.Language)
		}
		if f.FilePath != "certs/server-rsa.pem" {
			t.Errorf("finding path: %s", f.FilePath)
		}
		if strings.Contains(f.Snippet, "MII") {
			t.Errorf("snippet leaks certificate body: %q", f.Snippet)
		}
	}
	if !got["X509_CERT_PUBKEY_RSA"] || !got["X509_CERT_SIG_RSA"] {
		t.Errorf("missing expected rule ids, got %v", got)
	}
}
