// Copyright (c) 2026 Yasvanth Udayakumar
// SPDX-License-Identifier: Apache-2.0
// See LICENSE in the repository root for full terms.

// Package tlsscanner is the single-tenant OSS TLS/certificate scanner. Given a
// target host:port it performs a TLS handshake, inspects the
// negotiated protocol/cipher and the presented certificate chain, and emits
// CryptoFindings for quantum-vulnerable and otherwise weak transport crypto:
// classical certificate keys (RSA/ECDSA/DSA), undersized RSA keys, SHA-1
// signatures, expired/expiring certs, self-signed leaves, deprecated TLS 1.0/
// 1.1, and weak negotiated cipher suites.
//
// It uses crypto/tls with InsecureSkipVerify so it can report posture on
// self-signed or expired chains rather than failing the handshake — the
// scanner's job is to observe, not to enforce. Fleet-management concerns (rate
// limiting, ownership attribution, posture scoring, asset inventory) are
// intentionally out of scope for this package.
package tlsscanner

import (
	"context"
	"crypto/dsa" //lint:ignore SA1019 we report DSA when a server presents it
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/relix-q/relix-q/finding"
)

// Default timeouts.
const (
	DefaultDialTimeout = 5 * time.Second
	DefaultHSTimeout   = 5 * time.Second
)

// Target identifies one endpoint to scan.
type Target struct {
	Host        string
	Port        int
	SNI         string // optional; defaults to Host (omitted for IP literals)
	DialTimeout time.Duration
	HSTimeout   time.Duration
}

// Endpoint returns the host:port label used as the finding location.
func (t Target) Endpoint() string { return fmt.Sprintf("%s:%d", t.Host, t.Port) }

func (t Target) serverName() string {
	if t.SNI != "" {
		return t.SNI
	}
	if net.ParseIP(t.Host) != nil {
		return ""
	}
	return t.Host
}

// ParseTarget splits a "host", "host:port", or "[ipv6]:port" string into a
// Target, defaulting the port to 443.
func ParseTarget(s string) (Target, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return Target{}, fmt.Errorf("empty target")
	}
	// Strip a scheme if the user pasted a URL.
	if i := strings.Index(s, "://"); i >= 0 {
		s = s[i+3:]
		s = strings.SplitN(s, "/", 2)[0]
	}
	host, portStr, err := net.SplitHostPort(s)
	if err != nil {
		// No port — treat the whole string as host, default 443.
		return Target{Host: strings.Trim(s, "[]"), Port: 443}, nil
	}
	port := 443
	if portStr != "" {
		if _, e := fmt.Sscanf(portStr, "%d", &port); e != nil {
			return Target{}, fmt.Errorf("invalid port %q", portStr)
		}
	}
	return Target{Host: host, Port: port}, nil
}

type observation struct {
	version uint16
	cipher  uint16
	chain   []*x509.Certificate
}

// handshake performs one TLS handshake offering versions up to maxVersion and
// returns what the server negotiated. A dial failure is returned as an error;
// a handshake rejection (server refused the offered versions) is also an error.
func handshake(ctx context.Context, t Target, minVersion, maxVersion uint16) (*observation, error) {
	dialTimeout := t.DialTimeout
	if dialTimeout <= 0 {
		dialTimeout = DefaultDialTimeout
	}
	hsTimeout := t.HSTimeout
	if hsTimeout <= 0 {
		hsTimeout = DefaultHSTimeout
	}

	dialer := &net.Dialer{Timeout: dialTimeout}
	dialCtx, cancelDial := context.WithTimeout(ctx, dialTimeout)
	defer cancelDial()
	raw, err := dialer.DialContext(dialCtx, "tcp", t.Endpoint())
	if err != nil {
		return nil, fmt.Errorf("dial: %w", err)
	}

	conn := tls.Client(raw, &tls.Config{
		ServerName:         t.serverName(),
		InsecureSkipVerify: true, //nolint:gosec — we report posture, not enforce it
		MinVersion:         minVersion,
		MaxVersion:         maxVersion,
	})
	defer conn.Close()

	hsCtx, cancelHS := context.WithTimeout(ctx, hsTimeout)
	defer cancelHS()
	if err := conn.HandshakeContext(hsCtx); err != nil {
		return nil, fmt.Errorf("handshake: %w", err)
	}
	st := conn.ConnectionState()
	return &observation{version: st.Version, cipher: st.CipherSuite, chain: st.PeerCertificates}, nil
}

// Scan probes a single target and returns findings. The first return error is
// non-nil only when the endpoint could not be reached / negotiated at all; a
// reachable endpoint with no issues returns (nil, nil).
func Scan(ctx context.Context, t Target) ([]finding.Finding, error) {
	// Broadest handshake first: TLS 1.0–1.3, capture the chain + negotiated state.
	obs, err := handshake(ctx, t, tls.VersionTLS10, tls.VersionTLS13)
	if err != nil {
		return nil, err
	}

	var out []finding.Finding
	out = append(out, weakProtocolFindings(ctx, t)...)
	if cf := cipherFinding(obs.cipher); cf.RuleID != "" {
		out = append(out, cf)
	}
	if len(obs.chain) > 0 {
		out = append(out, certFindings(obs.chain, t.Endpoint())...)
	}

	// Stamp the endpoint as the finding location and default the taxonomy.
	endpoint := t.Endpoint()
	for i := range out {
		out[i].FilePath = endpoint
		out[i].Category = orDefault(out[i].Category, "tls")
		out[i].UsageType = orDefault(out[i].UsageType, "tls")
	}
	return out, nil
}

// weakProtocolFindings probes whether the server still accepts TLS 1.0 / 1.1 by
// offering each version alone and seeing if the handshake completes.
func weakProtocolFindings(ctx context.Context, t Target) []finding.Finding {
	var out []finding.Finding
	if _, err := handshake(ctx, t, tls.VersionTLS10, tls.VersionTLS10); err == nil {
		out = append(out, finding.Finding{
			RuleID: "TLS_VERSION_TLS10", Algorithm: "TLS 1.0", UsageType: "transport",
			QuantumSafety: finding.QuantumVulnerable, Severity: finding.SeverityCritical, Confidence: 1.0,
			Category: "weak-protocol", Snippet: "server accepts TLS 1.0",
			Message:        "TLS 1.0 is enabled — deprecated by RFC 8996 and insecure.",
			Recommendation: "Disable TLS 1.0 and 1.1; require TLS 1.2 minimum, prefer 1.3.",
			References:     []string{"https://datatracker.ietf.org/doc/html/rfc8996"},
		})
	}
	if _, err := handshake(ctx, t, tls.VersionTLS11, tls.VersionTLS11); err == nil {
		out = append(out, finding.Finding{
			RuleID: "TLS_VERSION_TLS11", Algorithm: "TLS 1.1", UsageType: "transport",
			QuantumSafety: finding.QuantumVulnerable, Severity: finding.SeverityHigh, Confidence: 1.0,
			Category: "weak-protocol", Snippet: "server accepts TLS 1.1",
			Message:        "TLS 1.1 is enabled — deprecated by RFC 8996.",
			Recommendation: "Disable TLS 1.1; require TLS 1.2 minimum, prefer 1.3.",
			References:     []string{"https://datatracker.ietf.org/doc/html/rfc8996"},
		})
	}
	return out
}

var weakCiphers = []struct {
	needle, algo string
	sev          finding.Severity
	qs           finding.QuantumSafety
}{
	{"_RC4_", "RC4", finding.SeverityCritical, finding.ClassicallyBroken},
	{"_3DES_", "3DES", finding.SeverityCritical, finding.GroverWeakened},
	{"_DES_", "DES", finding.SeverityCritical, finding.ClassicallyBroken},
	{"_NULL_", "NULL", finding.SeverityCritical, finding.ClassicallyBroken},
	{"_CBC_", "CBC", finding.SeverityMedium, finding.QuantumVulnerable},
}

func cipherFinding(c uint16) finding.Finding {
	name := cipherLabel(c)
	uc := strings.ToUpper(name)
	for _, w := range weakCiphers {
		if strings.Contains(uc, w.needle) {
			return finding.Finding{
				RuleID: "TLS_WEAK_CIPHER", Algorithm: w.algo, UsageType: "transport",
				QuantumSafety: w.qs, Severity: w.sev, Confidence: 1.0,
				Category: "weak-cipher", Snippet: name,
				Message:        "Weak cipher suite negotiated: " + name,
				Recommendation: "Prefer AEAD suites (AES-GCM, ChaCha20-Poly1305) on TLS 1.2+/1.3.",
			}
		}
	}
	return finding.Finding{} // sentinel: no weak cipher
}

func certFindings(chain []*x509.Certificate, endpoint string) []finding.Finding {
	leaf := chain[0]
	var out []finding.Finding

	keyAlg, keySize := classifyKey(leaf)

	// Classical (quantum-vulnerable) certificate key.
	if keyAlg == "RSA" || strings.HasPrefix(keyAlg, "ECDSA") || keyAlg == "DSA" {
		out = append(out, finding.Finding{
			RuleID: "TLS_CERT_CLASSICAL_KEY", Algorithm: keyAlg, UsageType: "certificate",
			QuantumSafety: finding.QuantumVulnerable, Severity: finding.SeverityHigh, Confidence: 0.9,
			Category: "crypto-api", Snippet: fmt.Sprintf("%s leaf key", keyAlg),
			Message:        fmt.Sprintf("Certificate uses a classical %s key — quantum-vulnerable (Shor's algorithm).", keyAlg),
			Recommendation: "Track CA support for ML-DSA (FIPS 204) and plan certificate migration.",
			References:     []string{"https://csrc.nist.gov/pubs/fips/204"},
			CWE:            []int{327},
		})
	}

	// Undersized RSA key.
	if keyAlg == "RSA" && keySize > 0 && keySize < 2048 {
		out = append(out, finding.Finding{
			RuleID: "TLS_CERT_RSA_WEAK", Algorithm: fmt.Sprintf("RSA-%d", keySize), UsageType: "certificate",
			QuantumSafety: finding.QuantumVulnerable, Severity: finding.SeverityCritical, Confidence: 1.0,
			Category: "weak-key-size", Snippet: fmt.Sprintf("RSA-%d", keySize),
			Message:        fmt.Sprintf("RSA key size %d is below the 2048-bit minimum.", keySize),
			Recommendation: "Re-issue with RSA-3072+ or ECDSA-P-256+ (interim); plan ML-DSA migration.",
			CWE:            []int{326},
		})
	}

	// SHA-1 signature.
	sigAlg := leaf.SignatureAlgorithm.String()
	if strings.Contains(strings.ToLower(sigAlg), "sha1") {
		out = append(out, finding.Finding{
			RuleID: "TLS_CERT_SHA1_SIG", Algorithm: sigAlg, UsageType: "signature",
			QuantumSafety: finding.QuantumVulnerable, Severity: finding.SeverityHigh, Confidence: 1.0,
			Category: "weak-hash", Snippet: sigAlg,
			Message:        "Certificate uses a SHA-1 signature — collision-vulnerable.",
			Recommendation: "Re-issue the certificate signed with SHA-256 or stronger.",
			CWE:            []int{327},
		})
	}

	// Expiry.
	expIn := time.Until(leaf.NotAfter)
	switch {
	case expIn <= 0:
		out = append(out, finding.Finding{
			RuleID: "TLS_CERT_EXPIRED", UsageType: "certificate", Severity: finding.SeverityCritical, Confidence: 1.0,
			Category: "cert-validation", QuantumSafety: finding.QuantumUnknown,
			Snippet:        "expired",
			Message:        fmt.Sprintf("Certificate expired %s ago.", (-expIn).Round(time.Hour)),
			Recommendation: "Renew immediately and automate renewal (ACME / cert-manager).",
		})
	case expIn < 30*24*time.Hour:
		sev := finding.SeverityHigh
		if expIn < 7*24*time.Hour {
			sev = finding.SeverityCritical
		}
		out = append(out, finding.Finding{
			RuleID: "TLS_CERT_EXPIRING", UsageType: "certificate", Severity: sev, Confidence: 1.0,
			Category: "cert-validation", QuantumSafety: finding.QuantumUnknown,
			Snippet:        "expiring",
			Message:        fmt.Sprintf("Certificate expires in %s.", expIn.Round(time.Hour)),
			Recommendation: "Schedule renewal and verify automation.",
		})
	}

	// Self-signed leaf.
	if isSelfSigned(leaf) {
		out = append(out, finding.Finding{
			RuleID: "TLS_CERT_SELF_SIGNED", Algorithm: sigAlg, UsageType: "certificate",
			Severity: finding.SeverityMedium, Confidence: 1.0, Category: "cert-validation",
			QuantumSafety:  finding.QuantumUnknown,
			Snippet:        "self-signed",
			Message:        "Endpoint presents a self-signed certificate.",
			Recommendation: "Issue from a trusted CA; self-signed is acceptable only for internal endpoints with pinned trust.",
		})
	}

	return out
}

func classifyKey(c *x509.Certificate) (string, int) {
	switch k := c.PublicKey.(type) {
	case *rsa.PublicKey:
		return "RSA", k.N.BitLen()
	case *ecdsa.PublicKey:
		return "ECDSA-" + k.Curve.Params().Name, k.Curve.Params().BitSize
	case ed25519.PublicKey:
		return "Ed25519", 256
	case *dsa.PublicKey:
		return "DSA", k.Parameters.P.BitLen()
	default:
		return c.PublicKeyAlgorithm.String(), 0
	}
}

func isSelfSigned(c *x509.Certificate) bool {
	if c.Subject.String() != c.Issuer.String() {
		return false
	}
	return c.CheckSignature(c.SignatureAlgorithm, c.RawTBSCertificate, c.Signature) == nil
}

func cipherLabel(c uint16) string {
	for _, s := range tls.CipherSuites() {
		if s.ID == c {
			return s.Name
		}
	}
	for _, s := range tls.InsecureCipherSuites() {
		if s.ID == c {
			return s.Name
		}
	}
	return fmt.Sprintf("0x%04x", c)
}

func orDefault(s, d string) string {
	if s == "" {
		return d
	}
	return s
}
