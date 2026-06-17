// Copyright (c) 2026 Yasvanth Udayakumar
// SPDX-License-Identifier: Apache-2.0
// See LICENSE in the repository root for full terms.
// Package x509 implements the certificate / key-material detector for files
// routed as scanner.LangX509 (.pem / .crt / .cer / .der / .key). Unlike the
// YAML-rule detectors it does not pattern-match text: it parses PEM blocks
// (and raw DER certificates) with crypto/x509 and inspects BOTH the public-key
// algorithm and the signature algorithm, emitting synthetic findings for
// quantum-vulnerable algorithms (RSA, ECDSA, Ed25519, DSA, X25519).
//
// PQC safety: material whose algorithm is not recognized (unknown OIDs —
// future ML-DSA / ML-KEM certificates and keys) is deliberately NOT flagged.
// Unparseable content never errors the scan; it simply yields no matches.
//
// Sensitivity: snippets contain only the "-----BEGIN ...-----" marker line —
// never key or certificate body bytes.
package x509

import (
	"bytes"
	"crypto/dsa"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	stdx509 "crypto/x509"
	"encoding/pem"
	"fmt"

	"golang.org/x/crypto/ssh"

	"github.com/relix-q/relix-q/finding"
)

// Detector metadata shared by every synthetic finding this package emits.
const (
	// Language is the routing language for certificate / key material files.
	Language = "x509"
	// Confidence reflects that findings come from actual ASN.1 parsing, not
	// pattern matching.
	Confidence = 0.99
	// Category groups all certificate / key-material findings.
	Category = "certificate"
)

// Recommendations: certificates get the CA/B-Forum-oriented guidance; private
// keys additionally need rotation out of version control.
const (
	certRecommendation = "Plan migration to ML-DSA (FIPS 204) certificates or hybrid certificates; track CA/B Forum PQC roadmap."
	keyRecommendation  = "Plan migration to ML-DSA (FIPS 204) / ML-KEM (FIPS 203) key material; rotate this key and remove committed private keys from version control."
)

// cweWeakCrypto is "Use of a Broken or Risky Cryptographic Algorithm".
// cweHardcodedCreds is "Use of Hard-coded Credentials" — applied to private
// keys, which are committed secret material by definition when scanned at rest.
const (
	cweWeakCrypto     = 327
	cweHardcodedCreds = 798
)

// Match is one detector hit, finding-shaped but without job/file metadata
// (mirrors the regex detector's Match → ToFinding split).
type Match struct {
	RuleID         string
	Algorithm      string
	KeySize        *int // bits, when determinable
	UsageType      string
	Line           int    // line of the "-----BEGIN ...-----" marker (1 for raw DER)
	Snippet        string // the BEGIN marker line ONLY — never body bytes
	Message        string
	Recommendation string
	CWE            []int
}

// ToFinding converts a Match plus job-level metadata into a canonical Finding.
// All x509 findings are critical / vulnerable: every algorithm this detector
// recognizes and reports is Shor-broken.
func ToFinding(scanJobID, relPath string, m Match) *finding.Finding {
	return &finding.Finding{
		ScanJobID:      scanJobID,
		RuleID:         m.RuleID,
		Language:       Language,
		Algorithm:      m.Algorithm,
		UsageType:      m.UsageType,
		QuantumSafety:  finding.QuantumVulnerable,
		Severity:       finding.SeverityCritical,
		KeySize:        m.KeySize,
		FilePath:       relPath,
		LineNumber:     m.Line,
		Column:         1,
		Snippet:        m.Snippet,
		Confidence:     Confidence,
		Category:       Category,
		Message:        m.Message,
		Recommendation: m.Recommendation,
		CWE:            m.CWE,
	}
}

// Detect parses certificate / key material and returns all matches. It never
// returns an error: malformed or unrecognized content yields no matches.
//
// PEM content: every block is examined (certificates, CSRs, private keys,
// public keys). Content with no PEM markers is tried as one raw DER
// certificate.
func Detect(content []byte) []Match {
	var out []Match

	rest := content
	offset := 0 // bytes of `content` already consumed by earlier blocks
	sawPEM := false
	for {
		block, next := pem.Decode(rest)
		if block == nil {
			break
		}
		sawPEM = true
		consumed := len(rest) - len(next)

		marker := "-----BEGIN " + block.Type + "-----"
		line := 1
		if idx := bytes.Index(rest[:consumed], []byte(marker)); idx >= 0 {
			line = 1 + bytes.Count(content[:offset+idx], []byte{'\n'})
		}

		out = append(out, matchBlock(block, line, marker)...)

		offset += consumed
		rest = next
	}

	if !sawPEM {
		// Raw DER: try the whole content as a single certificate.
		der := bytes.TrimRight(content, "\x00 \t\r\n")
		if cert, err := stdx509.ParseCertificate(der); err == nil {
			out = append(out, certMatches(cert, 1, "(binary DER certificate)")...)
		}
	}

	return out
}

// matchBlock dispatches one PEM block by type.
func matchBlock(block *pem.Block, line int, snippet string) []Match {
	switch block.Type {
	case "CERTIFICATE", "TRUSTED CERTIFICATE", "X509 CERTIFICATE":
		cert, err := stdx509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil
		}
		return certMatches(cert, line, snippet)

	case "CERTIFICATE REQUEST", "NEW CERTIFICATE REQUEST":
		csr, err := stdx509.ParseCertificateRequest(block.Bytes)
		if err != nil {
			return nil
		}
		return csrMatches(csr, line, snippet)

	case "RSA PRIVATE KEY", "EC PRIVATE KEY", "DSA PRIVATE KEY",
		"PRIVATE KEY", "OPENSSH PRIVATE KEY":
		if m := privateKeyMatch(block, line, snippet); m != nil {
			return []Match{*m}
		}
		return nil

	case "PUBLIC KEY", "RSA PUBLIC KEY":
		if m := publicKeyMatch(block, line, snippet); m != nil {
			return []Match{*m}
		}
		return nil
	}
	// Unknown block types (ENCRYPTED PRIVATE KEY, PKCS7, params, future PQC
	// types, ...): algorithm cannot be determined — emit nothing.
	return nil
}

// --- certificates -----------------------------------------------------------

// certMatches emits the public-key finding and the signature finding for one
// parsed certificate.
func certMatches(cert *stdx509.Certificate, line int, snippet string) []Match {
	subject := commonName(cert.Subject.CommonName)
	expiry := cert.NotAfter.UTC().Format("2006-01-02")
	var out []Match

	// (a) public-key algorithm
	if alg, label, bits, ok := publicKeyInfo(cert.PublicKey, cert.PublicKeyAlgorithm); ok {
		out = append(out, Match{
			RuleID:    "X509_CERT_PUBKEY_" + ruleSuffix(alg),
			Algorithm: alg,
			KeySize:   bits,
			UsageType: "certificate",
			Line:      line,
			Snippet:   snippet,
			Message: fmt.Sprintf(
				"X.509 certificate public key uses %s, which is quantum-vulnerable (Shor's algorithm). Subject CN=%s, expires %s.",
				label, subject, expiry),
			Recommendation: certRecommendation,
			CWE:            []int{cweWeakCrypto},
		})
	}

	// (b) signature algorithm
	if fam, name, weakHash, ok := signatureInfo(cert.SignatureAlgorithm); ok {
		msg := fmt.Sprintf(
			"X.509 certificate is signed with %s (%s), which is quantum-vulnerable (Shor's algorithm). Subject CN=%s, expires %s.",
			name, fam, subject, expiry)
		if weakHash {
			msg += " The signature hash is also classically weak (SHA-1/MD5 class); replace it regardless of PQC timelines."
		}
		out = append(out, Match{
			RuleID:         "X509_CERT_SIG_" + ruleSuffix(fam),
			Algorithm:      fam,
			UsageType:      "certificate",
			Line:           line,
			Snippet:        snippet,
			Message:        msg,
			Recommendation: certRecommendation,
			CWE:            []int{cweWeakCrypto},
		})
	}

	return out
}

// csrMatches emits the public-key and signature findings for one parsed CSR.
func csrMatches(csr *stdx509.CertificateRequest, line int, snippet string) []Match {
	subject := commonName(csr.Subject.CommonName)
	var out []Match

	if alg, label, bits, ok := publicKeyInfo(csr.PublicKey, csr.PublicKeyAlgorithm); ok {
		out = append(out, Match{
			RuleID:    "X509_CSR_PUBKEY_" + ruleSuffix(alg),
			Algorithm: alg,
			KeySize:   bits,
			UsageType: "certificate",
			Line:      line,
			Snippet:   snippet,
			Message: fmt.Sprintf(
				"Certificate signing request public key uses %s, which is quantum-vulnerable (Shor's algorithm). Subject CN=%s.",
				label, subject),
			Recommendation: certRecommendation,
			CWE:            []int{cweWeakCrypto},
		})
	}

	if fam, name, weakHash, ok := signatureInfo(csr.SignatureAlgorithm); ok {
		msg := fmt.Sprintf(
			"Certificate signing request is signed with %s (%s), which is quantum-vulnerable (Shor's algorithm). Subject CN=%s.",
			name, fam, subject)
		if weakHash {
			msg += " The signature hash is also classically weak (SHA-1/MD5 class); replace it regardless of PQC timelines."
		}
		out = append(out, Match{
			RuleID:         "X509_CSR_SIG_" + ruleSuffix(fam),
			Algorithm:      fam,
			UsageType:      "certificate",
			Line:           line,
			Snippet:        snippet,
			Message:        msg,
			Recommendation: certRecommendation,
			CWE:            []int{cweWeakCrypto},
		})
	}

	return out
}

// --- private keys ------------------------------------------------------------

// privateKeyMatch identifies the algorithm of one private-key block. Typed
// legacy blocks (RSA / EC / DSA PRIVATE KEY) assert their algorithm in the PEM
// type itself, so they are reported even when the DER body cannot be parsed
// (e.g. passphrase-encrypted legacy PEM). Untyped PKCS#8 blocks are reported
// only when the algorithm is positively identified — an unknown PKCS#8 OID
// (future ML-DSA / ML-KEM keys) emits nothing.
func privateKeyMatch(block *pem.Block, line int, snippet string) *Match {
	switch block.Type {
	case "RSA PRIVATE KEY":
		var bits *int
		label := "RSA"
		if k, err := stdx509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
			n := k.N.BitLen()
			bits = &n
			label = fmt.Sprintf("RSA-%d", n)
		}
		return keyMatch("RSA", label, bits, line, snippet)

	case "EC PRIVATE KEY":
		var bits *int
		label := "ECDSA"
		if k, err := stdx509.ParseECPrivateKey(block.Bytes); err == nil {
			p := k.Curve.Params()
			n := p.BitSize
			bits = &n
			label = "ECDSA " + p.Name
		}
		return keyMatch("ECDSA", label, bits, line, snippet)

	case "DSA PRIVATE KEY":
		return keyMatch("DSA", "DSA", nil, line, snippet)

	case "PRIVATE KEY": // PKCS#8
		key, err := stdx509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil // unknown algorithm — do not flag (PQC safety)
		}
		return keyMatchFromParsed(key, line, snippet)

	case "OPENSSH PRIVATE KEY":
		key, err := ssh.ParseRawPrivateKey(pem.EncodeToMemory(block))
		if err != nil {
			// Unreadable (e.g. passphrase-protected): the OpenSSH container is
			// still classical committed key material — classify generically.
			return keyMatch("SSH", "an OpenSSH private key (algorithm unreadable)", nil, line, snippet)
		}
		return keyMatchFromParsed(key, line, snippet)
	}
	return nil
}

// keyMatchFromParsed classifies an already-parsed private key (PKCS#8 or
// OpenSSH). Unrecognized concrete types emit nothing.
func keyMatchFromParsed(key any, line int, snippet string) *Match {
	switch k := key.(type) {
	case *rsa.PrivateKey:
		n := k.N.BitLen()
		return keyMatch("RSA", fmt.Sprintf("RSA-%d", n), &n, line, snippet)
	case *ecdsa.PrivateKey:
		p := k.Curve.Params()
		n := p.BitSize
		return keyMatch("ECDSA", "ECDSA "+p.Name, &n, line, snippet)
	case ed25519.PrivateKey:
		return keyMatch("Ed25519", "Ed25519", nil, line, snippet)
	case *ed25519.PrivateKey: // ssh.ParseRawPrivateKey returns a pointer
		return keyMatch("Ed25519", "Ed25519", nil, line, snippet)
	case *dsa.PrivateKey:
		return keyMatch("DSA", "DSA", nil, line, snippet)
	case *ecdh.PrivateKey:
		// X25519 (or NIST ECDH) key agreement keys are equally Shor-broken.
		return keyMatch("ECDH", "ECDH ("+ecdhCurveName(k.Curve())+")", nil, line, snippet)
	}
	return nil
}

// keyMatch builds the single private-key finding.
func keyMatch(alg, label string, bits *int, line int, snippet string) *Match {
	return &Match{
		RuleID:    "X509_PRIVATE_KEY_" + ruleSuffix(alg),
		Algorithm: alg,
		KeySize:   bits,
		UsageType: "key_storage",
		Line:      line,
		Snippet:   snippet,
		Message: fmt.Sprintf(
			"Committed private key uses %s, which is quantum-vulnerable (Shor's algorithm). Private key material checked into the repository is also a hard-coded credential.",
			label),
		Recommendation: keyRecommendation,
		CWE:            []int{cweWeakCrypto, cweHardcodedCreds},
	}
}

// --- public keys --------------------------------------------------------------

// publicKeyMatch identifies the algorithm of one standalone public-key block.
func publicKeyMatch(block *pem.Block, line int, snippet string) *Match {
	var (
		key any
		err error
	)
	switch block.Type {
	case "PUBLIC KEY": // SubjectPublicKeyInfo (PKIX)
		key, err = stdx509.ParsePKIXPublicKey(block.Bytes)
	case "RSA PUBLIC KEY": // PKCS#1
		key, err = stdx509.ParsePKCS1PublicKey(block.Bytes)
	}
	if err != nil || key == nil {
		return nil // unknown algorithm — do not flag (PQC safety)
	}

	alg, label, bits, ok := publicKeyInfo(key, stdx509.UnknownPublicKeyAlgorithm)
	if !ok {
		return nil
	}
	return &Match{
		RuleID:    "X509_PUBLIC_KEY_" + ruleSuffix(alg),
		Algorithm: alg,
		KeySize:   bits,
		UsageType: "key_storage",
		Line:      line,
		Snippet:   snippet,
		Message: fmt.Sprintf(
			"Public key material uses %s, which is quantum-vulnerable (Shor's algorithm).",
			label),
		Recommendation: certRecommendation,
		CWE:            []int{cweWeakCrypto},
	}
}

// --- algorithm classification --------------------------------------------------

// publicKeyInfo classifies a parsed public key. label is the human-readable
// form (RSA-2048, ECDSA P-256, ...); bits is the key size when meaningful.
// ok=false means the algorithm is unrecognized and MUST NOT be flagged.
//
// pkAlg is consulted as a fallback for algorithms crypto/x509 identifies but
// no longer materializes a key object for (DSA certificates in modern Go).
func publicKeyInfo(key any, pkAlg stdx509.PublicKeyAlgorithm) (alg, label string, bits *int, ok bool) {
	switch k := key.(type) {
	case *rsa.PublicKey:
		n := k.N.BitLen()
		return "RSA", fmt.Sprintf("RSA-%d", n), &n, true
	case *ecdsa.PublicKey:
		p := k.Curve.Params()
		n := p.BitSize
		return "ECDSA", "ECDSA " + p.Name, &n, true
	case ed25519.PublicKey:
		return "Ed25519", "Ed25519", nil, true
	case *dsa.PublicKey:
		if k.P != nil {
			n := k.P.BitLen()
			return "DSA", fmt.Sprintf("DSA-%d", n), &n, true
		}
		return "DSA", "DSA", nil, true
	case *ecdh.PublicKey:
		return "ECDH", "ECDH (" + ecdhCurveName(k.Curve()) + ")", nil, true
	}
	if pkAlg == stdx509.DSA {
		return "DSA", "DSA", nil, true
	}
	// Unknown public-key algorithm (future ML-DSA etc.) — never flag.
	return "", "", nil, false
}

// signatureInfo maps a crypto/x509 signature algorithm to its quantum-broken
// family and conventional name. ok=false means the algorithm is unrecognized
// (future PQC signature OIDs) and MUST NOT be flagged. weakHash marks SHA-1 /
// MD5 / MD2 based signatures, which are additionally classically weak.
func signatureInfo(alg stdx509.SignatureAlgorithm) (family, name string, weakHash, ok bool) {
	switch alg {
	case stdx509.MD2WithRSA:
		return "RSA", "md2WithRSAEncryption", true, true
	case stdx509.MD5WithRSA:
		return "RSA", "md5WithRSAEncryption", true, true
	case stdx509.SHA1WithRSA:
		return "RSA", "sha1WithRSAEncryption", true, true
	case stdx509.SHA256WithRSA:
		return "RSA", "sha256WithRSAEncryption", false, true
	case stdx509.SHA384WithRSA:
		return "RSA", "sha384WithRSAEncryption", false, true
	case stdx509.SHA512WithRSA:
		return "RSA", "sha512WithRSAEncryption", false, true
	case stdx509.SHA256WithRSAPSS:
		return "RSA", "RSASSA-PSS (SHA-256)", false, true
	case stdx509.SHA384WithRSAPSS:
		return "RSA", "RSASSA-PSS (SHA-384)", false, true
	case stdx509.SHA512WithRSAPSS:
		return "RSA", "RSASSA-PSS (SHA-512)", false, true
	case stdx509.DSAWithSHA1:
		return "DSA", "dsaWithSHA1", true, true
	case stdx509.DSAWithSHA256:
		return "DSA", "dsaWithSHA256", false, true
	case stdx509.ECDSAWithSHA1:
		return "ECDSA", "ecdsa-with-SHA1", true, true
	case stdx509.ECDSAWithSHA256:
		return "ECDSA", "ecdsa-with-SHA256", false, true
	case stdx509.ECDSAWithSHA384:
		return "ECDSA", "ecdsa-with-SHA384", false, true
	case stdx509.ECDSAWithSHA512:
		return "ECDSA", "ecdsa-with-SHA512", false, true
	case stdx509.PureEd25519:
		return "Ed25519", "Ed25519", false, true
	}
	// Unknown signature algorithm (future ML-DSA etc.) — never flag.
	return "", "", false, false
}

// ecdhCurveName names a crypto/ecdh curve (the Curve interface exposes no
// name accessor).
func ecdhCurveName(c ecdh.Curve) string {
	switch c {
	case ecdh.X25519():
		return "X25519"
	case ecdh.P256():
		return "P-256"
	case ecdh.P384():
		return "P-384"
	case ecdh.P521():
		return "P-521"
	}
	return "unknown curve"
}

// ruleSuffix normalizes an algorithm name for use in a synthetic rule id.
func ruleSuffix(alg string) string {
	switch alg {
	case "Ed25519":
		return "ED25519"
	}
	return alg
}

// commonName renders a subject CN for messages, tolerating empty subjects.
func commonName(cn string) string {
	if cn == "" {
		return "(none)"
	}
	return cn
}
