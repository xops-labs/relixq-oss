// Copyright (c) 2026 Yasvanth Udayakumar
// SPDX-License-Identifier: Apache-2.0
// See LICENSE in the repository root for full terms.
package sbom

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLookup_caseFold(t *testing.T) {
	cases := []struct {
		eco  Ecosystem
		name string
		want bool
	}{
		{EcosystemPython, "cryptography", true},
		{EcosystemPython, "Cryptography", true},  // case fold
		{EcosystemPython, "CRYPTOGRAPHY", true},  // case fold
		{EcosystemPython, "definitely-not-a-real-package-xyz", false},
		{EcosystemJavaScript, "crypto-js", true},
		{EcosystemJavaScript, "Crypto-JS", true}, // case fold
		{EcosystemGo, "github.com/cloudflare/circl", true},
		{EcosystemGo, "github.com/CloudFlare/circl", true},
		{EcosystemPython, "crypto-js", false}, // wrong ecosystem
	}
	for _, c := range cases {
		got := Lookup(c.eco, c.name) != nil
		if got != c.want {
			t.Errorf("Lookup(%q, %q) = %v, want %v", c.eco, c.name, got, c.want)
		}
	}
}

func TestParseRequirementsTxt(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "requirements.txt")
	body := `# header
cryptography==41.0.0
pycrypto

# blank line above
pyOpenSSL>=21.0
ecdsa[testing]==0.18.0  # inline comment
-r other-reqs.txt
django ; python_version >= "3.8"
not-a-crypto-pkg==1.2
package-with-url @ https://example.com/x.tgz
`
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	deps, err := parseRequirementsTxt(path, "requirements.txt")
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]bool{
		"cryptography": false, "pycrypto": false, "pyOpenSSL": false,
		"ecdsa": false, "django": false, "not-a-crypto-pkg": false,
		"package-with-url": false,
	}
	for _, d := range deps {
		if _, ok := want[d.PackageName]; ok {
			want[d.PackageName] = true
		} else {
			t.Errorf("unexpected dep %+v", d)
		}
	}
	for name, found := range want {
		if !found {
			t.Errorf("expected to find dep %q", name)
		}
	}
}

func TestParseGoMod(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "go.mod")
	body := `module example.com/foo

go 1.22

require example.com/single v1.0.0

require (
    github.com/cloudflare/circl v1.3.0
    github.com/dgrijalva/jwt-go v3.2.0+incompatible // indirect
    golang.org/x/crypto v0.20.0
)

// trailing comment
`
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	deps, err := parseGoMod(path, "go.mod")
	if err != nil {
		t.Fatal(err)
	}
	names := map[string]bool{}
	for _, d := range deps {
		names[d.PackageName] = true
	}
	for _, want := range []string{
		"example.com/single",
		"github.com/cloudflare/circl",
		"github.com/dgrijalva/jwt-go",
		"golang.org/x/crypto",
	} {
		if !names[want] {
			t.Errorf("expected dep %q in %v", want, names)
		}
	}
}

func TestParsePackageJSON(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "package.json")
	body := `{
  "name": "example",
  "version": "1.0.0",
  "dependencies": {
    "crypto-js": "^4.1.1",
    "lodash": "^4.17.21"
  },
  "devDependencies": {
    "jsonwebtoken": "^9.0.0"
  }
}
`
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	deps, err := parsePackageJSON(path, "package.json")
	if err != nil {
		t.Fatal(err)
	}
	names := map[string]bool{}
	for _, d := range deps {
		names[d.PackageName] = true
	}
	for _, want := range []string{"crypto-js", "lodash", "jsonwebtoken"} {
		if !names[want] {
			t.Errorf("expected dep %q in %v", want, names)
		}
	}
}

// TestIngest_endToEnd assembles a fake repo with three manifest files
// and confirms Ingest produces the right shape of findings.
func TestIngest_endToEnd(t *testing.T) {
	root := t.TempDir()

	// Python: requirements.txt with two known crypto deps + one unknown
	mustWrite(t, filepath.Join(root, "requirements.txt"), `cryptography==41.0.0
pycrypto
django==4.2.0
`)
	// Node: package.json with one known crypto dep
	mustWrite(t, filepath.Join(root, "package.json"), `{
  "dependencies": {"crypto-js": "^4.1.1", "lodash": "^4.17.21"}
}`)
	// Go: go.mod with a PQ-ready and a vulnerable lib
	mustWrite(t, filepath.Join(root, "go.mod"), `module example.com/foo
go 1.22
require (
    github.com/cloudflare/circl v1.3.0
    github.com/dgrijalva/jwt-go v3.2.0+incompatible
)
`)
	// A noise file inside node_modules — must be skipped.
	if err := os.MkdirAll(filepath.Join(root, "node_modules", "x"), 0o755); err != nil {
		t.Fatal(err)
	}
	mustWrite(t, filepath.Join(root, "node_modules", "x", "package.json"), `{"dependencies":{"crypto-js":"^1.0.0"}}`)

	findings, err := Ingest(root, "test-job")
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) == 0 {
		t.Fatal("expected non-zero findings from end-to-end ingest")
	}

	// Should NOT include node_modules findings.
	for _, f := range findings {
		if strings.Contains(f.FilePath, "node_modules") {
			t.Errorf("node_modules manifest should be skipped: %+v", f)
		}
	}

	// Spot-check one fan-out: pycrypto declares many algorithms; expect
	// at least 4 findings just from that one dep.
	pycryptoCount := 0
	for _, f := range findings {
		if strings.HasPrefix(f.RuleID, "SBOM_PYTHON_PYCRYPTO_") {
			pycryptoCount++
		}
	}
	if pycryptoCount < 4 {
		t.Errorf("expected ≥4 SBOM_PYTHON_PYCRYPTO_* findings (pycrypto declares many algos), got %d", pycryptoCount)
	}

	// Spot-check CIRCL: should be marked quantum-safe.
	var sawCircl bool
	for _, f := range findings {
		if strings.HasPrefix(f.RuleID, "SBOM_GO_GITHUB_COM_CLOUDFLARE_CIRCL_") {
			sawCircl = true
			if f.QuantumSafety != "quantum_safe" {
				t.Errorf("CIRCL findings should be quantum_safe (migration target), got %q on %s", f.QuantumSafety, f.RuleID)
			}
		}
	}
	if !sawCircl {
		t.Errorf("expected CIRCL findings to be emitted")
	}

	// Deprecated dgrijalva/jwt-go: should be flagged Deprecated in message.
	var sawDeprecatedJWT bool
	for _, f := range findings {
		if strings.HasPrefix(f.RuleID, "SBOM_GO_GITHUB_COM_DGRIJALVA_JWT_GO_") {
			sawDeprecatedJWT = true
			if !strings.Contains(strings.ToUpper(f.Message), "DEPRECATED") {
				t.Errorf("dgrijalva/jwt-go message should mention deprecation, got %q", f.Message)
			}
		}
	}
	if !sawDeprecatedJWT {
		t.Errorf("expected dgrijalva/jwt-go findings to be emitted")
	}
}

func TestSplitRequirementsSpec(t *testing.T) {
	cases := []struct {
		in   string
		name string
		ver  string
	}{
		{"cryptography==41.0.0", "cryptography", "==41.0.0"},
		{"pycrypto", "pycrypto", ""},
		{"pyOpenSSL>=21.0", "pyOpenSSL", ">=21.0"},
		{"ecdsa[testing]==0.18.0", "ecdsa", "==0.18.0"},
		{`django ; python_version >= "3.8"`, "django", ""},
		{"package @ https://example.com/x.tgz", "package", ""},
	}
	for _, c := range cases {
		n, v := splitRequirementsSpec(c.in)
		if n != c.name || v != c.ver {
			t.Errorf("splitRequirementsSpec(%q) = (%q, %q), want (%q, %q)",
				c.in, n, v, c.name, c.ver)
		}
	}
}

func mustWrite(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}
