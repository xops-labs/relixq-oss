// Copyright (c) 2026 Yasvanth Udayakumar
// SPDX-License-Identifier: Apache-2.0
// See LICENSE in the repository root for full terms.

//go:build integration
// +build integration

// Integration test for the CLI's local-scan path. The real scanner worker
// (relixq-scan-code) is not part of this repo, so we drop a tiny stub
// scanner script in a temp dir and point internal/scanner.RunLocal at it
// via RELIXQ_SCANNER_BIN. The test then runs the same pipeline the
// `relixq scan` Cobra command runs: scanner subprocess → JSONL ingest →
// severity filter → formatter.Write. We invoke that pipeline through the
// exported internal packages rather than exec'ing a freshly-built
// relixq.exe — building and immediately exec'ing native binaries from a
// temp dir trips endpoint-AV / WDAC on some Windows configurations, and
// the Cobra layer above runScan is a thin flag-parsing shell anyway.
//
// Run with: go test -tags=integration ./...
package main_test

import (
	"bytes"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/relix-q/relix-q/cmd/relixq/internal/formatter"
	"github.com/relix-q/relix-q/cmd/relixq/internal/scanner"
)

// stubScannerPSScript is a deterministic PowerShell stand-in for the real
// scanner worker (relixq-scan-code). It walks
// -path, greps each file for two well-known RSA keygen idioms (Go and C#),
// and emits one CryptoFinding-shaped JSONL row per match to -output —
// matching the JSONL contract internal/scanner.RunLocal consumes. We use a
// script (not a freshly-built Go binary) so the test doesn't fight
// endpoint-AV heuristics that flag small, just-compiled native binaries.
const stubScannerPSScript = `param([string]$path, [string]$output)
$findings = @()
$files = Get-ChildItem -Path $path -Recurse -File -ErrorAction SilentlyContinue
foreach ($file in $files) {
    $lines = @(Get-Content -Path $file.FullName -ErrorAction SilentlyContinue)
    for ($i = 0; $i -lt $lines.Count; $i++) {
        if ($lines[$i] -like '*rsa.GenerateKey(rand.Reader, 2048)*') {
            $findings += @{
                rule_id        = 'GO_RSA_GENERATE_KEY'
                algorithm      = 'RSA'
                usage_type     = 'key_generation'
                quantum_safety = 'vulnerable'
                key_size       = 2048
                file_path      = $file.FullName
                line_number    = ($i + 1)
                severity       = 'critical'
                confidence     = 0.97
                message        = 'rsa.GenerateKey produces a quantum-vulnerable key pair.'
            }
        }
        if ($lines[$i] -like '*RSA.Create(2048)*') {
            $findings += @{
                rule_id        = 'CSHARP_RSA_CREATE'
                algorithm      = 'RSA'
                usage_type     = 'key_generation'
                quantum_safety = 'vulnerable'
                key_size       = 2048
                file_path      = $file.FullName
                line_number    = ($i + 1)
                severity       = 'critical'
                confidence     = 0.97
                message        = 'RSA.Create(int) produces a quantum-vulnerable key pair.'
            }
        }
    }
}
$out = $findings | ForEach-Object { $_ | ConvertTo-Json -Compress }
Set-Content -Path $output -Value $out -Encoding ASCII
`

// stubScannerShScript is the POSIX equivalent. awk + a tiny shell loop is
// enough to mimic the JSONL contract for the two patterns we care about.
const stubScannerShScript = `#!/bin/sh
# Parse -path/-output flags (the only ones internal/scanner.buildArgs sets).
SCAN_PATH=""
OUT_FILE=""
while [ $# -gt 0 ]; do
  case "$1" in
    -path)   SCAN_PATH="$2"; shift 2 ;;
    -output) OUT_FILE="$2"; shift 2 ;;
    *)       shift ;;
  esac
done
: > "$OUT_FILE"
find "$SCAN_PATH" -type f | while read -r f; do
  awk -v F="$f" '
    /rsa\.GenerateKey\(rand\.Reader, 2048\)/ {
      printf "{\"rule_id\":\"GO_RSA_GENERATE_KEY\",\"algorithm\":\"RSA\",\"usage_type\":\"key_generation\",\"quantum_safety\":\"vulnerable\",\"key_size\":2048,\"file_path\":\"%s\",\"line_number\":%d,\"severity\":\"critical\",\"confidence\":0.97,\"message\":\"rsa.GenerateKey produces a quantum-vulnerable key pair.\"}\n", F, NR
    }
    /RSA\.Create\(2048\)/ {
      printf "{\"rule_id\":\"CSHARP_RSA_CREATE\",\"algorithm\":\"RSA\",\"usage_type\":\"key_generation\",\"quantum_safety\":\"vulnerable\",\"key_size\":2048,\"file_path\":\"%s\",\"line_number\":%d,\"severity\":\"critical\",\"confidence\":0.97,\"message\":\"RSA.Create(int) produces a quantum-vulnerable key pair.\"}\n", F, NR
    }
  ' "$f" >> "$OUT_FILE"
done
`

// writeStubScanner drops the platform-appropriate stub scanner into dir
// and returns the path the CLI should exec as RELIXQ_SCANNER_BIN. On
// Windows we emit a .cmd shim that hands off to PowerShell with the same
// -path/-output flag positions the real worker accepts.
func writeStubScanner(t *testing.T, dir string) string {
	t.Helper()
	if runtime.GOOS == "windows" {
		ps1 := filepath.Join(dir, "relixqstubscan.ps1")
		if err := os.WriteFile(ps1, []byte(stubScannerPSScript), 0o644); err != nil {
			t.Fatalf("write ps1: %v", err)
		}
		// The .cmd shim is what RELIXQ_SCANNER_BIN points at; it forwards
		// the CLI's flag list verbatim to PowerShell. PowerShell parses
		// -path / -output as PS-script parameters of the same name.
		cmdPath := filepath.Join(dir, "relixqstubscan.cmd")
		body := "@echo off\r\npowershell -NoProfile -ExecutionPolicy Bypass -File \"%~dp0relixqstubscan.ps1\" %*\r\n"
		if err := os.WriteFile(cmdPath, []byte(body), 0o644); err != nil {
			t.Fatalf("write cmd shim: %v", err)
		}
		return cmdPath
	}
	sh := filepath.Join(dir, "relixqstubscan.sh")
	if err := os.WriteFile(sh, []byte(stubScannerShScript), 0o755); err != nil {
		t.Fatalf("write sh: %v", err)
	}
	return sh
}

// writeFixtureProject lays down two small files under root: a Go file
// using rsa.GenerateKey(rand.Reader, 2048) and a C# file using
// RSA.Create(2048). Combined size stays well under 1 KB.
func writeFixtureProject(t *testing.T, root string) {
	t.Helper()
	goFile := `package demo

import (
	"crypto/rand"
	"crypto/rsa"
)

func MakeKey() (*rsa.PrivateKey, error) {
	return rsa.GenerateKey(rand.Reader, 2048)
}
`
	csFile := `using System.Security.Cryptography;

namespace Demo;

public static class KeyMaker
{
    public static RSA Create() => RSA.Create(2048);
}
`
	if err := os.WriteFile(filepath.Join(root, "demo.go"), []byte(goFile), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "KeyMaker.cs"), []byte(csFile), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestScanLocal_EndToEnd(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test skipped in short mode")
	}

	scannerDir := t.TempDir()
	fixtureDir := filepath.Join(t.TempDir(), "fixture")
	if err := os.MkdirAll(fixtureDir, 0o755); err != nil {
		t.Fatalf("mkdir fixture: %v", err)
	}
	writeFixtureProject(t, fixtureDir)

	stub := writeStubScanner(t, scannerDir)
	t.Setenv("RELIXQ_SCANNER_BIN", stub)

	// Exercise the same internal pipeline cmd/scan.go runs: scanner
	// subprocess → JSONL ingest, then formatter dispatch.
	findings, err := scanner.RunLocal([]string{fixtureDir}, nil, "", "")
	if err != nil {
		t.Fatalf("scanner.RunLocal: %v", err)
	}
	if len(findings) == 0 {
		t.Fatalf("expected nonzero findings against fixture %s, got 0", fixtureDir)
	}

	var sawGo, sawCS bool
	for _, f := range findings {
		if f.Algorithm != "RSA" {
			t.Fatalf("every fixture finding should be algorithm=RSA; got %q in %+v", f.Algorithm, f)
		}
		switch f.RuleID {
		case "GO_RSA_GENERATE_KEY":
			sawGo = true
		case "CSHARP_RSA_CREATE":
			sawCS = true
		}
	}
	if !sawGo {
		t.Errorf("expected a GO_RSA_GENERATE_KEY finding for demo.go; got findings=%+v", findings)
	}
	if !sawCS {
		t.Errorf("expected a CSHARP_RSA_CREATE finding for KeyMaker.cs; got findings=%+v", findings)
	}

	// Confirm the formatter chain the CLI uses surfaces the RSA algorithm
	// name in its JSON output — the assertion the prompt calls out.
	var jsonBuf bytes.Buffer
	if err := formatter.Write("json", findings, &jsonBuf, false, false); err != nil {
		t.Fatalf("formatter.Write json: %v", err)
	}
	if !strings.Contains(jsonBuf.String(), "\"RSA\"") {
		t.Fatalf("expected RSA algorithm to appear in JSON formatter output; got:\n%s", jsonBuf.String())
	}

	// Sanity-check the human-readable text format too — it should mention
	// both rule IDs.
	var textBuf bytes.Buffer
	if err := formatter.Write("text", findings, &textBuf, false, false); err != nil {
		t.Fatalf("formatter.Write text: %v", err)
	}
	if !strings.Contains(textBuf.String(), "GO_RSA_GENERATE_KEY") {
		t.Fatalf("text output missing GO_RSA_GENERATE_KEY:\n%s", textBuf.String())
	}
	if !strings.Contains(textBuf.String(), "CSHARP_RSA_CREATE") {
		t.Fatalf("text output missing CSHARP_RSA_CREATE:\n%s", textBuf.String())
	}
}
