// Copyright (c) 2026 Yasvanth Udayakumar
// SPDX-License-Identifier: Apache-2.0
// See LICENSE in the repository root for full terms.
package scanner

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func scannerBinName() string {
	if runtime.GOOS == "windows" {
		return scannerBinaryDefault + ".exe"
	}
	return scannerBinaryDefault
}

func writeFakeScanner(t *testing.T, dir string) string {
	t.Helper()
	path := filepath.Join(dir, scannerBinName())
	if err := os.WriteFile(path, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestResolveScannerBin_EnvWins(t *testing.T) {
	exeDir := t.TempDir()
	writeFakeScanner(t, exeDir) // present beside the exe, but env must win
	t.Setenv(scannerBinaryEnv, `C:\explicit\relixq-scan-code.exe`)

	got, err := resolveScannerBin(exeDir)
	if err != nil {
		t.Fatalf("resolveScannerBin: %v", err)
	}
	if got != `C:\explicit\relixq-scan-code.exe` {
		t.Fatalf("env override should win; got %q", got)
	}
}

func TestResolveScannerBin_SiblingBeatsPath(t *testing.T) {
	t.Setenv(scannerBinaryEnv, "")
	exeDir := t.TempDir()
	want := writeFakeScanner(t, exeDir)

	// Also put one on PATH to prove the sibling is preferred.
	pathDir := t.TempDir()
	writeFakeScanner(t, pathDir)
	t.Setenv("PATH", pathDir)

	got, err := resolveScannerBin(exeDir)
	if err != nil {
		t.Fatalf("resolveScannerBin: %v", err)
	}
	if got != want {
		t.Fatalf("sibling binary should be preferred; got %q want %q", got, want)
	}
}

func TestResolveScannerBin_FallsBackToPath(t *testing.T) {
	t.Setenv(scannerBinaryEnv, "")
	pathDir := t.TempDir()
	want := writeFakeScanner(t, pathDir)
	t.Setenv("PATH", pathDir)

	got, err := resolveScannerBin(t.TempDir()) // empty exe dir: no sibling
	if err != nil {
		t.Fatalf("resolveScannerBin: %v", err)
	}
	if got != want {
		t.Fatalf("PATH fallback; got %q want %q", got, want)
	}
}

func TestResolveScannerBin_NotFound(t *testing.T) {
	t.Setenv(scannerBinaryEnv, "")
	t.Setenv("PATH", t.TempDir())
	if _, err := resolveScannerBin(t.TempDir()); err == nil {
		t.Fatal("expected an error when the scanner is nowhere to be found")
	}
}

func TestBundledRuleDir(t *testing.T) {
	t.Run("rules beside exe", func(t *testing.T) {
		exeDir := t.TempDir()
		want := filepath.Join(exeDir, "rules")
		if err := os.Mkdir(want, 0o755); err != nil {
			t.Fatal(err)
		}
		if got := bundledRuleDir(exeDir); got != want {
			t.Fatalf("got %q want %q", got, want)
		}
	})

	t.Run("rules-community beside exe", func(t *testing.T) {
		exeDir := t.TempDir()
		want := filepath.Join(exeDir, "rules-community")
		if err := os.Mkdir(want, 0o755); err != nil {
			t.Fatal(err)
		}
		if got := bundledRuleDir(exeDir); got != want {
			t.Fatalf("got %q want %q", got, want)
		}
	})

	t.Run("share layout for deb/rpm", func(t *testing.T) {
		root := t.TempDir()
		exeDir := filepath.Join(root, "bin")
		want := filepath.Join(root, "share", "relixq", "rules")
		for _, d := range []string{exeDir, want} {
			if err := os.MkdirAll(d, 0o755); err != nil {
				t.Fatal(err)
			}
		}
		got := bundledRuleDir(exeDir)
		// bundledRuleDir joins "..": compare resolved paths.
		if filepath.Clean(got) != want {
			t.Fatalf("got %q want %q", got, want)
		}
	})

	t.Run("nothing bundled", func(t *testing.T) {
		if got := bundledRuleDir(t.TempDir()); got != "" {
			t.Fatalf("expected empty, got %q", got)
		}
	})
}
