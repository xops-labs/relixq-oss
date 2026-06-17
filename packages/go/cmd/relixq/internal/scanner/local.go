// Copyright (c) 2026 Yasvanth Udayakumar
// SPDX-License-Identifier: Apache-2.0
// See LICENSE in the repository root for full terms.
package scanner

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"

	"github.com/relix-q/relix-q/cmd/relixq/internal/model"
)

const (
	scannerBinaryEnv     = "RELIXQ_SCANNER_BIN"
	scannerBinaryDefault = "relixq-scan-code"
)

// ResolveScannerBin locates the relixq-scan-code engine binary, in order:
//  1. explicit RELIXQ_SCANNER_BIN
//  2. next to the relixq executable (the release-archive layout)
//  3. on PATH
func ResolveScannerBin() (string, error) {
	return resolveScannerBin(executableDir())
}

func resolveScannerBin(exeDir string) (string, error) {
	if bin := os.Getenv(scannerBinaryEnv); bin != "" {
		return bin, nil
	}
	if exeDir != "" {
		name := scannerBinaryDefault
		if runtime.GOOS == "windows" {
			name += ".exe"
		}
		sibling := filepath.Join(exeDir, name)
		if fi, err := os.Stat(sibling); err == nil && !fi.IsDir() {
			return sibling, nil
		}
	}
	if bin, err := exec.LookPath(scannerBinaryDefault); err == nil {
		return bin, nil
	}
	return "", fmt.Errorf(
		"scanner binary %q not found — keep it next to the relixq executable, install it on PATH, or set %s",
		scannerBinaryDefault, scannerBinaryEnv,
	)
}

// BundledRuleDir returns the community rule directory shipped with a release
// install, or "" when none is present. Checked relative to the relixq
// executable: rules/ and rules-community/ beside it (archive + MSI layouts),
// then ../share/relixq/rules (deb/rpm layout: /usr/bin + /usr/share/relixq).
func BundledRuleDir() string {
	return bundledRuleDir(executableDir())
}

func bundledRuleDir(exeDir string) string {
	if exeDir == "" {
		return ""
	}
	candidates := []string{
		filepath.Join(exeDir, "rules"),
		filepath.Join(exeDir, "rules-community"),
		filepath.Join(exeDir, "..", "share", "relixq", "rules"),
	}
	for _, dir := range candidates {
		if fi, err := os.Stat(dir); err == nil && fi.IsDir() {
			return dir
		}
	}
	return ""
}

func executableDir() string {
	exe, err := os.Executable()
	if err != nil {
		return ""
	}
	if resolved, err := filepath.EvalSymlinks(exe); err == nil {
		exe = resolved
	}
	return filepath.Dir(exe)
}

// RunLocal invokes the static-code-scanner as a subprocess and collects
// findings. relixq-scan-code writes JSONL to a file and prints its path to
// stdout; we use a temp file so the caller never needs to manage it.
func RunLocal(paths, exclude []string, rulesOverride, ruleDir string) ([]model.Finding, error) {
	bin, err := ResolveScannerBin()
	if err != nil {
		return nil, err
	}

	// No --rules flag and no configured rule_dir/RELIXQ_RULE_DIR: fall back to
	// the rules bundled with a release install so a downloaded relixq works
	// out of the box.
	if rulesOverride == "" && ruleDir == "" {
		ruleDir = BundledRuleDir()
	}

	outFile := filepath.Join(os.TempDir(), "relixq-local-findings.jsonl")
	args := buildArgs(paths, exclude, rulesOverride, ruleDir, outFile)

	cmd := exec.Command(bin, args...)
	cmd.Stdout = os.Stderr // progress lines to stderr
	cmd.Stderr = os.Stderr

	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("scanner exited with error: %w", err)
	}

	return readFindingsFile(outFile)
}

func readFindingsFile(path string) ([]model.Finding, error) {
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil // no findings written → empty result
		}
		return nil, err
	}
	defer f.Close()

	var findings []model.Finding
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		if line == "" {
			continue
		}
		var finding model.Finding
		if err := json.Unmarshal([]byte(line), &finding); err != nil {
			fmt.Fprintf(os.Stderr, "warn: skipping unparseable finding line: %v\n", err)
			continue
		}
		findings = append(findings, finding)
	}
	return findings, sc.Err()
}

// buildArgs constructs the relixq-scan-code flag set.
// The binary uses Go's flag package (no subcommands); -path may be repeated
// for multiple scan roots, but the binary only reads the first occurrence —
// callers should pass a single repo root when possible.
func buildArgs(paths, exclude []string, rulesOverride, ruleDir, outFile string) []string {
	args := []string{"-output", outFile}

	if len(paths) > 0 {
		args = append(args, "-path", paths[0])
	}

	switch {
	case rulesOverride != "":
		args = append(args, "-rules", rulesOverride)
	case ruleDir != "":
		args = append(args, "-rules", ruleDir)
	}

	// exclude is not yet a flag on relixq-scan-code; silently dropped.
	_ = exclude

	return args
}
