// Copyright (c) 2026 Yasvanth Udayakumar
// SPDX-License-Identifier: Apache-2.0
// See LICENSE in the repository root for full terms.
package cmd

import (
	"bufio"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/relix-q/relix-q/cmd/relixq/internal/config"
	"github.com/relix-q/relix-q/cmd/relixq/internal/scanner"
	"github.com/spf13/cobra"
)

var tlsCmd = &cobra.Command{
	Use:   "tls [target ...]",
	Short: "Scan TLS endpoints for quantum-vulnerable certificate and protocol crypto",
	Long: `tls performs a TLS handshake against each target host[:port] (default port
443) and flags weak transport crypto: classical certificate keys (RSA/ECDSA/
DSA — quantum-vulnerable), undersized RSA keys, SHA-1 signatures, expired or
soon-to-expire certs, self-signed leaves, deprecated TLS 1.0/1.1, and weak
negotiated cipher suites.

Targets come from positional args, repeated --target flags, and/or a --targets
file (one host[:port] per line). Findings flow through the same --format /
--severity-threshold / --baseline pipeline as 'relixq scan'.

Examples:
  relixq scan tls example.com:443
  relixq scan tls --targets hosts.txt --format sarif`,
	RunE: runTLS,
}

func runTLS(cmd *cobra.Command, args []string) error {
	cfg, _ := config.Load(".")
	applyOutputFlags(cmd, cfg)

	targets := append([]string{}, args...)
	if flagged, _ := cmd.Flags().GetStringArray("target"); len(flagged) > 0 {
		targets = append(targets, flagged...)
	}
	if file, _ := cmd.Flags().GetString("targets"); file != "" {
		lines, err := readTargetsFile(file)
		if err != nil {
			return fmt.Errorf("--targets: %w", err)
		}
		targets = append(targets, lines...)
	}
	if len(targets) == 0 {
		return fmt.Errorf("no targets: pass host[:port] args, --target, or --targets <file>")
	}

	timeout, _ := cmd.Flags().GetDuration("timeout")
	findings, errs := scanner.RunTLS(cmd.Context(), targets, timeout)
	for _, e := range errs {
		if !quietFlag {
			fmt.Fprintln(os.Stderr, "relixq scan tls:", e)
		}
	}
	// Only a hard failure when every target was unreachable.
	if len(findings) == 0 && len(errs) == len(targets) {
		return fmt.Errorf("all %d target(s) failed", len(targets))
	}

	return emitFindings(cmd, cfg, findings)
}

func readTargetsFile(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var out []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		out = append(out, line)
	}
	return out, sc.Err()
}

func init() {
	tlsCmd.Flags().StringArray("target", nil, "Target host[:port] to scan (repeatable; default port 443)")
	tlsCmd.Flags().String("targets", "", "File with one host[:port] per line")
	tlsCmd.Flags().Duration("timeout", 5*time.Second, "Per-connection dial/handshake timeout")
	tlsCmd.Flags().String("format", "text", "Output format: text|json|jsonl|sarif|markdown|html")
	tlsCmd.Flags().StringP("output", "o", "", "Write output to file instead of stdout")
	tlsCmd.Flags().String("severity-threshold", "", "Filter findings below this severity (info|low|medium|high|critical)")
	tlsCmd.Flags().String("exit-on", "", "Exit 1 if any finding meets or exceeds this severity")
	tlsCmd.Flags().String("baseline", "", "Suppress findings recorded in this baseline file; report only new ones")
	scanCmd.AddCommand(tlsCmd)
}
