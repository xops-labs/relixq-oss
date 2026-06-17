// Copyright 2026 Yasvanth Udayakumar
// SPDX-License-Identifier: Apache-2.0
//
// relixq-scan-code is the standalone scanner-engine binary for the OSS
// distribution. It scans an on-disk path against a rule directory and writes
// JSONL findings, optionally emitting a Crypto-Agility Scorecard. This is the
// binary the OSS API shells out to (and the one the `relixq` CLI's RunLocal
// resolves via RELIXQ_SCANNER_BIN / $PATH).
//
// Only the pure-Go detectors are wired in so the OSS image needs no CGO
// toolchain. Regex rule packs cover every other language; languages whose AST
// runner is CGO-gated (Java/Rust/C/C++/Kotlin/…) still get regex coverage.
// Rebuild with CGO + the tree-sitter detectors for full AST coverage.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	"github.com/google/uuid"

	"github.com/relix-q/relix-q/agility"
	// AST detectors. goast/jstsast/phpast are pure-Go; csharpast shells out to
	// the bundled relixq-roslyn .NET subprocess (resolved via RELIXQ_ROSLYN_BIN /
	// $PATH / ../tools). The remaining runners are Tree-sitter-backed and gated on
	// //go:build cgo: built with CGO_ENABLED=1 + a C toolchain (the shipped Docker
	// image) they compile the real grammar runners; otherwise they compile no-op
	// stubs and those languages fall back to the regex floor — never an error.
	_ "github.com/relix-q/relix-q/detectors/cppast"    // C / C++ AST (tree-sitter, CGO)
	_ "github.com/relix-q/relix-q/detectors/csharpast" // C# AST (Roslyn subprocess; bundled relixq-roslyn)
	_ "github.com/relix-q/relix-q/detectors/goast"     // Go AST (pure-Go, in-process)
	_ "github.com/relix-q/relix-q/detectors/javaast"   // Java AST (tree-sitter, CGO)
	_ "github.com/relix-q/relix-q/detectors/jstsast"   // JS+TS AST (pure-Go via goja/esbuild)
	_ "github.com/relix-q/relix-q/detectors/juliaast"  // Julia AST (tree-sitter, CGO)
	_ "github.com/relix-q/relix-q/detectors/kotlinast" // Kotlin AST (tree-sitter, CGO)
	_ "github.com/relix-q/relix-q/detectors/phpast"    // PHP AST (pure-Go)
	_ "github.com/relix-q/relix-q/detectors/rubyast"   // Ruby AST (tree-sitter, CGO)
	_ "github.com/relix-q/relix-q/detectors/rustast"   // Rust AST (tree-sitter, CGO)
	_ "github.com/relix-q/relix-q/detectors/scalaast"  // Scala AST (tree-sitter, CGO)
	_ "github.com/relix-q/relix-q/detectors/swiftast"  // Swift AST (tree-sitter, CGO)
	"github.com/relix-q/relix-q/enrich"
	// NOTE: pyast (Python) is omitted — it needs an external python interpreter
	// the slim image does not ship; Python is covered by the regex floor.
	"github.com/relix-q/relix-q/finding"
	"github.com/relix-q/relix-q/rules"
	"github.com/relix-q/relix-q/scanner"
)

// version and commit are stamped at release-build time via -ldflags
// (see .goreleaser.yaml); a plain `go build` reports "dev".
var (
	version = "dev"
	commit  = "unknown"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func run() error {
	var (
		showVersion = flag.Bool("version", false, "Print version information and exit")

		path       = flag.String("path", ".", "Path to the repository to scan")
		rulesDir   = flag.String("rules", "./rules", "Path to the rule pack directory")
		rulePack   = flag.String("rulepack", "", "Optional: path to an external rule-pack overlay tree (migration-enrichment). Falls back to $RELIXQ_RULE_PACK. Empty = detection-only OSS output.")
		output     = flag.String("output", "findings.jsonl", "Where to write the JSONL findings file")
		agilityOut = flag.String("agility", "", "Optional: path to write a Crypto-Agility Scorecard JSON. Empty disables.")
		summaryOut = flag.String("summary", "", "Optional: path to write a scan summary JSON (files scanned/skipped, findings, files per language). Empty disables.")
		orgID      = flag.String("org-id", "local", "scan_run organization_id stamped into findings")
		jobID      = flag.String("job-id", "", "Override scan_job_id (default: random uuid)")
		runID      = flag.String("run-id", "", "Override scan_run_id (default: random uuid)")
		verbose    = flag.Bool("v", false, "Verbose (debug) logging")
	)
	flag.Parse()

	if *showVersion {
		fmt.Printf("relixq-scan-code %s (commit %s)\n", version, commit)
		return nil
	}

	level := slog.LevelInfo
	if *verbose {
		level = slog.LevelDebug
	}
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level}))

	abs, err := filepath.Abs(*path)
	if err != nil {
		return err
	}

	pack, err := rules.LoadDir(*rulesDir)
	if err != nil {
		return fmt.Errorf("load rules: %w", err)
	}
	log.Info("rule pack loaded", "version", pack.Version, "rules", len(pack.All))

	scn := scanner.New(scanner.Job{
		OrganizationID: *orgID,
		ScanRunID:      orDefault(*runID, uuid.NewString()),
		ScanJobID:      orDefault(*jobID, uuid.NewString()),
	}, log)

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	res, err := scn.Scan(ctx, scanner.ScanRequest{
		RepoPath: abs,
		Pack:     pack,
		Output:   *output,
	})
	if err != nil {
		return err
	}
	log.Info("scan complete",
		"files_scanned", res.FilesScanned,
		"files_skipped", res.FilesSkipped,
		"findings", res.FindingsCount,
		"output", res.OutputPath)

	// enrichment overlay. Without an overlay (the default OSS path) this is
	// a no-op and findings stay detection-only. With one present, each finding
	// is enriched in place by rule id before any consumer reads the JSONL.
	if rp := resolveRulePack(*rulePack); rp != "" {
		if n, err := enrichFindings(res.OutputPath, rp); err != nil {
			log.Warn("rule-pack enrichment skipped", "rule_pack", rp, "error", err) // non-fatal; detection findings already written
		} else if n > 0 {
			log.Info("findings enriched from rule pack", "rule_pack", rp, "enriched", n)
		}
	}

	fmt.Println(res.OutputPath)

	if *summaryOut != "" {
		if err := writeScanSummary(*summaryOut, res); err != nil {
			log.Warn("scan summary failed", "error", err) // non-fatal; findings already written
		}
	}

	if *agilityOut != "" {
		findings, err := loadFindings(res.OutputPath)
		if err != nil {
			log.Warn("agility scorecard skipped: load findings", "error", err)
		} else if err := writeAgilityScorecard(*agilityOut, agility.Score(findings), log); err != nil {
			log.Warn("agility scorecard failed", "error", err) // non-fatal; findings already written
		}
	}
	return nil
}

// resolveRulePack prefers the explicit -rulepack flag, falling back to the
// RELIXQ_RULE_PACK environment variable so the `relixq` CLI (which spawns this
// binary) enables enrichment purely via the inherited environment.
func resolveRulePack(flagVal string) string {
	if flagVal != "" {
		return flagVal
	}
	return os.Getenv("RELIXQ_RULE_PACK")
}

// enrichFindings loads the rule-pack overlay, applies it to the findings on
// disk, and rewrites the JSONL in place. Returns the number enriched. A missing
// or empty overlay path yields (0, nil) — the OSS detection-only path.
func enrichFindings(path, rulePackDir string) (int, error) {
	idx, err := enrich.LoadDir(rulePackDir)
	if err != nil {
		return 0, fmt.Errorf("load rule pack: %w", err)
	}
	if len(idx) == 0 {
		return 0, nil
	}
	findings, err := loadFindings(path)
	if err != nil {
		return 0, fmt.Errorf("load findings: %w", err)
	}
	n := enrich.Apply(findings, idx)
	if n == 0 {
		return 0, nil
	}
	w, err := finding.NewJSONLWriter(path)
	if err != nil {
		return 0, fmt.Errorf("rewrite findings: %w", err)
	}
	for i := range findings {
		if err := w.Write(&findings[i]); err != nil {
			_ = w.Close()
			return 0, fmt.Errorf("rewrite findings: %w", err)
		}
	}
	if err := w.Close(); err != nil {
		return 0, fmt.Errorf("rewrite findings: %w", err)
	}
	return n, nil
}

func loadFindings(path string) ([]finding.Finding, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open findings: %w", err)
	}
	defer f.Close()
	return finding.ReadAll(f)
}

func writeAgilityScorecard(outPath string, sc agility.Scorecard, log *slog.Logger) error {
	out, err := os.Create(outPath)
	if err != nil {
		return fmt.Errorf("open agility output: %w", err)
	}
	defer out.Close()
	enc := json.NewEncoder(out)
	enc.SetIndent("", "  ")
	if err := enc.Encode(sc); err != nil {
		return fmt.Errorf("encode agility scorecard: %w", err)
	}
	log.Info("crypto-agility scorecard written", "path", outPath, "total_score", sc.TotalScore, "grade", sc.Grade)
	return nil
}

// writeScanSummary writes the machine-readable scan summary consumed by the
// OSS app (files scanned per language → the "Files scanned" coverage card).
func writeScanSummary(outPath string, res *scanner.ScanResult) error {
	byLang := make(map[string]int, len(res.FilesByLanguage))
	for lang, n := range res.FilesByLanguage {
		name := string(lang)
		if name == "" {
			name = "unknown"
		}
		byLang[name] = n
	}
	summary := struct {
		FilesScanned    int            `json:"files_scanned"`
		FilesSkipped    int            `json:"files_skipped"`
		Findings        int            `json:"findings"`
		FilesByLanguage map[string]int `json:"files_by_language"`
	}{res.FilesScanned, res.FilesSkipped, res.FindingsCount, byLang}

	out, err := os.Create(outPath)
	if err != nil {
		return fmt.Errorf("open summary output: %w", err)
	}
	defer out.Close()
	enc := json.NewEncoder(out)
	enc.SetIndent("", "  ")
	if err := enc.Encode(summary); err != nil {
		return fmt.Errorf("encode scan summary: %w", err)
	}
	return nil
}

func orDefault(s, d string) string {
	if s == "" {
		return d
	}
	return s
}
