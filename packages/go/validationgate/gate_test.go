// Copyright (c) 2026 Yasvanth Udayakumar
// SPDX-License-Identifier: Apache-2.0
// See LICENSE in the repository root for full terms.
// TestCorpus is the ground-truth regression gate: it runs the SAME scan
// pipeline the relixq-scan-code binary uses (rules.LoadDir over
// rules-community + scanner.Scan, plus sbom.Ingest for dependencies) over
// fixtures/validation-corpus and grades the output against
// expected-findings.yaml. Four properties are enforced:
//
//	Recall              every active manifest instance is matched
//	ForbiddenLocations  no risk-tagged finding at a bucket-C location
//	Precision           every emitted finding maps to some instance
//	Deps                dependency-scan expectations incl. must-not-flag
//
// A red gate means detection does not match ground truth — fix rules or
// detectors (or, only for genuine labeling errors, the manifest). Do not
// loosen this harness to make it pass.
package validationgate

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"text/tabwriter"

	astdet "github.com/relix-q/relix-q/detectors/ast"

	// Mirror the relixq-scan-code binary's detector set exactly (see
	// cmd/relixq-scan-code/main.go): pure-Go runners always register;
	// CGO-gated tree-sitter runners register only in CGO builds (otherwise
	// they are no-op stubs and the regex floor stands); csharpast registers
	// unconditionally and degrades gracefully when relixq-roslyn is absent.
	// pyast is deliberately omitted, as in the CLI.
	_ "github.com/relix-q/relix-q/detectors/cppast"
	_ "github.com/relix-q/relix-q/detectors/csharpast"
	_ "github.com/relix-q/relix-q/detectors/goast"
	_ "github.com/relix-q/relix-q/detectors/javaast"
	_ "github.com/relix-q/relix-q/detectors/jstsast"
	_ "github.com/relix-q/relix-q/detectors/juliaast"
	_ "github.com/relix-q/relix-q/detectors/kotlinast"
	_ "github.com/relix-q/relix-q/detectors/phpast"
	_ "github.com/relix-q/relix-q/detectors/rubyast"
	_ "github.com/relix-q/relix-q/detectors/rustast"
	_ "github.com/relix-q/relix-q/detectors/scalaast"
	_ "github.com/relix-q/relix-q/detectors/swiftast"

	"github.com/relix-q/relix-q/finding"
	"github.com/relix-q/relix-q/rules"
	"github.com/relix-q/relix-q/sbom"
	"github.com/relix-q/relix-q/scanner"
)

// repoRoot resolves the repository root relative to this package
// (packages/go/validationgate -> ../../..) so the gate needs no environment
// variables and works from any checkout location on Windows and Linux.
func repoRoot(t *testing.T) string {
	t.Helper()
	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	root, err := filepath.Abs(filepath.Join(wd, "..", "..", ".."))
	if err != nil {
		t.Fatalf("resolve repo root: %v", err)
	}
	for _, marker := range []string{
		filepath.Join("fixtures", "validation-corpus", "expected-findings.yaml"),
		filepath.Join("packages", "go", "rules-community"),
	} {
		if _, err := os.Stat(filepath.Join(root, marker)); err != nil {
			t.Fatalf("repo root %s missing %s: %v", root, marker, err)
		}
	}
	return root
}

// runCodeScan executes the production scan pipeline over the corpus and
// returns the parsed findings.
func runCodeScan(t *testing.T, root, corpus string) []finding.Finding {
	t.Helper()

	rulesDir := filepath.Join(root, "packages", "go", "rules-community")
	pack, err := rules.LoadDir(rulesDir)
	if err != nil {
		t.Fatalf("load rules %s: %v", rulesDir, err)
	}
	t.Logf("rule pack loaded: version=%s rules=%d", pack.Version, len(pack.All))

	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	scn := scanner.New(scanner.Job{
		OrganizationID: "validation-gate",
		ScanRunID:      "validation-gate",
		ScanJobID:      "validation-gate",
	}, log)

	out := filepath.Join(t.TempDir(), "findings.jsonl")
	res, err := scn.Scan(context.Background(), scanner.ScanRequest{
		RepoPath: corpus,
		Pack:     pack,
		Output:   out,
	})
	if err != nil {
		t.Fatalf("scan %s: %v", corpus, err)
	}
	t.Logf("code scan: files_scanned=%d files_skipped=%d findings=%d",
		res.FilesScanned, res.FilesSkipped, res.FindingsCount)

	f, err := os.Open(out)
	if err != nil {
		t.Fatalf("open findings output: %v", err)
	}
	defer f.Close()
	findings, err := finding.ReadAll(f)
	if err != nil {
		t.Fatalf("parse findings output: %v", err)
	}
	return findings
}

// sameFile compares a finding path against a manifest path, slash-normalized
// and case-insensitive (Windows checkouts).
func sameFile(findingPath, manifestPath string) bool {
	return strings.EqualFold(filepath.ToSlash(findingPath), filepath.ToSlash(manifestPath))
}

// astAvailable reports whether an AST runner is registered for the language
// the scanner would route this file to.
func astAvailable(file string) bool {
	lang := scanner.DetectLanguage(file)
	if lang == scanner.LangUnknown {
		return false
	}
	return astdet.Get(string(lang)) != nil
}

// table renders aligned rows for failure reports.
func table(header string, rows [][]string) string {
	var sb strings.Builder
	sb.WriteString(header)
	sb.WriteString("\n")
	w := tabwriter.NewWriter(&sb, 2, 4, 2, ' ', 0)
	for _, r := range rows {
		fmt.Fprintln(w, "  "+strings.Join(r, "\t"))
	}
	w.Flush()
	return sb.String()
}

func findingLoc(f *finding.Finding) string {
	return fmt.Sprintf("%s:%d", filepath.ToSlash(f.FilePath), f.LineNumber)
}

// TestCorpus is the gate entry point (CI runs -run TestCorpus).
func TestCorpus(t *testing.T) {
	root := repoRoot(t)
	corpus := filepath.Join(root, "fixtures", "validation-corpus")

	man, err := LoadManifest(filepath.Join(corpus, "expected-findings.yaml"))
	if err != nil {
		t.Fatalf("load manifest: %v", err)
	}
	t.Logf("manifest: %d instances, %d forbidden, %d policy_excluded, %d dep expectations, %d dep must-not-flag",
		len(man.Instances), len(man.Forbidden), len(man.PolicyExcluded),
		len(man.Deps.Expect), len(man.Deps.MustNotFlag))

	codeFindings := runCodeScan(t, root, corpus)

	t.Run("Recall", func(t *testing.T) { checkRecall(t, man, codeFindings) })
	t.Run("ForbiddenLocations", func(t *testing.T) { checkForbidden(t, man, codeFindings) })
	t.Run("Precision", func(t *testing.T) { checkPrecision(t, man, codeFindings) })
	t.Run("Deps", func(t *testing.T) { checkDeps(t, man, corpus) })
}

// checkRecall: every active instance must be matched by >=1 finding with the
// right file, algorithm, line (+/-LineTolerance), severity, and
// quantum_safety. Instances whose location+algorithm WAS hit but with wrong
// severity/quantum_safety are reported separately as MISMATCHES so taxonomy
// drift is diagnosable at a glance.
func checkRecall(t *testing.T, man *Manifest, findings []finding.Finding) {
	var (
		matched   int
		skipped   int
		misses    [][]string
		mismatch  [][]string
		mismIDs   []string
		missIDs   []string
		skippedID []string
	)

	for _, inst := range man.Instances {
		if inst.Tier == "ast" && !astAvailable(inst.File) {
			skipped++
			skippedID = append(skippedID, inst.ID)
			t.Logf("SKIP %s %s [%s]: tier=ast and no AST runner registered for %q in this build (floor build)",
				inst.ID, inst.Location(), strings.Join(inst.Algorithm, "|"), scanner.DetectLanguage(inst.File))
			continue
		}

		var candidates []*finding.Finding
		ok := false
		for i := range findings {
			f := &findings[i]
			if !sameFile(f.FilePath, inst.File) ||
				!inst.AcceptsAlgorithm(f.Algorithm) ||
				!strings.HasPrefix(f.RuleID, inst.RuleIDPrefix) ||
				!inst.LineNear(f.LineNumber) {
				continue
			}
			candidates = append(candidates, f)
			if inst.AcceptsSeverity(string(f.Severity)) && inst.AcceptsQuantumSafety(string(f.QuantumSafety)) {
				ok = true
				break
			}
		}

		switch {
		case ok:
			matched++
		case len(candidates) > 0:
			for _, c := range candidates {
				mismatch = append(mismatch, []string{
					inst.ID, findingLoc(c), c.RuleID,
					fmt.Sprintf("severity=%s want[%s]", c.Severity, strings.Join(inst.Severity, ",")),
					fmt.Sprintf("quantum_safety=%s want[%s]", c.QuantumSafety, strings.Join(inst.QuantumSafety, ",")),
				})
			}
			mismIDs = append(mismIDs, inst.ID)
		default:
			misses = append(misses, []string{
				inst.ID, inst.Location(), strings.Join(inst.Algorithm, "|"),
				"bucket=" + inst.Bucket, "tier=" + inst.Tier,
			})
			missIDs = append(missIDs, inst.ID)
		}
	}

	t.Logf("recall: matched=%d missed=%d mismatched=%d skipped(ast-unavailable)=%d of %d instances",
		matched, len(missIDs), len(mismIDs), skipped, len(man.Instances))
	if skipped > 0 {
		t.Logf("skipped instances: %s", strings.Join(skippedID, ", "))
	}

	if len(misses) > 0 {
		t.Errorf("\n%s", table(
			fmt.Sprintf("MISSES — %d instance(s) with NO finding at file+algorithm+line:", len(misses)),
			append([][]string{{"ID", "LOCATION", "EXPECTED ALGORITHM(S)", "BUCKET", "TIER"}}, misses...)))
	}
	if len(mismatch) > 0 {
		t.Errorf("\n%s", table(
			fmt.Sprintf("MISMATCHES — %d instance(s) hit at the right place but with wrong labels:", len(mismIDs)),
			append([][]string{{"ID", "FINDING", "RULE", "SEVERITY", "QUANTUM_SAFETY"}}, mismatch...)))
	}
}

// checkForbidden: no risk-tagged finding may locate at a forbidden (bucket-C)
// entry, except findings covered by that entry's explicit allowance.
func checkForbidden(t *testing.T, man *Manifest, findings []finding.Finding) {
	var rows [][]string
	for i := range findings {
		f := &findings[i]
		for fi := range man.Forbidden {
			fb := &man.Forbidden[fi]
			if !sameFile(f.FilePath, fb.File) || !fb.Covers(f.LineNumber) {
				continue
			}
			if fb.Allow.Tolerates(string(f.QuantumSafety), string(f.Severity)) {
				continue
			}
			if IsRiskTagged(string(f.QuantumSafety)) {
				rows = append(rows, []string{
					findingLoc(f), f.RuleID, f.Algorithm,
					string(f.Severity), string(f.QuantumSafety), fb.Reason,
				})
			}
		}
	}
	if len(rows) > 0 {
		t.Errorf("\n%s", table(
			fmt.Sprintf("FORBIDDEN VIOLATIONS — %d risk-tagged finding(s) at bucket-C locations:", len(rows)),
			append([][]string{{"FINDING", "RULE", "ALGORITHM", "SEVERITY", "QUANTUM_SAFETY", "WHY FORBIDDEN"}}, rows...)))
	} else {
		t.Logf("forbidden locations clean: 0 violations across %d entries", len(man.Forbidden))
	}
}

// checkPrecision: every emitted finding must be explainable — by mapping to
// some instance via file+algorithm (line-tolerant first, then file-level
// fallback), by an explicit forbidden-entry allowance, or by sitting in a
// policy_excluded file. Everything else is an EXTRA and fails the gate.
func checkPrecision(t *testing.T, man *Manifest, findings []finding.Finding) {
	mapsToInstance := func(f *finding.Finding, lineTolerant bool) bool {
		for _, inst := range man.Instances {
			if !sameFile(f.FilePath, inst.File) ||
				!inst.AcceptsAlgorithm(f.Algorithm) ||
				!strings.HasPrefix(f.RuleID, inst.RuleIDPrefix) {
				continue
			}
			if lineTolerant && !inst.LineNear(f.LineNumber) {
				continue
			}
			return true
		}
		return false
	}
	policyExcluded := func(path string) bool {
		for _, pe := range man.PolicyExcluded {
			if sameFile(path, pe.File) {
				return true
			}
		}
		return false
	}
	allowed := func(f *finding.Finding) bool {
		for fi := range man.Forbidden {
			fb := &man.Forbidden[fi]
			if sameFile(f.FilePath, fb.File) && fb.Covers(f.LineNumber) &&
				fb.Allow.Tolerates(string(f.QuantumSafety), string(f.Severity)) {
				return true
			}
		}
		return false
	}

	var extras [][]string
	for i := range findings {
		f := &findings[i]
		switch {
		case policyExcluded(f.FilePath):
		case allowed(f):
		case mapsToInstance(f, true): // exact-ish: file+algorithm+line within tolerance
		case mapsToInstance(f, false): // file-level fallback: file+algorithm anywhere in the file
		default:
			extras = append(extras, []string{
				findingLoc(f), f.RuleID, f.Algorithm,
				string(f.Severity), string(f.QuantumSafety),
				strings.TrimSpace(f.Snippet),
			})
		}
	}
	if len(extras) > 0 {
		t.Errorf("\n%s", table(
			fmt.Sprintf("EXTRAS — %d finding(s) that map to no ground-truth instance:", len(extras)),
			append([][]string{{"FINDING", "RULE", "ALGORITHM", "SEVERITY", "QUANTUM_SAFETY", "SNIPPET"}}, extras...)))
	} else {
		t.Logf("precision clean: all %d findings map to ground truth", len(findings))
	}
}

// checkDeps runs the dependency scan (the same pkg/sbom Ingest the CLI's
// `relixq scan deps` wraps) over the corpus and grades it: every expected
// (package, algorithm) pair must be risk-flagged, and must-not-flag packages
// must yield zero risk-tagged findings.
func checkDeps(t *testing.T, man *Manifest, corpus string) {
	depFindings, err := sbom.Ingest(corpus, "validation-gate")
	if err != nil {
		t.Fatalf("sbom ingest %s: %v", corpus, err)
	}
	t.Logf("deps scan: %d findings", len(depFindings))

	// pkgOf recovers the package name from the SBOM finding snippet
	// ("<package>@<version>"); LastIndex tolerates npm scoped names.
	pkgOf := func(f *finding.Finding) string {
		s := f.Snippet
		if at := strings.LastIndex(s, "@"); at > 0 {
			return s[:at]
		}
		return s
	}

	var misses [][]string
	for _, exp := range man.Deps.Expect {
		for _, algo := range exp.AlgorithmsInclude {
			found := false
			for i := range depFindings {
				f := &depFindings[i]
				if !sameFile(f.FilePath, exp.Manifest) ||
					!strings.EqualFold(pkgOf(f), exp.Package) ||
					NormalizeAlgorithm(f.Algorithm) != NormalizeAlgorithm(algo) ||
					!IsRiskTagged(string(f.QuantumSafety)) {
					continue
				}
				if exp.Ecosystem != "" && !strings.EqualFold(f.Language, exp.Ecosystem) {
					continue
				}
				found = true
				break
			}
			if !found {
				misses = append(misses, []string{exp.Manifest, exp.Package, algo})
			}
		}
	}

	var violations [][]string
	for _, mnf := range man.Deps.MustNotFlag {
		for i := range depFindings {
			f := &depFindings[i]
			if sameFile(f.FilePath, mnf.Manifest) &&
				strings.EqualFold(pkgOf(f), mnf.Package) &&
				IsRiskTagged(string(f.QuantumSafety)) {
				violations = append(violations, []string{
					mnf.Manifest, mnf.Package, f.RuleID, f.Algorithm,
					string(f.QuantumSafety), mnf.Reason,
				})
			}
		}
	}

	if len(misses) > 0 {
		t.Errorf("\n%s", table(
			fmt.Sprintf("DEPS MISSES — %d expected (package, algorithm) flag(s) absent:", len(misses)),
			append([][]string{{"MANIFEST", "PACKAGE", "EXPECTED ALGORITHM"}}, misses...)))
	}
	if len(violations) > 0 {
		t.Errorf("\n%s", table(
			fmt.Sprintf("DEPS VIOLATIONS — %d risk-tagged finding(s) on must-not-flag packages:", len(violations)),
			append([][]string{{"MANIFEST", "PACKAGE", "RULE", "ALGORITHM", "QUANTUM_SAFETY", "WHY CLEAN"}}, violations...)))
	}
	if len(misses) == 0 && len(violations) == 0 {
		t.Logf("deps gate clean: %d expectations, %d must-not-flag packages",
			len(man.Deps.Expect), len(man.Deps.MustNotFlag))
	}
}
