// Copyright (c) 2026 Yasvanth Udayakumar
// SPDX-License-Identifier: Apache-2.0
// See LICENSE in the repository root for full terms.
package formatter

import (
	"fmt"
	"io"
	"strings"

	sarif "github.com/owenrumney/go-sarif/v2/sarif"
	"github.com/relix-q/relix-q/cmd/relixq/internal/model"
)

const toolName = "relixq"
const toolURI = "https://relixq.io"

// WriteSARIF writes SARIF 2.1.0 output. GitHub displays these natively in PR
// Files Changed when uploaded as a code-scanning artifact. Rule metadata
// (help markdown, tags, security-severity) drives GitHub's alert rendering and
// severity; migration enrichment, when present, surfaces in help.markdown.
func WriteSARIF(findings []model.Finding, w io.Writer) error {
	run := sarif.NewRunWithInformationURI(toolName, toolURI)

	for _, f := range findings {
		// AddRule dedupes by id, so per-finding calls converge on one rule
		// descriptor; the last writer wins for shared metadata (consistent
		// because all findings of a rule carry the same enrichment).
		rule := run.AddRule(f.RuleID).
			WithShortDescription(sarif.NewMultiformatMessageString(f.Message)).
			WithHelpURI(toolURI + "/rules/" + f.RuleID).
			WithProperties(ruleProperties(f))
		if help := ruleHelpMarkdown(f); help != "" {
			rule.WithHelp(sarif.NewMarkdownMultiformatMessageString(help))
		}

		level := severityToSARIFLevel(f.Severity)

		result := sarif.NewRuleResult(f.RuleID).
			WithLevel(level).
			WithMessage(sarif.NewTextMessage(messageText(f))).
			WithPartialFingerPrints(map[string]interface{}{"relixq/v1": f.ComputeFingerprint()})

		loc := sarif.NewPhysicalLocation().
			WithArtifactLocation(sarif.NewSimpleArtifactLocation(f.FilePath)).
			WithRegion(sarif.NewRegion().WithStartLine(f.LineNumber))

		result.AddLocation(sarif.NewLocationWithPhysicalLocation(loc))
		run.AddResult(result)
	}

	report, err := sarif.New(sarif.Version210)
	if err != nil {
		return err
	}
	report.AddRun(run)
	return report.Write(w)
}

// ruleProperties builds the GitHub Code Scanning property bag: security-severity
// (a numeric string GitHub maps to its own severity bands) plus tags that
// classify the alert and link any CWE taxonomy entries.
func ruleProperties(f model.Finding) sarif.Properties {
	tags := []string{"security", "cryptography"}
	switch strings.ToLower(f.QuantumSafety) {
	case "vulnerable":
		tags = append(tags, "pqc", "quantum-vulnerable")
	case "grover_weakened":
		tags = append(tags, "pqc", "grover-weakened")
	case "classically_broken":
		tags = append(tags, "classically-broken")
	}
	for _, id := range f.CWE {
		tags = append(tags, fmt.Sprintf("external/cwe/cwe-%d", id))
	}
	return sarif.Properties{
		"security-severity": securitySeverity(f.Severity),
		"tags":              tags,
	}
}

// ruleHelpMarkdown assembles the long-form help rendered in a GitHub alert.
// Detection-only findings get a short stub; an enriched finding (rule-pack
// overlay present) gets full migration guidance.
func ruleHelpMarkdown(f model.Finding) string {
	var b strings.Builder
	if f.Message != "" {
		b.WriteString(f.Message)
		b.WriteString("\n")
	}
	if f.Algorithm != "" {
		fmt.Fprintf(&b, "\n- **Algorithm:** %s", f.Algorithm)
		if f.QuantumSafety != "" {
			fmt.Fprintf(&b, " (quantum safety: %s)", f.QuantumSafety)
		}
	}
	if f.Recommendation != "" {
		fmt.Fprintf(&b, "\n\n**Recommendation:** %s", f.Recommendation)
	}
	if f.MigrationTarget != "" {
		fmt.Fprintf(&b, "\n\n**Migration target:** %s", f.MigrationTarget)
	}
	if f.VerticalContext != "" {
		fmt.Fprintf(&b, "\n\n**Context:** %s", f.VerticalContext)
	}
	if len(f.References) > 0 {
		b.WriteString("\n\n**References:**\n")
		for _, ref := range f.References {
			fmt.Fprintf(&b, "- %s\n", ref)
		}
	}
	return strings.TrimSpace(b.String())
}

// securitySeverity maps our severity enum to the 0.0–10.0 numeric string GitHub
// Code Scanning uses to bucket alerts (>=9 critical, >=7 high, >=4 medium).
func securitySeverity(sev string) string {
	switch strings.ToLower(sev) {
	case "critical":
		return "9.5"
	case "high":
		return "8.1"
	case "medium":
		return "5.5"
	case "low":
		return "3.0"
	default:
		return "1.0"
	}
}

func severityToSARIFLevel(sev string) string {
	switch strings.ToLower(sev) {
	case "critical", "high":
		return "error"
	case "medium":
		return "warning"
	default:
		return "note"
	}
}

func messageText(f model.Finding) string {
	if f.Recommendation != "" {
		return f.Message + " " + f.Recommendation
	}
	return f.Message
}

// ReadSARIF reads a SARIF 2.1.0 file and returns findings from the first run.
func ReadSARIF(path string) ([]model.Finding, error) {
	report, err := sarif.Open(path)
	if err != nil {
		return nil, err
	}
	if len(report.Runs) == 0 {
		return nil, nil
	}
	var findings []model.Finding
	for _, result := range report.Runs[0].Results {
		f := model.Finding{
			Severity: sarifLevelToSeverity(derefStr(result.Level)),
			Message:  derefStr(result.Message.Text),
		}
		if result.RuleID != nil {
			f.RuleID = *result.RuleID
		}
		for _, loc := range result.Locations {
			if pl := loc.PhysicalLocation; pl != nil {
				if al := pl.ArtifactLocation; al != nil && al.URI != nil {
					f.FilePath = *al.URI
				}
				if region := pl.Region; region != nil && region.StartLine != nil {
					f.LineNumber = *region.StartLine
				}
			}
			break
		}
		findings = append(findings, f)
	}
	return findings, nil
}

func sarifLevelToSeverity(level string) string {
	switch level {
	case "error":
		return "high"
	case "warning":
		return "medium"
	default:
		return "low"
	}
}

func derefStr(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}
