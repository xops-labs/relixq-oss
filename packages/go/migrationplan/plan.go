// Copyright (c) 2026 Yasvanth Udayakumar
// SPDX-License-Identifier: Apache-2.0
// See LICENSE in the repository root for full terms.

// Package migrationplan composes the three migration-readiness signals
// into one deterministic work list:
//
//   - agility.Scorecard: repo-level mechanical migration difficulty
//   - fusion.Cluster: cross-channel confidence and corroboration
//   - graph.ImpactReport: per-finding blast radius and affected files
//
// The package is deliberately pure and dependency-light. It does not ask an
// LLM to invent a plan; it converts already-auditable scanner outputs into a
// sorted JSON structure that dashboards, demos, and future LLM prompts can use
// as grounded input.
package migrationplan

import (
	"fmt"
	"math"
	"sort"
	"strings"

	"github.com/relix-q/relix-q/agility"
	"github.com/relix-q/relix-q/finding"
	"github.com/relix-q/relix-q/fusion"
	"github.com/relix-q/relix-q/graph"
)

const SchemaVersion = "relixq.migration_plan.v1"

// Input is the complete signal bundle consumed by Build.
type Input struct {
	ASTFindings    []finding.Finding
	SBOMFindings   []finding.Finding
	Scorecard      agility.Scorecard
	FusionClusters []fusion.Cluster
	ImpactReports  []graph.ImpactReport
}

// Plan is the top-level JSON payload emitted by the deterministic migration
// planner.
type Plan struct {
	SchemaVersion     string          `json:"schema_version"`
	Summary           Summary         `json:"summary"`
	RepositoryAgility AgilitySnapshot `json:"repository_agility"`
	Inputs            InputSummary    `json:"inputs"`
	WorkItems         []WorkItem      `json:"work_items"`
	Phases            []Phase         `json:"phases,omitempty"`
}

// Summary holds dashboard-ready counters so consumers do not need to scan the
// whole work list to draw the headline cards.
type Summary struct {
	TotalWorkItems        int `json:"total_work_items"`
	ImmediateWorkItems    int `json:"immediate_work_items"`
	CorroboratedWorkItems int `json:"corroborated_work_items"`
	HighBlastWorkItems    int `json:"high_blast_work_items"`
	CriticalWorkItems     int `json:"critical_work_items"`
	TopPriorityScore      int `json:"top_priority_score"`
}

// AgilitySnapshot is the subset of the scorecard that belongs on each plan.
type AgilitySnapshot struct {
	TotalScore             int      `json:"total_score"`
	Grade                  string   `json:"grade"`
	DistinctAlgorithms     []string `json:"distinct_algorithms,omitempty"`
	DistinctLibraries      []string `json:"distinct_libraries,omitempty"`
	FilesWithFindings      int      `json:"files_with_findings"`
	HardcodedKeyCount      int      `json:"hardcoded_key_count"`
	CallSiteConcentration  int      `json:"call_site_concentration"`
	AlgorithmDiversity     int      `json:"algorithm_diversity"`
	LibraryConsolidation   int      `json:"library_consolidation"`
	HardcodedKeyPrevalence int      `json:"hardcoded_key_prevalence"`
}

// InputSummary captures how much evidence fed the plan.
type InputSummary struct {
	ASTFindings        int `json:"ast_findings"`
	SBOMFindings       int `json:"sbom_findings"`
	FusionClusters     int `json:"fusion_clusters"`
	BlastRadiusReports int `json:"blast_radius_reports"`
}

// WorkItem is one prioritized migration target. It is intentionally small
// enough to render directly in a table while preserving enough evidence for
// drill-down.
type WorkItem struct {
	PriorityRank       int      `json:"priority_rank"`
	PriorityScore      int      `json:"priority_score"`
	PriorityBand       string   `json:"priority_band"`
	FilePath           string   `json:"file_path"`
	LineNumber         int      `json:"line_number,omitempty"`
	Column             int      `json:"column,omitempty"`
	FindingID          string   `json:"finding_id,omitempty"`
	RuleID             string   `json:"rule_id"`
	Algorithm          string   `json:"algorithm,omitempty"`
	Severity           string   `json:"severity"`
	Category           string   `json:"category,omitempty"`
	Message            string   `json:"message,omitempty"`
	Recommendation     string   `json:"recommendation"`
	FusedConfidence    float64  `json:"fused_confidence"`
	CorroborationCount int      `json:"corroboration_count"`
	Channels           []string `json:"channels,omitempty"`
	BlastRadius        int      `json:"blast_radius"`
	MigrationCostBand  string   `json:"migration_cost_band,omitempty"`
	AffectedFiles      []string `json:"affected_files,omitempty"`
	Rationale          []string `json:"rationale"`
}

// Phase groups the prioritized work list into a compact execution outline.
type Phase struct {
	Name                string `json:"name"`
	EstimatedEffortDays int    `json:"estimated_effort_days"`
	WorkItemRanks       []int  `json:"work_item_ranks"`
	Focus               string `json:"focus"`
}

type clusterSignal struct {
	confidence    float64
	corroboration int
	channels      []string
}

// Build composes the input signals into a deterministic migration plan.
func Build(in Input) Plan {
	sc := in.Scorecard
	if sc.Grade == "" {
		sc = agility.Score(in.ASTFindings)
	}

	clusterByFinding := indexClusters(in.FusionClusters)
	impactByFinding := indexImpacts(in.ImpactReports)

	items := make([]WorkItem, 0, len(in.ASTFindings))
	for _, f := range in.ASTFindings {
		cluster := clusterForFinding(f, clusterByFinding)
		impact := impactByFinding[findingKey(f)]
		item := workItem(f, sc, cluster, impact)
		items = append(items, item)
	}

	sort.Slice(items, func(i, j int) bool {
		if items[i].PriorityScore != items[j].PriorityScore {
			return items[i].PriorityScore > items[j].PriorityScore
		}
		if items[i].BlastRadius != items[j].BlastRadius {
			return items[i].BlastRadius > items[j].BlastRadius
		}
		if items[i].FilePath != items[j].FilePath {
			return items[i].FilePath < items[j].FilePath
		}
		if items[i].LineNumber != items[j].LineNumber {
			return items[i].LineNumber < items[j].LineNumber
		}
		return items[i].RuleID < items[j].RuleID
	})

	for i := range items {
		items[i].PriorityRank = i + 1
	}

	return Plan{
		SchemaVersion:     SchemaVersion,
		Summary:           summarize(items),
		RepositoryAgility: agilitySnapshot(sc),
		Inputs: InputSummary{
			ASTFindings:        len(in.ASTFindings),
			SBOMFindings:       len(in.SBOMFindings),
			FusionClusters:     len(in.FusionClusters),
			BlastRadiusReports: len(in.ImpactReports),
		},
		WorkItems: items,
		Phases:    buildPhases(items),
	}
}

func workItem(f finding.Finding, sc agility.Scorecard, cluster clusterSignal, impact graph.ImpactReport) WorkItem {
	confidence := cluster.confidence
	if confidence == 0 {
		confidence = f.Confidence
	}
	if confidence == 0 {
		confidence = 0.5
	}
	corroboration := cluster.corroboration
	if corroboration == 0 {
		corroboration = 1
	}
	channels := append([]string(nil), cluster.channels...)
	if len(channels) == 0 {
		channels = []string{"ast"}
	}

	score := priorityScore(f.Severity, confidence, corroboration, impact, sc)
	return WorkItem{
		PriorityScore:      score,
		PriorityBand:       priorityBand(score),
		FilePath:           f.FilePath,
		LineNumber:         f.LineNumber,
		Column:             f.Column,
		FindingID:          f.FindingID,
		RuleID:             f.RuleID,
		Algorithm:          f.Algorithm,
		Severity:           string(f.Severity),
		Category:           f.Category,
		Message:            f.Message,
		Recommendation:     recommendedAction(f),
		FusedConfidence:    round2(confidence),
		CorroborationCount: corroboration,
		Channels:           channels,
		BlastRadius:        impact.BlastRadius,
		MigrationCostBand:  impact.MigrationCostBand,
		AffectedFiles:      append([]string(nil), impact.AffectedFiles...),
		Rationale:          rationale(f, sc, confidence, corroboration, channels, impact),
	}
}

func priorityScore(sev finding.Severity, confidence float64, corroboration int, impact graph.ImpactReport, sc agility.Scorecard) int {
	score := severityPoints(sev)

	confPoints := int(math.Round(confidence * 20))
	if corroboration > 1 {
		confPoints += (corroboration - 1) * 3
	}
	if confPoints > 25 {
		confPoints = 25
	}
	score += confPoints

	score += impactPoints(impact)

	agilityPenalty := (100 - sc.TotalScore) / 10
	if agilityPenalty < 0 {
		agilityPenalty = 0
	}
	if agilityPenalty > 10 {
		agilityPenalty = 10
	}
	score += agilityPenalty

	if score > 100 {
		return 100
	}
	return score
}

func severityPoints(sev finding.Severity) int {
	switch sev {
	case finding.SeverityCritical:
		return 25
	case finding.SeverityHigh:
		return 20
	case finding.SeverityMedium:
		return 12
	case finding.SeverityLow:
		return 6
	case finding.SeverityInfo:
		return 2
	default:
		return 6
	}
}

func impactPoints(impact graph.ImpactReport) int {
	switch impact.MigrationCostBand {
	case "Catastrophic":
		return 35
	case "High":
		return 28
	case "Medium":
		return 16
	case "Low":
		if impact.BlastRadius > 0 {
			return 5
		}
		return 0
	default:
		switch {
		case impact.BlastRadius >= 200:
			return 35
		case impact.BlastRadius >= 50:
			return 28
		case impact.BlastRadius >= 10:
			return 16
		case impact.BlastRadius > 0:
			return 5
		default:
			return 0
		}
	}
}

func priorityBand(score int) string {
	switch {
	case score >= 80:
		return "Immediate"
	case score >= 60:
		return "Scheduled"
	case score >= 40:
		return "Backlog"
	default:
		return "Monitor"
	}
}

func recommendedAction(f finding.Finding) string {
	rule := strings.ToUpper(f.RuleID)
	algo := strings.ToUpper(strings.TrimSpace(f.Algorithm))
	category := strings.ToLower(f.Category)

	if strings.Contains(category, "hardcoded") || strings.Contains(rule, "HARDCODED") {
		return "Move key material to managed secret storage, rotate it, and replace embedded literals with secret-provider lookups."
	}
	if strings.Contains(category, "dependency") || f.UsageType == "dependency" || strings.HasPrefix(rule, "SBOM_") {
		return "Audit dependency usage, upgrade or replace the package, and pin a PQC-capable alternative where available."
	}
	switch algo {
	case "MD5", "MD4", "MD2", "SHA1", "SHA-1":
		return "Replace weak digest usage with SHA-256 or SHA-3 for integrity checks; use Argon2id, bcrypt, or scrypt for password storage."
	case "DES", "3DES", "TRIPLEDES", "RC4", "RC2":
		return "Replace legacy cipher usage with AES-GCM or ChaCha20-Poly1305 and remove compatibility fallbacks."
	case "RSA", "RSA-1024", "DSA", "DH", "ECDSA", "ECDH", "ECC":
		return "Inventory key owners, isolate the call site behind a crypto-provider abstraction, and plan hybrid or PQC replacement using ML-KEM, ML-DSA, or SLH-DSA as appropriate."
	case "TLS":
		return "Disable obsolete TLS versions and weak cipher suites, then verify clients against a TLS 1.3 baseline."
	}
	if strings.Contains(rule, "TLS") {
		return "Disable obsolete TLS versions and weak cipher suites, then verify clients against a TLS 1.3 baseline."
	}
	return "Review the crypto primitive, isolate direct API usage behind a replaceable abstraction, and add a regression test for the migrated path."
}

func rationale(f finding.Finding, sc agility.Scorecard, confidence float64, corroboration int, channels []string, impact graph.ImpactReport) []string {
	out := []string{
		fmt.Sprintf("%s severity finding from rule %s", nonEmpty(string(f.Severity), "unknown"), f.RuleID),
	}
	if corroboration > 1 {
		out = append(out, fmt.Sprintf("corroborated across %s at %.2f fused confidence", strings.Join(channels, "+"), confidence))
	} else {
		out = append(out, fmt.Sprintf("single-channel confidence %.2f", confidence))
	}
	if impact.MigrationCostBand != "" {
		out = append(out, fmt.Sprintf("%s blast-radius band with score %d", impact.MigrationCostBand, impact.BlastRadius))
	}
	if sc.Grade != "" {
		out = append(out, fmt.Sprintf("repository agility is %s (%d/100)", sc.Grade, sc.TotalScore))
	}
	return out
}

func summarize(items []WorkItem) Summary {
	var s Summary
	s.TotalWorkItems = len(items)
	for _, it := range items {
		if it.PriorityScore >= 80 {
			s.ImmediateWorkItems++
		}
		if it.CorroborationCount >= 2 {
			s.CorroboratedWorkItems++
		}
		if it.MigrationCostBand == "High" || it.MigrationCostBand == "Catastrophic" {
			s.HighBlastWorkItems++
		}
		if it.Severity == string(finding.SeverityCritical) {
			s.CriticalWorkItems++
		}
		if it.PriorityScore > s.TopPriorityScore {
			s.TopPriorityScore = it.PriorityScore
		}
	}
	return s
}

func agilitySnapshot(sc agility.Scorecard) AgilitySnapshot {
	return AgilitySnapshot{
		TotalScore:             sc.TotalScore,
		Grade:                  sc.Grade,
		DistinctAlgorithms:     append([]string(nil), sc.DistinctAlgorithms...),
		DistinctLibraries:      append([]string(nil), sc.DistinctLibraries...),
		FilesWithFindings:      sc.FilesWithFindings,
		HardcodedKeyCount:      sc.HardcodedKeyCount,
		CallSiteConcentration:  sc.CallSiteConcentration.Score,
		AlgorithmDiversity:     sc.AlgorithmDiversity.Score,
		LibraryConsolidation:   sc.LibraryConsolidation.Score,
		HardcodedKeyPrevalence: sc.HardcodedKeyPrevalence.Score,
	}
}

func buildPhases(items []WorkItem) []Phase {
	if len(items) == 0 {
		return nil
	}

	var confirm, isolate, residual []int
	for _, it := range items {
		switch {
		case it.PriorityScore >= 80 || it.CorroborationCount >= 2 || it.Severity == string(finding.SeverityCritical):
			confirm = append(confirm, it.PriorityRank)
		case it.BlastRadius >= 10 || it.PriorityScore >= 40:
			isolate = append(isolate, it.PriorityRank)
		default:
			residual = append(residual, it.PriorityRank)
		}
	}

	var phases []Phase
	add := func(name, focus string, ranks []int) {
		if len(ranks) == 0 {
			return
		}
		phases = append(phases, Phase{
			Name:                name,
			Focus:               focus,
			WorkItemRanks:       capRanks(ranks, 20),
			EstimatedEffortDays: effortDays(len(ranks)),
		})
	}
	add("Confirm high-confidence hotspots", "Validate corroborated, critical, or immediate-score findings and assign owners.", confirm)
	add("Isolate shared crypto surfaces", "Refactor high-impact call sites behind provider abstractions before primitive replacement.", isolate)
	add("Close residual inventory", "Batch low-impact replacements, document exceptions, and add regression coverage.", residual)
	return phases
}

func effortDays(n int) int {
	if n <= 0 {
		return 0
	}
	days := n * 2
	if days < 1 {
		return 1
	}
	if days > 60 {
		return 60
	}
	return days
}

func capRanks(ranks []int, max int) []int {
	if len(ranks) > max {
		ranks = ranks[:max]
	}
	return append([]int(nil), ranks...)
}

func indexClusters(clusters []fusion.Cluster) map[string]clusterSignal {
	out := map[string]clusterSignal{}
	for _, c := range clusters {
		signal := clusterSignal{
			confidence:    c.FusedConfidence,
			corroboration: c.CorroborationCount,
			channels:      append([]string(nil), c.Channels...),
		}
		for _, f := range c.Findings {
			out[findingKey(f)] = signal
		}
	}
	return out
}

func indexImpacts(reports []graph.ImpactReport) map[string]graph.ImpactReport {
	out := map[string]graph.ImpactReport{}
	for _, r := range reports {
		out[impactKey(r)] = r
	}
	return out
}

func clusterForFinding(f finding.Finding, idx map[string]clusterSignal) clusterSignal {
	return idx[findingKey(f)]
}

func findingKey(f finding.Finding) string {
	if f.FindingID != "" {
		return "id:" + f.FindingID
	}
	return strings.Join([]string{
		normalisePath(f.FilePath),
		fmt.Sprint(f.LineNumber),
		fmt.Sprint(f.Column),
		f.RuleID,
		strings.ToUpper(f.Algorithm),
		string(f.Severity),
	}, "|")
}

func impactKey(r graph.ImpactReport) string {
	if r.FindingID != "" {
		return "id:" + r.FindingID
	}
	return strings.Join([]string{
		normalisePath(r.FilePath),
		fmt.Sprint(r.LineNumber),
		fmt.Sprint(r.Column),
		r.RuleID,
		strings.ToUpper(r.Algorithm),
		r.Severity,
	}, "|")
}

func normalisePath(path string) string {
	return strings.ToLower(strings.ReplaceAll(path, "\\", "/"))
}

func round2(v float64) float64 {
	return math.Round(v*100) / 100
}

func nonEmpty(s, fallback string) string {
	if s == "" {
		return fallback
	}
	return s
}
