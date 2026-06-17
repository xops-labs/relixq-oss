// Copyright (c) 2026 Yasvanth Udayakumar
// SPDX-License-Identifier: Apache-2.0
// See LICENSE in the repository root for full terms.
package migrationplan

import (
	"strings"
	"testing"

	"github.com/relix-q/relix-q/agility"
	"github.com/relix-q/relix-q/finding"
	"github.com/relix-q/relix-q/fusion"
	"github.com/relix-q/relix-q/graph"
)

func TestBuild_prioritizesCorroboratedHighBlastFindings(t *testing.T) {
	ast := []finding.Finding{
		{
			FindingID:  "f-high",
			RuleID:     "PYTHON_RSA_KEYGEN_WEAK",
			Algorithm:  "RSA-2048",
			Severity:   finding.SeverityHigh,
			FilePath:   "src/crypto/core.py",
			LineNumber: 42,
			Column:     7,
			Confidence: 0.85,
			Category:   "crypto-api",
		},
		{
			FindingID:  "f-low",
			RuleID:     "PYTHON_HASHLIB_MD5",
			Algorithm:  "MD5",
			Severity:   finding.SeverityMedium,
			FilePath:   "tools/checksum.py",
			LineNumber: 8,
			Column:     3,
			Confidence: 0.7,
			Category:   "weak-hash",
		},
	}
	sbom := []finding.Finding{
		{
			RuleID:     "SBOM_PYTHON_CRYPTOGRAPHY_RSA",
			Algorithm:  "RSA",
			Severity:   finding.SeverityInfo,
			FilePath:   "requirements.txt",
			LineNumber: 1,
			Column:     1,
			Confidence: 0.7,
			Category:   "crypto-dependency",
		},
	}
	clusters := fusion.Fuse(
		fusion.Channel{Name: "ast", Findings: ast},
		fusion.Channel{Name: "sbom", Findings: sbom},
	)
	impacts := []graph.ImpactReport{
		{
			FindingID:           "f-high",
			FilePath:            "src/crypto/core.py",
			RuleID:              "PYTHON_RSA_KEYGEN_WEAK",
			Algorithm:           "RSA-2048",
			Severity:            "high",
			LineNumber:          42,
			Column:              7,
			BlastRadius:         80,
			MigrationCostBand:   "High",
			DirectImporters:     4,
			TransitiveImporters: 24,
			AffectedFiles:       []string{"src/api.py", "src/jobs.py"},
		},
		{
			FindingID:         "f-low",
			FilePath:          "tools/checksum.py",
			RuleID:            "PYTHON_HASHLIB_MD5",
			Algorithm:         "MD5",
			Severity:          "medium",
			LineNumber:        8,
			Column:            3,
			BlastRadius:       0,
			MigrationCostBand: "Low",
		},
	}

	plan := Build(Input{
		ASTFindings:    ast,
		SBOMFindings:   sbom,
		Scorecard:      agility.Score(ast),
		FusionClusters: clusters,
		ImpactReports:  impacts,
	})

	if plan.SchemaVersion != SchemaVersion {
		t.Fatalf("schema version = %q, want %q", plan.SchemaVersion, SchemaVersion)
	}
	if len(plan.WorkItems) != 2 {
		t.Fatalf("work items = %d, want 2", len(plan.WorkItems))
	}
	top := plan.WorkItems[0]
	if top.FindingID != "f-high" {
		t.Fatalf("top finding = %q, want f-high (items=%+v)", top.FindingID, plan.WorkItems)
	}
	if top.CorroborationCount != 2 {
		t.Errorf("corroboration = %d, want 2", top.CorroborationCount)
	}
	if top.FusedConfidence < 0.95 {
		t.Errorf("fused confidence = %v, want >=0.95", top.FusedConfidence)
	}
	if top.BlastRadius != 80 || top.MigrationCostBand != "High" {
		t.Errorf("impact = %d/%q, want 80/High", top.BlastRadius, top.MigrationCostBand)
	}
	if plan.Summary.CorroboratedWorkItems != 1 {
		t.Errorf("corroborated summary = %d, want 1", plan.Summary.CorroboratedWorkItems)
	}
	if plan.Summary.HighBlastWorkItems != 1 {
		t.Errorf("high blast summary = %d, want 1", plan.Summary.HighBlastWorkItems)
	}
	if len(plan.Phases) == 0 {
		t.Errorf("expected non-empty phases")
	}
}

func TestBuild_emptyInputProducesAgileEmptyPlan(t *testing.T) {
	plan := Build(Input{})
	if plan.RepositoryAgility.TotalScore != 100 {
		t.Errorf("empty agility score = %d, want 100", plan.RepositoryAgility.TotalScore)
	}
	if plan.RepositoryAgility.Grade != "Agile" {
		t.Errorf("empty agility grade = %q, want Agile", plan.RepositoryAgility.Grade)
	}
	if len(plan.WorkItems) != 0 {
		t.Errorf("empty work items = %d, want 0", len(plan.WorkItems))
	}
	if len(plan.Phases) != 0 {
		t.Errorf("empty phases = %d, want 0", len(plan.Phases))
	}
}

func TestBuild_hardcodedKeyRecommendation(t *testing.T) {
	ast := []finding.Finding{
		{
			FindingID:  "f-key",
			RuleID:     "CONFIG_HARDCODED_RSA_PRIVATE_KEY",
			Algorithm:  "RSA",
			Severity:   finding.SeverityCritical,
			FilePath:   "config/secrets.pem",
			LineNumber: 1,
			Confidence: 0.95,
			Category:   "hardcoded-key",
		},
	}
	plan := Build(Input{
		ASTFindings: ast,
		Scorecard:   agility.Score(ast),
		ImpactReports: []graph.ImpactReport{
			{
				FindingID:         "f-key",
				FilePath:          "config/secrets.pem",
				RuleID:            "CONFIG_HARDCODED_RSA_PRIVATE_KEY",
				Algorithm:         "RSA",
				Severity:          "critical",
				LineNumber:        1,
				BlastRadius:       3,
				MigrationCostBand: "Low",
			},
		},
	})

	if len(plan.WorkItems) != 1 {
		t.Fatalf("work items = %d, want 1", len(plan.WorkItems))
	}
	if !strings.Contains(plan.WorkItems[0].Recommendation, "managed secret storage") {
		t.Errorf("recommendation = %q, want secret-storage guidance", plan.WorkItems[0].Recommendation)
	}
	if plan.Summary.CriticalWorkItems != 1 {
		t.Errorf("critical summary = %d, want 1", plan.Summary.CriticalWorkItems)
	}
}
