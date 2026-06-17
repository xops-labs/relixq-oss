// Copyright (c) 2026 Yasvanth Udayakumar
// SPDX-License-Identifier: Apache-2.0
// See LICENSE in the repository root for full terms.
package scanner

import (
	"encoding/json"

	"github.com/relix-q/relix-q/cmd/relixq/internal/model"
	"github.com/relix-q/relix-q/sbom"
)

// RunDeps scans dependency manifests under path (requirements.txt, Pipfile,
// pyproject.toml, package.json, go.mod) against the embedded crypto knowledge
// base and returns findings in the CLI model shape. It runs
// pkg/sbom in-process — no scanner subprocess — so it works wherever the CLI
// does, with no toolchain.
func RunDeps(path string) ([]model.Finding, error) {
	raw, err := sbom.Ingest(path, "local")
	if err != nil {
		return nil, err
	}
	out := make([]model.Finding, 0, len(raw))
	for i := range raw {
		// Round-trip through JSON so the engine-side finding.Finding maps onto
		// the CLI model.Finding by their shared json tags (rule_id, algorithm,
		// quantum_safety, severity, file_path, ...) without a hand-maintained
		// field-by-field copy.
		b, err := json.Marshal(raw[i])
		if err != nil {
			return nil, err
		}
		var m model.Finding
		if err := json.Unmarshal(b, &m); err != nil {
			return nil, err
		}
		out = append(out, m)
	}
	return out, nil
}
