// Copyright (c) 2026 Yasvanth Udayakumar
// SPDX-License-Identifier: Apache-2.0
// See LICENSE in the repository root for full terms.
package scanner

import (
	"bytes"
	"fmt"
	"os/exec"
	"strings"
)

// ChangedFiles returns paths of files changed between ref and HEAD, relative to
// repoRoot. Uses three-dot diff so feature branches work correctly.
func ChangedFiles(repoRoot, ref string) ([]string, error) {
	cmd := exec.Command("git", "-C", repoRoot, "diff", "--name-only", ref+"...HEAD")
	var out, errBuf bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &errBuf

	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("git diff failed: %s", strings.TrimSpace(errBuf.String()))
	}

	var files []string
	for _, line := range strings.Split(out.String(), "\n") {
		if line = strings.TrimSpace(line); line != "" {
			files = append(files, line)
		}
	}
	return files, nil
}
