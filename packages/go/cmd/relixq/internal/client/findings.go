// Copyright (c) 2026 Yasvanth Udayakumar
// SPDX-License-Identifier: Apache-2.0
// See LICENSE in the repository root for full terms.
package client

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/relix-q/relix-q/cmd/relixq/internal/model"
)

// GetFindings downloads findings for a completed scan run.
func (c *Client) GetFindings(scanRunID string) ([]model.Finding, error) {
	resp, err := c.Get("/scans/" + scanRunID + "/findings")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("get findings: HTTP %d", resp.StatusCode)
	}
	var findings []model.Finding
	return findings, json.NewDecoder(resp.Body).Decode(&findings)
}
