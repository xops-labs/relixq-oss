// Copyright (c) 2026 Yasvanth Udayakumar
// SPDX-License-Identifier: Apache-2.0
// See LICENSE in the repository root for full terms.
package client

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
)

type CreateScanRequest struct {
	ProjectSlug string `json:"project_slug"`
	Ref         string `json:"ref,omitempty"`
}

type ScanRun struct {
	ScanRunID string `json:"scan_run_id"`
	Status    string `json:"status"`
	Progress  int    `json:"progress"`
}

// CreateScan triggers a server-side scan and returns the ScanRun.
func (c *Client) CreateScan(req CreateScanRequest) (*ScanRun, error) {
	body, _ := json.Marshal(req)
	resp, err := c.Post("/scans", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusAccepted && resp.StatusCode != http.StatusCreated {
		return nil, fmt.Errorf("create scan: HTTP %d", resp.StatusCode)
	}
	var run ScanRun
	return &run, json.NewDecoder(resp.Body).Decode(&run)
}

// GetScan returns the current status of a scan run.
func (c *Client) GetScan(scanRunID string) (*ScanRun, error) {
	resp, err := c.Get("/scans/" + scanRunID)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("get scan: HTTP %d", resp.StatusCode)
	}
	var run ScanRun
	return &run, json.NewDecoder(resp.Body).Decode(&run)
}
