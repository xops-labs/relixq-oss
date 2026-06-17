// Copyright (c) 2026 Yasvanth Udayakumar
// SPDX-License-Identifier: Apache-2.0
// See LICENSE in the repository root for full terms.
package client

import (
	"fmt"
	"io"
	"net/http"
)

// GetReport downloads a formatted report for the given scan run.
// The format parameter should match what the API accepts (e.g., "markdown", "sarif").
func (c *Client) GetReport(scanRunID, format string) (io.ReadCloser, error) {
	path := "/scans/" + scanRunID + "/report"
	if format != "" {
		path += "?format=" + format
	}
	resp, err := c.Get(path)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		resp.Body.Close()
		return nil, fmt.Errorf("get report: HTTP %d", resp.StatusCode)
	}
	return resp.Body, nil
}
