// Copyright (c) 2026 Yasvanth Udayakumar
// SPDX-License-Identifier: Apache-2.0
// See LICENSE in the repository root for full terms.
package client

import (
	"encoding/json"
	"fmt"
	"net/http"
)

type Project struct {
	Slug        string `json:"slug"`
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
}

// ListProjects returns all projects the authenticated user has access to.
func (c *Client) ListProjects() ([]Project, error) {
	resp, err := c.Get("/projects")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("list projects: HTTP %d", resp.StatusCode)
	}
	var projects []Project
	return projects, json.NewDecoder(resp.Body).Decode(&projects)
}
