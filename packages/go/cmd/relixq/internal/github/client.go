// Copyright (c) 2026 Yasvanth Udayakumar
// SPDX-License-Identifier: Apache-2.0
// See LICENSE in the repository root for full terms.
package github

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
)

const apiBase = "https://api.github.com"

// Client is a minimal GitHub REST client scoped to a single token.
type Client struct {
	token string
	http  *http.Client
}

func NewClient(token string) *Client {
	return &Client{token: token, http: &http.Client{}}
}

func (c *Client) do(method, path string, body any) (*http.Response, error) {
	var buf bytes.Buffer
	if body != nil {
		if err := json.NewEncoder(&buf).Encode(body); err != nil {
			return nil, err
		}
	}
	req, err := http.NewRequest(method, apiBase+path, &buf)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	req.Header.Set("User-Agent", "relixq/1.0")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode >= 400 {
		defer resp.Body.Close()
		return nil, fmt.Errorf("github API %s %s: status %d", method, path, resp.StatusCode)
	}
	return resp, nil
}

// PRNumberFromEventPayload reads the PR number from the GITHUB_EVENT_PATH JSON file.
func PRNumberFromEventPayload(path string) (int, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return 0, err
	}
	var payload struct {
		Number int `json:"number"`
	}
	if err := json.Unmarshal(data, &payload); err != nil {
		return 0, err
	}
	if payload.Number == 0 {
		return 0, fmt.Errorf("no PR number in event payload")
	}
	return payload.Number, nil
}
