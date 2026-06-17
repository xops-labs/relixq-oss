// Copyright (c) 2026 Yasvanth Udayakumar
// SPDX-License-Identifier: Apache-2.0
// See LICENSE in the repository root for full terms.
package client

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

// OrgEntry represents one org the authenticated user belongs to.
type OrgEntry struct {
	OrganizationID string    `json:"organizationId"`
	Name           string    `json:"name"`
	Slug           string    `json:"slug"`
	OrgRole        string    `json:"orgRole"`
	JoinedAt       time.Time `json:"joinedAt"`
}

// SwitchOrgTokens holds the re-minted tokens returned after an org switch.
type SwitchOrgTokens struct {
	AccessToken  string `json:"accessToken"`
	RefreshToken string `json:"refreshToken"`
	ExpiresIn    int    `json:"expiresIn"`
}

// ListMyOrgs returns all orgs the authenticated user belongs to.
func (c *Client) ListMyOrgs() ([]OrgEntry, error) {
	resp, err := c.Get("/api/v1/me/orgs")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("list orgs: HTTP %d", resp.StatusCode)
	}
	var orgs []OrgEntry
	return orgs, json.NewDecoder(resp.Body).Decode(&orgs)
}

// SwitchOrg re-mints the JWT for the given org and returns the new tokens.
func (c *Client) SwitchOrg(orgID string) (*SwitchOrgTokens, error) {
	body, _ := json.Marshal(struct{}{})
	resp, err := c.Post("/api/v1/me/orgs/"+orgID+"/switch", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	switch resp.StatusCode {
	case http.StatusOK:
	case http.StatusNotFound:
		return nil, fmt.Errorf("switch org: not a member of that organization")
	default:
		return nil, fmt.Errorf("switch org: HTTP %d", resp.StatusCode)
	}
	var tokens SwitchOrgTokens
	return &tokens, json.NewDecoder(resp.Body).Decode(&tokens)
}
