// Copyright (c) 2026 Yasvanth Udayakumar
// SPDX-License-Identifier: Apache-2.0
// See LICENSE in the repository root for full terms.
package auth

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// DeviceCodeResponse is returned by POST /oauth/device/code.
type DeviceCodeResponse struct {
	DeviceCode              string `json:"device_code"`
	UserCode                string `json:"user_code"`
	VerificationURL         string `json:"verification_url"`
	ExpiresIn               int    `json:"expires_in"`
	Interval                int    `json:"interval"`
}

// Login performs the RFC 8628 device-code flow against the Relix-Q auth endpoint
// and stores the resulting tokens in the OS keychain.
func Login(apiURL string, printPrompt func(verificationURL, userCode string)) error {
	dc, err := requestDeviceCode(apiURL)
	if err != nil {
		return err
	}

	printPrompt(dc.VerificationURL, dc.UserCode)

	token, err := pollForToken(apiURL, dc)
	if err != nil {
		return err
	}
	return SaveToken(token)
}

func requestDeviceCode(apiURL string) (*DeviceCodeResponse, error) {
	resp, err := http.PostForm(apiURL+"/oauth/device/code",
		url.Values{"client_id": {"relixq-cli"}})
	if err != nil {
		return nil, fmt.Errorf("device code request: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("device code request: HTTP %d", resp.StatusCode)
	}
	var dc DeviceCodeResponse
	if err := json.NewDecoder(resp.Body).Decode(&dc); err != nil {
		return nil, fmt.Errorf("parsing device code response: %w", err)
	}
	if dc.Interval == 0 {
		dc.Interval = 5
	}
	return &dc, nil
}

func pollForToken(apiURL string, dc *DeviceCodeResponse) (*Token, error) {
	deadline := time.Now().Add(time.Duration(dc.ExpiresIn) * time.Second)
	interval := time.Duration(dc.Interval) * time.Second

	for time.Now().Before(deadline) {
		time.Sleep(interval)

		resp, err := http.PostForm(apiURL+"/oauth/token", url.Values{
			"grant_type":  {"urn:ietf:params:oauth:grant-type:device_code"},
			"device_code": {dc.DeviceCode},
			"client_id":   {"relixq-cli"},
		})
		if err != nil {
			return nil, fmt.Errorf("token poll: %w", err)
		}

		var body map[string]interface{}
		json.NewDecoder(resp.Body).Decode(&body)
		resp.Body.Close()

		if errCode, ok := body["error"].(string); ok {
			switch errCode {
			case "authorization_pending":
				continue
			case "slow_down":
				interval += 5 * time.Second
				continue
			case "expired_token":
				return nil, fmt.Errorf("device code expired — run relixq login again")
			default:
				return nil, fmt.Errorf("auth error: %s", strings.TrimSpace(errCode))
			}
		}

		access, _ := body["access_token"].(string)
		refresh, _ := body["refresh_token"].(string)
		if access == "" {
			continue
		}
		return &Token{AccessToken: access, RefreshToken: refresh}, nil
	}
	return nil, fmt.Errorf("timed out waiting for device authorization")
}
