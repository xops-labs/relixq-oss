// Copyright (c) 2026 Yasvanth Udayakumar
// SPDX-License-Identifier: Apache-2.0
// See LICENSE in the repository root for full terms.
package client

import (
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/relix-q/relix-q/cmd/relixq/internal/auth"
)

const (
	defaultTimeout    = 30 * time.Second
	maxRetries        = 3
	retryInitialDelay = 500 * time.Millisecond
)

// Client is a thin HTTP client that injects the Bearer token and retries on 5xx.
type Client struct {
	BaseURL    string
	httpClient *http.Client
}

// New creates a Client pointed at the given API base URL.
func New(baseURL string) *Client {
	return &Client{
		BaseURL:    baseURL,
		httpClient: &http.Client{Timeout: defaultTimeout},
	}
}

func (c *Client) do(method, path string, body io.Reader) (*http.Response, error) {
	token, err := auth.GetToken()
	if err != nil {
		return nil, err
	}

	var lastErr error
	delay := retryInitialDelay
	for attempt := 0; attempt < maxRetries; attempt++ {
		if attempt > 0 {
			time.Sleep(delay)
			delay *= 2
		}

		req, err := http.NewRequest(method, c.BaseURL+path, body)
		if err != nil {
			return nil, err
		}
		req.Header.Set("Authorization", "Bearer "+token.AccessToken)
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Accept", "application/json")

		resp, err := c.httpClient.Do(req)
		if err != nil {
			lastErr = err
			continue
		}
		if resp.StatusCode >= 500 {
			resp.Body.Close()
			lastErr = fmt.Errorf("HTTP %d from %s %s", resp.StatusCode, method, path)
			continue
		}
		return resp, nil
	}
	return nil, fmt.Errorf("request failed after %d attempts: %w", maxRetries, lastErr)
}

func (c *Client) Get(path string) (*http.Response, error) {
	return c.do(http.MethodGet, path, nil)
}

func (c *Client) Post(path string, body io.Reader) (*http.Response, error) {
	return c.do(http.MethodPost, path, body)
}
