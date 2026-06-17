// Copyright (c) 2026 Yasvanth Udayakumar
// SPDX-License-Identifier: Apache-2.0
// See LICENSE in the repository root for full terms.
package auth

import (
	"errors"
	"os"

	"github.com/zalando/go-keyring"
)

const (
	keychainService      = "relixq"
	keychainAccessToken  = "access_token"
	keychainRefreshToken = "refresh_token"
)

// Token holds the access and refresh tokens.
type Token struct {
	AccessToken  string
	RefreshToken string
}

// GetToken returns the stored token. RELIXQ_TOKEN env var takes precedence
// (for CI pipelines where interactive keychain is unavailable).
func GetToken() (*Token, error) {
	if v := os.Getenv("RELIXQ_TOKEN"); v != "" {
		return &Token{AccessToken: v}, nil
	}
	return loadFromKeychain()
}

// SaveToken stores access and refresh tokens in the OS keychain.
func SaveToken(t *Token) error {
	if err := keyring.Set(keychainService, keychainAccessToken, t.AccessToken); err != nil {
		return err
	}
	if t.RefreshToken != "" {
		return keyring.Set(keychainService, keychainRefreshToken, t.RefreshToken)
	}
	return nil
}

// DeleteToken removes stored tokens (logout).
func DeleteToken() error {
	_ = keyring.Delete(keychainService, keychainRefreshToken)
	return keyring.Delete(keychainService, keychainAccessToken)
}

func loadFromKeychain() (*Token, error) {
	access, err := keyring.Get(keychainService, keychainAccessToken)
	if err != nil {
		if errors.Is(err, keyring.ErrNotFound) {
			return nil, errors.New("not logged in — run: relixq login")
		}
		return nil, err
	}
	refresh, _ := keyring.Get(keychainService, keychainRefreshToken)
	return &Token{AccessToken: access, RefreshToken: refresh}, nil
}
