// Copyright (c) 2026 Yasvanth Udayakumar
// SPDX-License-Identifier: Apache-2.0
// See LICENSE in the repository root for full terms.

//go:build !cgo

// Package kotlinast is a no-op shell when the worker is built without CGO.
// The real Tree-sitter-backed runner lives in runner.go and only compiles
// when `CGO_ENABLED=1` and a C toolchain is present. Without it, no Kotlin
// AST runner registers itself and the scanner falls back to regex-only for
// `.kt`/`.kts` files. See runner.go for the active implementation.
package kotlinast
