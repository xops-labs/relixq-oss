// Copyright (c) 2026 Yasvanth Udayakumar
// SPDX-License-Identifier: Apache-2.0
// See LICENSE in the repository root for full terms.
package scanner

import "testing"

func TestDetectLanguage(t *testing.T) {
	cases := []struct {
		path string
		want Language
	}{
		{"src/Foo.cs", LangCSharp},
		{"app/main.py", LangPython},
		{"web/app.js", LangJavaScript},
		{"web/app.tsx", LangTypeScript},
		{"cmd/run.go", LangGo},
		{"deploy/Dockerfile", LangDockerfile},
		{"deploy/Dockerfile.prod", LangDockerfile},
		{"infra/main.tf", LangTerraform},
		{"k8s/deploy.yaml", LangYAML},
		{".env.production", LangEnv},
		// CUDA routes to LangCpp so the existing C++ rule pack and cppast
		// Tree-sitter runner cover GPU host-side crypto without a new pack.
		{"gpu/kernels.cu", LangCpp},
		{"gpu/include/kernels.cuh", LangCpp},
		// IEC 61131-3 Structured Text — PLC / SCADA / ICS source.
		{"plc/legacy_crypto.st", LangIEC61131},
		{"plc/opcua_config.iecst", LangIEC61131},
		{"build/output.bin", LangUnknown},
		{"README.md", LangUnknown},
	}
	for _, c := range cases {
		got := DetectLanguage(c.path)
		if got != c.want {
			t.Errorf("DetectLanguage(%q) = %q, want %q", c.path, got, c.want)
		}
	}
}
