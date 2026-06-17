// Copyright (c) 2026 Yasvanth Udayakumar
// SPDX-License-Identifier: Apache-2.0
// See LICENSE in the repository root for full terms.
package scanner

import (
	"path/filepath"
	"strings"
)

// Language is a normalized identifier matching the rule pack's `language:` field.
type Language string

const (
	LangCSharp     Language = "csharp"
	LangPython     Language = "python"
	LangJavaScript Language = "javascript"
	LangTypeScript Language = "typescript"
	LangGo         Language = "go"
	LangJava       Language = "java"
	LangKotlin     Language = "kotlin"
	LangSwift      Language = "swift"
	LangRuby       Language = "ruby"
	LangCpp        Language = "cpp"
	LangC          Language = "c"
	LangRust       Language = "rust"
	LangPHP        Language = "php"
	LangScala      Language = "scala"
	LangJulia      Language = "julia"
	LangQSharp     Language = "qsharp"
	LangSolidity   Language = "solidity"
	LangAda        Language = "ada"
	LangObjectiveC Language = "objc"
	LangShell      Language = "shell"
	LangElixir     Language = "elixir"
	LangErlang     Language = "erlang"
	LangDart       Language = "dart"
	LangFSharp     Language = "fsharp"
	LangClojure    Language = "clojure"
	LangPerl       Language = "perl"
	LangVerilog    Language = "verilog"
	LangVHDL       Language = "vhdl"
	LangMove       Language = "move"
	LangVyper      Language = "vyper"
	LangIEC61131   Language = "iec61131"
	// LangJupyter is the routing sentinel for .ipynb files. The notebook
	// preprocessor lifts code cells out and re-runs them through the Python
	// AST runner, so emitted findings carry language="python", not "jupyter".
	LangJupyter Language = "jupyter"

	LangYAML        Language = "yaml"
	LangJSON        Language = "json"
	LangXML         Language = "xml"
	LangINI         Language = "ini"
	LangTOML        Language = "toml"
	LangEnv         Language = "env"
	LangDockerfile  Language = "dockerfile"
	LangTerraform   Language = "terraform"
	LangBicep       Language = "bicep"
	LangNginx       Language = "nginx"
	LangApache      Language = "apache"
	LangOpenSSLConf Language = "openssl-cnf"
	// LangSSHConfig routes OpenSSH server/client configuration (sshd_config,
	// ssh_config) to the rules-community/ssh pack: host keys, KexAlgorithms,
	// and cipher lists are config-only crypto the PQC inventory must see.
	LangSSHConfig Language = "ssh-config"
	// LangX509 routes certificate / key material files (.pem, .crt, .cer,
	// .der, .key) to the dedicated x509 detector, which parses both the
	// public-key algorithm and the signature algorithm rather than pattern
	// matching text.
	LangX509 Language = "x509"

	LangAny     Language = "any"
	LangUnknown Language = ""
)

// extToLanguage maps file extensions (lowercase, with dot) to a Language.
var extToLanguage = map[string]Language{
	".cs":  LangCSharp,
	".py":  LangPython,
	".js":  LangJavaScript,
	".jsx": LangJavaScript,
	".mjs": LangJavaScript,
	".cjs": LangJavaScript,
	".ts":  LangTypeScript,
	".tsx": LangTypeScript,
	".go":  LangGo,
	".java": LangJava,
	".kt":   LangKotlin,
	".kts":  LangKotlin,
	".swift": LangSwift,
	".rb":  LangRuby,
	".cpp": LangCpp,
	".cc":  LangCpp,
	".cxx": LangCpp,
	".hpp": LangCpp,
	".hxx": LangCpp,
	// CUDA is C++ with extensions (`__global__`, `__device__`, `__host__`).
	// The cppast runner's C++ grammar tolerates these keywords as identifiers
	// and matches the same OpenSSL call sites we already cover. PQC migration
	// is relevant on the GPU side because batched ML-KEM kernels and CUDA
	// crypto kernels repurposed from mining live here.
	".cu":  LangCpp,
	".cuh": LangCpp,
	".c":   LangC,
	".h":   LangC,
	".rs":  LangRust,
	".php":   LangPHP,
	".phtml": LangPHP,
	".scala": LangScala,
	".sc":    LangScala,
	".jl":    LangJulia,
	".qs":    LangQSharp,
	".sol":   LangSolidity,
	".ipynb": LangJupyter,
	// Ada / SPARK: `.adb` is body, `.ads` is spec, `.ada` is legacy combined.
	".adb": LangAda,
	".ads": LangAda,
	".ada": LangAda,
	// Objective-C and Objective-C++. The `.m` extension is also used by
	// MATLAB; MATLAB is Tier 4 (skip), so the
	// collision is accepted — Obj-C-specific rules harmlessly no-op on
	// MATLAB files.
	".m":  LangObjectiveC,
	".mm": LangObjectiveC,
	// Shell scripts (POSIX sh / bash / zsh / ksh share rule semantics).
	".sh":   LangShell,
	".bash": LangShell,
	".zsh":  LangShell,
	".ksh":  LangShell,
	// Helm templates are YAML with `{{ }}` interpolation. Mapping `.tpl` to
	// LangYAML lets the Helm rule pack's per-rule file_globs narrow it.
	".tpl": LangYAML,
	// Bicep (Azure DSL transpiling to ARM JSON).
	".bicep":      LangBicep,
	".bicepparam": LangBicep,
	// Elixir (.exs is a script flavor).
	".ex":  LangElixir,
	".exs": LangElixir,
	// Erlang headers + source.
	".erl": LangErlang,
	".hrl": LangErlang,
	// Dart / Flutter.
	".dart": LangDart,
	// F# (.fsi is interface, .fsx is script).
	".fs":  LangFSharp,
	".fsi": LangFSharp,
	".fsx": LangFSharp,
	// Clojure / ClojureScript / EDN data.
	".clj":  LangClojure,
	".cljs": LangClojure,
	".cljc": LangClojure,
	".edn":  LangClojure,
	// Perl source + module + tests. The `.t` extension is Perl test
	// convention; no other supported language uses it.
	".pl": LangPerl,
	".pm": LangPerl,
	".t":  LangPerl,
	// Verilog / SystemVerilog. SystemVerilog (.sv/.svh) bundled into the
	// Verilog rule pack for v1.
	".v":   LangVerilog,
	".vh":  LangVerilog,
	".sv":  LangVerilog,
	".svh": LangVerilog,
	// VHDL.
	".vhd":  LangVHDL,
	".vhdl": LangVHDL,
	// Move (Aptos / Sui / Diem-derived chains).
	".move": LangMove,
	// Vyper (Ethereum Python-syntax smart contracts).
	".vy": LangVyper,
	// IEC 61131-3 Structured Text (PLC / SCADA / industrial controls).
	// `.st` is the standard IEC ST extension; `.iecst` is the CODESYS-explicit
	// variant. The `.st` extension is sometimes used by Smalltalk, which is
	// Tier 4 (skip) — the regex patterns target
	// IEC 61131-3 keywords (`FUNCTION_BLOCK`, `VAR_INPUT`, `:=`) that don't
	// appear in Smalltalk, so the worst case is zero false-positive findings.
	".st":    LangIEC61131,
	".iecst": LangIEC61131,

	// Certificate / key material. Routed to the x509 detector, not text rules.
	".pem": LangX509,
	".crt": LangX509,
	".cer": LangX509,
	".der": LangX509,
	".key": LangX509,

	".yaml": LangYAML,
	".yml":  LangYAML,
	".json": LangJSON,
	".xml":  LangXML,
	".ini":  LangINI,
	".cfg":  LangINI,
	".conf": LangINI,
	".toml": LangTOML,
	".env":  LangEnv,
	".tf":   LangTerraform,
	".tfvars": LangTerraform,
}

// nameToLanguage matches files by exact name (Dockerfile, .env, etc.).
var nameToLanguage = map[string]Language{
	"dockerfile":      LangDockerfile,
	"containerfile":   LangDockerfile,
	".env":            LangEnv,
	".env.local":      LangEnv,
	".env.production": LangEnv,
	// Web-server configs: filename routing covers the conventional names;
	// per-rule file_globs in rules/nginx and rules/apache narrow further.
	"nginx.conf":   LangNginx,
	"httpd.conf":   LangApache,
	"apache2.conf": LangApache,
	".htaccess":    LangApache,
	// OpenSSL master configuration. The `.cnf` extension is intentionally
	// NOT in extToLanguage — most `.cnf` files in the wild are not OpenSSL
	// configs, so the name-based route keeps the openssl-cnf rule pack
	// scoped to actual openssl configuration files.
	"openssl.cnf":      LangOpenSSLConf,
	"openssl-fips.cnf": LangOpenSSLConf,
	// OpenSSH daemon/client configuration (conventional names).
	"sshd_config": LangSSHConfig,
	"ssh_config":  LangSSHConfig,
}

// DetectLanguage determines a file's language by extension first, then by exact name.
// Returns LangUnknown when no rule applies.
func DetectLanguage(path string) Language {
	base := strings.ToLower(filepath.Base(path))
	if l, ok := nameToLanguage[base]; ok {
		return l
	}
	// Dockerfile.* / *.Dockerfile patterns
	if strings.HasPrefix(base, "dockerfile.") || strings.HasSuffix(base, ".dockerfile") {
		return LangDockerfile
	}
	// *.nginx.conf / *.nginx → LangNginx
	if strings.HasSuffix(base, ".nginx.conf") || strings.HasSuffix(base, ".nginx") {
		return LangNginx
	}
	// *.apache.conf / *.htaccess → LangApache
	if strings.HasSuffix(base, ".apache.conf") || strings.HasSuffix(base, ".htaccess") {
		return LangApache
	}
	// *.openssl.cnf → LangOpenSSLConf
	if strings.HasSuffix(base, ".openssl.cnf") {
		return LangOpenSSLConf
	}
	ext := strings.ToLower(filepath.Ext(base))
	if ext == "" {
		return LangUnknown
	}
	if l, ok := extToLanguage[ext]; ok {
		return l
	}
	return LangUnknown
}

// IsSourceLanguage reports whether the language is a programming language
// (vs. config / IaC / unknown).
func IsSourceLanguage(l Language) bool {
	switch l {
	case LangCSharp, LangPython, LangJavaScript, LangTypeScript, LangGo,
		LangJava, LangKotlin, LangSwift, LangRuby, LangCpp, LangC, LangRust,
		LangPHP, LangScala, LangJulia, LangQSharp, LangSolidity,
		LangAda, LangObjectiveC, LangShell,
		LangElixir, LangErlang, LangDart, LangFSharp, LangClojure, LangPerl,
		LangVerilog, LangVHDL, LangMove, LangVyper, LangIEC61131:
		return true
	}
	// NOTE: LangJupyter is deliberately excluded — .ipynb is a JSON wrapper,
	// not source. The notebook preprocessor surfaces findings under
	// language="python" so the Python branch above is what counts.
	return false
}
