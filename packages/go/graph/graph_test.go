// Copyright (c) 2026 Yasvanth Udayakumar
// SPDX-License-Identifier: Apache-2.0
// See LICENSE in the repository root for full terms.
package graph

import (
	"os"
	"path/filepath"
	"sort"
	"testing"

	"github.com/relix-q/relix-q/finding"
)

func TestGraph_basicEdges(t *testing.T) {
	g := New()
	g.AddEdge("a.go", "b.go")
	g.AddEdge("b.go", "c.go")
	g.AddEdge("d.go", "c.go")

	got := g.DirectImporters("c.go")
	sort.Strings(got)
	want := []string{"b.go", "d.go"}
	if !equalSlices(got, want) {
		t.Errorf("DirectImporters(c.go) = %v, want %v", got, want)
	}

	transit := g.TransitiveImporters("c.go", 0)
	sort.Strings(transit)
	wantTransit := []string{"a.go", "b.go", "d.go"}
	if !equalSlices(transit, wantTransit) {
		t.Errorf("TransitiveImporters(c.go) = %v, want %v", transit, wantTransit)
	}
}

func TestGraph_cycleSafe(t *testing.T) {
	g := New()
	g.AddEdge("a.go", "b.go")
	g.AddEdge("b.go", "c.go")
	g.AddEdge("c.go", "a.go") // cycle

	// Must terminate without panic. Each file should appear in the
	// transitive set of every other.
	for _, f := range []string{"a.go", "b.go", "c.go"} {
		got := g.TransitiveImporters(f, 0)
		if len(got) != 2 {
			t.Errorf("TransitiveImporters(%s) on cycle = %v, want 2 entries", f, got)
		}
	}
}

func TestGraph_maxHopsBound(t *testing.T) {
	g := New()
	// Linear chain: e → d → c → b → a
	g.AddEdge("e.go", "d.go")
	g.AddEdge("d.go", "c.go")
	g.AddEdge("c.go", "b.go")
	g.AddEdge("b.go", "a.go")

	// Unbounded — should find all 4 importers of a.
	full := g.TransitiveImporters("a.go", 0)
	if len(full) != 4 {
		t.Errorf("full closure: want 4 importers, got %v", full)
	}

	// 1 hop — only b should show.
	oneHop := g.TransitiveImporters("a.go", 1)
	if len(oneHop) != 1 || oneHop[0] != "b.go" {
		t.Errorf("1-hop: want [b.go], got %v", oneHop)
	}

	// 2 hops — b and c.
	twoHop := g.TransitiveImporters("a.go", 2)
	sort.Strings(twoHop)
	if !equalSlices(twoHop, []string{"b.go", "c.go"}) {
		t.Errorf("2-hop: want [b.go, c.go], got %v", twoHop)
	}
}

func TestGraph_sameDirFallback(t *testing.T) {
	g := New()
	g.AddFile("internal/agility/scorer.go")
	g.AddFile("internal/agility/scorer_test.go")
	g.AddFile("internal/agility/README.md")
	g.AddFile("internal/fusion/fusion.go")
	g.AddFile("cmd/main.go")

	sibs := g.SameDirectoryFiles("internal/agility/scorer.go")
	sort.Strings(sibs)
	if !equalSlices(sibs, []string{"internal/agility/readme.md", "internal/agility/scorer_test.go"}) {
		t.Errorf("siblings = %v", sibs)
	}
}

func TestImpact_weightedBlastRadius(t *testing.T) {
	g := New()
	// Build: x.go is imported by 3 direct files, those 3 are imported
	// by 5 more transitive files. Plus 2 same-directory siblings.
	g.AddEdge("a.go", "internal/x/x.go")
	g.AddEdge("b.go", "internal/x/x.go")
	g.AddEdge("c.go", "internal/x/x.go")
	g.AddEdge("d.go", "a.go")
	g.AddEdge("e.go", "a.go")
	g.AddEdge("f.go", "b.go")
	g.AddEdge("g.go", "c.go")
	g.AddEdge("h.go", "c.go")
	g.AddFile("internal/x/y.go")
	g.AddFile("internal/x/z.go")

	findings := []finding.Finding{
		{RuleID: "R1", FilePath: "internal/x/x.go", Algorithm: "RSA", Severity: finding.SeverityHigh},
	}
	reports := Impact(g, findings)
	if len(reports) != 1 {
		t.Fatalf("want 1 report, got %d", len(reports))
	}
	r := reports[0]
	if r.DirectImporters != 3 {
		t.Errorf("direct = %d, want 3", r.DirectImporters)
	}
	// transitive = a,b,c + d,e,f,g,h = 8
	if r.TransitiveImporters != 8 {
		t.Errorf("transitive = %d, want 8", r.TransitiveImporters)
	}
	if r.SameDirectoryFiles != 2 {
		t.Errorf("same-dir = %d, want 2", r.SameDirectoryFiles)
	}
	// br = 3*8 + 3 + 2 = 29
	if r.BlastRadius != 29 {
		t.Errorf("br = %d, want 29", r.BlastRadius)
	}
	if r.MigrationCostBand != "Medium" {
		t.Errorf("band = %q, want Medium", r.MigrationCostBand)
	}
}

func TestImpact_bandThresholds(t *testing.T) {
	cases := []struct {
		br   int
		want string
	}{
		{0, "Low"},
		{9, "Low"},
		{10, "Medium"},
		{49, "Medium"},
		{50, "High"},
		{199, "High"},
		{200, "Catastrophic"},
		{10000, "Catastrophic"},
	}
	for _, c := range cases {
		got := bandForBlastRadius(c.br)
		if got != c.want {
			t.Errorf("bandForBlastRadius(%d) = %q, want %q", c.br, got, c.want)
		}
	}
}

func TestImpact_deduplicatesPerFile(t *testing.T) {
	g := New()
	g.AddEdge("a.go", "x.go")
	g.AddEdge("b.go", "x.go")

	findings := []finding.Finding{
		{RuleID: "R1", FilePath: "x.go"},
		{RuleID: "R2", FilePath: "x.go"},
		{RuleID: "R3", FilePath: "x.go"},
	}
	reports := Impact(g, findings)
	if len(reports) != 3 {
		t.Errorf("want 3 reports (one per finding), got %d", len(reports))
	}
	// All three should share the same direct/transitive/sameDir counts.
	for i := 1; i < len(reports); i++ {
		if reports[i].DirectImporters != reports[0].DirectImporters ||
			reports[i].TransitiveImporters != reports[0].TransitiveImporters ||
			reports[i].SameDirectoryFiles != reports[0].SameDirectoryFiles {
			t.Errorf("per-file numbers should be stable; report[%d]=%+v vs report[0]=%+v", i, reports[i], reports[0])
		}
	}
}

func TestBuildFromRepo_goImports(t *testing.T) {
	root := t.TempDir()
	mustWrite(t, filepath.Join(root, "main.go"), `package main

import (
    "fmt"
    "example.com/myrepo/internal/lib"
)

func main() { lib.X(); fmt.Println("hi") }
`)
	mustWrite(t, filepath.Join(root, "internal/lib/lib.go"), `package lib
import "example.com/myrepo/internal/helper"
func X() { helper.Y() }
`)
	mustWrite(t, filepath.Join(root, "internal/helper/helper.go"), `package helper
func Y() {}
`)

	g, err := BuildFromRepo(root)
	if err != nil {
		t.Fatal(err)
	}
	if g.NodeCount() < 3 {
		t.Errorf("want at least 3 nodes, got %d", g.NodeCount())
	}
	if g.EdgeCount() < 2 {
		t.Errorf("want at least 2 edges, got %d", g.EdgeCount())
	}

	// helper.go should have lib.go as direct importer.
	direct := g.DirectImporters("internal/helper/helper.go")
	if len(direct) == 0 {
		t.Errorf("expected lib.go to import helper.go; importers=%v", direct)
	}

	// Transitively, main.go should import helper.go through lib.go.
	trans := g.TransitiveImporters("internal/helper/helper.go", 0)
	sawMain := false
	for _, f := range trans {
		if f == "main.go" {
			sawMain = true
		}
	}
	if !sawMain {
		t.Errorf("transitive closure should include main.go; got %v", trans)
	}
}

func TestBuildFromRepo_pythonImports(t *testing.T) {
	root := t.TempDir()
	mustWrite(t, filepath.Join(root, "app.py"), `from lib import helper
import lib.util
helper.do()
`)
	mustWrite(t, filepath.Join(root, "lib/__init__.py"), ``)
	mustWrite(t, filepath.Join(root, "lib/helper.py"), `def do(): pass
`)
	mustWrite(t, filepath.Join(root, "lib/util.py"), `def x(): pass
`)

	g, err := BuildFromRepo(root)
	if err != nil {
		t.Fatal(err)
	}
	direct := g.DirectImporters("lib/helper.py")
	if len(direct) == 0 {
		t.Errorf("expected app.py to import lib/helper.py; importers=%v", direct)
	}
}

func TestBuildFromRepo_skipsNodeModules(t *testing.T) {
	root := t.TempDir()
	mustWrite(t, filepath.Join(root, "main.go"), `package main`)
	mustWrite(t, filepath.Join(root, "node_modules/x/main.go"), `package main`)
	mustWrite(t, filepath.Join(root, "vendor/y/main.go"), `package main`)

	g, err := BuildFromRepo(root)
	if err != nil {
		t.Fatal(err)
	}
	for f := range g.files {
		if filepath.HasPrefix(f, "node_modules") || filepath.HasPrefix(f, "vendor") {
			t.Errorf("noise dir should be skipped: %s", f)
		}
	}
}

func TestImpact_sortedByBlastRadiusDesc(t *testing.T) {
	g := New()
	g.AddEdge("a.go", "low.go")               // low: 1 direct, 0 transitive
	g.AddEdge("a.go", "med.go")
	g.AddEdge("b.go", "med.go")
	g.AddEdge("c.go", "med.go")               // med: 3 direct
	for _, src := range []string{"d.go", "e.go", "f.go", "g.go"} {
		g.AddEdge(src, "high.go")
	}
	for _, src := range []string{"h.go", "i.go", "j.go", "k.go", "l.go"} {
		g.AddEdge(src, "d.go") // transitive importers of high.go
	}

	findings := []finding.Finding{
		{RuleID: "Rlo", FilePath: "low.go"},
		{RuleID: "Rmd", FilePath: "med.go"},
		{RuleID: "Rhi", FilePath: "high.go"},
	}
	reports := Impact(g, findings)
	if len(reports) != 3 {
		t.Fatalf("want 3 reports, got %d", len(reports))
	}
	if reports[0].FilePath != "high.go" || reports[2].FilePath != "low.go" {
		t.Errorf("sort order broken: %v %v %v", reports[0].FilePath, reports[1].FilePath, reports[2].FilePath)
	}
	// Bands sanity.
	for _, r := range reports {
		if r.MigrationCostBand == "" {
			t.Errorf("missing band on %s", r.FilePath)
		}
	}
}

func mustWrite(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func equalSlices(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
