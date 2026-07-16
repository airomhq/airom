package engine

import (
	"context"
	"strings"
	"testing"

	"github.com/Roro1727/airom/pkg/airom/detect"
)

type catDet struct {
	id   string
	tags []string
}

func (d *catDet) ID() string                { return d.id }
func (d *catDet) Version() int              { return 1 }
func (d *catDet) Selector() detect.Selector { return detect.Selector{} }
func (d *catDet) Tags() []string            { return d.tags }
func (d *catDet) DetectFile(context.Context, *detect.File) ([]detect.Finding, error) {
	return nil, nil
}

func newCat(t *testing.T) *Catalog {
	t.Helper()
	c := NewCatalog()
	c.Add(&catDet{id: "modelfile/gguf", tags: []string{"model-file"}})
	c.Add(&catDet{id: "manifest/pypi", tags: []string{"python", "manifest"}})
	c.Add(&catDet{id: "rules/engine", tags: []string{"rules", "python"}})
	return c
}

func selectedIDs(t *testing.T, c *Catalog, expr string) []string {
	t.Helper()
	sel, err := c.Select(expr)
	if err != nil {
		t.Fatalf("Select(%q): %v", expr, err)
	}
	var ids []string
	for _, d := range sel.File {
		ids = append(ids, d.ID())
	}
	return ids
}

func TestSelectDefaultsToAll(t *testing.T) {
	if got := selectedIDs(t, newCat(t), ""); len(got) != 3 {
		t.Errorf("empty expr = %v, want all 3", got)
	}
}

func TestSelectBareTagSubselects(t *testing.T) {
	got := selectedIDs(t, newCat(t), "python")
	if len(got) != 2 {
		t.Errorf("python = %v, want manifest/pypi + rules/engine", got)
	}
}

func TestSelectAddRemove(t *testing.T) {
	got := selectedIDs(t, newCat(t), "python,-rules,+modelfile/gguf")
	if strings.Join(got, ",") != "modelfile/gguf,manifest/pypi" {
		t.Errorf("compound = %v", got)
	}
}

func TestSelectUnknownTokenIsError(t *testing.T) {
	if _, err := newCat(t).Select("pythn"); err == nil {
		t.Error("typo'd selection silently ignored; want loud error")
	}
}

func TestSelectExplanationRecorded(t *testing.T) {
	sel, err := newCat(t).Select("python")
	if err != nil {
		t.Fatal(err)
	}
	if len(sel.Explanation) != 2 || !strings.Contains(sel.Explanation[0], `selected by "python"`) {
		t.Errorf("explanation = %v", sel.Explanation)
	}
}

func TestCatalogPanicsOnDuplicate(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Error("duplicate ID did not panic")
		}
	}()
	c := NewCatalog()
	c.Add(&catDet{id: "x"})
	c.Add(&catDet{id: "x"})
}

// TestSelectAllOnEmptyCatalog: "all" is definitionally valid even when the
// catalog is empty (regression: it errored while "" succeeded).
func TestSelectAllOnEmptyCatalog(t *testing.T) {
	sel, err := NewCatalog().Select("all")
	if err != nil {
		t.Fatalf(`Select("all") on empty catalog: %v`, err)
	}
	if len(sel.File)+len(sel.Project) != 0 {
		t.Errorf("selection = %+v, want empty", sel)
	}
}
