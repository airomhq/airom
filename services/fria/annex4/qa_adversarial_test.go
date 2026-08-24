package annex4

import (
	"fmt"
	"strings"
	"testing"

	"github.com/airomhq/airom/pkg/airom"
)

func TestQA_AdversarialEmptyStrings(t *testing.T) {
	generator := NewGenerator()

	doc := generator.GenerateTechnicalDoc("", "", "", "", nil)
	if len(doc.Sections) != 6 {
		t.Errorf("expected 6 sections")
	}
}

func TestQA_AdversarialExtremeComponentInventory(t *testing.T) {
	generator := NewGenerator()

	var comps []airom.Component
	for i := 0; i < 1000; i++ {
		comps = append(comps, airom.Component{
			ID:   airom.ID(fmt.Sprintf("comp-%d", i)),
			Kind: airom.KindHostedLLM,
			Name: fmt.Sprintf("model-%d", i),
		})
	}
	inv := &airom.Inventory{Components: comps}

	doc := generator.GenerateTechnicalDoc("Extreme-System", "Provider", "1.0", "Purpose", inv)
	sec2 := doc.Sections[Section2_ComponentSpecifications]

	if !strings.Contains(sec2, "Total Discovered Components: 1000") {
		t.Errorf("expected 1000 components in section 2 summary")
	}
}
