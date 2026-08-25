package remediation

import (
	"strings"
	"testing"
)

func TestRemediation_PythonAndNodeUpgrade(t *testing.T) {
	engine := NewEngine()

	files := map[string]string{
		"src/rag_pipeline.py": "import openai\nclient = openai.OpenAI()\nresp = client.chat.completions.create(model=\"gpt-3.5-turbo-0613\", messages=[])\n",
		"config/models.json":  "{\n  \"default_model\": \"claude-2.0\"\n}\n",
	}

	plan := engine.CreateRemediationPlan("my-org/ai-service", files)
	if plan == nil {
		t.Fatalf("expected non-nil remediation plan")
	}

	if len(plan.Patches) != 2 {
		t.Errorf("expected 2 patches, got %d", len(plan.Patches))
	}

	for _, p := range plan.Patches {
		if p.FilePath == "src/rag_pipeline.py" {
			if !strings.Contains(p.ModifiedText, "gpt-4o-mini") {
				t.Errorf("expected python file to be upgraded to gpt-4o-mini")
			}
		}
		if p.FilePath == "config/models.json" {
			if !strings.Contains(p.ModifiedText, "claude-3-5-sonnet-20240620") {
				t.Errorf("expected json file to be upgraded to claude-3-5-sonnet")
			}
		}
	}

	if !strings.Contains(plan.BodyMarkdown, "AIROM Automated Model Upgrade Remediation") {
		t.Errorf("missing title in PR description")
	}
}

func TestRemediation_NoDeprecatedModels(t *testing.T) {
	engine := NewEngine()
	files := map[string]string{
		"src/app.py": "print('clean application with no model calls')\n",
	}
	plan := engine.CreateRemediationPlan("repo-clean", files)
	if plan != nil {
		t.Errorf("expected nil plan for clean repo, got: %+v", plan)
	}
}
