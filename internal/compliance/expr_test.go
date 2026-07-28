package compliance

import (
	"reflect"
	"testing"

	"github.com/airomhq/airom/pkg/airom"
)

// TestCompileErrors: malformed / unknown terms fail to compile.
func TestCompileErrors(t *testing.T) {
	for _, bad := range []string{"", "not-a-kind", "risk:nope", "hosted-llm &", "| framework"} {
		if _, err := compile(bad); err == nil {
			t.Errorf("compile(%q) succeeded, want error", bad)
		}
	}
}

// TestMatch: the subset grammar matches the right components and never the
// application root.
func TestMatch(t *testing.T) {
	in := inv()
	cases := []struct {
		expr string
		want []airom.ID
	}{
		{"*", []airom.ID{"airom:1111111111111111", "airom:2222222222222222", "airom:3333333333333333"}},
		{"hosted-llm", []airom.ID{"airom:1111111111111111"}},
		{"framework | hosted-llm", []airom.ID{"airom:1111111111111111", "airom:2222222222222222"}},
		{"risk", []airom.ID{"airom:3333333333333333"}},
		{"risk:unsafe-load", []airom.ID{"airom:3333333333333333"}},
		{"risk:medium", []airom.ID{"airom:3333333333333333"}},
		{"risk:high", nil}, // no high-severity risk present
		{"local-model-file & risk", []airom.ID{"airom:3333333333333333"}},
		{"local-model-file & hosted-llm", nil}, // one component can't be two kinds
	}
	for _, c := range cases {
		e, err := compile(c.expr)
		if err != nil {
			t.Fatalf("compile(%q): %v", c.expr, err)
		}
		got := e.match(in, false)
		if !reflect.DeepEqual(got, c.want) {
			t.Errorf("match(%q) = %v, want %v", c.expr, got, c.want)
		}
	}
}
