package airom

import (
	"encoding/json"
	"testing"
)

// TestTriStateJSON pins the native-format contract: Absent omitted (via
// omitzero), Unknown null, Known the value — losslessly round-tripped.
func TestTriStateJSON(t *testing.T) {
	type wrap struct {
		A OptString `json:"a,omitzero"`
		B OptString `json:"b,omitzero"`
		C OptString `json:"c,omitzero"`
		N OptInt64  `json:"n,omitzero"`
	}
	in := wrap{
		B: UnknownString(),
		C: KnownString("v1"),
		N: KnownInt64(42),
	}
	data, err := json.Marshal(in)
	if err != nil {
		t.Fatal(err)
	}
	want := `{"b":null,"c":"v1","n":42}`
	if string(data) != want {
		t.Fatalf("json = %s, want %s (Absent omitted, Unknown null, Known value)", data, want)
	}

	var out wrap
	if err := json.Unmarshal(data, &out); err != nil {
		t.Fatal(err)
	}
	if out.A.P != PresenceAbsent || out.B.P != PresenceUnknown || out.C.P != PresenceKnown {
		t.Errorf("round-trip presence lost: %+v", out)
	}
	if v, _ := out.C.Value(); v != "v1" {
		t.Errorf("round-trip value lost: %+v", out.C)
	}
}

func TestTriStateStates(t *testing.T) {
	data, _ := json.Marshal(struct {
		Y TriState `json:"y"`
		N TriState `json:"n"`
		U TriState `json:"u"`
	}{TriYes, TriNo, TriUnknown})
	if string(data) != `{"y":"yes","n":"no","u":"unknown"}` {
		t.Errorf("TriState json = %s", data)
	}
}

func TestConfidenceBand(t *testing.T) {
	if Confidence(0.95).Band() != "high" || Confidence(0.7).Band() != "medium" || Confidence(0.2).Band() != "low" {
		t.Error("Band boundaries wrong")
	}
}
