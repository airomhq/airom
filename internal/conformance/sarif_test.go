package conformance

import (
	"crypto/sha256"
	"encoding/hex"
	"regexp"
	"strings"
	"testing"

	"github.com/airomhq/airom/internal/writer"
)

// SARIF envelope constants the writer commits to (docs/mapping.md §7.3).
const (
	sarifSchemaURI = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"
	fingerprintKey = "airomComponentIdentity/v1"
)

var hex64 = regexp.MustCompile(`^[0-9a-f]{64}$`)

// TestSARIFStructuralConformance is the required structural floor for SARIF
// 2.1.0 (docs/mapping.md §7). No JSON-Schema validation: the OASIS SARIF schema
// is not vendored (fetch is unavailable and there is no in-tree JSON-Schema
// validator — see the package report), and these structural asserts are the
// task's specified floor.
func TestSARIFStructuralConformance(t *testing.T) {
	report := mustJSONMap(t, render(t, "sarif", writer.Options{}))

	if got := str(t, report["$schema"]); got != sarifSchemaURI {
		t.Errorf("$schema = %q, want the OASIS 2.1.0 URI", got)
	}
	if got := str(t, report["version"]); got != "2.1.0" {
		t.Errorf("version = %q, want 2.1.0", got)
	}

	runs := arr(t, report["runs"])
	if len(runs) != 1 {
		t.Fatalf("runs len = %d, want 1", len(runs))
	}
	run := obj(t, runs[0])

	if got := str(t, run["columnKind"]); got != "utf16CodeUnits" {
		t.Errorf("columnKind = %q, want utf16CodeUnits", got)
	}
	driver := obj(t, obj(t, run["tool"])["driver"])
	if got := str(t, driver["name"]); got != "airom" {
		t.Errorf("tool.driver.name = %q, want airom", got)
	}

	// Rule id set + index alignment.
	rules := arr(t, driver["rules"])
	ruleIDByIndex := make([]string, len(rules))
	ruleIDs := map[string]bool{}
	for i, r := range rules {
		id := str(t, obj(t, r)["id"])
		ruleIDByIndex[i] = id
		ruleIDs[id] = true
	}

	results := arr(t, run["results"])
	if len(results) == 0 {
		t.Fatal("no results emitted")
	}
	for i, r := range results {
		res := obj(t, r)
		ruleID := str(t, res["ruleId"])
		if !ruleIDs[ruleID] {
			t.Errorf("result[%d] ruleId %q not in tool.driver.rules[]", i, ruleID)
		}
		idx := int(res["ruleIndex"].(float64))
		if idx < 0 || idx >= len(ruleIDByIndex) || ruleIDByIndex[idx] != ruleID {
			t.Errorf("result[%d] ruleIndex %d does not point at ruleId %q", i, idx, ruleID)
		}

		// Risk and CVE results are security findings with their own severity
		// level and no component-identity fingerprint; the §7.1 inventory
		// encoding below applies to detector results only.
		if strings.HasPrefix(ruleID, "risk/") || strings.HasPrefix(ruleID, "cve/") || strings.HasPrefix(ruleID, "eol/") {
			continue
		}

		// Default mode: level "note", no kind (§7.1).
		if got := res["level"]; got != "note" {
			t.Errorf("result[%d] level = %v, want note", i, got)
		}
		if _, ok := res["kind"]; ok {
			t.Errorf("result[%d] carries kind in default mode: %v", i, res["kind"])
		}

		// partialFingerprints present, 64 lowercase hex.
		fp := str(t, obj(t, res["partialFingerprints"])[fingerprintKey])
		if !hex64.MatchString(fp) {
			t.Errorf("result[%d] fingerprint %q is not 64 lowercase hex chars", i, fp)
		}
	}
}

// TestSARIFStrictKindToggle covers the §7.1 encoding flip: strict mode emits
// kind "informational" and omits level.
func TestSARIFStrictKindToggle(t *testing.T) {
	report := mustJSONMap(t, render(t, "sarif", writer.Options{SARIFStrict: true}))
	results := arr(t, obj(t, arr(t, report["runs"])[0])["results"])
	if len(results) == 0 {
		t.Fatal("no results in strict mode")
	}
	for i, r := range results {
		res := obj(t, r)
		if id := str(t, res["ruleId"]); strings.HasPrefix(id, "risk/") || strings.HasPrefix(id, "cve/") || strings.HasPrefix(id, "eol/") {
			continue // security findings keep their level in strict mode
		}
		if got := res["kind"]; got != "informational" {
			t.Errorf("strict result[%d] kind = %v, want informational", i, got)
		}
		if _, ok := res["level"]; ok {
			t.Errorf("strict result[%d] carries level: %v", i, res["level"])
		}
	}
}

// TestSARIFFingerprintRecipe recomputes the §7.2 recipe for one result and
// asserts it matches: hex(sha256(ruleId | componentId | artifactLocation.uri)).
func TestSARIFFingerprintRecipe(t *testing.T) {
	report := mustJSONMap(t, render(t, "sarif", writer.Options{}))
	results := arr(t, obj(t, arr(t, report["runs"])[0])["results"])

	checked := 0
	for _, r := range results {
		res := obj(t, r)
		ruleID := str(t, res["ruleId"])
		if strings.HasPrefix(ruleID, "risk/") || strings.HasPrefix(ruleID, "cve/") || strings.HasPrefix(ruleID, "eol/") {
			continue // security findings are not component-identity fingerprinted
		}
		compID := str(t, obj(t, res["properties"])["airom:componentId"])
		loc := obj(t, arr(t, res["locations"])[0])
		uri := str(t, obj(t, obj(t, loc["physicalLocation"])["artifactLocation"])["uri"])

		sum := sha256.Sum256([]byte(ruleID + "|" + compID + "|" + uri))
		want := hex.EncodeToString(sum[:])
		got := str(t, obj(t, res["partialFingerprints"])[fingerprintKey])
		if got != want {
			t.Errorf("fingerprint for (%s,%s,%s) = %s, want %s", ruleID, compID, uri, got, want)
		}
		checked++
	}
	if checked == 0 {
		t.Fatal("no results to check the fingerprint recipe against")
	}
	t.Logf("verified §7.2 fingerprint recipe on all %d results", checked)
}
