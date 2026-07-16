package modelfilex

import (
	"context"
	"testing"

	"github.com/Roro1727/airom/pkg/airom/detect"
)

// fileFrom builds a *detect.File whose Header and Content both return data,
// with no ReaderAt (mimicking a stream source).
func fileFrom(path string, data []byte) *detect.File {
	header := data
	if len(header) > 32*1024 {
		header = header[:32*1024]
	}
	return detect.NewFile(
		detect.FileRef{Path: path, Size: int64(len(data)), Language: detect.LanguageOf(path)},
		header,
		detect.FileProviders{
			Content: func() ([]byte, bool, error) { return data, false, nil },
		},
	)
}

func TestSavedModelSniff(t *testing.T) {
	valid := []byte{0x08, 0x01, 0x12, 0x02, 0x0a, 0x00} // field1 varint, field2 LEN
	if !looksLikeSavedModel(valid) {
		t.Error("valid SavedModel proto rejected")
	}
	// field 2 present but body length runs past a truncated buffer.
	if !looksLikeSavedModel([]byte{0x12, 0x40, 0x00, 0x01}) {
		t.Error("truncated meta_graph body should still be accepted")
	}
	reject := map[string][]byte{
		"empty":              nil,
		"unknown-field-3":    {0x1a, 0x01, 0x00}, // field 3 LEN
		"field1-wrong-wire":  {0x0a, 0x00},       // field 1 as LEN
		"field2-varint-wire": {0x10, 0x01},       // field 2 as varint
		"random-text":        []byte("hello world this is not a proto"),
		"truncated-tag":      {0xff},
	}
	for name, buf := range reject {
		if looksLikeSavedModel(buf) {
			t.Errorf("%s: accepted, want rejected", name)
		}
	}
}

func TestSavedModelName(t *testing.T) {
	cases := map[string]string{
		"my_model/saved_model.pb":   "my_model",
		"a/b/resnet/saved_model.pb": "resnet",
		"saved_model.pb":            "saved_model.pb", // no parent dir
	}
	for in, want := range cases {
		if got := savedModelName(in); got != want {
			t.Errorf("savedModelName(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestSavedModelDetectSkipsNonProto(t *testing.T) {
	f := fileFrom("bad/saved_model.pb", []byte("clearly not a protobuf"))
	got, err := SavedModel{}.DetectFile(context.Background(), f)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 0 {
		t.Errorf("non-proto saved_model.pb produced %d findings, want 0", len(got))
	}
}

func TestTensorRTHeuristic(t *testing.T) {
	binary := append([]byte("trt\x00engine"), make([]byte, 16)...)
	if !looksLikeTensorRTEngine(binary) {
		t.Error("binary blob rejected")
	}
	if looksLikeTensorRTEngine([]byte("this is just ascii text with a plan ext")) {
		t.Error("plain ASCII text accepted as an engine")
	}
	if looksLikeTensorRTEngine([]byte("short")) {
		t.Error("tiny header accepted")
	}
	if looksLikeTensorRTEngine(nil) {
		t.Error("empty header accepted")
	}
}

func TestTensorRTDetectRejectsText(t *testing.T) {
	// A .engine file whose bytes are plain text must not be flagged.
	f := fileFrom("model.engine", []byte("just a normal text file pretending to be an engine\n"))
	got, err := TensorRT{}.DetectFile(context.Background(), f)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 0 {
		t.Errorf("text .engine produced %d findings, want 0", len(got))
	}
}

func TestTorchLegacyBenign(t *testing.T) {
	// Bare protocol-2 pickle with a benign global -> torch-pickle, conf 0.9.
	buf := []byte{0x80, 0x02, 'c'}
	buf = append(buf, "collections\nOrderedDict\n"...)
	buf = append(buf, '.')

	got, err := Torch{}.DetectFile(context.Background(), fileFrom("m.bin", buf))
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 {
		t.Fatalf("got %d findings, want 1", len(got))
	}
	m := got[0].Claim.Model
	if m == nil || m.Format != "torch-pickle" {
		t.Fatalf("format = %+v, want torch-pickle", m)
	}
	if m.PickleRisk != nil {
		t.Errorf("benign pickle flagged risk: %v", m.PickleRisk)
	}
	if c := got[0].Occurrence.Confidence; c != 0.9 {
		t.Errorf("confidence = %v, want 0.9", c)
	}
}

func TestTorchEvilRaisesConfidence(t *testing.T) {
	buf := []byte{0x80, 0x02, 'c'}
	buf = append(buf, "os\nsystem\n"...)
	buf = append(buf, '.')

	got, err := Torch{}.DetectFile(context.Background(), fileFrom("m.pt", buf))
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 {
		t.Fatalf("got %d findings, want 1", len(got))
	}
	m := got[0].Claim.Model
	if m.PickleRisk == nil || len(m.PickleRisk.Globals) != 1 || m.PickleRisk.Globals[0] != "os.system" {
		t.Fatalf("PickleRisk = %+v, want globals [os.system]", m.PickleRisk)
	}
	if c := got[0].Occurrence.Confidence; c != 0.95 {
		t.Errorf("confidence = %v, want 0.95", c)
	}
}

func TestTorchEmptyContent(t *testing.T) {
	got, err := Torch{}.DetectFile(context.Background(), fileFrom("m.pt", nil))
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 0 {
		t.Errorf("empty content produced %d findings, want 0", len(got))
	}
}
