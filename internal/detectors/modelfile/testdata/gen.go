// Command gen produces the tiny, handcrafted binary fixtures used by the
// modelfile detector tests. It is deliberately parked under testdata/ so the
// Go toolchain and golangci-lint ignore it; run it by explicit path to
// regenerate the fixtures:
//
//	go run ./internal/detectors/modelfile/testdata/gen.go
//
// The fixtures are header-only: a valid magic/version/metadata block with NO
// tensor payload, which is all a header-only detector reads. None of them
// contain real model weights.
package main

import (
	"bytes"
	"encoding/binary"
	"log"
	"os"
	"path/filepath"
	"runtime"
)

// GGUF metadata value type tags.
const (
	gT_UINT32 = 4
	gT_STRING = 8
	gT_ARRAY  = 9
	gT_UINT64 = 10
)

func main() {
	_, self, _, ok := runtime.Caller(0)
	if !ok {
		log.Fatal("cannot locate gen.go")
	}
	root := filepath.Dir(self) // .../modelfile/testdata

	write(filepath.Join(root, "gguf", "model.gguf"), ggufFixture())
	write(filepath.Join(root, "gguf", "decoy.txt"), decoy())

	write(filepath.Join(root, "safetensors", "model.safetensors"), safetensorsFixture())
	write(filepath.Join(root, "safetensors", "decoy.txt"), decoy())

	write(filepath.Join(root, "onnx", "model.onnx"), onnxFixture())
	write(filepath.Join(root, "onnx", "decoy.txt"), decoy())
}

func decoy() []byte {
	return []byte("this is a plain text file, not a model - the selector must reject it\n")
}

// ── GGUF ────────────────────────────────────────────────────────────────────

func ggufFixture() []byte {
	var b bytes.Buffer
	b.WriteString("GGUF")
	putU32(&b, 3) // version 3
	putU64(&b, 1) // tensor_count (tensor table omitted; header-only)

	// metadata_kv_count
	putU64(&b, 7)

	kvString(&b, "general.architecture", "llama")
	kvString(&b, "general.name", "tinyllama-test")
	kvU32(&b, "general.quantization_version", 2)
	kvU32(&b, "general.file_type", 1) // MOSTLY_F16 -> "F16"
	kvU64(&b, "general.parameter_count", 1234)
	kvArrayU32(&b, "test.ints", []uint32{1, 2, 3})
	kvArrayStr(&b, "test.strs", []string{"a", "bb"})

	return b.Bytes()
}

func ggufString(b *bytes.Buffer, s string) {
	putU64(b, uint64(len(s)))
	b.WriteString(s)
}

func kvString(b *bytes.Buffer, key, val string) {
	ggufString(b, key)
	putU32(b, gT_STRING)
	ggufString(b, val)
}

func kvU32(b *bytes.Buffer, key string, v uint32) {
	ggufString(b, key)
	putU32(b, gT_UINT32)
	putU32(b, v)
}

func kvU64(b *bytes.Buffer, key string, v uint64) {
	ggufString(b, key)
	putU32(b, gT_UINT64)
	putU64(b, v)
}

func kvArrayU32(b *bytes.Buffer, key string, vals []uint32) {
	ggufString(b, key)
	putU32(b, gT_ARRAY)
	putU32(b, gT_UINT32)
	putU64(b, uint64(len(vals)))
	for _, v := range vals {
		putU32(b, v)
	}
}

func kvArrayStr(b *bytes.Buffer, key string, vals []string) {
	ggufString(b, key)
	putU32(b, gT_ARRAY)
	putU32(b, gT_STRING)
	putU64(b, uint64(len(vals)))
	for _, v := range vals {
		ggufString(b, v)
	}
}

// ── safetensors ──────────────────────────────────────────────────────────────

func safetensorsFixture() []byte {
	// Two F16 tensors: weight [4,8]=32 and bias [8]=8 -> 40 params, dtype F16.
	header := `{"__metadata__":{"format":"pt","architecture":"bert"},` +
		`"weight":{"dtype":"F16","shape":[4,8],"data_offsets":[0,64]},` +
		`"bias":{"dtype":"F16","shape":[8],"data_offsets":[64,80]}}`

	var b bytes.Buffer
	putU64(&b, uint64(len(header)))
	b.WriteString(header)
	// Realistic trailing tensor data region (zeros); the detector never reads it.
	b.Write(make([]byte, 80))
	return b.Bytes()
}

// ── ONNX ─────────────────────────────────────────────────────────────────────

func onnxFixture() []byte {
	var b bytes.Buffer
	// field 1 (ir_version, varint) = 7
	pbTag(&b, 1, 0)
	pbVarint(&b, 7)
	// field 2 (producer_name, len) = "airom-test"
	pbTag(&b, 2, 2)
	pbBytes(&b, []byte("airom-test"))
	// field 3 (producer_version, len) = "0.0.1"
	pbTag(&b, 3, 2)
	pbBytes(&b, []byte("0.0.1"))
	// field 7 (graph, message) = { field 2 name = "g" }
	var graph bytes.Buffer
	pbTag(&graph, 2, 2)
	pbBytes(&graph, []byte("g"))
	pbTag(&b, 7, 2)
	pbBytes(&b, graph.Bytes())
	return b.Bytes()
}

func pbTag(b *bytes.Buffer, field, wire uint64) { pbVarint(b, field<<3|wire) }

func pbVarint(b *bytes.Buffer, v uint64) {
	var tmp [binary.MaxVarintLen64]byte
	n := binary.PutUvarint(tmp[:], v)
	b.Write(tmp[:n])
}

func pbBytes(b *bytes.Buffer, p []byte) {
	pbVarint(b, uint64(len(p)))
	b.Write(p)
}

// ── shared helpers ───────────────────────────────────────────────────────────

func putU32(b *bytes.Buffer, v uint32) {
	var tmp [4]byte
	binary.LittleEndian.PutUint32(tmp[:], v)
	b.Write(tmp[:])
}

func putU64(b *bytes.Buffer, v uint64) {
	var tmp [8]byte
	binary.LittleEndian.PutUint64(tmp[:], v)
	b.Write(tmp[:])
}

func write(path string, data []byte) {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		log.Fatalf("mkdir %s: %v", filepath.Dir(path), err)
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		log.Fatalf("write %s: %v", path, err)
	}
	log.Printf("wrote %d bytes to %s", len(data), path)
}
