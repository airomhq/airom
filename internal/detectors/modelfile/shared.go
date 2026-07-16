package modelfile

import "encoding/binary"

// Safety caps. Every one of these bounds an allocation or a loop against an
// attacker-controlled length field parsed out of an untrusted header (§13):
// the parsers here must never allocate proportional to a claimed size, and
// must never spin on a hostile count. The content buffer itself is already
// bounded by the engine's single capped read, so these are a second, parser-
// local line of defense.
const (
	// maxGGUFKV caps the number of GGUF metadata key/value pairs parsed,
	// regardless of the file's declared metadata_kv_count.
	maxGGUFKV = 4096
	// maxGGUFArrayElems caps how many elements of one GGUF array value are
	// walked before the parse gives up on that value.
	maxGGUFArrayElems = 1 << 20
	// maxKeyLen caps a single GGUF metadata key length.
	maxKeyLen = 1 << 16
	// maxStringLen caps a single GGUF string value length.
	maxStringLen = 1 << 24
	// maxSafetensorsHeader caps the safetensors JSON header length (100 MiB).
	maxSafetensorsHeader = 100 << 20
	// maxSafetensorsTensors caps how many tensor entries are summed.
	maxSafetensorsTensors = 1 << 20
	// maxProtobufFields caps the number of top-level protobuf fields walked
	// in an ONNX sniff.
	maxProtobufFields = 1 << 16
	// maxVarintBytes is the ceiling on a base-128 varint (a 64-bit value).
	maxVarintBytes = 10
)

// cursor is a bounds-checked, little-endian read cursor over an in-memory
// byte slice. Every accessor reports success with a bool and never panics on
// a short buffer — the whole point is that hostile, truncated headers dead-
// end in an ok==false, not an out-of-range slice.
type cursor struct {
	b   []byte
	pos int
}

// rem returns the number of unread bytes. It is always >= 0: the cursor only
// advances past bytes it has verified are present.
func (c *cursor) rem() int { return len(c.b) - c.pos }

// u32 reads a little-endian uint32.
func (c *cursor) u32() (uint32, bool) {
	if c.rem() < 4 {
		return 0, false
	}
	v := binary.LittleEndian.Uint32(c.b[c.pos:])
	c.pos += 4
	return v, true
}

// u64 reads a little-endian uint64.
func (c *cursor) u64() (uint64, bool) {
	if c.rem() < 8 {
		return 0, false
	}
	v := binary.LittleEndian.Uint64(c.b[c.pos:])
	c.pos += 8
	return v, true
}

// take returns the next n bytes as a subslice, or ok==false if fewer than n
// remain. The result aliases the underlying buffer; callers that retain it
// past the file's lifetime must copy (string(b) does).
func (c *cursor) take(n uint64) ([]byte, bool) {
	rem := c.rem()       // always >= 0: the cursor never advances past verified bytes
	if n > uint64(rem) { // #nosec G115 -- rem is non-negative, so the conversion is exact
		return nil, false
	}
	ni := int(n) // #nosec G115 -- n <= rem <= len(b), so it fits an int
	b := c.b[c.pos : c.pos+ni]
	c.pos += ni
	return b, true
}

// skip advances the cursor by n bytes, or reports false if fewer remain.
func (c *cursor) skip(n uint64) bool {
	_, ok := c.take(n)
	return ok
}

// uvarint reads a protobuf base-128 varint. It consumes at most
// maxVarintBytes and reports false on a truncated or overlong encoding — a
// hostile stream of continuation bytes can never loop it unbounded.
func (c *cursor) uvarint() (uint64, bool) {
	var x uint64
	var s uint
	for i := 0; i < maxVarintBytes; i++ {
		if c.pos >= len(c.b) {
			return 0, false
		}
		b := c.b[c.pos]
		c.pos++
		if b < 0x80 {
			if i == maxVarintBytes-1 && b > 1 {
				return 0, false // 64-bit overflow
			}
			return x | uint64(b)<<s, true
		}
		x |= uint64(b&0x7f) << s
		s += 7
	}
	return 0, false // no terminating byte within the cap
}
