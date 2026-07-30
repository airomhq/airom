package frozen

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"sort"
	"strings"
)

// pyzMagic opens a PYZ archive: "PYZ\0", then the target interpreter's 4-byte
// pyc magic, then a big-endian offset to the marshaled directory.
var pyzMagic = []byte{'P', 'Y', 'Z', 0}

const pyzHeaderLen = 4 + 4 + 4

// PYZModule is one frozen module: where its (compressed) body lives inside the
// PYZ, so a version string can be dug out of it later without inflating the
// whole archive.
type PYZModule struct {
	Name   string
	Offset int64
	Length int64
}

// PYZ is a parsed frozen-module directory.
type PYZ struct {
	PyMagic uint32
	Modules []PYZModule
	byName  map[string]PYZModule
}

// Lookup finds one module by its dotted name.
func (p *PYZ) Lookup(name string) (PYZModule, bool) {
	m, ok := p.byName[name]
	return m, ok
}

// TopLevelPackages returns the distinct first path segment of every module,
// sorted. "crawl4ai.async_webcrawler" and 70 siblings collapse to "crawl4ai".
func (p *PYZ) TopLevelPackages() []string {
	seen := map[string]bool{}
	for _, m := range p.Modules {
		top, _, _ := strings.Cut(m.Name, ".")
		if top != "" {
			seen[top] = true
		}
	}
	out := make([]string, 0, len(seen))
	for k := range seen {
		out = append(out, k)
	}
	sort.Strings(out) // map iteration must not reach the output (P7)
	return out
}

// ParsePYZ reads the directory of a decompressed PYZ archive.
func ParsePYZ(data []byte) (*PYZ, error) {
	if len(data) < pyzHeaderLen || !bytes.HasPrefix(data, pyzMagic) {
		return nil, errors.New("frozen: not a PYZ archive")
	}
	pyMagic := binary.LittleEndian.Uint32(data[4:8])
	tocOff := int64(binary.BigEndian.Uint32(data[8:12]))
	if tocOff < 0 || tocOff >= int64(len(data)) {
		return nil, fmt.Errorf("frozen: PYZ directory offset %d outside a %d-byte archive", tocOff, len(data))
	}

	d := &unmarshaller{buf: data[tocOff:]}
	v, err := d.value(0)
	if err != nil {
		return nil, fmt.Errorf("frozen: PYZ directory: %w", err)
	}
	entries, err := directoryEntries(v)
	if err != nil {
		return nil, err
	}

	p := &PYZ{PyMagic: pyMagic, byName: make(map[string]PYZModule, len(entries))}
	for name, raw := range entries {
		tup, ok := raw.([]any)
		if !ok || len(tup) < 3 {
			continue
		}
		off, ok1 := tup[1].(int64)
		length, ok2 := tup[2].(int64)
		if !ok1 || !ok2 || off < 0 || length < 0 {
			continue
		}
		m := PYZModule{Name: name, Offset: off, Length: length}
		p.Modules = append(p.Modules, m)
		p.byName[name] = m
	}
	if len(p.Modules) == 0 {
		return nil, errors.New("frozen: PYZ directory listed no modules")
	}
	sort.Slice(p.Modules, func(i, j int) bool { return p.Modules[i].Name < p.Modules[j].Name })
	return p, nil
}

// directoryEntries normalizes the two shapes a PYZ directory takes.
//
// PyInstaller writes a LIST of (name, (typecode, offset, length)) pairs —
// verified against a 6.21 build — while older writers and most descriptions of
// the format use a dict keyed by name. Both are accepted, because reading only
// the documented shape is what made this parser return nothing for every real
// binary while passing a fixture that shared its assumption.
func directoryEntries(v any) (map[string]any, error) {
	switch t := v.(type) {
	case map[string]any:
		return t, nil
	case []any:
		out := make(map[string]any, len(t))
		for _, item := range t {
			pair, ok := item.([]any)
			if !ok || len(pair) != 2 {
				continue
			}
			name, ok := pair[0].(string)
			if !ok {
				continue
			}
			out[name] = pair[1]
		}
		if len(out) == 0 {
			return nil, errors.New("frozen: PYZ directory list held no (name, entry) pairs")
		}
		return out, nil
	}
	return nil, fmt.Errorf("frozen: PYZ directory is a %T, want a list or dict", v)
}

// ── A minimal, deliberately incomplete marshal reader ──────────────────────
//
// Only what a PYZ directory can contain is decoded: a dict of string →
// (int, int, int) tuples, plus the reference machinery those share. Every other
// type — above all TYPE_CODE — is refused rather than parsed.
//
// That is not laziness. marshal.loads on untrusted bytes is a documented
// code-execution surface in Python, and the reason this reader exists in Go at
// all is to never hand a frozen binary's bytes to an interpreter. Refusing the
// types we do not need is the property, not a limitation of it.

const (
	mTypeNull       = '0'
	mTypeNone       = 'N'
	mTypeFalse      = 'F'
	mTypeTrue       = 'T'
	mTypeInt        = 'i'
	mTypeDict       = '{'
	mTypeTuple      = '('
	mTypeSmallTuple = ')'
	mTypeList       = '['
	mTypeString     = 's' // bytes
	mTypeInterned   = 't'
	mTypeUnicode    = 'u'
	mTypeASCII      = 'a'
	mTypeASCIIInt   = 'A'
	mTypeShortASCII = 'z'
	mTypeShortAscII = 'Z' // short ascii, interned
	mTypeRef        = 'r'

	// marshalRefFlag marks a value that also enters the reference table.
	marshalRefFlag = 0x80

	// maxMarshalDepth stops a crafted archive from recursing this parser to
	// death. A PYZ directory is two levels deep.
	maxMarshalDepth = 16
)

type unmarshaller struct {
	buf  []byte
	pos  int
	refs []any
}

func (d *unmarshaller) byte() (byte, error) {
	if d.pos >= len(d.buf) {
		return 0, errors.New("truncated")
	}
	b := d.buf[d.pos]
	d.pos++
	return b, nil
}

func (d *unmarshaller) int32() (int32, error) {
	if d.pos+4 > len(d.buf) {
		return 0, errors.New("truncated")
	}
	// #nosec G115 -- marshal's TYPE_INT is a signed int32; callers reject the
	// negatives this can produce (lengths, offsets, and ref indices are all
	// range-checked at their use sites).
	v := int32(binary.LittleEndian.Uint32(d.buf[d.pos:]))
	d.pos += 4
	return v, nil
}

func (d *unmarshaller) bytes(n int32) ([]byte, error) {
	if n < 0 || d.pos+int(n) > len(d.buf) {
		return nil, errors.New("truncated")
	}
	b := d.buf[d.pos : d.pos+int(n)]
	d.pos += int(n)
	return b, nil
}

// value decodes one marshaled object.
func (d *unmarshaller) value(depth int) (any, error) {
	if depth > maxMarshalDepth {
		return nil, errors.New("nesting too deep")
	}
	raw, err := d.byte()
	if err != nil {
		return nil, err
	}
	typ := raw &^ marshalRefFlag
	ref := raw&marshalRefFlag != 0

	// A referenced value reserves its slot BEFORE being decoded, because a
	// container can refer back to itself.
	slot := -1
	if ref {
		d.refs = append(d.refs, nil)
		slot = len(d.refs) - 1
	}
	remember := func(v any) any {
		if slot >= 0 {
			d.refs[slot] = v
		}
		return v
	}

	switch typ {
	case mTypeNull, mTypeNone:
		return remember(nil), nil
	case mTypeTrue:
		return remember(true), nil
	case mTypeFalse:
		return remember(false), nil

	case mTypeInt:
		n, err := d.int32()
		if err != nil {
			return nil, err
		}
		return remember(int64(n)), nil

	case mTypeShortASCII, mTypeShortAscII:
		n, err := d.byte()
		if err != nil {
			return nil, err
		}
		b, err := d.bytes(int32(n))
		if err != nil {
			return nil, err
		}
		return remember(string(b)), nil

	case mTypeString, mTypeInterned, mTypeUnicode, mTypeASCII, mTypeASCIIInt:
		n, err := d.int32()
		if err != nil {
			return nil, err
		}
		b, err := d.bytes(n)
		if err != nil {
			return nil, err
		}
		return remember(string(b)), nil

	case mTypeSmallTuple, mTypeTuple, mTypeList:
		var n int32
		if typ == mTypeSmallTuple {
			b, err := d.byte()
			if err != nil {
				return nil, err
			}
			n = int32(b)
		} else {
			if n, err = d.int32(); err != nil {
				return nil, err
			}
		}
		if n < 0 || int(n) > len(d.buf)-d.pos+1 {
			return nil, errors.New("implausible sequence length")
		}
		seq := make([]any, 0, min(int(n), 1024))
		remember(seq)
		for i := int32(0); i < n; i++ {
			v, err := d.value(depth + 1)
			if err != nil {
				return nil, err
			}
			seq = append(seq, v)
		}
		if slot >= 0 {
			d.refs[slot] = seq
		}
		return seq, nil

	case mTypeDict:
		m := map[string]any{}
		remember(m)
		for {
			k, err := d.value(depth + 1)
			if err != nil {
				return nil, err
			}
			if k == nil { // NULL key terminates a marshaled dict
				return m, nil
			}
			v, err := d.value(depth + 1)
			if err != nil {
				return nil, err
			}
			if ks, ok := k.(string); ok {
				m[ks] = v
			}
			if len(m) > maxEntries {
				return nil, errors.New("dict too large")
			}
		}

	case mTypeRef:
		n, err := d.int32()
		if err != nil {
			return nil, err
		}
		if n < 0 || int(n) >= len(d.refs) {
			return nil, errors.New("reference out of range")
		}
		return d.refs[n], nil

	default:
		// Everything else, TYPE_CODE included. Refused on purpose — see the
		// note above this type table.
		return nil, fmt.Errorf("unsupported marshal type %q", rune(typ))
	}
}
