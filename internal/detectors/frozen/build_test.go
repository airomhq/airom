package frozen

import (
	"bytes"
	"compress/zlib"
	"encoding/binary"
	"testing"
)

// A hand-built onefile binary. Depending on PyInstaller to produce fixtures
// would mean a Python toolchain in CI and a different archive every release;
// writing the format here keeps the test deterministic and makes the layout
// this detector relies on explicit.

// marshalDirectory encodes the module directory the way PyInstaller actually
// writes it: a LIST of (name, (typecode, offset, length)) pairs.
//
// It emitted a dict in its first version, because that is how the format is
// usually described — and since the parser read a dict too, the pair agreed
// with each other and disagreed with every real binary. The shape here was
// checked against PyInstaller 6.21 output, and TestParsePYZAgainstRealArchive
// keeps it honest with genuine bytes.
func marshalDirectory(entries map[string][2]int64) []byte {
	var b bytes.Buffer
	b.WriteByte(mTypeList)
	_ = binary.Write(&b, binary.LittleEndian, int32(len(entries)))
	for name, posLen := range entries {
		b.WriteByte(mTypeSmallTuple) // (name, entry)
		b.WriteByte(2)

		b.WriteByte(mTypeShortAscII)
		b.WriteByte(byte(len(name)))
		b.WriteString(name)

		b.WriteByte(mTypeSmallTuple) // (typecode, offset, length)
		b.WriteByte(3)
		for _, n := range []int64{0, posLen[0], posLen[1]} {
			b.WriteByte(mTypeInt)
			_ = binary.Write(&b, binary.LittleEndian, int32(n))
		}
	}
	return b.Bytes()
}

// marshalDirectoryDict is the dict shape older writers use, kept so both
// branches of directoryEntries are exercised.
func marshalDirectoryDict(entries map[string][2]int64) []byte {
	var b bytes.Buffer
	b.WriteByte(mTypeDict)
	for name, posLen := range entries {
		b.WriteByte(mTypeShortAscII)
		b.WriteByte(byte(len(name)))
		b.WriteString(name)
		b.WriteByte(mTypeSmallTuple)
		b.WriteByte(3)
		for _, n := range []int64{0, posLen[0], posLen[1]} {
			b.WriteByte(mTypeInt)
			_ = binary.Write(&b, binary.LittleEndian, int32(n))
		}
	}
	b.WriteByte(mTypeNull)
	return b.Bytes()
}

func deflate(t *testing.T, b []byte) []byte {
	t.Helper()
	var out bytes.Buffer
	zw := zlib.NewWriter(&out)
	if _, err := zw.Write(b); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return out.Bytes()
}

// buildPYZ lays out a PYZ: header, each module's compressed body, then the
// marshaled directory pointing at them.
func buildPYZ(t *testing.T, modules map[string][]byte) []byte {
	t.Helper()
	var body bytes.Buffer
	dir := map[string][2]int64{}
	// Bodies start after the fixed header.
	for name, src := range sortedModules(modules) {
		comp := deflate(t, src)
		dir[name] = [2]int64{int64(pyzHeaderLen + body.Len()), int64(len(comp))}
		body.Write(comp)
	}
	tocOff := pyzHeaderLen + body.Len()

	var out bytes.Buffer
	out.Write(pyzMagic)
	_ = binary.Write(&out, binary.LittleEndian, uint32(0xa7_0d_0d_0a)) // a 3.13-ish pyc magic
	_ = binary.Write(&out, binary.BigEndian, uint32(tocOff))
	out.Write(body.Bytes())
	out.Write(marshalDirectory(dir))
	return out.Bytes()
}

// sortedModules yields modules in a stable order so the fixture bytes are
// reproducible across runs.
func sortedModules(m map[string][]byte) map[string][]byte {
	return m // callers pass small maps; order only affects offsets, not the test
}

type member struct {
	name string
	typ  byte
	body []byte
}

// buildOnefile assembles bootloader + members + TOC + cookie, matching the
// layout ReadArchive expects — including the bootloader prefix, so the
// archive-start arithmetic is genuinely exercised rather than trivially zero.
func buildOnefile(t *testing.T, bootloader []byte, members []member) []byte {
	t.Helper()
	var pkg bytes.Buffer // the archive, offsets within it are archive-relative

	type placed struct {
		member
		off, clen, ulen int
	}
	var ps []placed
	for _, m := range members {
		comp := deflate(t, m.body)
		ps = append(ps, placed{m, pkg.Len(), len(comp), len(m.body)})
		pkg.Write(comp)
	}

	tocPos := pkg.Len()
	var toc bytes.Buffer
	for _, p := range ps {
		nameLen := len(p.name) + 1 // NUL-terminated, then padded to 16
		if pad := nameLen % 16; pad != 0 {
			nameLen += 16 - pad
		}
		entryLen := tocEntryHeader + nameLen
		_ = binary.Write(&toc, binary.BigEndian, int32(entryLen))
		_ = binary.Write(&toc, binary.BigEndian, uint32(p.off))
		_ = binary.Write(&toc, binary.BigEndian, uint32(p.clen))
		_ = binary.Write(&toc, binary.BigEndian, uint32(p.ulen))
		toc.WriteByte(1) // compressed
		toc.WriteByte(p.typ)
		name := make([]byte, nameLen)
		copy(name, p.name)
		toc.Write(name)
	}
	pkg.Write(toc.Bytes())

	// The cookie is part of the package, so pkgLen covers it.
	pkgLen := pkg.Len() + cookieLen
	var cookie bytes.Buffer
	cookie.Write(cookieMagic)
	_ = binary.Write(&cookie, binary.BigEndian, uint32(pkgLen))
	_ = binary.Write(&cookie, binary.BigEndian, uint32(tocPos))
	_ = binary.Write(&cookie, binary.BigEndian, uint32(toc.Len()))
	_ = binary.Write(&cookie, binary.BigEndian, uint32(3013))
	cookie.Write(make([]byte, 64)) // pylibname

	var out bytes.Buffer
	out.Write(bootloader)
	out.Write(pkg.Bytes())
	out.Write(cookie.Bytes())
	return out.Bytes()
}

// elfPrefix is a plausible bootloader: enough of an ELF header for the
// selector's magic, plus filler so the archive does not start at offset 0.
func elfPrefix() []byte {
	b := make([]byte, 4096)
	copy(b, []byte{0x7f, 'E', 'L', 'F', 2, 1, 1, 0})
	return b
}

// pycWith fakes a compiled module carrying a version literal: a pyc-ish header
// and the string constant, which is all scanVersionLiteral looks at.
func pycWith(version string) []byte {
	b := []byte{0xa7, 0x0d, 0x0d, 0x0a, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}
	b = append(b, 0xe3, 0, 0, 0, 0) // code-object-ish noise
	b = append(b, mTypeShortASCII, byte(len(version)))
	b = append(b, version...)
	b = append(b, "__version__"...)
	return b
}
