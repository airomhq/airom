package modelfilex

import (
	"encoding/binary"
	"sort"
	"strconv"
	"strings"
)

// This file implements a STATIC pickle opcode reader. It walks the opcode
// stream to recover the (module, name) operands of GLOBAL / STACK_GLOBAL /
// INST opcodes — the import references a pickle would resolve at load time —
// WITHOUT ever executing, resolving, or importing anything. That static walk
// is the whole point: a malicious PyTorch checkpoint smuggles code execution
// through a pickle GLOBAL such as os.system or subprocess.Popen, and we want
// to surface that as a security signal, never to trigger it.
//
// Safety invariants (docs/ARCHITECTURE.md §13), all covered by FuzzTorchPickle:
//   - Every read is bounds-checked; a short/lying length ends the walk cleanly.
//   - No allocation is proportional to an attacker-controlled length field:
//     string operands are sliced out of the existing buffer (already capped)
//     and only their bytes are copied.
//   - Termination is guaranteed: the cursor advances by at least the one
//     opcode byte each iteration, and an explicit iteration cap backs that up.
//   - Any opcode not in the recognized set stops the walk safely.

const (
	// maxPickleBytes caps how many pickle bytes we walk (and, for zip-form
	// torch files, how many bytes we decompress out of data.pkl) — a defense
	// against decompression bombs and oversized inputs.
	maxPickleBytes = 16 << 20 // 16 MiB
	// maxPickleOps bounds the opcode loop independently of the byte length.
	maxPickleOps = 1 << 20
	// maxMemoEntries caps the memo table so a stream of PUT/MEMOIZE opcodes
	// cannot grow memory without bound (P2). The op loop is already capped, so
	// this is a belt-and-suspenders ceiling.
	maxMemoEntries = 1 << 20
)

// Recognized pickle opcodes. Names and values follow CPython's pickle module.
// We handle enough of the common set to walk real PyTorch state-dict pickles
// end to end; anything outside this set ends the walk (see the default arm).
const (
	opMark            = '('  // 0x28
	opStop            = '.'  // 0x2e
	opPop             = '0'  // 0x30
	opPopMark         = '1'  // 0x31
	opDup             = '2'  // 0x32
	opBinFloat        = 'G'  // 0x47 8-byte float
	opBinInt          = 'J'  // 0x4a 4-byte signed
	opBinInt1         = 'K'  // 0x4b 1-byte unsigned
	opBinInt2         = 'M'  // 0x4d 2-byte unsigned
	opNone            = 'N'  // 0x4e
	opReduce          = 'R'  // 0x52
	opString          = 'S'  // 0x53 newline-terminated
	opBinString       = 'T'  // 0x54 4-byte length + bytes
	opShortBinString  = 'U'  // 0x55 1-byte length + bytes
	opUnicode         = 'V'  // 0x56 newline-terminated
	opBinUnicode      = 'X'  // 0x58 4-byte length + bytes
	opEmptyList       = ']'  // 0x5d
	opAppend          = 'a'  // 0x61
	opBuild           = 'b'  // 0x62
	opGlobal          = 'c'  // 0x63 module\n name\n
	opDict            = 'd'  // 0x64
	opAppends         = 'e'  // 0x65
	opGet             = 'g'  // 0x67 newline-terminated
	opBinGet          = 'h'  // 0x68 1-byte arg
	opInst            = 'i'  // 0x69 module\n class\n
	opLongBinGet      = 'j'  // 0x6a 4-byte arg
	opList            = 'l'  // 0x6c
	opObj             = 'o'  // 0x6f
	opPut             = 'p'  // 0x70 newline-terminated
	opBinPut          = 'q'  // 0x71 1-byte arg
	opLongBinPut      = 'r'  // 0x72 4-byte arg
	opSetItem         = 's'  // 0x73
	opTuple           = 't'  // 0x74
	opSetItems        = 'u'  // 0x75
	opEmptyDict       = '}'  // 0x7d
	opProto           = 0x80 // 1-byte protocol version
	opNewObj          = 0x81
	opExt1            = 0x82 // 1-byte arg
	opExt2            = 0x83 // 2-byte arg
	opExt4            = 0x84 // 4-byte arg
	opTuple1          = 0x85
	opTuple2          = 0x86
	opTuple3          = 0x87
	opNewTrue         = 0x88
	opNewFalse        = 0x89
	opLong1           = 0x8a // 1-byte length + bytes
	opLong4           = 0x8b // 4-byte length + bytes
	opShortBinUnicode = 0x8c // 1-byte length + bytes
	opBinUnicode8     = 0x8d // 8-byte length + bytes
	opBinBytes8       = 0x8e // 8-byte length + bytes
	opEmptySet        = 0x8f
	opAddItems        = 0x90
	opFrozenSet       = 0x91
	opNewObjEx        = 0x92
	opStackGlobal     = 0x93 // pops name, module from the stack
	opMemoize         = 0x94
	opFrame           = 0x95 // 8-byte frame length
	opBinBytes        = 'B'  // 0x42 4-byte length + bytes
	opShortBinBytes   = 0xc4 // 1-byte length + bytes
	opEmptyTuple      = ')'  // 0x29
	opBinPersid       = 'Q'  // 0x51 no operand
)

// pickleGlobals statically walks buf and returns the (module, name) operands
// of every GLOBAL / STACK_GLOBAL / INST opcode it can decode. It never
// executes the pickle. The returned slice preserves encounter order.
//
// STACK_GLOBAL resolution: in protocol 2+ a global is encoded as two string
// pushes (module, then name) immediately followed by STACK_GLOBAL, so we track
// the two most recently pushed strings rather than a full VM stack. But the
// memo table is load-bearing: a checkpoint can memoize its module/name strings
// (MEMOIZE/PUT) and restore them to the top of stack via the GET family
// immediately before STACK_GLOBAL. We therefore track a bounded memo map and
// replay a memoized string through push() on GET, so the two-slot operand
// tracking reflects what a real unpickler would see. Without this, GET
// indirection silently evades the scan (Phase 10 review, modelfile-parsers).
func pickleGlobals(buf []byte) [][2]string {
	if len(buf) > maxPickleBytes {
		buf = buf[:maxPickleBytes]
	}

	var globals [][2]string
	var prev1, prev2 string // two most recently pushed string operands
	push := func(s string) { prev2, prev1 = prev1, s }

	// memo maps a pickle memo index to the string pushed there. MEMOIZE stores
	// the current top of stack at the next sequential index; BINPUT/LONG_BINPUT/
	// PUT store at an explicit index; the GET family restores by index.
	memo := make(map[int]string)
	memoNext := 0
	memoStore := func(idx int, s string) {
		if idx < 0 || len(memo) >= maxMemoEntries {
			return
		}
		memo[idx] = s
	}

	i := 0
	for ops := 0; i < len(buf) && ops < maxPickleOps; ops++ {
		op := buf[i]
		i++

		switch op {
		case opStop:
			return globals

		case opProto, opExt1:
			// 1-byte operand; no memo interaction.
			if i >= len(buf) {
				return globals
			}
			i++

		case opBinGet:
			// 1-byte memo index; restores the memoized string to the stack.
			if i >= len(buf) {
				return globals
			}
			push(memo[int(buf[i])])
			i++

		case opBinPut:
			// 1-byte memo index; memoizes the current top of stack.
			if i >= len(buf) {
				return globals
			}
			memoStore(int(buf[i]), prev1)
			i++

		case opBinInt2, opExt2:
			if i+2 > len(buf) {
				return globals
			}
			i += 2

		case opBinInt, opExt4:
			if i+4 > len(buf) {
				return globals
			}
			i += 4

		case opLongBinGet:
			// 4-byte memo index; restores the memoized string to the stack.
			if i+4 > len(buf) {
				return globals
			}
			push(memo[int(binary.LittleEndian.Uint32(buf[i:]))])
			i += 4

		case opLongBinPut:
			// 4-byte memo index; memoizes the current top of stack.
			if i+4 > len(buf) {
				return globals
			}
			memoStore(int(binary.LittleEndian.Uint32(buf[i:])), prev1)
			i += 4

		case opBinFloat:
			if i+8 > len(buf) {
				return globals
			}
			i += 8

		case opFrame:
			// Frame length is metadata; the frame body is more opcodes, so we
			// skip only the 8-byte length and keep walking.
			if i+8 > len(buf) {
				return globals
			}
			i += 8

		case opGlobal, opInst:
			mod, ni, ok := readLine(buf, i)
			if !ok {
				return globals
			}
			name, nj, ok := readLine(buf, ni)
			if !ok {
				return globals
			}
			i = nj
			globals = append(globals, [2]string{mod, name})

		case opStackGlobal:
			globals = append(globals, [2]string{prev2, prev1})
			prev1, prev2 = "", "" // operands consumed

		case opShortBinUnicode, opShortBinString, opShortBinBytes, opLong1:
			s, ni, ok := readLen1(buf, i)
			if !ok {
				return globals
			}
			i = ni
			push(s)

		case opBinUnicode, opBinString, opBinBytes, opLong4:
			s, ni, ok := readLen4(buf, i)
			if !ok {
				return globals
			}
			i = ni
			push(s)

		case opBinUnicode8, opBinBytes8:
			s, ni, ok := readLen8(buf, i)
			if !ok {
				return globals
			}
			i = ni
			push(s)

		case opString, opUnicode:
			s, ni, ok := readLine(buf, i)
			if !ok {
				return globals
			}
			i = ni
			push(s)

		case opGet:
			// Newline-terminated decimal memo index; restores to the stack.
			line, ni, ok := readLine(buf, i)
			if !ok {
				return globals
			}
			i = ni
			if idx, err := strconv.Atoi(strings.TrimSpace(line)); err == nil {
				push(memo[idx])
			} else {
				push("") // matches unpickler semantics: a value is pushed
			}

		case opPut:
			// Newline-terminated decimal memo index; memoizes the stack top.
			line, ni, ok := readLine(buf, i)
			if !ok {
				return globals
			}
			i = ni
			if idx, err := strconv.Atoi(strings.TrimSpace(line)); err == nil {
				memoStore(idx, prev1)
			}

		case opMemoize:
			// Memoizes the current top of stack at the next sequential index.
			memoStore(memoNext, prev1)
			memoNext++

		// Operand-free opcodes we simply step over. They never sit between a
		// global's two string operands and its STACK_GLOBAL, so leaving prev1
		// and prev2 untouched keeps resolution correct.
		case opMark, opPop, opPopMark, opDup, opNone, opReduce, opBuild,
			opNewTrue, opNewFalse, opEmptyList, opEmptyDict, opEmptyTuple,
			opEmptySet, opAppend, opAppends, opSetItem, opSetItems, opList,
			opDict, opTuple, opTuple1, opTuple2, opTuple3, opNewObj,
			opNewObjEx, opObj, opAddItems, opFrozenSet,
			opBinPersid:
			// no operand

		default:
			// Unknown/unsupported opcode: stop safely rather than guess how
			// many operand bytes to skip.
			return globals
		}
	}
	return globals
}

// readLine returns the bytes from i up to (not including) the next '\n', and
// the index just past that '\n'. ok is false if no terminator is found.
func readLine(buf []byte, i int) (string, int, bool) {
	for j := i; j < len(buf); j++ {
		if buf[j] == '\n' {
			return string(buf[i:j]), j + 1, true
		}
	}
	return "", i, false
}

// readLen1 reads a 1-byte length prefix followed by that many bytes.
func readLen1(buf []byte, i int) (string, int, bool) {
	if i >= len(buf) {
		return "", i, false
	}
	n := int(buf[i]) // 0..255, always in range
	i++
	if n > len(buf)-i {
		return "", i, false
	}
	end := i + n
	return string(buf[i:end]), end, true
}

// readLen4 reads a 4-byte little-endian length prefix followed by that many
// bytes. The length is validated against the remaining buffer BEFORE any
// conversion or slicing, so no allocation tracks the attacker's length field.
func readLen4(buf []byte, i int) (string, int, bool) {
	if i+4 > len(buf) {
		return "", i, false
	}
	n := binary.LittleEndian.Uint32(buf[i:])
	i += 4
	// int64 widening only (uint32 and the non-negative int both fit) — no
	// down-conversion of the attacker-controlled length.
	if int64(n) > int64(len(buf)-i) {
		return "", i, false
	}
	end := i + int(n) // n <= len(buf)-i, so fits int
	return string(buf[i:end]), end, true
}

// readLen8 reads an 8-byte little-endian length prefix followed by that many
// bytes, with the same bounds-before-alloc discipline as readLen4.
func readLen8(buf []byte, i int) (string, int, bool) {
	if i+8 > len(buf) {
		return "", i, false
	}
	n := binary.LittleEndian.Uint64(buf[i:])
	i += 8
	rem := len(buf) - i  // >= 0 (i <= len(buf))
	if n > uint64(rem) { // #nosec G115 -- rem >= 0, so int->uint64 is exact
		return "", i, false
	}
	end := i + int(n) // #nosec G115 -- n <= rem <= len(buf) < 2^31, so it fits int
	return string(buf[i:end]), end, true
}

// suspiciousImports for a pickle's globals reference callables that let a
// checkpoint execute code, spawn processes, open sockets, or import arbitrary
// modules at unpickle time. Populating PickleRisk.Globals with these is a real
// security signal, not a parsing artifact.
var suspiciousExact = map[string]bool{
	"os.system":           true,
	"posix.system":        true,
	"nt.system":           true,
	"builtins.eval":       true,
	"builtins.exec":       true,
	"__builtin__.eval":    true,
	"__builtin__.exec":    true,
	"pty.spawn":           true,
	"pickle.loads":        true,
	"_pickle.loads":       true,
	"cPickle.loads":       true,
	"webbrowser.open":     true,
	"os.popen":            true,
	"posix.popen":         true,
	"builtins.__import__": true,
}

// suspiciousModules flags every callable under these modules (e.g.
// subprocess.Popen, subprocess.call, runpy.run_path, socket.create_connection,
// importlib.import_module).
var suspiciousModules = map[string]bool{
	"subprocess": true,
	"runpy":      true,
	"socket":     true,
	"importlib":  true,
}

func isSuspicious(module, name string) bool {
	if suspiciousModules[module] {
		return true
	}
	return suspiciousExact[module+"."+name]
}

// suspiciousGlobals filters a global list down to the dotted "module.name"
// callables worth flagging, deduplicated and sorted for deterministic output.
func suspiciousGlobals(globals [][2]string) []string {
	seen := map[string]bool{}
	var out []string
	for _, g := range globals {
		if !isSuspicious(g[0], g[1]) {
			continue
		}
		full := g[0] + "." + g[1]
		if !seen[full] {
			seen[full] = true
			out = append(out, full)
		}
	}
	sort.Strings(out)
	return out
}
