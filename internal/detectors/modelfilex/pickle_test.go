package modelfilex

import (
	"reflect"
	"strconv"
	"testing"
)

func shortStr(s string) []byte { return append([]byte{0x8c, byte(len(s))}, s...) }

func TestPickleGlobalsGlobalOpcode(t *testing.T) {
	// PROTO 2, GLOBAL os system, STOP.
	buf := []byte{0x80, 0x02, 'c'}
	buf = append(buf, "os\nsystem\n"...)
	buf = append(buf, '.')

	got := pickleGlobals(buf)
	want := [][2]string{{"os", "system"}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("globals = %v, want %v", got, want)
	}
	if risky := suspiciousGlobals(got); len(risky) != 1 || risky[0] != "os.system" {
		t.Fatalf("suspicious = %v, want [os.system]", risky)
	}
}

func TestPickleGlobalsStackGlobal(t *testing.T) {
	// PROTO 4, FRAME, SHORT_BINUNICODE posix, SHORT_BINUNICODE system,
	// STACK_GLOBAL, MEMOIZE, STOP — the modern encoding of os.system.
	var buf []byte
	buf = append(buf, 0x80, 0x04)
	buf = append(buf, 0x95)
	buf = append(buf, make([]byte, 8)...)
	buf = append(buf, shortStr("posix")...)
	buf = append(buf, shortStr("system")...)
	buf = append(buf, 0x93, 0x94, '.')

	got := pickleGlobals(buf)
	want := [][2]string{{"posix", "system"}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("globals = %v, want %v", got, want)
	}
	if risky := suspiciousGlobals(got); len(risky) != 1 || risky[0] != "posix.system" {
		t.Fatalf("suspicious = %v, want [posix.system]", risky)
	}
}

func TestPickleGlobalsMemoizeBetweenOperands(t *testing.T) {
	// A pickler may MEMOIZE each string before STACK_GLOBAL; because MEMOIZE
	// pushes nothing, prev1/prev2 tracking must still resolve correctly.
	var buf []byte
	buf = append(buf, 0x80, 0x04)
	buf = append(buf, shortStr("subprocess")...)
	buf = append(buf, 0x94) // MEMOIZE
	buf = append(buf, shortStr("Popen")...)
	buf = append(buf, 0x94) // MEMOIZE
	buf = append(buf, 0x93, '.')

	got := pickleGlobals(buf)
	want := [][2]string{{"subprocess", "Popen"}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("globals = %v, want %v", got, want)
	}
	if risky := suspiciousGlobals(got); len(risky) != 1 || risky[0] != "subprocess.Popen" {
		t.Fatalf("suspicious = %v, want [subprocess.Popen]", risky)
	}
}

func TestPickleGlobalsMemoGetRestore(t *testing.T) {
	// The GET family (BINGET/LONG_BINGET/GET) restores a memoized value to the
	// top of stack. A checkpoint can memoize its module/name strings, push
	// decoys, then restore the real operands via GET immediately before
	// STACK_GLOBAL — evading two-slot tracking unless the memo table is
	// modeled. All three GET spellings must resolve subprocess.Popen.
	// (Phase 10 review, modelfile-parsers finding.)
	cases := []struct {
		name string
		get  func(idx byte) []byte
	}{
		{"BINGET", func(idx byte) []byte { return []byte{0x68, idx} }},
		{"LONG_BINGET", func(idx byte) []byte { return []byte{0x6a, idx, 0, 0, 0} }},
		{"GET", func(idx byte) []byte { return append([]byte{'g'}, append([]byte(strconv.Itoa(int(idx))), '\n')...) }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var buf []byte
			buf = append(buf, 0x80, 0x04)
			buf = append(buf, shortStr("subprocess")...)
			buf = append(buf, 0x94) // MEMOIZE -> memo[0]
			buf = append(buf, shortStr("Popen")...)
			buf = append(buf, 0x94) // MEMOIZE -> memo[1]
			buf = append(buf, shortStr("x")...)
			buf = append(buf, shortStr("y")...)
			buf = append(buf, tc.get(0)...) // restore memo[0] = subprocess
			buf = append(buf, tc.get(1)...) // restore memo[1] = Popen
			buf = append(buf, 0x93, '.')    // STACK_GLOBAL, STOP

			got := pickleGlobals(buf)
			want := [][2]string{{"subprocess", "Popen"}}
			if !reflect.DeepEqual(got, want) {
				t.Fatalf("globals = %v, want %v", got, want)
			}
			if risky := suspiciousGlobals(got); len(risky) != 1 || risky[0] != "subprocess.Popen" {
				t.Fatalf("suspicious = %v, want [subprocess.Popen]", risky)
			}
		})
	}
}

func TestPickleGlobalsBenign(t *testing.T) {
	var buf []byte
	buf = append(buf, 0x80, 0x04)
	buf = append(buf, shortStr("collections")...)
	buf = append(buf, shortStr("OrderedDict")...)
	buf = append(buf, 0x93, '.')

	if risky := suspiciousGlobals(pickleGlobals(buf)); len(risky) != 0 {
		t.Fatalf("benign pickle flagged: %v", risky)
	}
}

func TestPickleGlobalsMultipleDedupSorted(t *testing.T) {
	// Two GLOBAL os.system references plus subprocess.call — output must be
	// deduplicated and sorted.
	var buf []byte
	buf = append(buf, 0x80, 0x02)
	buf = append(buf, 'c')
	buf = append(buf, "os\nsystem\n"...)
	buf = append(buf, 'c')
	buf = append(buf, "subprocess\ncall\n"...)
	buf = append(buf, 'c')
	buf = append(buf, "os\nsystem\n"...)
	buf = append(buf, '.')

	risky := suspiciousGlobals(pickleGlobals(buf))
	want := []string{"os.system", "subprocess.call"}
	if !reflect.DeepEqual(risky, want) {
		t.Fatalf("suspicious = %v, want %v", risky, want)
	}
}

func TestPickleGlobalsUnknownOpcodeStopsSafely(t *testing.T) {
	// A byte we do not model (0xff) must halt the walk without panic, keeping
	// globals found before it.
	var buf []byte
	buf = append(buf, 'c')
	buf = append(buf, "os\nsystem\n"...)
	buf = append(buf, 0xff) // unknown
	buf = append(buf, 'c')
	buf = append(buf, "socket\nsocket\n"...) // never reached

	got := pickleGlobals(buf)
	want := [][2]string{{"os", "system"}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("globals = %v, want %v (walk should stop at unknown opcode)", got, want)
	}
}

func TestPickleGlobalsTruncatedOperands(t *testing.T) {
	cases := map[string][]byte{
		"global-no-newline":       {'c', 'o', 's'},
		"global-name-truncated":   append([]byte{'c'}, "os\nsys"...),
		"short-unicode-past-end":  {0x8c, 0x40, 'a', 'b'}, // claims 64 bytes, has 2
		"binunicode4-past-end":    {0x58, 0xff, 0xff, 0xff, 0x7f, 'a'},
		"binunicode8-past-end":    {0x8d, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f},
		"frame-truncated":         {0x95, 0x00, 0x00},
		"proto-truncated":         {0x80},
		"stackglobal-empty-stack": {0x93, '.'},
		"empty":                   nil,
	}
	for name, buf := range cases {
		t.Run(name, func(_ *testing.T) {
			// Must not panic and must terminate.
			_ = pickleGlobals(buf)
		})
	}
}

func TestSuspiciousMatchers(t *testing.T) {
	suspicious := [][2]string{
		{"os", "system"},
		{"posix", "system"},
		{"nt", "system"},
		{"subprocess", "Popen"},
		{"subprocess", "check_output"},
		{"runpy", "run_path"},
		{"socket", "create_connection"},
		{"importlib", "import_module"},
		{"builtins", "eval"},
		{"__builtin__", "exec"},
		{"pty", "spawn"},
		{"pickle", "loads"},
	}
	for _, g := range suspicious {
		if !isSuspicious(g[0], g[1]) {
			t.Errorf("isSuspicious(%q,%q) = false, want true", g[0], g[1])
		}
	}
	benign := [][2]string{
		{"collections", "OrderedDict"},
		{"torch", "FloatStorage"},
		{"torch._utils", "_rebuild_tensor_v2"},
		{"numpy.core.multiarray", "_reconstruct"},
		{"os", "getcwd"},
		{"builtins", "list"},
	}
	for _, g := range benign {
		if isSuspicious(g[0], g[1]) {
			t.Errorf("isSuspicious(%q,%q) = true, want false", g[0], g[1])
		}
	}
}
