package fixui

import (
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"golang.org/x/term"
)

// ANSI control sequences. Kept as named constants because a bare escape string
// in the middle of a render is unreadable and, when wrong, silently leaves the
// user's terminal in a broken mode.
const (
	altScreenOn  = "\x1b[?1049h" // switch to the alternate buffer
	altScreenOff = "\x1b[?1049l" // ...and back, restoring the scrollback intact
	cursorHide   = "\x1b[?25l"
	cursorShow   = "\x1b[?25h"
	cursorHome   = "\x1b[H"
	clearScreen  = "\x1b[2J"
	clearToEnd   = "\x1b[0J"

	// Mouse reporting: button events only (1000), addressed in SGR form (1006)
	// so coordinates past column 223 still arrive intact. 1000 rather than 1003
	// deliberately — tracking motion would flood the reader for a table that
	// only reacts to clicks, and it disables text selection more aggressively
	// than a user expects.
	mouseOn  = "\x1b[?1000h\x1b[?1006h"
	mouseOff = "\x1b[?1006l\x1b[?1000l"
)

// errNoTTY reports that the process has no controlling terminal to draw on.
var errNoTTY = errors.New("no terminal available")

// screen owns the terminal for the lifetime of the interactive table: the tty
// handle, the saved termios state, and the modes that must be undone.
//
// It prefers /dev/tty over stdin/stderr. Two reasons, both real: the AIBOM may
// be flowing down stdout to a file at the same moment, and a blocking read left
// on os.Stdin would go on to swallow the first keystroke the user typed at
// their shell after quitting. A private handle can simply be closed.
type screen struct {
	in    *os.File
	out   io.Writer
	fd    int
	state *term.State
	own   bool // in was opened here and must be closed
}

// openScreen takes over the terminal. The returned screen must be closed, and
// closing it restores every mode this function set, in reverse order.
func openScreen() (*screen, error) {
	s := &screen{}
	if f, err := os.OpenFile("/dev/tty", os.O_RDWR, 0); err == nil {
		s.in, s.out, s.own = f, f, true
	} else {
		// No /dev/tty (Windows, or a stripped container): fall back to the
		// standard handles, which is only viable when stdin really is a
		// terminal — otherwise there is nobody to click.
		if !term.IsTerminal(int(os.Stdin.Fd())) {
			return nil, errNoTTY
		}
		s.in, s.out = os.Stdin, os.Stderr
	}
	s.fd = int(s.in.Fd())

	state, err := term.MakeRaw(s.fd)
	if err != nil {
		s.closeHandle()
		return nil, fmt.Errorf("take over the terminal: %w", err)
	}
	s.state = state
	fmt.Fprint(s.out, altScreenOn+cursorHide+mouseOn)
	return s, nil
}

// close restores the terminal. Safe to call twice; the second call is a no-op.
func (s *screen) close() {
	if s.state != nil {
		fmt.Fprint(s.out, mouseOff+cursorShow+altScreenOff)
		_ = term.Restore(s.fd, s.state)
		s.state = nil
	}
	s.closeHandle()
}

func (s *screen) closeHandle() {
	if s.own && s.in != nil {
		_ = s.in.Close()
		s.own = false
	}
}

// size reports the current terminal dimensions, falling back to a conventional
// 80x24 when the query fails — a wrong-but-usable frame beats none.
func (s *screen) size() (w, h int) {
	w, h, err := term.GetSize(s.fd)
	if err != nil || w <= 0 || h <= 0 {
		return 80, 24
	}
	return w, h
}

// paint writes one whole frame: home the cursor, clear, draw. Rendering the
// frame as a single write keeps the repaint atomic enough that a fast redraw
// does not tear.
func (s *screen) paint(frame string) {
	fmt.Fprint(s.out, cursorHome+clearScreen+frame+clearToEnd)
}

// Confirm asks a yes/no question on the controlling terminal and reports
// whether the answer was yes. ok is false when there is no terminal to ask on,
// which the caller must treat as "nobody was asked" rather than as "no".
//
// It deliberately uses the same /dev/tty the table does, not os.Stdin. The two
// diverge exactly when it matters: `airom scan . --fix < /dev/null`, or a scan
// whose stdin is a pipe, still has a human at a terminal — and gating on stdin
// there silently skips the revert this package promises, leaving a tree the
// resolver just said is broken. The private handle is also why the read cannot
// swallow input meant for the shell: it is closed here, buffer and all.
//
// Cooked mode, on purpose: the table has already restored the terminal by the
// time anything asks a question, so the user gets line editing and a visible
// answer rather than a raw single-key grab.
func Confirm(prompt string) (yes bool, ok bool) {
	f, err := os.OpenFile("/dev/tty", os.O_RDWR, 0)
	if err != nil {
		if !term.IsTerminal(int(os.Stdin.Fd())) {
			return false, false
		}
		f = os.Stdin
	} else {
		defer func() { _ = f.Close() }()
	}

	fmt.Fprint(f, prompt)

	// Byte at a time, stopping at the newline: a buffered reader would pull in
	// whatever else is queued on the terminal and discard it.
	var answer []byte
	buf := make([]byte, 1)
	for len(answer) < 16 {
		n, err := f.Read(buf)
		if n == 0 || err != nil {
			break
		}
		if buf[0] == '\n' || buf[0] == '\r' {
			break
		}
		answer = append(answer, buf[0])
	}
	return strings.EqualFold(strings.TrimSpace(string(answer)), "y"), true
}
