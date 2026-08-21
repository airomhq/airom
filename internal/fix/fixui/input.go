package fixui

import (
	"bufio"
	"io"
	"strconv"
	"strings"
)

// eventKind classifies one decoded terminal event.
type eventKind int

// The events the table reacts to. Everything else decodes to evtNone and is
// discarded rather than guessed at.
const (
	evtNone eventKind = iota
	evtUp
	evtDown
	evtPageUp
	evtPageDown
	evtHome
	evtEnd
	evtActivate // enter / space: fix the selected package
	evtFixAll   // a
	evtQuit     // q / esc / ctrl-c
	evtHelp     // ?
	evtClick    // a mouse press, with Col/Row filled
)

// event is one decoded keystroke or click. Col and Row are 0-based screen
// coordinates and are meaningful only for evtClick.
type event struct {
	Kind eventKind
	Col  int
	Row  int
}

// reader decodes a terminal byte stream into events.
//
// It reads on the caller's goroutine, blocking. That is the point: with no
// background reader there is no read left in flight when the table exits, so
// the shell's next line of input cannot be swallowed by a goroutine nobody can
// cancel.
type reader struct{ br *bufio.Reader }

func newReader(r io.Reader) *reader { return &reader{br: bufio.NewReaderSize(r, 256)} }

// next blocks for the next event. It returns evtQuit on EOF so a closed
// terminal ends the loop the same way `q` does.
func (r *reader) next() event {
	b, err := r.br.ReadByte()
	if err != nil {
		return event{Kind: evtQuit}
	}
	switch b {
	case 0x03, 0x04: // ctrl-c, ctrl-d
		return event{Kind: evtQuit}
	case '\r', '\n', ' ':
		return event{Kind: evtActivate}
	case 'q', 'Q':
		return event{Kind: evtQuit}
	case 'a', 'A':
		return event{Kind: evtFixAll}
	case 'j':
		return event{Kind: evtDown}
	case 'k':
		return event{Kind: evtUp}
	case 'g':
		return event{Kind: evtHome}
	case 'G':
		return event{Kind: evtEnd}
	case '?':
		return event{Kind: evtHelp}
	case 0x1b:
		return r.escape()
	default:
		return event{Kind: evtNone}
	}
}

// escape decodes what follows an ESC. A bare ESC quits; a CSI sequence is
// parsed; anything else is ignored.
//
// The Buffered check is what makes "a bare ESC quits" true rather than
// aspirational. Every escape sequence a terminal sends arrives as one burst, so
// an ESC with nothing behind it in the buffer IS the whole keypress — whereas
// reading ahead for the next byte blocks until the user presses some other key,
// which is not quitting, it is hanging.
func (r *reader) escape() event {
	if r.br.Buffered() == 0 {
		return event{Kind: evtQuit}
	}
	b, err := r.br.ReadByte()
	if err != nil {
		return event{Kind: evtQuit}
	}
	if b != '[' && b != 'O' {
		_ = r.br.UnreadByte()
		return event{Kind: evtQuit} // lone ESC
	}
	params, final, ok := r.csi()
	if !ok {
		return event{Kind: evtNone}
	}
	if strings.HasPrefix(params, "<") {
		return mouseEvent(params[1:], final)
	}
	switch final {
	case 'A':
		return event{Kind: evtUp}
	case 'B':
		return event{Kind: evtDown}
	case 'H':
		return event{Kind: evtHome}
	case 'F':
		return event{Kind: evtEnd}
	case '~':
		switch params {
		case "5":
			return event{Kind: evtPageUp}
		case "6":
			return event{Kind: evtPageDown}
		case "1", "7":
			return event{Kind: evtHome}
		case "4", "8":
			return event{Kind: evtEnd}
		}
	}
	return event{Kind: evtNone}
}

// csi consumes a control sequence's parameter bytes and its final byte, which
// per ECMA-48 is the first byte in [0x40,0x7E]. The cap stops a malformed or
// hostile stream from growing the parameter string without bound.
func (r *reader) csi() (params string, final byte, ok bool) {
	var sb strings.Builder
	for sb.Len() < 32 {
		b, err := r.br.ReadByte()
		if err != nil {
			return "", 0, false
		}
		if b >= 0x40 && b <= 0x7e {
			return sb.String(), b, true
		}
		sb.WriteByte(b)
	}
	return "", 0, false
}

// mouseEvent decodes an SGR mouse report: "<button>;<col>;<row>" with a final
// 'M' (press) or 'm' (release).
//
// Only presses become events, and only from the left button — a release would
// double every click, and the wheel is mapped to scrolling instead. Coordinates
// arrive 1-based and are returned 0-based, matching the row arithmetic the
// table does everywhere else.
func mouseEvent(params string, final byte) event {
	if final != 'M' {
		return event{Kind: evtNone}
	}
	f := strings.Split(params, ";")
	if len(f) != 3 {
		return event{Kind: evtNone}
	}
	btn, err1 := strconv.Atoi(f[0])
	col, err2 := strconv.Atoi(f[1])
	row, err3 := strconv.Atoi(f[2])
	if err1 != nil || err2 != nil || err3 != nil {
		return event{Kind: evtNone}
	}
	switch btn &^ 0x1c { // strip the shift/alt/ctrl modifier bits
	case 0: // left button
		return event{Kind: evtClick, Col: col - 1, Row: row - 1}
	case 64: // wheel up
		return event{Kind: evtUp}
	case 65: // wheel down
		return event{Kind: evtDown}
	default:
		return event{Kind: evtNone}
	}
}
