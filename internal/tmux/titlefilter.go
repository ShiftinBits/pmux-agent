package tmux

import "bytes"

const maxTitleLen = 512

// Title filter states.
const (
	tfPassthrough   = iota // Normal: copying bytes to output
	tfSawEsc               // Saw ESC; waiting to see if next byte is 'k'
	tfInTitle              // Inside ESC k ...; discarding until ESC \
	tfSawEscInTitle        // Inside title, saw ESC; waiting for '\' to end
)

// TitleFilter strips tmux/screen-specific ESC k ... ESC \ (set window
// title) escape sequences from terminal output. These sequences are not
// part of the ANSI standard and are not recognized by xterm.js, which
// renders the title text as visible output.
//
// The filter is stateful to handle sequences that span chunk boundaries.
// All other escape sequences (CSI, OSC, etc.) pass through unmodified.
type TitleFilter struct {
	state    int
	titleBuf []byte // buffered bytes for safety-valve flush
	out      []byte // reusable output buffer
}

// NewTitleFilter returns a TitleFilter in passthrough state.
func NewTitleFilter() *TitleFilter {
	return &TitleFilter{}
}

// Reset clears internal state, returning to passthrough mode.
// Any partially buffered title sequence is discarded.
func (f *TitleFilter) Reset() {
	f.state = tfPassthrough
	f.titleBuf = f.titleBuf[:0]
}

// Filter processes a chunk of terminal output, stripping ESC k ... ESC \
// title sequences. Returns filtered data.
//
// The returned slice is valid only until the next call to Filter.
func (f *TitleFilter) Filter(data []byte) []byte {
	if len(data) == 0 {
		return nil
	}

	f.out = f.out[:0] // reset output, keep backing array
	i := 0

	for i < len(data) {
		switch f.state {
		case tfPassthrough:
			// Fast path: scan for ESC byte using optimized search
			idx := bytes.IndexByte(data[i:], 0x1b)
			if idx < 0 {
				// No ESC in remaining data — bulk copy
				f.out = append(f.out, data[i:]...)
				i = len(data)
			} else {
				// Copy everything before the ESC
				f.out = append(f.out, data[i:i+idx]...)
				i += idx + 1 // consume the ESC
				f.state = tfSawEsc
			}

		case tfSawEsc:
			b := data[i]
			i++
			if b == 'k' {
				// ESC k — start of title sequence
				f.state = tfInTitle
				f.titleBuf = append(f.titleBuf[:0], 0x1b, 'k')
			} else if b == 0x1b {
				// Another ESC — emit the previous ESC, stay in tfSawEsc
				// so this new ESC can potentially start ESC k
				f.out = append(f.out, 0x1b)
			} else {
				// Not a title — emit the buffered ESC + this byte
				f.out = append(f.out, 0x1b, b)
				f.state = tfPassthrough
			}

		case tfInTitle:
			b := data[i]
			i++
			f.titleBuf = append(f.titleBuf, b)
			if b == 0x1b {
				f.state = tfSawEscInTitle
			}
			// Safety valve
			if len(f.titleBuf) > maxTitleLen {
				f.out = append(f.out, f.titleBuf...)
				f.titleBuf = f.titleBuf[:0]
				f.state = tfPassthrough
			}

		case tfSawEscInTitle:
			b := data[i]
			i++
			if b == '\\' {
				// ESC \ (ST) ��� end of title. Discard titleBuf.
				f.titleBuf = f.titleBuf[:0]
				f.state = tfPassthrough
			} else if b == 0x1b {
				// Another ESC — the previous ESC was content in the title,
				// this new ESC might be the start of ST.
				f.titleBuf = append(f.titleBuf, b)
				// stay in tfSawEscInTitle
			} else {
				// Not ST — keep buffering
				f.titleBuf = append(f.titleBuf, b)
				f.state = tfInTitle
				// Safety valve
				if len(f.titleBuf) > maxTitleLen {
					f.out = append(f.out, f.titleBuf...)
					f.titleBuf = f.titleBuf[:0]
					f.state = tfPassthrough
				}
			}
		}
	}

	if len(f.out) == 0 {
		return nil
	}
	return f.out
}
