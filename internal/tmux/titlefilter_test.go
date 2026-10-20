package tmux

import (
	"bytes"
	"testing"
)

func TestTitleFilter(t *testing.T) {
	tests := []struct {
		name   string
		chunks [][]byte // sequential inputs to Filter()
		want   [][]byte // expected output per chunk (nil = empty/nil)
	}{
		// --- Passthrough (no title sequences) ---
		{"nil input", [][]byte{nil}, [][]byte{nil}},
		{"empty input", [][]byte{{}}, [][]byte{nil}},
		{"plain text", [][]byte{[]byte("hello world")}, [][]byte{[]byte("hello world")}},
		{"CSI passthrough", [][]byte{[]byte("\x1b[31mred\x1b[0m")}, [][]byte{[]byte("\x1b[31mred\x1b[0m")}},
		{"OSC passthrough", [][]byte{[]byte("\x1b]0;title\x07")}, [][]byte{[]byte("\x1b]0;title\x07")}},
		{"ESC then non-k", [][]byte{[]byte("\x1b[Ahello")}, [][]byte{[]byte("\x1b[Ahello")}},

		// --- Single-chunk title stripping ---
		{"complete title", [][]byte{[]byte("\x1bktitle\x1b\\")}, [][]byte{nil}},
		{"empty title", [][]byte{[]byte("\x1bk\x1b\\")}, [][]byte{nil}},
		{"title with surrounding text",
			[][]byte{[]byte("before\x1bktitle\x1b\\after")},
			[][]byte{[]byte("beforeafter")}},
		{"multiple consecutive titles",
			[][]byte{[]byte("\x1bka\x1b\\\x1bkb\x1b\\")},
			[][]byte{nil}},
		{"multiple titles with text between",
			[][]byte{[]byte("\x1bka\x1b\\mid\x1bkb\x1b\\end")},
			[][]byte{[]byte("midend")}},

		// --- Cross-chunk boundaries ---
		{"ESC at chunk boundary",
			[][]byte{[]byte("text\x1b"), []byte("ktitle\x1b\\")},
			[][]byte{[]byte("text"), nil}},
		{"ESC k split across chunks",
			[][]byte{[]byte("\x1bk"), []byte("title\x1b\\")},
			[][]byte{nil, nil}},
		{"ST split across chunks",
			[][]byte{[]byte("\x1bktitle\x1b"), []byte("\\more")},
			[][]byte{nil, []byte("more")}},
		{"title body across 3 chunks",
			[][]byte{[]byte("\x1bk"), []byte("title"), []byte("\x1b\\")},
			[][]byte{nil, nil, nil}},
		{"ESC at end then non-k next chunk",
			[][]byte{[]byte("text\x1b"), []byte("[31m")},
			[][]byte{[]byte("text"), []byte("\x1b[31m")}},

		// --- ESC disambiguation inside title ---
		{"ESC non-backslash inside title",
			[][]byte{[]byte("\x1bktitle\x1bxmore\x1b\\")},
			[][]byte{nil}},
		{"consecutive ESCs before title",
			[][]byte{[]byte("\x1b\x1bktitle\x1b\\")},
			[][]byte{[]byte("\x1b")}},
		{"ESC ESC backslash terminates title",
			[][]byte{[]byte("\x1bkfoo\x1b\x1b\\after")},
			[][]byte{[]byte("after")}},

		// --- Safety valve ---
		{"safety valve flushes on oversized title",
			[][]byte{append([]byte("\x1bk"), bytes.Repeat([]byte("x"), 511)...)},
			[][]byte{append([]byte("\x1bk"), bytes.Repeat([]byte("x"), 511)...)}},
		{"safety valve then normal title",
			[][]byte{
				append([]byte("\x1bk"), bytes.Repeat([]byte("x"), 511)...),
				[]byte("\x1bkshort\x1b\\"),
			},
			[][]byte{
				append([]byte("\x1bk"), bytes.Repeat([]byte("x"), 511)...),
				nil,
			}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := NewTitleFilter()
			for i, chunk := range tt.chunks {
				got := f.Filter(chunk)
				want := tt.want[i]
				if want == nil && len(got) != 0 {
					t.Errorf("chunk %d: got %q, want nil/empty", i, got)
				} else if want != nil && !bytes.Equal(got, want) {
					t.Errorf("chunk %d: got %q, want %q", i, got, want)
				}
			}
		})
	}
}

func TestTitleFilter_Reset(t *testing.T) {
	f := NewTitleFilter()
	// Start a title sequence but don't finish it
	f.Filter([]byte("\x1bkpartial"))
	// Reset should discard buffered state
	f.Reset()
	// Normal text should pass through
	got := f.Filter([]byte("hello"))
	if string(got) != "hello" {
		t.Errorf("after Reset: got %q, want %q", got, "hello")
	}
}

func TestTitleFilter_EscFloodInTitleIsBounded(t *testing.T) {
	const floodLen = 100000
	f := NewTitleFilter()

	input := append([]byte("\x1bk"), bytes.Repeat([]byte{0x1b}, floodLen)...)
	input = append(input, 'x')

	var total int
	for i, b := range input {
		out := f.Filter([]byte{b})
		total += len(out)
		if len(f.titleBuf) > maxTitleLen+1 {
			t.Fatalf("titleBuf len %d exceeds %d after byte %d", len(f.titleBuf), maxTitleLen+1, i)
		}
	}

	// Nothing may be amplified: output never exceeds input, and the buffer
	// was flushed (not retained) once the cap was hit.
	if total > len(input) {
		t.Errorf("output %d bytes exceeds input %d bytes", total, len(input))
	}
	if total+len(f.titleBuf) < len(input)-1 {
		t.Errorf("bytes lost: out=%d buffered=%d input=%d", total, len(f.titleBuf), len(input))
	}
}
