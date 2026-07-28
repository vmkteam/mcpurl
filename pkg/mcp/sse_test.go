package mcp

import (
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func collectEvents(t *testing.T, in string) []Event {
	t.Helper()
	r := newSSEReader(strings.NewReader(in))
	var evs []Event
	for {
		ev, err := r.Next()
		if errors.Is(err, io.EOF) {
			return evs
		}
		require.NoError(t, err)
		evs = append(evs, ev)
	}
}

func TestSSEParser(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want []Event
	}{
		{
			name: "single event",
			in:   "data: {\"a\":1}\n\n",
			want: []Event{{Data: []byte(`{"a":1}`)}},
		},
		{
			name: "multi-line data joined with LF",
			in:   "data: {\"a\":\ndata: 1}\n\n",
			want: []Event{{Data: []byte("{\"a\":\n1}")}},
		},
		{
			name: "comments and keep-alives ignored",
			in:   ": keep-alive\n\ndata: x\n: mid\ndata: y\n\n",
			want: []Event{{Data: []byte("x\ny")}},
		},
		{
			name: "CRLF line endings",
			in:   "data: one\r\n\r\ndata: two\r\n\r\n",
			want: []Event{{Data: []byte("one")}, {Data: []byte("two")}},
		},
		{
			name: "id tracking carries forward",
			in:   "id: 7\ndata: a\n\ndata: b\n\nid: 9\ndata: c\n\n",
			want: []Event{
				{ID: "7", Data: []byte("a")},
				{ID: "7", Data: []byte("b")},
				{ID: "9", Data: []byte("c")},
			},
		},
		{
			name: "event name field ignored",
			in:   "event: message\ndata: m\n\n",
			want: []Event{{Data: []byte("m")}},
		},
		{
			name: "empty-data events skipped",
			in:   "event: ping\n\ndata: real\n\n",
			want: []Event{{Data: []byte("real")}},
		},
		{
			name: "no trailing blank line before EOF",
			in:   "data: tail",
			want: []Event{{Data: []byte("tail")}},
		},
		{
			name: "no space after colon",
			in:   "data:x\n\n",
			want: []Event{{Data: []byte("x")}},
		},
		{
			name: "retry field ignored",
			in:   "retry: 5000\ndata: r\n\n",
			want: []Event{{Data: []byte("r")}},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := collectEvents(t, tt.in)
			require.Len(t, got, len(tt.want))
			for i := range got {
				assert.Equal(t, string(tt.want[i].Data), string(got[i].Data), "event %d data", i)
				if tt.want[i].ID != "" {
					assert.Equal(t, tt.want[i].ID, got[i].ID, "event %d id", i)
				}
			}
		})
	}
}

func TestSSEParserHugeEvent(t *testing.T) {
	big := strings.Repeat("x", 2<<20) // 2 MB single data line
	evs := collectEvents(t, "data: "+big+"\n\n")
	require.Len(t, evs, 1)
	assert.Len(t, evs[0].Data, len(big))
}

// event split across TCP reads — simulate with a reader that returns one byte
// at a time.
type trickleReader struct{ s string }

func (r *trickleReader) Read(p []byte) (int, error) {
	if len(r.s) == 0 {
		return 0, io.EOF
	}
	p[0] = r.s[0]
	r.s = r.s[1:]
	return 1, nil
}

func TestSSEParserTrickle(t *testing.T) {
	r := newSSEReader(&trickleReader{s: "id: 1\ndata: hello\ndata: world\n\n"})
	ev, err := r.Next()
	require.NoError(t, err)
	assert.Equal(t, "hello\nworld", string(ev.Data))
	assert.Equal(t, "1", ev.ID)
}
