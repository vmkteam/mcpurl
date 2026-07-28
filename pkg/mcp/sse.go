package mcp

import (
	"bufio"
	"bytes"
	"errors"
	"io"
)

// Event is a single server-sent event. The "event:" name field is ignored —
// it is irrelevant for MCP (03-transport.md).
type Event struct {
	ID   string // last seen "id:" field value
	Data []byte // "data:" lines joined with \n, no trailing newline
}

// sseReader parses a text/event-stream body per the WHATWG EventSource
// format: data/id/event/retry fields, ":" comments, blank-line event
// terminator, CRLF tolerance.
type sseReader struct {
	r      *bufio.Reader
	lastID string
}

func newSSEReader(r io.Reader) *sseReader {
	// 8 KB: a reader is allocated per POST response; ReadBytes accumulates
	// longer lines anyway, so a big buffer only costs garbage.
	return &sseReader{r: bufio.NewReaderSize(r, 8*1024)}
}

// Next returns the next event with non-empty data. It returns io.EOF when the
// stream ends; a trailing event without a blank-line terminator is still
// delivered before EOF.
func (s *sseReader) Next() (Event, error) {
	var (
		data  bytes.Buffer
		found bool
	)
	for {
		line, err := s.readLine()
		if err != nil {
			if errors.Is(err, io.EOF) && found {
				return Event{ID: s.lastID, Data: data.Bytes()}, nil
			}
			return Event{}, err
		}
		if len(line) == 0 { // event boundary
			if !found {
				continue // empty event: nothing dispatched
			}
			return Event{ID: s.lastID, Data: data.Bytes()}, nil
		}
		if line[0] == ':' { // comment / keep-alive
			continue
		}
		field, value := splitField(line)
		switch string(field) { // no alloc: compiler optimizes switch string([]byte)
		case "data":
			if found {
				data.WriteByte('\n')
			}
			data.Write(value)
			found = true
		case "id":
			if !bytes.ContainsRune(value, 0) {
				s.lastID = string(value)
			}
		case "event", "retry":
			// event names are irrelevant for MCP; the bridge uses its own
			// reconnect backoff instead of retry hints
		}
	}
}

// readLine reads one line of any length, stripping \n and a trailing \r.
func (s *sseReader) readLine() ([]byte, error) {
	line, err := s.r.ReadBytes('\n')
	if errors.Is(err, io.EOF) && len(line) > 0 {
		err = nil
	}
	if err != nil {
		return nil, err
	}
	return trimEOL(line), nil
}

func trimEOL(b []byte) []byte {
	b = bytes.TrimSuffix(b, []byte("\n"))
	return bytes.TrimSuffix(b, []byte("\r"))
}

// splitField returns sub-slices of line — no copies; the payload is copied
// exactly once, into the event's data buffer.
func splitField(line []byte) (field, value []byte) {
	i := bytes.IndexByte(line, ':')
	if i < 0 {
		return line, nil
	}
	value = line[i+1:]
	if len(value) > 0 && value[0] == ' ' { // single leading space is stripped
		value = value[1:]
	}
	return line[:i], value
}
