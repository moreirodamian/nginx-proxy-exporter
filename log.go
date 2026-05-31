package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os"
	"time"
)

// logEntry is a generic representation of one parsed nginx log line.
// Field names are resolved through the LogFieldsConfig mapping so the
// exporter doesn't hard-code the user's log_format.
type logEntry struct {
	ServerName    string
	RequestURI    string
	RequestMethod string
	Status        string
	RequestTime   string
	UpstreamTime  string
	BodyBytesSent string
	BytesSent     string
	UserAgent     string
	UAClass       string
	SSLProtocol   string
	HTTPProtocol  string
}

// parseLine decodes one JSON line into a generic map, then projects it onto
// logEntry using the user-configured field names. Unknown fields are ignored.
func parseLine(line []byte, fields LogFieldsConfig) (*logEntry, error) {
	var raw map[string]string
	if err := json.Unmarshal(line, &raw); err != nil {
		// Some log_format definitions emit numeric values (e.g. "status": 200).
		// Try a permissive decode.
		var loose map[string]interface{}
		if err2 := json.Unmarshal(line, &loose); err2 != nil {
			return nil, err
		}
		raw = make(map[string]string, len(loose))
		for k, v := range loose {
			raw[k] = fmt.Sprintf("%v", v)
		}
	}

	get := func(name string) string {
		if name == "" {
			return ""
		}
		return raw[name]
	}

	return &logEntry{
		ServerName:    get(fields.ServerName),
		RequestURI:    get(fields.RequestURI),
		RequestMethod: get(fields.RequestMethod),
		Status:        get(fields.Status),
		RequestTime:   get(fields.RequestTime),
		UpstreamTime:  get(fields.UpstreamResponseTime),
		BodyBytesSent: get(fields.BodyBytesSent),
		BytesSent:     get(fields.BytesSent),
		UserAgent:     get(fields.UserAgent),
		UAClass:       get(fields.UAClass),
		SSLProtocol:   get(fields.SSLProtocol),
		HTTPProtocol:  get(fields.HTTPProtocol),
	}, nil
}

type lineProcessor interface {
	processLine(line []byte)
}

// tailer follows a log file, handling rotation and truncation.
type tailer struct {
	path string
	proc lineProcessor
}

func newTailer(path string, proc lineProcessor) *tailer {
	return &tailer{path: path, proc: proc}
}

func (t *tailer) run() {
	for {
		if err := t.followFile(); err != nil {
			log.Printf("tail: %v, retrying in 1s", err)
			time.Sleep(time.Second)
		}
	}
}

func (t *tailer) followFile() error {
	f, err := os.Open(t.path)
	if err != nil {
		return fmt.Errorf("open: %w", err)
	}
	defer f.Close()

	if _, err := f.Seek(0, io.SeekEnd); err != nil {
		return fmt.Errorf("seek: %w", err)
	}

	fi, _ := f.Stat()
	lastSize := fi.Size()
	lastIno := fileIno(fi)
	reader := bufio.NewReaderSize(f, 64*1024)

	for {
		line, err := reader.ReadBytes('\n')
		if err != nil {
			if err != io.EOF {
				return fmt.Errorf("read: %w", err)
			}
			newFi, statErr := os.Stat(t.path)
			if statErr != nil {
				return fmt.Errorf("stat: %w", statErr)
			}
			if fileIno(newFi) != lastIno {
				return fmt.Errorf("file rotated")
			}
			if newFi.Size() < lastSize {
				f.Seek(0, io.SeekStart)
				reader.Reset(f)
				lastSize = 0
				continue
			}
			lastSize = newFi.Size()
			time.Sleep(100 * time.Millisecond)
			continue
		}
		if len(line) > 1 {
			t.proc.processLine(line)
		}
	}
}
