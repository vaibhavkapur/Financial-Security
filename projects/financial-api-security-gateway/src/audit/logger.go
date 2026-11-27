package audit

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"

	"github.com/financial-security/financial-api-security-gateway/src/domain"
)

// Sink defines the audit event persistence boundary.
type Sink interface {
	Write(event domain.AuditEvent) error
}

// MemorySink retains audit events in memory for tests and inspection.
type MemorySink struct {
	mu     sync.RWMutex
	events []domain.AuditEvent
}

func NewMemorySink() *MemorySink {
	return &MemorySink{}
}

func (s *MemorySink) Write(ev domain.AuditEvent) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.events = append(s.events, ev)
	return nil
}

func (s *MemorySink) Events() []domain.AuditEvent {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]domain.AuditEvent, len(s.events))
	copy(out, s.events)
	return out
}

// JSONLSink appends newline-delimited JSON audit events to a file.
type JSONLSink struct {
	mu   sync.Mutex
	file *os.File
}

func NewJSONLSink(path string) (*JSONLSink, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, fmt.Errorf("create audit log dir: %w", err)
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
	if err != nil {
		return nil, fmt.Errorf("open audit log %q: %w", path, err)
	}
	return &JSONLSink{file: f}, nil
}

func (s *JSONLSink) Write(ev domain.AuditEvent) error {
	line, err := json.Marshal(ev)
	if err != nil {
		return err
	}
	line = append(line, '\n')
	s.mu.Lock()
	defer s.mu.Unlock()
	_, err = s.file.Write(line)
	return err
}

func (s *JSONLSink) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.file != nil {
		return s.file.Close()
	}
	return nil
}

// MultiSink fans out audit events to multiple sinks.
type MultiSink struct {
	sinks []Sink
}

func NewMultiSink(sinks ...Sink) *MultiSink {
	return &MultiSink{sinks: sinks}
}

func (m *MultiSink) Write(ev domain.AuditEvent) error {
	for _, s := range m.sinks {
		if s == nil {
			continue
		}
		if err := s.Write(ev); err != nil {
			return err
		}
	}
	return nil
}

// Logger formats, redacts, assigns stable event IDs, and dispatches audit events.
type Logger struct {
	redactor *Redactor
	sink     Sink
	seq      atomic.Uint64
}

func NewLogger(redactor *Redactor, sink Sink) *Logger {
	if redactor == nil {
		redactor = NewRedactor(nil, nil)
	}
	if sink == nil {
		sink = NewMemorySink()
	}
	return &Logger{
		redactor: redactor,
		sink:     sink,
	}
}

// Log sanitizes and writes an AuditEvent, guaranteeing no raw secrets enter the sink.
func (l *Logger) Log(ev domain.AuditEvent, rawHeaders map[string][]string) (domain.AuditEvent, error) {
	seq := l.seq.Add(1)
	if ev.EventID == "" {
		ev.EventID = fmt.Sprintf("aud-%06d", seq)
	}
	ev.SchemaVersion = domain.SchemaVersion

	redactedHdrs, nHdr := l.redactor.RedactHeaders(rawHeaders)
	cleanMsg, nMsg := l.redactor.RedactString(ev.Message)
	cleanPath, nPath := l.redactor.RedactString(ev.Path)

	ev.RedactedHeaders = redactedHdrs
	ev.Message = cleanMsg
	ev.Path = cleanPath
	ev.RedactedCount = nHdr + nMsg + nPath

	if err := l.sink.Write(ev); err != nil {
		return ev, err
	}
	return ev, nil
}
