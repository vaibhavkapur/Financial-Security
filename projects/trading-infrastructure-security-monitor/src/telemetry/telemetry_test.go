package telemetry

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"trading-infrastructure-security-monitor/src/contracts"
)

func TestRecorderRedactsSpanAttributesAndDeterministicTraceID(t *testing.T) {
	cfg := contracts.MonitorConfig{
		OtelServiceName:    "tism",
		OtelServiceVersion: "1.0.0",
		Environment:        "synthetic-trading-lab",
	}
	redactor := func(s string) string {
		return strings.ReplaceAll(s, "secret-token-123", "[REDACTED]")
	}
	var logBuf bytes.Buffer
	rec1 := NewRecorder(cfg, "RUN-FIXED-01", redactor, &logBuf)
	rec2 := NewRecorder(cfg, "RUN-FIXED-01", redactor, nil)

	ts := time.Date(2026, 6, 1, 10, 0, 0, 0, time.UTC)
	s1 := rec1.RecordSpan("normalize", "", "OK", ts, ts.Add(time.Millisecond), map[string]string{
		"note": "contained secret-token-123 here",
	})
	s2 := rec2.RecordSpan("normalize", "", "OK", ts, ts.Add(time.Millisecond), map[string]string{
		"note": "contained secret-token-123 here",
	})

	if s1 != s2 {
		t.Fatalf("expected deterministic span IDs, got %s vs %s", s1, s2)
	}
	exp := rec1.Export(contracts.DiagnosticMetrics{EventsIngested: 5})
	if strings.Contains(exp.Spans[0].Attributes["note"], "secret-token-123") {
		t.Fatalf("secret leaked into telemetry span attribute: %v", exp.Spans[0].Attributes)
	}
	if !strings.Contains(logBuf.String(), `"span_name":"normalize"`) {
		t.Fatalf("expected structured JSON log output, got: %s", logBuf.String())
	}
}
