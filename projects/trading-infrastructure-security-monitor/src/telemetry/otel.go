package telemetry

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"os"
	"sort"
	"time"

	"trading-infrastructure-security-monitor/src/contracts"
)

// OTLPSpan is a deterministic OpenTelemetry-compatible span representation for OTLP/JSON export.
type OTLPSpan struct {
	TraceID           string            `json:"trace_id"`
	SpanID            string            `json:"span_id"`
	ParentSpanID      string            `json:"parent_span_id,omitempty"`
	Name              string            `json:"name"`
	Kind              string            `json:"kind"`
	StartTimeUnixNano int64             `json:"start_time_unix_nano"`
	EndTimeUnixNano   int64             `json:"end_time_unix_nano"`
	Status            string            `json:"status"`
	Attributes        map[string]string `json:"attributes"`
}

// OTLPExport is the versioned OpenTelemetry-compatible telemetry bundle emitted per run.
type OTLPExport struct {
	SchemaVersion string                    `json:"schema_version"`
	Resource      map[string]string         `json:"resource"`
	Spans         []OTLPSpan                `json:"spans"`
	Counters      contracts.DiagnosticMetrics `json:"counters"`
}

// Recorder captures redacted OTLP spans, structured JSON logs, and diagnostic counters.
type Recorder struct {
	serviceName    string
	serviceVersion string
	environment    string
	runID          string
	traceID        string
	redactorFn     func(string) string
	logger         *slog.Logger
	spans          []OTLPSpan
	spanCounter    int
}

func NewRecorder(cfg contracts.MonitorConfig, runID string, redactorFn func(string) string, logWriter io.Writer) *Recorder {
	if logWriter == nil {
		logWriter = io.Discard
	}
	if redactorFn == nil {
		redactorFn = func(s string) string { return s }
	}
	sum := sha256.Sum256([]byte("trace:" + runID))
	traceID := hex.EncodeToString(sum[:16])

	logger := slog.New(slog.NewJSONHandler(logWriter, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	}))

	return &Recorder{
		serviceName:    cfg.OtelServiceName,
		serviceVersion: cfg.OtelServiceVersion,
		environment:    cfg.Environment,
		runID:          runID,
		traceID:        traceID,
		redactorFn:     redactorFn,
		logger:         logger,
		spans:          make([]OTLPSpan, 0),
	}
}

// RecordSpan records a completed span with redacted attribute values.
func (r *Recorder) RecordSpan(name, parentSpanID, status string, start, end time.Time, attrs map[string]string) string {
	r.spanCounter++
	sum := sha256.Sum256([]byte(fmt.Sprintf("%s:%d:%s", r.traceID, r.spanCounter, name)))
	spanID := hex.EncodeToString(sum[:8])

	cleanAttrs := make(map[string]string, len(attrs))
	keys := make([]string, 0, len(attrs))
	for k := range attrs {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		cleanAttrs[k] = r.redactorFn(attrs[k])
	}

	span := OTLPSpan{
		TraceID:           r.traceID,
		SpanID:            spanID,
		ParentSpanID:      parentSpanID,
		Name:              name,
		Kind:              "SPAN_KIND_INTERNAL",
		StartTimeUnixNano: start.UTC().UnixNano(),
		EndTimeUnixNano:   end.UTC().UnixNano(),
		Status:            status,
		Attributes:        cleanAttrs,
	}
	r.spans = append(r.spans, span)

	r.logger.Info("pipeline_span",
		slog.String("run_id", r.runID),
		slog.String("trace_id", r.traceID),
		slog.String("span_id", spanID),
		slog.String("span_name", name),
		slog.String("status", status),
	)
	return spanID
}

// Export builds the OTLP/JSON export payload.
func (r *Recorder) Export(metrics contracts.DiagnosticMetrics) OTLPExport {
	return OTLPExport{
		SchemaVersion: contracts.SchemaVersion,
		Resource: map[string]string{
			"service.name":           r.serviceName,
			"service.version":        r.serviceVersion,
			"deployment.environment": r.environment,
			"tism.run_id":            r.runID,
		},
		Spans:    append([]OTLPSpan{}, r.spans...),
		Counters: metrics,
	}
}

// WriteExport persists the OTLP/JSON payload to disk.
func (r *Recorder) WriteExport(path string, metrics contracts.DiagnosticMetrics) error {
	exp := r.Export(metrics)
	data, err := json.MarshalIndent(exp, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(data, '\n'), 0o644)
}
