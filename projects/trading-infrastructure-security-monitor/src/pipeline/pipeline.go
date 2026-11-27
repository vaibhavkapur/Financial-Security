package pipeline

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"time"

	"trading-infrastructure-security-monitor/src/containment"
	"trading-infrastructure-security-monitor/src/contracts"
	"trading-infrastructure-security-monitor/src/correlator"
	"trading-infrastructure-security-monitor/src/detector"
	"trading-infrastructure-security-monitor/src/normalizer"
	"trading-infrastructure-security-monitor/src/rules"
	"trading-infrastructure-security-monitor/src/store"
	"trading-infrastructure-security-monitor/src/telemetry"
)

// Pipeline wires configuration, normalization, deduplication, detection, correlation, containment simulation, and telemetry.
type Pipeline struct {
	Config     contracts.MonitorConfig
	Policy     contracts.SecurityPolicy
	Redaction  contracts.RedactionPolicy
	Rules      []rules.SigmaRule
	Normalizer *normalizer.Normalizer
	Detector   *detector.Engine
	Correlator *correlator.Correlator
	Simulator  *containment.Simulator
	Store      store.EventStore
	LogWriter  io.Writer
	Clock      func() time.Time
}

// LoadFromConfig loads all versioned configuration, policies, and Sigma rules relative to baseDir.
func LoadFromConfig(configPath string, logWriter io.Writer, clock func() time.Time) (*Pipeline, error) {
	cfg, err := contracts.LoadJSONFile[contracts.MonitorConfig](configPath)
	if err != nil {
		return nil, err
	}
	if err := cfg.Validate(); err != nil {
		return nil, err
	}

	baseDir := filepath.Dir(filepath.Dir(configPath))
	if !filepath.IsAbs(cfg.PolicyPath) {
		cfg.PolicyPath = resolvePath(baseDir, cfg.PolicyPath)
	}
	if !filepath.IsAbs(cfg.RedactionPolicyPath) {
		cfg.RedactionPolicyPath = resolvePath(baseDir, cfg.RedactionPolicyPath)
	}
	if !filepath.IsAbs(cfg.RulesDir) {
		cfg.RulesDir = resolvePath(baseDir, cfg.RulesDir)
	}

	policy, err := contracts.LoadJSONFile[contracts.SecurityPolicy](cfg.PolicyPath)
	if err != nil {
		return nil, err
	}
	if err := policy.Validate(); err != nil {
		return nil, err
	}

	redPolicy, err := contracts.LoadJSONFile[contracts.RedactionPolicy](cfg.RedactionPolicyPath)
	if err != nil {
		return nil, err
	}

	sigmaRules, err := rules.LoadRulesDir(cfg.RulesDir)
	if err != nil {
		return nil, err
	}

	return NewPipeline(cfg, policy, redPolicy, sigmaRules, store.NewMemoryStore(), logWriter, clock)
}

func resolvePath(baseDir, rel string) string {
	if _, err := os.Stat(rel); err == nil {
		return rel
	}
	return filepath.Join(baseDir, rel)
}

func NewPipeline(
	cfg contracts.MonitorConfig,
	policy contracts.SecurityPolicy,
	redPolicy contracts.RedactionPolicy,
	sigmaRules []rules.SigmaRule,
	st store.EventStore,
	logWriter io.Writer,
	clock func() time.Time,
) (*Pipeline, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	if clock == nil {
		clock = func() time.Time { return time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC) }
	}
	if st == nil {
		st = store.NewMemoryStore()
	}
	norm, err := normalizer.NewNormalizer(redPolicy, clock)
	if err != nil {
		return nil, err
	}
	det, err := detector.NewEngine(policy, sigmaRules)
	if err != nil {
		return nil, err
	}
	sim, err := containment.NewSimulator(policy)
	if err != nil {
		return nil, err
	}
	return &Pipeline{
		Config:     cfg,
		Policy:     policy,
		Redaction:  redPolicy,
		Rules:      sigmaRules,
		Normalizer: norm,
		Detector:   det,
		Correlator: correlator.NewCorrelator(cfg.CorrelationWindowSec),
		Simulator:  sim,
		Store:      st,
		LogWriter:  logWriter,
		Clock:      clock,
	}, nil
}

// RunResult contains the report, normalized events (for replay), and OTLP telemetry export.
type RunResult struct {
	Report           contracts.RunReport
	NormalizedEvents []contracts.NormalizedEvent
	Telemetry        telemetry.OTLPExport
}

// RunFromJSONL reads a JSONL file of raw events and executes the full monitoring pipeline.
func (p *Pipeline) RunFromJSONL(ctx context.Context, inputPath string) (RunResult, error) {
	rawBytes, err := os.ReadFile(inputPath)
	if err != nil {
		if os.IsNotExist(err) {
			return RunResult{}, fmt.Errorf("%w: input file %s", contracts.ErrMissingConfig, inputPath)
		}
		return RunResult{}, err
	}
	sum := sha256.Sum256(rawBytes)
	inputSHA := hex.EncodeToString(sum[:])

	lines := strings.Split(strings.ReplaceAll(string(rawBytes), "\r\n", "\n"), "\n")
	rawEvents := make([]contracts.RawEvent, 0, len(lines))
	lineNums := make([]int, 0, len(lines))
	parseErrors := make([]contracts.ValidationErrorRecord, 0)

	for idx, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		var ev contracts.RawEvent
		if err := json.Unmarshal([]byte(trimmed), &ev); err != nil {
			parseErrors = append(parseErrors, contracts.ValidationErrorRecord{
				LineNumber: idx + 1,
				Error:      fmt.Sprintf("%v: %v", contracts.ErrValidationFailed, err),
			})
			continue
		}
		rawEvents = append(rawEvents, ev)
		lineNums = append(lineNums, idx+1)
	}

	return p.runRawEvents(ctx, rawEvents, lineNums, parseErrors, inputPath, inputSHA)
}

// RunRawEvents runs the pipeline directly over in-memory RawEvents.
func (p *Pipeline) RunRawEvents(ctx context.Context, rawEvents []contracts.RawEvent) (RunResult, error) {
	lineNums := make([]int, len(rawEvents))
	for i := range rawEvents {
		lineNums[i] = i + 1
	}
	b, _ := json.Marshal(rawEvents)
	sum := sha256.Sum256(b)
	return p.runRawEvents(ctx, rawEvents, lineNums, nil, "in-memory", hex.EncodeToString(sum[:]))
}

// ReplayNormalized executes detection, correlation, and containment simulation from previously normalized events.
func (p *Pipeline) ReplayNormalized(ctx context.Context, events []contracts.NormalizedEvent, inputPath string) (RunResult, error) {
	b, _ := json.Marshal(events)
	sum := sha256.Sum256(b)
	inputSHA := hex.EncodeToString(sum[:])

	metrics := contracts.DiagnosticMetrics{
		EventsIngested:   len(events),
		EventsNormalized: len(events),
	}
	for _, ev := range events {
		metrics.FieldsRedacted += len(ev.RedactedFields)
	}
	return p.runNormalizedStage(ctx, events, nil, metrics, inputPath, inputSHA)
}

func (p *Pipeline) runRawEvents(
	ctx context.Context,
	rawEvents []contracts.RawEvent,
	lineNums []int,
	parseErrors []contracts.ValidationErrorRecord,
	inputPath, inputSHA string,
) (RunResult, error) {
	metrics := contracts.DiagnosticMetrics{
		EventsIngested: len(rawEvents) + len(parseErrors),
		EventsInvalid:  len(parseErrors),
	}
	valErrors := append([]contracts.ValidationErrorRecord{}, parseErrors...)
	normalized := make([]contracts.NormalizedEvent, 0, len(rawEvents))
	seenEventIDs := make(map[string]bool)

	for i, raw := range rawEvents {
		ev, err := p.Normalizer.Normalize(raw)
		if err != nil {
			metrics.EventsInvalid++
			valErrors = append(valErrors, contracts.ValidationErrorRecord{
				LineNumber: lineNums[i],
				EventID:    raw.EventID,
				Error:      err.Error(),
			})
			continue
		}
		if p.Config.DeduplicationEnabled {
			dupHash, err := p.Store.HasCanonicalHash(ctx, ev.CanonicalHash)
			if err != nil {
				return RunResult{}, err
			}
			if dupHash || seenEventIDs[ev.EventID] {
				metrics.EventsDeduplicated++
				continue
			}
		}
		seenEventIDs[ev.EventID] = true
		if err := p.Store.SaveNormalizedEvent(ctx, ev); err != nil {
			return RunResult{}, err
		}
		metrics.EventsNormalized++
		metrics.FieldsRedacted += len(ev.RedactedFields)
		normalized = append(normalized, ev)
	}

	return p.runNormalizedStage(ctx, normalized, valErrors, metrics, inputPath, inputSHA)
}

func (p *Pipeline) runNormalizedStage(
	ctx context.Context,
	normalized []contracts.NormalizedEvent,
	valErrors []contracts.ValidationErrorRecord,
	metrics contracts.DiagnosticMetrics,
	inputPath, inputSHA string,
) (RunResult, error) {
	runID := contracts.StableID("RUN", p.Config.SchemaVersion, fmt.Sprintf("%d", p.Config.DeterministicSeed), inputSHA)
	rec := telemetry.NewRecorder(p.Config, runID, p.Normalizer.RedactString, p.LogWriter)

	t0 := p.Clock()
	rootSpan := rec.RecordSpan("pipeline.run", "", "OK", t0, t0.Add(time.Millisecond), map[string]string{
		"input.path":       inputPath,
		"events.ingested":  fmt.Sprintf("%d", metrics.EventsIngested),
		"containment.mode": p.Config.ContainmentMode,
	})

	// Detect
	tDet := t0.Add(2 * time.Millisecond)
	detRes := p.Detector.Evaluate(normalized, p.Config.ExpectedSources, p.Config.TelemetryGapThresholdSec)
	rec.RecordSpan("pipeline.detect", rootSpan, "OK", tDet, tDet.Add(time.Millisecond), map[string]string{
		"alerts.total":         fmt.Sprintf("%d", len(detRes.Alerts)),
		"telemetry.gaps_found": fmt.Sprintf("%d", len(detRes.TelemetryGaps)),
	})

	// Record suppression audits into tamper-evident reviewer audit log
	for _, sa := range detRes.SuppressionAudits {
		p.Simulator.RecordSuppressionAudit(sa.SuppressionID, sa.AlertID, sa.ApprovedBy, sa.Reason, sa.Timestamp)
	}

	// Correlate active alerts into cases
	tCorr := t0.Add(4 * time.Millisecond)
	cases := p.Correlator.Correlate(detRes.Alerts)
	rec.RecordSpan("pipeline.correlate", rootSpan, "OK", tCorr, tCorr.Add(time.Millisecond), map[string]string{
		"cases.created": fmt.Sprintf("%d", len(cases)),
	})

	// Propose simulation-only containment actions (never auto-executed)
	tCont := t0.Add(6 * time.Millisecond)
	for _, c := range cases {
		if c.Severity.Rank() >= contracts.SeverityHigh.Rank() {
			p.Simulator.ProposeFromCase(c, "tism-correlator", tCont)
		}
	}
	proposals := p.Simulator.Proposals()
	rec.RecordSpan("pipeline.propose_containment", rootSpan, "OK", tCont, tCont.Add(time.Millisecond), map[string]string{
		"proposals.created": fmt.Sprintf("%d", len(proposals)),
		"live.executed":     "false",
	})

	activeCount := 0
	suppressedCount := 0
	for _, a := range detRes.Alerts {
		if a.Suppressed {
			suppressedCount++
		} else {
			activeCount++
		}
	}

	metrics.TelemetryGapsDetected = len(detRes.TelemetryGaps)
	metrics.AlertsTotal = len(detRes.Alerts)
	metrics.AlertsActive = activeCount
	metrics.AlertsSuppressed = suppressedCount
	metrics.CasesCreated = len(cases)
	metrics.ProposalsCreated = len(proposals)

	if valErrors == nil {
		valErrors = []contracts.ValidationErrorRecord{}
	}

	report := contracts.RunReport{
		Metadata: contracts.RunMetadata{
			RunID:             runID,
			SchemaVersion:     contracts.SchemaVersion,
			Environment:       p.Config.Environment,
			DeterministicSeed: p.Config.DeterministicSeed,
			ContainmentMode:   p.Config.ContainmentMode,
			LiveContainment:   false,
			GoVersion:         runtime.Version(),
			OS:                runtime.GOOS,
			Arch:              runtime.GOARCH,
			InputPath:         inputPath,
			InputSHA256:       inputSHA,
		},
		Metrics:              metrics,
		TelemetryGaps:        detRes.TelemetryGaps,
		ValidationErrors:     valErrors,
		Alerts:               detRes.Alerts,
		Cases:                cases,
		ContainmentProposals: proposals,
		ReviewerAuditLog:     p.Simulator.AuditLog(),
	}

	if err := p.Store.SaveReport(ctx, report); err != nil {
		return RunResult{}, err
	}

	return RunResult{
		Report:           report,
		NormalizedEvents: normalized,
		Telemetry:        rec.Export(metrics),
	}, nil
}

// GroundTruthExpectedAlert identifies an expected active alert by (rule_id, source_event_id).
type GroundTruthExpectedAlert struct {
	RuleID        string `json:"rule_id"`
	SourceEventID string `json:"source_event_id"`
	Description   string `json:"description,omitempty"`
}

// GroundTruthDataset defines expected detections for evaluation metrics.
type GroundTruthDataset struct {
	SchemaVersion      string                     `json:"schema_version"`
	DatasetName        string                     `json:"dataset_name"`
	ExpectedCaseCount  int                        `json:"expected_case_count"`
	ExpectedAlerts     []GroundTruthExpectedAlert `json:"expected_alerts"`
}

// Evaluate computes synthetic detection recall, precision, F1, false-positive count, and provenance invariants.
func Evaluate(report contracts.RunReport, gt GroundTruthDataset) contracts.EvaluationReport {
	expectedSet := make(map[string]bool, len(gt.ExpectedAlerts))
	for _, exp := range gt.ExpectedAlerts {
		expectedSet[exp.RuleID+"|"+exp.SourceEventID] = true
	}

	matchedExpected := make(map[string]bool)
	observedActive := 0
	suppressed := 0
	fp := 0
	unexpected := make([]string, 0)
	allTraced := true

	for _, a := range report.Alerts {
		if len(a.SourceEventIDs) == 0 {
			allTraced = false
		}
		if a.Suppressed {
			suppressed++
			continue
		}
		observedActive++
		// An alert matches ground truth if its rule_id + any of its source_event_ids is in expectedSet
		matched := false
		for _, eid := range a.SourceEventIDs {
			key := a.RuleID + "|" + eid
			if expectedSet[key] {
				matchedExpected[key] = true
				matched = true
			}
		}
		if !matched {
			fp++
			unexpected = append(unexpected, fmt.Sprintf("%s|%s", a.RuleID, strings.Join(a.SourceEventIDs, ",")))
		}
	}

	missing := make([]string, 0)
	for key := range expectedSet {
		if !matchedExpected[key] {
			missing = append(missing, key)
		}
	}
	sort.Strings(missing)
	sort.Strings(unexpected)

	tp := len(matchedExpected)
	fn := len(missing)

	var recall, precision, f1 float64
	if tp+fn > 0 {
		recall = float64(tp) / float64(tp+fn)
	}
	if tp+fp > 0 {
		precision = float64(tp) / float64(tp+fp)
	}
	if precision+recall > 0 {
		f1 = 2 * precision * recall / (precision + recall)
	}

	liveCount := 0
	for _, prop := range report.ContainmentProposals {
		if prop.LiveExecuted {
			liveCount++
		}
	}

	return contracts.EvaluationReport{
		Metadata:              report.Metadata,
		ExpectedAlertCount:    len(expectedSet),
		ObservedActiveAlerts:  observedActive,
		SuppressedAlerts:      suppressed,
		TruePositives:         tp,
		FalsePositives:        fp,
		FalseNegatives:        fn,
		Recall:                recall,
		Precision:             precision,
		F1Score:               f1,
		AllAlertsTraced:       allTraced,
		LiveContainmentCount:  liveCount,
		ExpectedCaseCount:     gt.ExpectedCaseCount,
		ObservedCaseCount:     len(report.Cases),
		MissingExpectedAlerts: missing,
		UnexpectedAlerts:      unexpected,
	}
}
