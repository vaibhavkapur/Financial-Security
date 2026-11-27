"""Boundary 3: Structured redacted audit logger and diagnostic counters."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from fin_redteam.models import AuditEvent, Decision, ReasonCode
from fin_redteam.redaction import CanaryGuard


class AuditLogger:
    """Produces deterministic, canary-redacted structured audit telemetry and counters."""

    def __init__(
        self,
        run_id: str,
        canary_guard: CanaryGuard,
        fixed_timestamp_utc: str | None = None,
    ) -> None:
        self._run_id = run_id
        self._canary_guard = canary_guard
        self._fixed_timestamp_utc = fixed_timestamp_utc
        self._events: list[AuditEvent] = []
        self._counters: dict[str, int] = {
            "tool_calls_total": 0,
            "tool_calls_allowed": 0,
            "tool_calls_denied": 0,
            "taint_blocks": 0,
            "policy_denials": 0,
            "canary_blocks": 0,
            "canary_leaks_unguarded": 0,
            "approval_outage_blocks": 0,
            "conflict_blocks": 0,
        }

    def record(
        self,
        *,
        scenario_id: str,
        boundary: str,
        event_type: str,
        actor_role: str,
        decision: Decision | None = None,
        reason_code: ReasonCode | None = None,
        details: dict[str, Any] | None = None,
    ) -> AuditEvent:
        """Append a redacted audit event and update diagnostic counters."""
        seq = len(self._events) + 1
        event_id = f"EVT-{self._run_id}-{seq:04d}"
        timestamp = (
            self._fixed_timestamp_utc
            if self._fixed_timestamp_utc is not None
            else datetime.now(UTC).isoformat()
        )
        redacted_details = self._canary_guard.redact_payload(details or {})
        event = AuditEvent(
            event_id=event_id,
            run_id=self._run_id,
            scenario_id=scenario_id,
            sequence=seq,
            timestamp_utc=timestamp,
            boundary=boundary,
            event_type=event_type,
            actor_role=actor_role,
            decision=decision,
            reason_code=reason_code,
            details=redacted_details,
        )
        self._events.append(event)
        self._update_counters(event_type, decision, reason_code)
        return event

    def _update_counters(
        self,
        event_type: str,
        decision: Decision | None,
        reason_code: ReasonCode | None,
    ) -> None:
        if event_type == "tool_invocation":
            self._counters["tool_calls_total"] += 1
            if decision == Decision.ALLOW:
                self._counters["tool_calls_allowed"] += 1
            elif decision == Decision.DENY:
                self._counters["tool_calls_denied"] += 1

        if reason_code == ReasonCode.TAINTED_WRITE_DENIED:
            self._counters["taint_blocks"] += 1
        elif reason_code in {
            ReasonCode.POLICY_ROLE_DENIED,
            ReasonCode.POLICY_TOOL_DENIED,
            ReasonCode.POLICY_LIMIT_EXCEEDED,
            ReasonCode.POLICY_EXPORT_DENIED,
            ReasonCode.APPROVAL_REQUIRED,
        }:
            self._counters["policy_denials"] += 1
        elif reason_code == ReasonCode.CANARY_EGRESS_BLOCKED:
            self._counters["canary_blocks"] += 1
        elif reason_code == ReasonCode.APPROVAL_UNAVAILABLE:
            self._counters["approval_outage_blocks"] += 1
        elif reason_code == ReasonCode.CONFLICTING_INSTRUCTIONS_DENIED:
            self._counters["conflict_blocks"] += 1
        elif event_type == "egress_canary_leak_unguarded":
            self._counters["canary_leaks_unguarded"] += 1

    @property
    def events(self) -> list[AuditEvent]:
        return list(self._events)

    @property
    def counters(self) -> dict[str, int]:
        return dict(self._counters)
