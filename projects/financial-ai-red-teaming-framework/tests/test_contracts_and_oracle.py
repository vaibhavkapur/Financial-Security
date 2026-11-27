"""M1 tests: data contracts, invalid input rejection, and deterministic reference oracle."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from pydantic import ValidationError

from fin_redteam.harness import EvaluationHarness
from fin_redteam.models import CanarySecret, GoldPolicySet, Scenario, ScenarioSuite


def test_reference_oracle_matches_hand_calculated_expectations(harness: EvaluationHarness) -> None:
    ok, report, discrepancies = harness.verify_reference_oracle(
        fixed_timestamp_utc="2026-11-27T00:00:00+00:00"
    )
    assert ok, f"Reference oracle discrepancies: {discrepancies}"
    assert report.summary.total_scenarios == 4
    assert report.summary.adversarial_scenarios == 3
    assert report.summary.benign_scenarios == 1
    assert report.summary.attack_success_rate == 0.0
    assert report.summary.false_refusal_rate == 0.0
    assert report.summary.canary_leak_count == 0


def test_invalid_inputs_fixture_cases_fail_schema_validation(project_root: Path) -> None:
    invalid_path = project_root / "data" / "fixtures" / "invalid_inputs.json"
    data = json.loads(invalid_path.read_text(encoding="utf-8"))
    model_map = {
        "ScenarioSuite": ScenarioSuite,
        "Scenario": Scenario,
        "CanarySecret": CanarySecret,
    }
    assert len(data["cases"]) >= 4
    for case in data["cases"]:
        model_cls = model_map[case["target_model"]]
        with pytest.raises(ValidationError):
            model_cls.model_validate(case["payload"])


def test_gold_policy_rejects_allow_by_default() -> None:
    with pytest.raises(ValidationError, match="deny-by-default"):
        GoldPolicySet.model_validate(
            {
                "schema_version": "1.0.0",
                "policy_set_id": "unsafe-policy",
                "default_decision": "ALLOW",
                "approved_export_destinations": [],
                "mutating_tools": [],
                "read_only_tools": [],
                "roles": {},
            }
        )
