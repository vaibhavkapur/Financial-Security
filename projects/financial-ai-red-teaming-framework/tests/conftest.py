"""Shared pytest fixtures for the Financial AI Red Teaming Framework."""

from __future__ import annotations

from pathlib import Path

import pytest

from fin_redteam.harness import EvaluationHarness

PROJECT_ROOT = Path(__file__).resolve().parents[1]
CONFIG_PATH = PROJECT_ROOT / "config" / "harness_config.json"


@pytest.fixture
def project_root() -> Path:
    return PROJECT_ROOT


@pytest.fixture
def config_path() -> Path:
    return CONFIG_PATH


@pytest.fixture
def harness() -> EvaluationHarness:
    return EvaluationHarness(CONFIG_PATH)
