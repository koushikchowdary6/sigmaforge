"""Offline checks for opt-in pySigma parsing beyond structural preflight."""

import pytest
from pydantic import ValidationError

from app.detection.semantic import parse_rule_with_pysigma
from app.detection.validation import RulePreflightRequest


def rule(modifier="contains"):
    return {
        "title": "Suspicious PowerShell command",
        "logsource": {"category": "process_creation", "product": "windows"},
        "detection": {
            "selection": {f"CommandLine|{modifier}": "powershell"},
            "condition": "selection",
        },
    }


def test_semantic_preflight_parses_valid_sigma_rule():
    draft = RulePreflightRequest.model_validate(rule())
    result = parse_rule_with_pysigma(draft)
    assert result == {
        "valid": True,
        "validation_level": "pysigma_parsed",
        "selector_count": 1,
        "selector_names": ["selection"],
    }


def test_unknown_modifier_passes_structural_guard_but_fails_pysigma():
    draft = RulePreflightRequest.model_validate(rule("not_a_sigma_modifier"))
    with pytest.raises(ValueError, match="pySigma rejected"):
        parse_rule_with_pysigma(draft)


def test_structural_validation_remains_first_boundary():
    payload = rule()
    payload["detection"]["condition"] = "undefined_selector"
    with pytest.raises(ValidationError):
        RulePreflightRequest.model_validate(payload)
