"""Sigma field modifiers must be structurally valid before rule persistence."""

import pytest
from pydantic import ValidationError

from app.detection.validation import RulePreflightRequest


def draft(field):
    return {
        "title": "Suspicious command",
        "logsource": {"product": "windows"},
        "detection": {
            "selection": {field: "powershell"},
            "condition": "selection",
        },
    }


@pytest.mark.parametrize("field", [
    "CommandLine",
    "CommandLine|contains",
    "CommandLine|contains|all",
    "Image|endswith",
    "Field With Spaces|re",
])
def test_accepts_structurally_valid_field_modifier_chains(field):
    assert RulePreflightRequest.model_validate(draft(field)).selector_names == ["selection"]


@pytest.mark.parametrize("field", [
    "|contains", "CommandLine|", "CommandLine||contains",
    "CommandLine|contains|", "CommandLine|bad modifier",
    "CommandLine|contains!", "   |contains",
])
def test_rejects_empty_or_malformed_modifier_segments(field):
    with pytest.raises(ValidationError, match="invalid selection mapping"):
        RulePreflightRequest.model_validate(draft(field))


def test_does_not_claim_semantic_modifier_validation():
    # Unknown but structurally shaped modifiers remain pySigma's responsibility.
    assert RulePreflightRequest.model_validate(
        draft("CommandLine|custommodifier")
    ).selector_names == ["selection"]
