"""Regression tests for invisible Sigma field-name obfuscation.

Structural preflight should reject hard-to-review field names without
rejecting legitimate punctuation or accented identifiers.
"""

import pytest
from pydantic import ValidationError

from app.detection.validation import RulePreflightRequest


def draft(field: str) -> dict:
    return {
        "title": "Suspicious PowerShell",
        "logsource": {"product": "windows"},
        "detection": {
            "selection": {field: "powershell"},
            "condition": "selection",
        },
    }


@pytest.mark.parametrize("field", [
    "Command\u034fLine",       # Combining grapheme joiner
    "Command\ufe0fLine",       # Variation selector-16
    "Command\ufe00Line",       # Variation selector-1
    "Command\U000e0100Line",  # Supplementary variation selector
    "Command\u2028Line",       # Unicode line separator
    "Command\u2029Line",       # Unicode paragraph separator
])
def test_invisible_or_layout_changing_field_names_fail_closed(field):
    with pytest.raises(ValidationError, match="invalid selection mapping"):
        RulePreflightRequest.model_validate(draft(field))


@pytest.mark.parametrize("field", [
    "CommandLine",
    "User-Agent|contains",
    "winlog.event_data.CommandLine",
    "München|contains",
    "Cafe\u0301|contains",  # Normal combining accent is not an invisible joiner
    "Field With Spaces",
])
def test_legitimate_identifiers_remain_supported(field):
    assert RulePreflightRequest.model_validate(draft(field)).selector_names == [
        "selection"
    ]


@pytest.mark.parametrize("field", ["\u0301", "\u0301\u0300", "\u20dd"])
def test_standalone_combining_marks_are_not_valid_field_names(field):
    with pytest.raises(ValidationError, match="invalid selection mapping"):
        RulePreflightRequest.model_validate(draft(field))
