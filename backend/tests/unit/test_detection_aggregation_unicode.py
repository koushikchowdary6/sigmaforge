"""Sigma aggregation suffixes must not bypass Unicode/UTF-8 preflight."""

import pytest
from pydantic import ValidationError

from app.detection.validation import RulePreflightRequest


def draft(condition):
    return {
        "title": "Repeated failed logins",
        "logsource": {"product": "windows"},
        "detection": {
            "selection_login": {"EventID": 4625},
            "selection_logout": {"EventID": 4634},
            "condition": condition,
        },
    }


@pytest.mark.parametrize("hidden", [
    "\u202e",  # Right-to-left override: misleading visual order
    "\u200b",  # Zero-width space
    "\u034f",  # Combining grapheme joiner
    "\ufe0f",  # Variation selector
    "\ud800",  # Lone UTF-16 surrogate cannot be UTF-8 encoded
    "\x00",    # Non-whitespace control
    "\u2028",  # Invisible Unicode line separator
])
def test_hidden_unicode_in_aggregation_suffix_fails_closed(hidden):
    condition = "selection_login | count() by User" + hidden + " > 3"
    with pytest.raises(ValidationError, match="invisible or invalid Unicode"):
        RulePreflightRequest.model_validate(draft(condition))


def test_hidden_unicode_in_any_condition_list_item_is_rejected():
    with pytest.raises(ValidationError, match="invisible or invalid Unicode"):
        RulePreflightRequest.model_validate(draft([
            "selection_login",
            "selection_logout | count()\u202e > 3",
        ]))


@pytest.mark.parametrize("condition", [
    "selection_login | count() by User > 3",
    "selection_login\nand selection_logout | count() by User > 3",
    "selection_login\r\nand selection_logout | count() by User > 3",
])
def test_legitimate_aggregation_and_multiline_boolean_syntax_remain_valid(condition):
    parsed = RulePreflightRequest.model_validate(draft(condition))
    assert parsed.selector_names == ["selection_login", "selection_logout"]
