"""Aggregation preflight rejects suffixes with no visible syntax."""

import pytest
from pydantic import ValidationError

from app.detection.validation import RulePreflightRequest


def draft(condition):
    return {
        "title": "Repeated failed logins",
        "logsource": {"product": "windows"},
        "detection": {
            "selection": {"EventID": 4625},
            "condition": condition,
        },
    }


@pytest.mark.parametrize("suffix", [
    "\u0301",
    "\u0301\u0308",
    "  \u0301\t\u0308  ",
    "\u20dd",  # Enclosing combining mark without a visible base
])
def test_combining_marks_alone_are_not_aggregation_expressions(suffix):
    with pytest.raises(ValidationError, match="malformed aggregation boundary"):
        RulePreflightRequest.model_validate(draft(f"selection | {suffix}"))


@pytest.mark.parametrize("condition", [
    "selection | count() > 3",
    "selection | count() by Cafe\u0301 > 3",
    "selection | count()\nby User > 3",
])
def test_visible_aggregation_expressions_remain_structurally_accepted(condition):
    parsed = RulePreflightRequest.model_validate(draft(condition))
    assert parsed.selector_names == ["selection"]
