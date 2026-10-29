"""Quantifier tokens require separators, not regex-only concatenation."""

import pytest
from pydantic import ValidationError

from app.detection.validation import RulePreflightRequest


def draft(condition):
    return {
        "title": "Authentication activity",
        "logsource": {"product": "windows"},
        "detection": {
            "selection_login": {"EventID": 4625},
            "selection_logout": {"EventID": 4634},
            "condition": condition,
        },
    }


@pytest.mark.parametrize("condition", [
    "1of them",
    "2of them",
    "1of selection_*",
    "2of selection_*",
    "allof them",
    "1 ofthem",
    "2 ofselection_*",
    "all ofselection_*",
])
def test_concatenated_quantifiers_fail_structural_preflight(condition):
    with pytest.raises(ValidationError):
        RulePreflightRequest.model_validate(draft(condition))


@pytest.mark.parametrize("condition", [
    "1 of them",
    "2 of selection_*",
    "all of them",
    "1\tof\tselection_*",
    "1\nof\nselection_*",
    "(1 of selection_*) and selection_login",
])
def test_separated_quantifiers_remain_accepted(condition):
    assert RulePreflightRequest.model_validate(draft(condition)).selector_names == [
        "selection_login", "selection_logout"
    ]
