"""Reject malformed Sigma boolean expressions without claiming pySigma semantics."""

import pytest
from pydantic import ValidationError

from app.detection.validation import RulePreflightRequest


def draft(condition):
    return {
        "title": "Suspicious authentication",
        "logsource": {"product": "windows"},
        "detection": {
            "selection_login": {"EventID": 4625},
            "selection_logout": {"EventID": 4634},
            "condition": condition,
        },
    }


@pytest.mark.parametrize("condition", [
    "selection_login",
    "selection_login and not selection_logout",
    "(selection_login or selection_logout) and not selection_logout",
    "not (selection_login and selection_logout)",
    "1 of selection_*",
    "all of them",
    "selection_login | count() by User > 3",
    ["selection_login", "selection_logout"],
])
def test_supported_boolean_subset_remains_valid(condition):
    assert RulePreflightRequest.model_validate(draft(condition)).selector_names == [
        "selection_login", "selection_logout"
    ]


@pytest.mark.parametrize("condition", [
    "selection_login or",
    "selection_login and",
    "not",
    "selection_login && selection_logout",
    "selection_login + selection_logout",
    "selection_login not selection_logout",
    "(selection_login or selection_logout",
    "selection_login)",
    "selection_login or ()",
    "0 of them",
    "selection_*",
])
def test_malformed_boolean_conditions_are_rejected(condition):
    with pytest.raises(ValidationError):
        RulePreflightRequest.model_validate(draft(condition))
