"""Impossible Sigma selector quantifiers must fail structural preflight."""

import pytest
from pydantic import ValidationError

from app.detection.validation import RulePreflightRequest


def draft(condition, *, extra_selectors=None):
    selectors = {
        "selection_login": {"EventID": 4625},
        "selection_logout": {"EventID": 4634},
    }
    selectors.update(extra_selectors or {})
    return {
        "title": "Authentication activity",
        "logsource": {"product": "windows"},
        "detection": {**selectors, "condition": condition},
    }


@pytest.mark.parametrize("condition", [
    "1 of them",
    "2 of them",
    "2 of selection_*",
    "all of selection_*",
    "selection_login and 1 of selection_*",
    "2 of selection_* | count() by Computer > 5",
])
def test_feasible_quantifiers_remain_valid(condition):
    assert RulePreflightRequest.model_validate(draft(condition)).selector_names == [
        "selection_login", "selection_logout"
    ]


@pytest.mark.parametrize("condition", [
    "3 of them",
    "3 of selection_*",
    "2 of selection_login",
    "selection_login or 99 of selection_*",
    "3 of selection_* | count() by Computer > 5",
])
def test_impossible_quantifiers_are_rejected(condition):
    with pytest.raises(ValidationError, match="quantifier exceeds"):
        RulePreflightRequest.model_validate(draft(condition))


@pytest.mark.parametrize("name", ["and", "or", "not", "of", "all", "them", "AND"])
def test_reserved_condition_keywords_cannot_be_selector_names(name):
    with pytest.raises(ValidationError, match="invalid selector name"):
        RulePreflightRequest.model_validate(
            draft("selection_login", extra_selectors={name: {"EventID": 42}})
        )
