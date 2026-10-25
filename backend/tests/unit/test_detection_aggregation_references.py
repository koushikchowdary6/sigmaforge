"""Sigma aggregation conditions must resolve selectors before the pipe."""

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


@pytest.mark.parametrize("condition", [
    "selection_login | count() by Computer > 5",
    "selection_login and not selection_logout | count() > 2",
    "1 of selection_* | count() > 2",
    "all of them | count() by User > 3",
])
def test_known_selectors_remain_valid_with_aggregation(condition):
    parsed = RulePreflightRequest.model_validate(draft(condition))
    assert parsed.selector_names == ["selection_login", "selection_logout"]


@pytest.mark.parametrize("condition", [
    "missing | count() > 5",
    "selection_login or missing | count() by Computer > 5",
    "1 of unknown_* | count() > 3",
    "| count() > 3",
    "and | count() > 3",
    ["selection_login", "missing | count() > 3"],
])
def test_unknown_or_missing_aggregation_selectors_are_rejected(condition):
    with pytest.raises(ValidationError, match="undefined selector"):
        RulePreflightRequest.model_validate(draft(condition))


def test_aggregation_tokens_are_not_mistaken_for_selector_references():
    """Preflight checks the LHS only; pySigma semantics are still future work."""
    assert RulePreflightRequest.model_validate(
        draft("selection_login | count() by Computer > 5")
    ).selector_names


@pytest.mark.parametrize("condition", [
    "selection_login |",
    "selection_login |   ",
    "selection_login | count() |",
    "selection_login | count() | count()",
    ["selection_login", "selection_logout |"],
])
def test_incomplete_or_repeated_aggregation_separators_are_rejected(condition):
    with pytest.raises(ValidationError, match="malformed aggregation boundary"):
        RulePreflightRequest.model_validate(draft(condition))


def test_single_aggregation_segment_remains_supported():
    parsed = RulePreflightRequest.model_validate(
        draft("selection_login | count() by Computer > 5")
    )
    assert parsed.selector_names == ["selection_login", "selection_logout"]
