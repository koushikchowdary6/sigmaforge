"""Basic Sigma condition references must resolve to declared selectors."""

import pytest
from pydantic import ValidationError

from app.detection.validation import RulePreflightRequest


def rule(condition):
    return {
        "title": "Windows authentication",
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
    "1 of selection_*",
    "all of them",
    ["selection_login", "selection_logout"],
])
def test_known_selectors_and_sigma_quantifiers_are_accepted(condition):
    assert RulePreflightRequest.model_validate(rule(condition)).selector_names == [
        "selection_login", "selection_logout"
    ]


@pytest.mark.parametrize("condition", [
    "missing",
    "selection_login or missing",
    "1 of unknown_*",
    "and",
    ["selection_login", "unknown"],
])
def test_unknown_or_unreferenced_conditions_are_rejected(condition):
    with pytest.raises(ValidationError, match="undefined selector"):
        RulePreflightRequest.model_validate(rule(condition))


def test_advanced_aggregation_is_left_for_future_pysigma_semantic_validation():
    # Preflight is structural-only; do not falsely claim to parse aggregations.
    assert RulePreflightRequest.model_validate(
        rule("selection_login | count() by Computer > 5")
    ).selector_names
