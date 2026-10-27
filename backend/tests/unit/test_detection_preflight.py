"""Structural Sigma preflight must reject malformed or unbounded field values."""

import pytest
from pydantic import ValidationError

from app.detection.validation import RulePreflightRequest


def draft(value):
    return {
        "title": "Failed logins",
        "logsource": {"product": "windows"},
        "detection": {"selection": {"EventID": value}, "condition": "selection"},
    }


@pytest.mark.parametrize("value", [
    4625, -1, True, None, 1.25, "", "failed login",
    ["4625", "4624"], [None, True, 4625],
])
def test_accepts_valid_sigma_scalar_and_list_values(value):
    parsed = RulePreflightRequest.model_validate(draft(value))
    assert parsed.selector_names == ["selection"]


@pytest.mark.parametrize("value", [
    {"nested": "unexpected"}, [["nested"]], [], ["x"] * 65,
    "x" * 2049, float("nan"), float("inf"), -float("inf"),
    ["valid", {"nested": "unexpected"}], ["x" * 2049],
])
def test_rejects_nested_unbounded_and_nonfinite_field_values(value):
    with pytest.raises(ValidationError):
        RulePreflightRequest.model_validate(draft(value))


def test_rejects_overlong_field_name():
    payload = draft(4625)
    payload["detection"]["selection"] = {"x" * 201: 4625}
    with pytest.raises(ValidationError):
        RulePreflightRequest.model_validate(payload)


def test_accepts_sigma_selector_list_of_mappings():
    payload = draft(4625)
    payload["detection"]["selection"] = [{"EventID": 4625}, {"EventID": 4624}]
    assert RulePreflightRequest.model_validate(payload).selector_names == ["selection"]


@pytest.mark.parametrize("value", [
    10 ** 5000, -(10 ** 5000), 2 ** 4096, [10 ** 5000],
])
def test_rejects_extreme_integer_values_before_json_serialization(value):
    # These can trigger Python's int-to-decimal conversion limit in
    # json.dumps, which must not turn a malformed rule into an HTTP 500.
    with pytest.raises(ValidationError, match="invalid selection mapping"):
        RulePreflightRequest.model_validate(draft(value))


def test_accepts_large_but_bounded_integer_value():
    assert RulePreflightRequest.model_validate(
        draft(2 ** 4095)
    ).selector_names == ["selection"]
