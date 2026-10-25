"""Bounded Sigma draft timeframe and condition nesting preflight tests.

These are structural checks, not full pySigma validation.
"""

import pytest
from pydantic import ValidationError

from app.detection.validation import RulePreflightRequest


def draft(condition="selection", timeframe=None):
    detection = {
        "selection": {"EventID": 4625},
        "condition": condition,
    }
    if timeframe is not None:
        detection["timeframe"] = timeframe
    return {
        "title": "Repeated failed logins",
        "logsource": {"product": "windows"},
        "detection": detection,
    }


@pytest.mark.parametrize("timeframe", ["5m", "1h", "2d", "3w", "1M", "1y"])
def test_optional_sigma_timeframe_does_not_count_as_selector(timeframe):
    parsed = RulePreflightRequest.model_validate(draft(timeframe=timeframe))
    assert parsed.selector_names == ["selection"]


@pytest.mark.parametrize("timeframe", [
    "", "0m", "01m", "5 minutes", "5ms", "9999999h", "1m ",
    5, False, [], {}, None,
])
def test_invalid_sigma_timeframes_fail_closed(timeframe):
    payload = draft()
    payload["detection"]["timeframe"] = timeframe
    with pytest.raises(ValidationError, match="timeframe"):
        RulePreflightRequest.model_validate(payload)


def test_timeframe_without_any_selector_is_not_a_rule():
    payload = draft(timeframe="5m")
    del payload["detection"]["selection"]
    with pytest.raises(ValidationError, match="selector"):
        RulePreflightRequest.model_validate(payload)


def test_bounded_nested_condition_is_accepted():
    condition = "(" * 32 + "selection" + ")" * 32
    assert RulePreflightRequest.model_validate(draft(condition)).selector_names == ["selection"]


@pytest.mark.parametrize("depth", [65, 200])
def test_excessive_condition_nesting_is_a_validation_error(depth):
    condition = "(" * depth + "selection" + ")" * depth
    with pytest.raises(ValidationError, match="malformed boolean syntax"):
        RulePreflightRequest.model_validate(draft(condition))
