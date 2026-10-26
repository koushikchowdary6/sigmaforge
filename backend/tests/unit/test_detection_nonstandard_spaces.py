"""Reject deceptive Unicode whitespace in reviewer-facing Sigma draft syntax."""

import pytest
from pydantic import ValidationError

from app.detection.validation import RulePreflightRequest


def draft():
    return {
        "title": "Suspicious authentication",
        "logsource": {"product": "windows"},
        "detection": {
            "selection_login": {"EventID": 4625},
            "selection_logout": {"EventID": 4634},
            "condition": "selection_login and selection_logout",
        },
    }


@pytest.mark.parametrize("space", [
    "\u00a0",  # NO-BREAK SPACE: looks like an ordinary space
    "\u2009",  # THIN SPACE
    "\u202f",  # NARROW NO-BREAK SPACE
    "\u3000",  # IDEOGRAPHIC SPACE
])
def test_nonstandard_spaces_are_rejected_in_condition_and_metadata(space):
    for field in ("condition", "title", "logsource", "selection_key"):
        payload = draft()
        if field == "condition":
            payload["detection"]["condition"] = f"selection_login{space}and{space}selection_logout"
        elif field == "title":
            payload["title"] = f"Suspicious{space}authentication"
        elif field == "logsource":
            payload["logsource"]["product"] = f"windows{space}server"
        else:
            payload["detection"]["selection_login"] = {f"Command{space}Line": "powershell"}
        with pytest.raises(ValidationError):
            RulePreflightRequest.model_validate(payload)


def test_plain_ascii_spaces_and_combining_accents_remain_valid():
    payload = draft()
    payload["title"] = "Suspicious login activity"
    payload["detection"]["selection_login"] = {
        "Command Line": "powershell",
        "Cafe\u0301|contains": "example",
    }
    assert RulePreflightRequest.model_validate(payload).selector_names == [
        "selection_login", "selection_logout"
    ]


def test_detection_values_can_still_match_literal_nonbreaking_spaces():
    # A detection string is evidence to match, not a reviewer-facing identifier.
    payload = draft()
    payload["detection"]["selection_login"] = {"CommandLine|contains": "hello\u00a0world"}
    assert RulePreflightRequest.model_validate(payload).selector_names
