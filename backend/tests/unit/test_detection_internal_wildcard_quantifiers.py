"""Sigma selector patterns may use '*' in the middle, not only at the end."""

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
            "filter_known": {"User": "service"},
            "condition": condition,
        },
    }


@pytest.mark.parametrize("condition", [
    "1 of selection_*in",
    "1 of sel*log*n",
    "1 of selection_*out",
    "2 of sel*ion_*",
    "all of sel*ion_*",
    "(1 of sel*login) and not filter_known",
    "1 of selection_*",
])
def test_internal_and_trailing_globs_match_known_selectors(condition):
    assert RulePreflightRequest.model_validate(draft(condition)).selector_names == [
        "filter_known", "selection_login", "selection_logout"
    ]


@pytest.mark.parametrize("condition", [
    "2 of selection_*in",  # Only selection_login matches.
    "2 of selection_*out",  # Only selection_logout matches.
    "1 of sel*missing",  # No matching selector.
    "sel*login",  # A wildcard is only valid as a quantifier target.
])
def test_impossible_or_standalone_globs_are_rejected(condition):
    with pytest.raises(ValidationError):
        RulePreflightRequest.model_validate(draft(condition))
