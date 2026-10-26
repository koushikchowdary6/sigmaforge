"""Malformed Unicode in Sigma field values must produce validation errors.

An escaped lone UTF-16 surrogate can be parsed from JSON but cannot be
encoded as UTF-8. Preflight must reject it before measuring draft bytes.
"""

import json

import pytest
from pydantic import ValidationError

from app.detection.validation import RulePreflightRequest


def _draft(value):
    return {
        "title": "Suspicious process",
        "logsource": {"product": "windows"},
        "detection": {
            "selection": {"CommandLine|contains": value},
            "condition": "selection",
        },
    }


@pytest.mark.parametrize("value", [
    "\\ud800",  # lone high surrogate
    "\\udfff",  # lone low surrogate
    "prefix\\ud800suffix",
    ["safe", "\\udc00"],
    ["\\ud800", "safe"],
])
def test_rejects_surrogate_scalar_and_list_values(value):
    # JSON decoding does not reject escaped lone surrogates, so a request can
    # reach Pydantic validation with such a string.
    payload = json.loads(json.dumps(_draft(value), ensure_ascii=True))
    with pytest.raises(ValidationError, match="invalid selection mapping"):
        RulePreflightRequest.model_validate(payload)


@pytest.mark.parametrize("value", [
    "Détection — 安全",
    "emoji 🔒",
    "line\\nfeed",
    "plain text",
    ["normal", "café", "🔍"],
])
def test_preserves_valid_unicode_and_detection_strings(value):
    assert RulePreflightRequest.model_validate(_draft(value)).selector_names == [
        "selection"
    ]
