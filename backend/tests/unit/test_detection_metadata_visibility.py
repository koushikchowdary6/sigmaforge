"""Metadata must be readable and stable for Sigma rule review and matching."""

import pytest
from pydantic import ValidationError

from app.detection.validation import RulePreflightRequest


def draft():
    return {
        "title": "Suspicious PowerShell execution",
        "logsource": {"product": "windows", "category": "process_creation"},
        "detection": {
            "selection": {"CommandLine|contains": "powershell"},
            "condition": "selection",
        },
    }


@pytest.mark.parametrize("bad_text", [
    "win\u200bdows",        # Zero-width space
    "win\u202edows",        # Bidi override
    "win\u034fdows",        # Combining grapheme joiner
    "win\ufe0fdows",        # Variation selector
    "win\u2028dows",        # Unicode line separator
    "win\ndows",            # Control newline
    " windows",             # Leading whitespace alters exact metadata matching
    "windows ",             # Trailing whitespace
])
@pytest.mark.parametrize("field", ["title", "logsource"])
def test_hidden_or_ambiguous_metadata_is_rejected(field, bad_text):
    payload = draft()
    if field == "title":
        payload["title"] = bad_text
    else:
        payload["logsource"]["product"] = bad_text
    with pytest.raises(ValidationError):
        RulePreflightRequest.model_validate(payload)


def test_legitimate_unicode_metadata_and_spaces_remain_valid():
    payload = draft()
    payload["title"] = "Détection d'accès inhabituel — équipe sécurité"
    payload["logsource"]["product"] = "windows"
    payload["logsource"]["definition"] = "Windows process creation events"
    assert RulePreflightRequest.model_validate(payload).selector_names == ["selection"]
