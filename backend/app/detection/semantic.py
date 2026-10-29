"""Opt-in pySigma parser validation for structurally accepted rule drafts.

This checks Sigma grammar and supported modifiers using the upstream parser.
It does not convert a rule to a SIEM query, validate backend field mappings,
approve a detection, or make a draft deployable.
"""
from __future__ import annotations

from sigma.exceptions import SigmaError
from sigma.rule import SigmaRule

from app.detection.validation import RulePreflightRequest


def parse_rule_with_pysigma(draft: RulePreflightRequest) -> dict[str, object]:
    """Parse an already bounded, structurally validated draft with pySigma."""
    try:
        parsed = SigmaRule.from_dict(draft.model_dump())
    except (SigmaError, ValueError, TypeError, RecursionError) as exc:
        # Do not expose untrusted rule contents through raw parser errors.
        raise ValueError("pySigma rejected rule syntax or modifiers") from exc
    if getattr(parsed, "errors", None):
        raise ValueError("pySigma reported rule parsing errors")
    return {
        "valid": True,
        "validation_level": "pysigma_parsed",
        "selector_count": len(draft.selector_names),
        "selector_names": draft.selector_names,
    }
