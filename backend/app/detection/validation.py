"""Bounded structural preflight for JSON Sigma rule drafts.

This is intentionally *not* pySigma semantic validation, conversion, or
execution. It rejects malformed drafts early before E1 rule persistence.
"""
from __future__ import annotations

import json
import math
import re
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, model_validator

_MAX_DRAFT_BYTES = 65536
_SELECTOR_NAME = re.compile(r"^[A-Za-z][A-Za-z0-9_]*$")
_LOGSOURCE_KEYS = {"category", "product", "service", "definition"}

_CONDITION_IDENTIFIERS = re.compile(r"[A-Za-z][A-Za-z0-9_]*\*?")
_CONDITION_KEYWORDS = {"and", "or", "not", "of", "all", "them"}


def _references_known_selectors(condition: str, selectors: set[str]) -> bool:
    """Check basic Sigma boolean-condition references without claiming full parsing.

    Aggregation pipelines require semantic parsing by pySigma and remain outside
    structural preflight; this guard only handles ordinary selector expressions.
    """
    # Aggregation syntax after "|" is not parsed by this structural guard,
    # but the selector expression before it must still resolve. Otherwise
    # typos such as "missing | count()" silently pass preflight.
    selector_expression = condition.split("|", 1)[0]
    words = _CONDITION_IDENTIFIERS.findall(selector_expression)
    references = [word for word in words if word.lower() not in _CONDITION_KEYWORDS]
    if not references and "them" not in (word.lower() for word in words):
        return False
    return all(
        any(name.startswith(word[:-1]) for name in selectors)
        if word.endswith("*") else word in selectors
        for word in references
    )


def _valid_field_key(key: Any) -> bool:
    """Reject malformed Sigma field-modifier chains without interpreting semantics.

    Structural preflight does not claim to recognize supported pySigma
    modifiers, but an empty field/modifier or punctuation in a modifier
    cannot form a valid field expression.
    """
    if not isinstance(key, str) or not key or len(key) > 200:
        return False
    field, *modifiers = key.split("|")
    return bool(field.strip()) and all(_SELECTOR_NAME.fullmatch(modifier) for modifier in modifiers)


def _valid_scalar(value: Any) -> bool:
    """Only JSON scalar Sigma field values; no nested objects or arrays."""
    if value is None or isinstance(value, bool | int):
        return True
    if isinstance(value, float):
        return math.isfinite(value)
    return isinstance(value, str) and len(value) <= 2048


def _valid_field_value(value: Any) -> bool:
    if isinstance(value, list):
        return 1 <= len(value) <= 64 and all(_valid_scalar(item) for item in value)
    return _valid_scalar(value)


class RulePreflightRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    title: str = Field(min_length=1, max_length=200)
    logsource: dict[str, str]
    detection: dict[str, Any]

    @model_validator(mode="after")
    def validate_structure(self) -> RulePreflightRequest:
        if not self.title.strip():
            raise ValueError("title must not be blank")
        if not self.logsource or not ({"category", "product", "service"} & self.logsource.keys()):
            raise ValueError("logsource requires category, product, or service")
        if any(
            key not in _LOGSOURCE_KEYS or not value.strip() or len(value) > 200
            for key, value in self.logsource.items()
        ):
            raise ValueError("invalid logsource field")

        selectors = {name: value for name, value in self.detection.items() if name != "condition"}
        if not selectors or len(selectors) > 64:
            raise ValueError("detection requires 1 to 64 selectors")
        if any(not _SELECTOR_NAME.fullmatch(name) for name in selectors):
            raise ValueError("invalid selector name")

        condition = self.detection.get("condition")
        conditions = [condition] if isinstance(condition, str) else condition
        if (
            not isinstance(conditions, list) or not 1 <= len(conditions) <= 8
            or any(not isinstance(item, str) or not item.strip() or len(item) > 512
                   for item in conditions)
        ):
            raise ValueError("detection requires non-empty condition text")

        if any(not _references_known_selectors(item, set(selectors)) for item in conditions):
            raise ValueError("condition references an undefined selector")

        for name, selection in selectors.items():
            selections = selection if isinstance(selection, list) else [selection]
            if not selections or len(selections) > 64 or any(
                not isinstance(item, dict) or not item
                or any(
                    not _valid_field_key(key) or not _valid_field_value(value)
                    for key, value in item.items()
                )
                for item in selections
            ):
                raise ValueError(f"invalid selection mapping: {name}")

        if len(json.dumps(self.model_dump(), ensure_ascii=False).encode("utf-8")) > _MAX_DRAFT_BYTES:
            raise ValueError("rule draft exceeds 64 KiB")
        return self

    @property
    def selector_names(self) -> list[str]:
        return sorted(name for name in self.detection if name != "condition")
