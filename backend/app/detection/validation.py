"""Bounded structural preflight for JSON Sigma rule drafts.

This is intentionally *not* pySigma semantic validation, conversion, or
execution. It rejects malformed drafts early before E1 rule persistence.
"""
from __future__ import annotations

import json
import re
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, model_validator

_MAX_DRAFT_BYTES = 65536
_SELECTOR_NAME = re.compile(r"^[A-Za-z][A-Za-z0-9_]*$")
_LOGSOURCE_KEYS = {"category", "product", "service", "definition"}


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

        for name, selection in selectors.items():
            selections = selection if isinstance(selection, list) else [selection]
            if not selections or len(selections) > 64 or any(
                not isinstance(item, dict) or not item
                or any(not isinstance(key, str) or not key.strip() for key in item)
                for item in selections
            ):
                raise ValueError(f"invalid selection mapping: {name}")

        if len(json.dumps(self.model_dump(), ensure_ascii=False).encode("utf-8")) > _MAX_DRAFT_BYTES:
            raise ValueError("rule draft exceeds 64 KiB")
        return self

    @property
    def selector_names(self) -> list[str]:
        return sorted(name for name in self.detection if name != "condition")
