"""Bounded structural preflight for JSON Sigma rule drafts.

This is intentionally *not* pySigma semantic validation, conversion, or
execution. It rejects malformed drafts early before E1 rule persistence.
"""
from __future__ import annotations

import json
import math
import re
import unicodedata
from fnmatch import fnmatchcase
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, model_validator

_MAX_DRAFT_BYTES = 65536
_MAX_CONDITION_NESTING = 64
# Structural subset of Sigma timeframe durations; semantic validity is deferred.
_TIMEFRAME = re.compile(r"^[1-9][0-9]{0,5}(?:s|m|h|d|w|M|y)$")
_SELECTOR_NAME = re.compile(r"^[A-Za-z][A-Za-z0-9_]*$")
_LOGSOURCE_KEYS = {"category", "product", "service", "definition"}

_CONDITION_IDENTIFIERS = re.compile(r"[A-Za-z][A-Za-z0-9_*]*")
_CONDITION_KEYWORDS = {"and", "or", "not", "of", "all", "them"}
_CONDITION_TOKENS = re.compile(r"[A-Za-z][A-Za-z0-9_*]*|[0-9]+|[()]")  # lexical subset
_CONDITION_PATTERN = re.compile(r"^[A-Za-z][A-Za-z0-9_*]*$")


def _well_formed_boolean_condition(condition: str) -> bool:
    """Parse the basic selector/and/or/not/quantifier subset before an aggregation.

    This is intentionally not pySigma semantic validation. Reject broken
    expressions (including punctuation silently skipped by a regex scan)
    without interpreting aggregation pipelines after the first pipe.
    """
    expression = condition.split("|", 1)[0]
    # Bound recursive-descent depth for untrusted rule drafts. The maximum
    # input length alone does not guarantee a shallow parse tree.
    depth = 0
    for char in expression:
        if char == "(":
            depth += 1
            if depth > _MAX_CONDITION_NESTING:
                return False
        elif char == ")":
            depth -= 1
            if depth < 0:
                return False
    if depth:
        return False
    matches = list(_CONDITION_TOKENS.finditer(expression))
    if not matches:
        return False
    offset = 0
    tokens = []
    for match in matches:
        if expression[offset:match.start()].strip():
            return False
        tokens.append(match.group())
        offset = match.end()
    if expression[offset:].strip():
        return False

    # Regex tokenization alone accepts malformed concatenations such as
    # "2of them" by splitting a digit from the adjacent keyword. Sigma
    # quantifiers require separators around "of"; preserve tabs/newlines.
    for position in range(len(matches) - 2):
        first, operator, target = matches[position:position + 3]
        if (
            (first.group().isdigit() or first.group().lower() == "all")
            and operator.group().lower() == "of"
            and (first.end() == operator.start() or operator.end() == target.start())
        ):
            return False

    index = 0

    def atom() -> bool:
        nonlocal index
        if index >= len(tokens):
            return False
        token = tokens[index]
        index += 1
        lower = token.lower()
        if lower == "not":
            return atom()
        if token == "(":
            if not disjunction() or index >= len(tokens) or tokens[index] != ")":
                return False
            index += 1
            return True
        if lower == "all" or token.isdigit():
            if token.isdigit() and int(token) < 1:
                return False
            if index + 1 >= len(tokens) or tokens[index].lower() != "of":
                return False
            index += 1
            target = tokens[index]
            index += 1
            return target.lower() == "them" or bool(_CONDITION_PATTERN.fullmatch(target))
        if lower in _CONDITION_KEYWORDS or token == ")" or "*" in token:
            return False
        return bool(_SELECTOR_NAME.fullmatch(token))

    def conjunction() -> bool:
        nonlocal index
        if not atom():
            return False
        while index < len(tokens) and tokens[index].lower() == "and":
            index += 1
            if not atom():
                return False
        return True

    def disjunction() -> bool:
        nonlocal index
        if not conjunction():
            return False
        while index < len(tokens) and tokens[index].lower() == "or":
            index += 1
            if not conjunction():
                return False
        return True

    return disjunction() and index == len(tokens)


def _valid_aggregation_boundary(condition: str) -> bool:
    """Reject empty or repeated aggregation pipes without parsing pySigma semantics.

    A condition may have one aggregation segment after its boolean selector
    expression. An empty suffix (or a second pipe) is an incomplete draft,
    not a meaningful aggregation to defer to semantic validation.
    """
    if "|" not in condition:
        return True
    before, _, after = condition.partition("|")
    # A suffix made entirely of combining marks can pass str.strip() even
    # though it contains no readable aggregation expression. This is always
    # an incomplete draft, regardless of future pySigma grammar support.
    return bool(before.strip() and after.strip()) and _has_visible_character(after) and "|" not in after


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
        any(fnmatchcase(name, word) for name in selectors)
        if "*" in word else word in selectors
        for word in references
    )


def _feasible_quantifiers(condition: str, selectors: set[str]) -> bool:
    """Reject numeric 'N of ...' requests with too few matching selectors.

    This only checks the count of declared selector names, not pySigma
    aggregation or full rule semantics. Impossible counts cannot match.
    """
    tokens = _CONDITION_TOKENS.findall(condition.split("|", 1)[0])
    for index in range(len(tokens) - 2):
        count, operator, target = tokens[index:index + 3]
        if not count.isdigit() or operator.lower() != "of":
            continue
        if target.lower() == "them":
            available = len(selectors)
        elif "*" in target:
            available = sum(fnmatchcase(name, target) for name in selectors)
        else:
            available = int(target in selectors)
        if int(count) > available:
            return False
    return True


def _invisible_field_character(char: str) -> bool:
    """Flag characters that can hide or split field identifiers in rule review.

    Do not reject ordinary combining accents or plain ASCII spaces.
    Non-ASCII Unicode space separators (such as NBSP and thin space) can
    look like regular spaces while parsing differently in downstream Sigma
    tooling; reject them in reviewer-facing identifiers and conditions.
    """
    category = unicodedata.category(char)
    return (
        category in {"Cc", "Cf", "Cs", "Zl", "Zp"}
        or (category == "Zs" and char != " ")
        or char == "\u034f"  # Combining grapheme joiner
        or "\ufe00" <= char <= "\ufe0f"  # Variation selectors
        or "\U000e0100" <= char <= "\U000e01ef"
    )


def _has_visible_character(value: str) -> bool:
    """Require a visible base character, not just standalone combining marks."""
    return any(
        not char.isspace() and not unicodedata.category(char).startswith(("C", "M"))
        for char in value
    )


def _valid_metadata_text(value: str) -> bool:
    """Reject invisible or ambiguous text in reviewer-facing rule metadata."""
    return (
        bool(value.strip())
        and _has_visible_character(value)
        and value == value.strip()
        and not any(_invisible_field_character(char) for char in value)
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
    # Keep legitimate field names with internal spaces or punctuation, but
    # reject hidden controls, bidi overrides, and ambiguous edge whitespace.
    # Such names are hard to review safely in a detection-rule editor.
    return (
        bool(field)
        and _has_visible_character(field)
        and field == field.strip()
        and not any(_invisible_field_character(char) for char in field)
        and all(_SELECTOR_NAME.fullmatch(modifier) for modifier in modifiers)
    )


def _valid_scalar(value: Any) -> bool:
    """Only JSON scalar Sigma field values; no nested objects or arrays."""
    if value is None or isinstance(value, bool):
        return True
    if isinstance(value, int):
        # Python 3.11+ rejects decimal serialization of extremely large ints
        # (normally >4300 digits). A malicious JSON/Python draft must fail
        # preflight with a validation error, not a 500 during json.dumps.
        # 4096 bits still permits identifiers much wider than 64/128 bits.
        return value.bit_length() <= 4096
    if isinstance(value, float):
        return math.isfinite(value)
    # JSON may legally escape a lone UTF-16 surrogate (\\ud800), but it is
    # not valid UTF-8. Without this guard the final byte-size check raises
    # UnicodeEncodeError and a malformed draft becomes a server error.
    return (
        isinstance(value, str)
        and len(value) <= 2048
        and not any(unicodedata.category(char) == "Cs" for char in value)
    )


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
        if not _valid_metadata_text(self.title):
            raise ValueError("title must not contain invisible characters or edge whitespace")
        if not self.logsource or not ({"category", "product", "service"} & self.logsource.keys()):
            raise ValueError("logsource requires category, product, or service")
        if any(
            key not in _LOGSOURCE_KEYS or not _valid_metadata_text(value) or len(value) > 200
            for key, value in self.logsource.items()
        ):
            raise ValueError("invalid logsource field")

        # The existing detection_rules.log_source column is VARCHAR(100).
        # Reject oversize values at the API boundary rather than failing
        # midway through a database transaction with a server error.
        if any(len(self.logsource[key]) > 100 for key in ("product", "category", "service")
               if key in self.logsource):
            raise ValueError("logsource identifier exceeds 100 characters")

        timeframe = self.detection.get("timeframe")
        if "timeframe" in self.detection and (
            not isinstance(timeframe, str) or not _TIMEFRAME.fullmatch(timeframe)
        ):
            raise ValueError("timeframe must be a bounded Sigma duration")

        selectors = {
            name: value for name, value in self.detection.items()
            if name not in {"condition", "timeframe"}
        }
        if not selectors or len(selectors) > 64:
            raise ValueError("detection requires 1 to 64 selectors")
        if any(
            not _SELECTOR_NAME.fullmatch(name) or name.lower() in _CONDITION_KEYWORDS
            for name in selectors
        ):
            raise ValueError("invalid selector name")

        condition = self.detection.get("condition")
        conditions = [condition] if isinstance(condition, str) else condition
        if (
            not isinstance(conditions, list) or not 1 <= len(conditions) <= 8
            or any(not isinstance(item, str) or not item.strip() or len(item) > 512
                   for item in conditions)
        ):
            raise ValueError("detection requires non-empty condition text")

        # The boolean parser examines only the part before an aggregation
        # pipe. Validate the entire condition first: a hidden bidi control
        # or lone UTF-16 surrogate in the suffix could otherwise bypass the
        # parser, mislead reviewers, or raise UnicodeEncodeError during the
        # final UTF-8 size check. Preserve ordinary multiline formatting.
        if any(
            _invisible_field_character(char) and char not in "\t\n\r"
            for item in conditions for char in item
        ):
            raise ValueError("condition contains invisible or invalid Unicode")

        if any(not _references_known_selectors(item, set(selectors)) for item in conditions):
            raise ValueError("condition references an undefined selector")
        if any(not _valid_aggregation_boundary(item) for item in conditions):
            raise ValueError("condition has malformed aggregation boundary")
        if any(not _well_formed_boolean_condition(item) for item in conditions):
            raise ValueError("condition has malformed boolean syntax")
        if any(not _feasible_quantifiers(item, set(selectors)) for item in conditions):
            raise ValueError("condition quantifier exceeds matching selectors")

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
        return sorted(name for name in self.detection if name not in {"condition", "timeframe"})
