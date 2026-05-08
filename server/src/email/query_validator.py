"""Validation helpers for /query_insights payloads."""

from collections.abc import Iterable, Mapping
from typing import Any, Dict, List

from src.email.safety import ALLOWED_ACTIONS, BLOCKED_ACTIONS

DEFAULT_QUERY = "in:inbox"
DEFAULT_MAX_RESULTS = 25
MAX_QUERY_LENGTH = 512
MIN_RESULTS = 1
MAX_RESULTS = 100
MAX_ACTION_LENGTH = 64
MAX_REQUESTED_ACTIONS = 20
SUPPORTED_ACTIONS = ALLOWED_ACTIONS | BLOCKED_ACTIONS


class QueryInsightsValidationError(ValueError):
    """Raised when /query_insights payload validation fails."""

    def __init__(self, message: str = "Invalid request"):
        super().__init__(message)
        self.public_message = message


def _normalize_requested_actions(actions: Any) -> List[str] | None:
    if actions is None:
        return None
    if isinstance(actions, str):
        raw_parts = actions.split(",")
    elif isinstance(actions, Mapping):
        raise QueryInsightsValidationError("Invalid requested_actions: must be action names")
    elif isinstance(actions, Iterable):
        raw_parts = []
        for part in actions:
            if isinstance(part, str):
                raw_parts.append(part)
            elif part is None or isinstance(part, Mapping) or isinstance(part, Iterable):
                raise QueryInsightsValidationError(
                    "Invalid requested_actions: entries must be scalar action names"
                )
            else:
                raw_parts.append(str(part))
            if len(raw_parts) > MAX_REQUESTED_ACTIONS:
                raise QueryInsightsValidationError(
                    f"Invalid requested_actions: must include {MAX_REQUESTED_ACTIONS} actions or fewer"
                )
    else:
        raise QueryInsightsValidationError(
            "Invalid requested_actions: must be a comma-separated string or a list of action names"
        )

    if len(raw_parts) > MAX_REQUESTED_ACTIONS:
        raise QueryInsightsValidationError(
            f"Invalid requested_actions: must include {MAX_REQUESTED_ACTIONS} actions or fewer"
        )

    normalized = []
    seen = set()
    for raw_part in raw_parts:
        if len(raw_part) > MAX_ACTION_LENGTH:
            raise QueryInsightsValidationError(
                f"Invalid requested_actions: action entries must be {MAX_ACTION_LENGTH} characters or fewer"
            )
        if any(ord(char) < 32 or ord(char) == 127 for char in raw_part):
            raise QueryInsightsValidationError(
                "Invalid requested_actions: control characters are not allowed"
            )

        part = raw_part.strip()
        if not part:
            continue

        action = part.lower()
        if action not in SUPPORTED_ACTIONS:
            raise QueryInsightsValidationError(
                f"Invalid requested_actions: unsupported action '{action}'"
            )
        if action in seen:
            continue
        seen.add(action)
        normalized.append(action)

    return normalized


def _validate_query(raw_query: Any) -> str:
    if raw_query is None:
        return DEFAULT_QUERY
    if not isinstance(raw_query, str):
        raise QueryInsightsValidationError("Invalid query: must be a string")

    query = raw_query.strip()
    if not query:
        return DEFAULT_QUERY
    if len(query) > MAX_QUERY_LENGTH:
        raise QueryInsightsValidationError("Invalid query: must be 512 characters or fewer")
    if any(ord(char) < 32 or ord(char) == 127 for char in query):
        raise QueryInsightsValidationError("Invalid query: control characters are not allowed")

    return query


def _validate_max_results(raw_max_results: Any) -> int:
    if raw_max_results is None:
        return DEFAULT_MAX_RESULTS
    if isinstance(raw_max_results, bool):
        raise QueryInsightsValidationError("Invalid max_results: must be an integer between 1 and 100")

    candidate = raw_max_results
    if isinstance(raw_max_results, str):
        candidate = raw_max_results.strip()
        if not candidate:
            raise QueryInsightsValidationError("Invalid max_results: must be an integer between 1 and 100")

    if isinstance(candidate, float) and not candidate.is_integer():
        raise QueryInsightsValidationError("Invalid max_results: must be an integer between 1 and 100")

    try:
        max_results = int(candidate)
    except (TypeError, ValueError) as exc:
        raise QueryInsightsValidationError(
            "Invalid max_results: must be an integer between 1 and 100"
        ) from exc

    if not MIN_RESULTS <= max_results <= MAX_RESULTS:
        raise QueryInsightsValidationError("Invalid max_results: must be between 1 and 100")

    return max_results


def validate_query_insights_payload(payload: Mapping[str, Any] | None) -> Dict[str, Any]:
    """Validate and normalize the subset of payload fields used by /query_insights."""
    if payload is None:
        payload = {}
    if not isinstance(payload, Mapping):
        raise QueryInsightsValidationError("Invalid request payload")

    return {
        "query": _validate_query(payload.get("query")),
        "max_results": _validate_max_results(payload.get("max_results")),
        "requested_actions": _normalize_requested_actions(payload.get("requested_actions")),
    }
