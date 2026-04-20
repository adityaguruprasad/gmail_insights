"""Validation helpers for /query_insights payloads."""

from collections.abc import Iterable, Mapping
from typing import Any, Dict, List

DEFAULT_QUERY = "in:inbox"
DEFAULT_MAX_RESULTS = 25
MAX_QUERY_LENGTH = 512
MIN_RESULTS = 1
MAX_RESULTS = 100


class QueryInsightsValidationError(ValueError):
    """Raised when /query_insights payload validation fails."""


def _normalize_requested_actions(actions: Any) -> List[str] | None:
    if actions is None:
        return None
    if isinstance(actions, str):
        parts = [part.strip() for part in actions.split(",")]
    elif isinstance(actions, Iterable):
        parts = [str(part).strip() for part in actions]
    else:
        parts = [str(actions).strip()]

    return [part.lower() for part in parts if part]


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
