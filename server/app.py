import re
import traceback

from flask import Flask, request, jsonify
from flask_cors import CORS
from google.oauth2.credentials import Credentials
from googleapiclient.discovery import build

from src.email.fetcher import get_emails_from_domains, get_emails_by_query
from src.email.processor import extract_insights
from src.email.safety import BLOCKED_ACTIONS, safety_metadata
from src.email.query_validator import (
    QueryInsightsValidationError,
    validate_query_insights_payload,
)
from src.config.settings import TARGET_DOMAINS, CHROME_EXTENSION_ID

app = Flask(__name__)
# Form-submission requests often mean "summarize the form workflow"; keep serving
# read-only summaries while reporting that the requested side effect is blocked.
READ_THROUGH_BLOCKED_ACTIONS = {"submit_form"}
if not READ_THROUGH_BLOCKED_ACTIONS <= BLOCKED_ACTIONS:
    raise RuntimeError("READ_THROUGH_BLOCKED_ACTIONS must be blocked actions")

cors_resources = {
    r"/get_insights": {"origins": f"chrome-extension://{CHROME_EXTENSION_ID}"},
    r"/query_insights": {"origins": f"chrome-extension://{CHROME_EXTENSION_ID}"},
}
CORS(app, resources=cors_resources)


_LOG_REDACTIONS = (
    (re.compile(r"ya29\.[A-Za-z0-9._-]+"), "[REDACTED:token]"),
    (re.compile(r"1//[A-Za-z0-9._~+/-]+"), "[REDACTED:token]"),
    (re.compile(r"eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+"), "[REDACTED:token]"),
    (
        re.compile(
            r"(?i)\b(access[_-]?token|refresh[_-]?token|id[_-]?token|bearer|token)"
            r"(\s*[:=]\s*)['\"]?[^'\"\s,)}]+"
        ),
        r"\1\2[REDACTED:token]",
    ),
    (re.compile(r"/[^\s:'\"]*\.config/gmail/token\.json"), "[REDACTED:token-file]"),
    (re.compile(r"/home/[^\s:'\",)]+"), "[REDACTED:path]"),
    (re.compile(r"\bdebug_id=[A-Za-z0-9._-]+"), "debug_id=[REDACTED:debug-id]"),
    (
        re.compile(
            r"\b(RefreshError|InvalidGrantError|DefaultCredentialsError|TransportError)"
            r"(?::[^\n]*)?"
        ),
        "[REDACTED:auth-error]",
    ),
)


def _redact_log_text(text):
    redacted = text
    for pattern, replacement in _LOG_REDACTIONS:
        redacted = pattern.sub(replacement, redacted)
    return redacted


def _log_unhandled_api_exception(route):
    redacted_traceback = _redact_log_text(traceback.format_exc())
    app.logger.error(
        "Unhandled exception while processing %s; sensitive details redacted\n%s",
        route,
        redacted_traceback,
    )


def _gmail_service_from_token(token):
    creds = Credentials(token)
    return build("gmail", "v1", credentials=creds)


def _internal_error_response(message):
    return jsonify({"error": message}), 500


def _validation_error_response(exc):
    return jsonify({"error": exc.public_message}), 400


@app.route("/get_insights", methods=["POST"])
def get_insights():
    payload = request.json or {}
    token = payload.get("token")
    if not token:
        return jsonify({"error": "No token provided"}), 400

    try:
        service = _gmail_service_from_token(token)
        emails = get_emails_from_domains(service, TARGET_DOMAINS)
        insights = [extract_insights(email) for email in emails]

        return jsonify(
            {
                "mode": "read_only",
                "scope": {"target_domains": TARGET_DOMAINS},
                "insights": insights,
            }
        )
    except Exception:
        _log_unhandled_api_exception("/get_insights")
        return _internal_error_response("Unable to get insights at this time.")


@app.route("/query_insights", methods=["POST"])
def query_insights():
    payload = request.json or {}
    token = payload.get("token")

    if not token:
        return jsonify({"error": "No token provided"}), 400

    try:
        validated_payload = validate_query_insights_payload(payload)
    except QueryInsightsValidationError as exc:
        return _validation_error_response(exc)

    query = validated_payload["query"]
    max_results = validated_payload["max_results"]
    requested_actions = validated_payload["requested_actions"]

    safety = safety_metadata(requested_actions)
    blocked_actions = set(safety["blocked_actions"])
    if blocked_actions and not blocked_actions.issubset(READ_THROUGH_BLOCKED_ACTIONS):
        return (
            jsonify(
                {
                    "error": "Blocked actions requested. This API is read-only.",
                    "safety": safety,
                }
            ),
            400,
        )

    try:
        service = _gmail_service_from_token(token)
        emails = get_emails_by_query(service, query=query, max_results=max_results)
        insights = [extract_insights(email) for email in emails]

        return jsonify(
            {
                "mode": "read_only",
                "query": query,
                "safety": safety,
                "count": len(insights),
                "insights": insights,
            }
        )
    except Exception:
        _log_unhandled_api_exception("/query_insights")
        return _internal_error_response("Unable to query insights at this time.")


if __name__ == "__main__":
    app.run(debug=True)
