from flask import Flask, request, jsonify
from flask_cors import CORS
from google.oauth2.credentials import Credentials
from googleapiclient.discovery import build

from src.email.fetcher import get_emails_from_domains, get_emails_by_query
from src.email.processor import extract_insights
from src.email.safety import safety_metadata
from src.config.settings import TARGET_DOMAINS, CHROME_EXTENSION_ID

app = Flask(__name__)

cors_resources = {
    r"/get_insights": {"origins": f"chrome-extension://{CHROME_EXTENSION_ID}"},
    r"/query_insights": {"origins": f"chrome-extension://{CHROME_EXTENSION_ID}"},
}
CORS(app, resources=cors_resources)


def _gmail_service_from_token(token):
    creds = Credentials(token)
    return build("gmail", "v1", credentials=creds)


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
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/query_insights", methods=["POST"])
def query_insights():
    payload = request.json or {}
    token = payload.get("token")
    query = payload.get("query", "in:inbox")
    max_results = int(payload.get("max_results", 25))
    requested_actions = payload.get("requested_actions")

    if not token:
        return jsonify({"error": "No token provided"}), 400

    safety = safety_metadata(requested_actions)
    if safety["blocked_actions"]:
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
    except Exception as e:
        return jsonify({"error": str(e)}), 500


if __name__ == "__main__":
    app.run(debug=True)
