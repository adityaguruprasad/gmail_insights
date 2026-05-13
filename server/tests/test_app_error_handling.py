import sys
import types
import unittest
from unittest.mock import patch


anthropic_stub = types.ModuleType("anthropic")
anthropic_stub.HUMAN_PROMPT = "\n\nHuman:"
anthropic_stub.AI_PROMPT = "\n\nAssistant:"


class _StubAnthropic:
    def __init__(self, api_key=None):
        self.api_key = api_key
        self.completions = types.SimpleNamespace(
            create=lambda **kwargs: types.SimpleNamespace(completion="ok")
        )


anthropic_stub.Anthropic = _StubAnthropic
sys.modules.setdefault("anthropic", anthropic_stub)

import app as app_module  # noqa: E402


def _fixture_secret(*parts):
    return "".join(parts)


def _openai_project_api_key_fixture():
    return _fixture_secret(
        "sk",
        "-",
        "proj",
        "-",
        "abcdEFGHij",
        "klMNOPqrst",
        "UVWXyz0123",
        "456789_-AB",
    )


def _basic_auth_credential_fixture():
    return _fixture_secret("cmVh", "ZGVy", "OnNh", "bXBs", "ZS1w", "YXNz", "MTIz")


def _sensitive_error_message():
    return (
        f"api_key={_openai_project_api_key_fixture()} "
        f"Authorization: Basic {_basic_auth_credential_fixture()} "
        "Cookie: sid=session-cookie-secret-123; theme=dark\n"
        "RefreshError: token ya29.secret-token failed with "
        "refresh_token=1//refresh-secret id_token=eyJheader.eyJpayload.signature "
        "at /home/aditya/.config/gmail/token.json and "
        "/home/aditya/projects/gmail_insights/server/app.py debug_id=abc123"
    )


class ApiErrorHandlingTests(unittest.TestCase):
    def setUp(self):
        app_module.app.config["TESTING"] = True
        self.client = app_module.app.test_client()
        self.scope_guard = patch("app._validate_gmail_token_scope", return_value=None)
        self.scope_guard.start()
        self.addCleanup(self.scope_guard.stop)

    def assert_sensitive_text_absent(self, response_body):
        serialized = str(response_body)
        self.assertNotIn("ya29.secret-token", serialized)
        self.assertNotIn("1//refresh-secret", serialized)
        self.assertNotIn("eyJheader.eyJpayload.signature", serialized)
        self.assertNotIn("/home/aditya/.config/gmail/token.json", serialized)
        self.assertNotIn("/home/aditya/projects/gmail_insights/server/app.py", serialized)
        self.assertNotIn("RefreshError", serialized)
        self.assertNotIn("InvalidGrantError", serialized)
        self.assertNotIn("debug_id=abc123", serialized)
        self.assertNotIn(_openai_project_api_key_fixture(), serialized)
        self.assertNotIn(_basic_auth_credential_fixture(), serialized)
        self.assertNotIn("session-cookie-secret-123", serialized)

    def assert_sanitized_exception_logged(self, logs, route):
        self.assertIn(f"Unhandled exception while processing {route}", logs)
        self.assertIn("Traceback", logs)
        self.assertIn("[REDACTED:", logs)
        self.assertIn("[REDACTED_OPENAI_API_KEY]", logs)
        self.assertIn("Basic [REDACTED_BASIC_AUTH]", logs)
        self.assertIn("sid=[REDACTED_COOKIE_SECRET]", logs)
        self.assert_sensitive_text_absent(logs)

    def test_get_insights_500_response_is_sanitized_and_exception_is_logged(self):
        sensitive_error = RuntimeError(_sensitive_error_message())

        with patch("app._gmail_service_from_token", return_value=object()), patch(
            "app.get_emails_from_domains", side_effect=sensitive_error
        ), self.assertLogs(app_module.app.logger.name, level="ERROR") as captured:
            response = self.client.post(
                "/get_insights",
                json={"token": "ya29.secret-token"},
            )

        self.assertEqual(response.status_code, 500)
        body = response.get_json()
        self.assertEqual(body, {"error": "Unable to get insights at this time."})
        self.assert_sensitive_text_absent(body)

        logs = "\n".join(captured.output)
        self.assert_sanitized_exception_logged(logs, "/get_insights")

    def test_query_insights_500_response_is_sanitized_and_exception_is_logged(self):
        sensitive_error = RuntimeError(_sensitive_error_message())

        with patch("app._gmail_service_from_token", return_value=object()), patch(
            "app.get_emails_by_query", side_effect=sensitive_error
        ), self.assertLogs(app_module.app.logger.name, level="ERROR") as captured:
            response = self.client.post(
                "/query_insights",
                json={"token": "ya29.secret-token", "query": "in:inbox"},
            )

        self.assertEqual(response.status_code, 500)
        body = response.get_json()
        self.assertEqual(body, {"error": "Unable to query insights at this time."})
        self.assert_sensitive_text_absent(body)

        logs = "\n".join(captured.output)
        self.assert_sanitized_exception_logged(logs, "/query_insights")


if __name__ == "__main__":
    unittest.main()
