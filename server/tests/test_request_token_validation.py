import sys
import types
import unittest
from unittest.mock import patch

processor_stub = types.ModuleType("src.email.processor")
processor_stub.extract_insights = lambda email: email
sys.modules.setdefault("src.email.processor", processor_stub)

import app as app_module  # noqa: E402


class RequestTokenValidationRouteTests(unittest.TestCase):
    def setUp(self):
        app_module.app.config["TESTING"] = True
        self.client = app_module.app.test_client()

    def _post_with_google_mocks(self, route, payload):
        fetcher_name = (
            "app.get_emails_from_domains"
            if route == "/get_insights"
            else "app.get_emails_by_query"
        )
        with patch("app._validate_gmail_token_scope") as mock_scope, patch(
            "app._gmail_service_from_token"
        ) as mock_service, patch(fetcher_name) as mock_fetch:
            response = self.client.post(route, json=payload)

        return response, mock_scope, mock_service, mock_fetch

    def _assert_rejected_before_google(self, route, payload, expected_error):
        response, mock_scope, mock_service, mock_fetch = self._post_with_google_mocks(
            route,
            payload,
        )

        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.get_json(), {"error": expected_error})
        mock_scope.assert_not_called()
        mock_service.assert_not_called()
        mock_fetch.assert_not_called()

    def test_missing_and_blank_tokens_rejected_before_google(self):
        cases = [
            ({}, "missing"),
            ({"token": ""}, "empty"),
            ({"token": "   "}, "whitespace"),
        ]

        for route in ("/get_insights", "/query_insights"):
            for payload, label in cases:
                with self.subTest(route=route, label=label):
                    self._assert_rejected_before_google(
                        route,
                        payload,
                        "No token provided",
                    )

    def test_non_string_tokens_rejected_before_google(self):
        cases = [
            {"token": 123},
            {"token": ["ya29.secret-token"]},
            {"token": {"access_token": "ya29.secret-token"}},
        ]

        for route in ("/get_insights", "/query_insights"):
            for payload in cases:
                with self.subTest(route=route, token_type=type(payload["token"])):
                    response, mock_scope, mock_service, mock_fetch = (
                        self._post_with_google_mocks(route, payload)
                    )

                    self.assertEqual(response.status_code, 400)
                    self.assertEqual(
                        response.get_json(),
                        {"error": "Token type must be a valid string."},
                    )
                    self.assertIn("Token", response.get_json()["error"])
                    self.assertIn("string", response.get_json()["error"])
                    mock_scope.assert_not_called()
                    mock_service.assert_not_called()
                    mock_fetch.assert_not_called()

    def test_tokens_with_control_characters_rejected_before_google(self):
        cases = [
            "ya29.secret-token\n",
            "ya29.secret-token\twith-tab",
            "ya29.secret-token\x7f",
        ]

        for route in ("/get_insights", "/query_insights"):
            for token in cases:
                with self.subTest(route=route, token=repr(token)):
                    self._assert_rejected_before_google(
                        route,
                        {"token": token},
                        "Token must not contain control characters.",
                    )

    def test_overly_long_tokens_rejected_before_google(self):
        token = "a" * (app_module.MAX_REQUEST_TOKEN_LENGTH + 1)

        for route in ("/get_insights", "/query_insights"):
            with self.subTest(route=route):
                response, mock_scope, mock_service, mock_fetch = (
                    self._post_with_google_mocks(route, {"token": token})
                )

                self.assertEqual(response.status_code, 400)
                self.assertEqual(
                    response.get_json(),
                    {
                        "error": (
                            "Token exceeds max length of "
                            f"{app_module.MAX_REQUEST_TOKEN_LENGTH} characters."
                        )
                    },
                )
                mock_scope.assert_not_called()
                mock_service.assert_not_called()
                mock_fetch.assert_not_called()

    def test_max_length_token_accepted_by_both_routes(self):
        token = "a" * app_module.MAX_REQUEST_TOKEN_LENGTH
        service = object()
        cases = [
            (
                "/get_insights",
                {"token": token},
                "app.get_emails_from_domains",
            ),
            (
                "/query_insights",
                {
                    "token": token,
                    "query": "from:alerts",
                    "max_results": 3,
                },
                "app.get_emails_by_query",
            ),
        ]

        for route, payload, fetcher_name in cases:
            with self.subTest(route=route), patch(
                "app._validate_gmail_token_scope"
            ) as mock_scope, patch(
                "app._gmail_service_from_token", return_value=service
            ) as mock_service, patch(
                fetcher_name, return_value=[]
            ) as mock_fetch:
                response = self.client.post(route, json=payload)

                self.assertEqual(response.status_code, 200)
                mock_scope.assert_called_once_with(token)
                mock_service.assert_called_once_with(token)
                if route == "/get_insights":
                    mock_fetch.assert_called_once_with(
                        service, app_module.TARGET_DOMAINS
                    )
                else:
                    mock_fetch.assert_called_once_with(
                        service,
                        query="from:alerts",
                        max_results=3,
                    )

    def test_get_insights_valid_token_keeps_response_shape(self):
        service = object()
        with patch("app._validate_gmail_token_scope") as mock_scope, patch(
            "app._gmail_service_from_token", return_value=service
        ) as mock_service, patch(
            "app.get_emails_from_domains", return_value=[{"id": "email-1"}]
        ) as mock_fetch, patch(
            "app.extract_insights", side_effect=lambda email: {"insight": email["id"]}
        ):
            response = self.client.post(
                "/get_insights",
                json={"token": "ya29.valid-token"},
            )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            response.get_json(),
            {
                "mode": "read_only",
                "scope": {"target_domains": app_module.TARGET_DOMAINS},
                "insights": [{"insight": "email-1"}],
            },
        )
        mock_scope.assert_called_once_with("ya29.valid-token")
        mock_service.assert_called_once_with("ya29.valid-token")
        mock_fetch.assert_called_once_with(service, app_module.TARGET_DOMAINS)

    def test_query_insights_valid_token_keeps_response_shape(self):
        service = object()
        with patch("app._validate_gmail_token_scope") as mock_scope, patch(
            "app._gmail_service_from_token", return_value=service
        ) as mock_service, patch(
            "app.get_emails_by_query", return_value=[{"id": "email-1"}]
        ) as mock_fetch, patch(
            "app.extract_insights", side_effect=lambda email: {"insight": email["id"]}
        ):
            response = self.client.post(
                "/query_insights",
                json={
                    "token": "ya29.valid-token",
                    "query": "from:alerts",
                    "max_results": 3,
                },
            )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            response.get_json(),
            {
                "mode": "read_only",
                "query": "from:alerts",
                "safety": {
                    "mode": "read_only",
                    "effective_actions": ["read", "summarize"],
                    "blocked_actions": [],
                },
                "count": 1,
                "insights": [{"insight": "email-1"}],
            },
        )
        mock_scope.assert_called_once_with("ya29.valid-token")
        mock_service.assert_called_once_with("ya29.valid-token")
        mock_fetch.assert_called_once_with(service, query="from:alerts", max_results=3)


if __name__ == "__main__":
    unittest.main()
