import unittest
import sys
import types
from unittest.mock import patch

processor_stub = types.ModuleType("src.email.processor")
processor_stub.extract_insights = lambda email: email
sys.modules.setdefault("src.email.processor", processor_stub)

import app as app_module


class QueryInsightsValidationTests(unittest.TestCase):
    def setUp(self):
        app_module.app.config["TESTING"] = True
        self.client = app_module.app.test_client()

    def test_invalid_max_results_rejected(self):
        with patch("app._gmail_service_from_token") as mock_gmail:
            response = self.client.post(
                "/query_insights",
                json={"token": "***", "query": "in:inbox", "max_results": "abc"},
            )

        self.assertEqual(response.status_code, 400)
        self.assertIn("max_results", response.get_json()["error"])
        mock_gmail.assert_not_called()

    def test_fractional_max_results_rejected(self):
        with patch("app._gmail_service_from_token") as mock_gmail:
            response = self.client.post(
                "/query_insights",
                json={"token": "***", "query": "in:inbox", "max_results": 5.7},
            )

        self.assertEqual(response.status_code, 400)
        self.assertIn("max_results", response.get_json()["error"])
        mock_gmail.assert_not_called()

    def test_overly_long_query_rejected(self):
        long_query = "a" * 513
        with patch("app._gmail_service_from_token") as mock_gmail:
            response = self.client.post(
                "/query_insights",
                json={"token": "test-token", "query": long_query},
            )

        self.assertEqual(response.status_code, 400)
        self.assertIn("query", response.get_json()["error"])
        mock_gmail.assert_not_called()

    def test_query_with_control_characters_rejected(self):
        with patch("app._gmail_service_from_token") as mock_gmail:
            response = self.client.post(
                "/query_insights",
                json={"token": "test-token", "query": "from:alerts\nsubject:urgent"},
            )

        self.assertEqual(response.status_code, 400)
        self.assertIn("control characters", response.get_json()["error"])
        mock_gmail.assert_not_called()

    def test_empty_query_defaults_to_inbox(self):
        with patch("app._gmail_service_from_token", return_value=object()), patch(
            "app.get_emails_by_query", return_value=[]
        ) as mock_fetch:
            response = self.client.post(
                "/query_insights",
                json={"token": "test-token", "query": "   "},
            )

        self.assertEqual(response.status_code, 200)
        body = response.get_json()
        self.assertEqual(body["query"], "in:inbox")
        mock_fetch.assert_called_once()
        self.assertEqual(mock_fetch.call_args.kwargs["query"], "in:inbox")

    def test_blocked_requested_actions_still_rejected(self):
        with patch("app._gmail_service_from_token") as mock_gmail:
            response = self.client.post(
                "/query_insights",
                json={
                    "token": "test-token",
                    "query": "in:inbox",
                    "requested_actions": "read,delete",
                },
            )

        self.assertEqual(response.status_code, 400)
        body = response.get_json()
        self.assertIn("Blocked actions requested", body["error"])
        self.assertIn("delete", body["safety"]["blocked_actions"])
        mock_gmail.assert_not_called()


if __name__ == "__main__":
    unittest.main()
