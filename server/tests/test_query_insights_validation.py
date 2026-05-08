import unittest
import sys
import types
from unittest.mock import patch

processor_stub = types.ModuleType("src.email.processor")
processor_stub.extract_insights = lambda email: email
sys.modules.setdefault("src.email.processor", processor_stub)

import app as app_module  # noqa: E402
from src.email.query_validator import (  # noqa: E402
    MAX_ACTION_LENGTH,
    MAX_REQUESTED_ACTIONS,
    QueryInsightsValidationError,
    _normalize_requested_actions,
)


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

    def test_unknown_requested_actions_rejected_before_gmail(self):
        with patch("app._gmail_service_from_token") as mock_gmail:
            response = self.client.post(
                "/query_insights",
                json={
                    "token": "test-token",
                    "query": "in:inbox",
                    "requested_actions": "read,send_email",
                },
            )

        self.assertEqual(response.status_code, 400)
        body = response.get_json()
        self.assertIn("requested_actions", body["error"])
        self.assertIn("send_email", body["error"])
        mock_gmail.assert_not_called()

    def test_structured_requested_actions_rejected_before_gmail(self):
        cases = [
            {"read": True},
            ["read", ["draft"]],
        ]

        for requested_actions in cases:
            with self.subTest(requested_actions=requested_actions):
                with patch("app._gmail_service_from_token") as mock_gmail:
                    response = self.client.post(
                        "/query_insights",
                        json={
                            "token": "test-token",
                            "query": "in:inbox",
                            "requested_actions": requested_actions,
                        },
                    )

                self.assertEqual(response.status_code, 400)
                self.assertIn("requested_actions", response.get_json()["error"])
                mock_gmail.assert_not_called()

    def test_requested_action_control_characters_rejected_before_gmail(self):
        with patch("app._gmail_service_from_token") as mock_gmail:
            response = self.client.post(
                "/query_insights",
                json={
                    "token": "test-token",
                    "query": "in:inbox",
                    "requested_actions": "read,\nsummarize",
                },
            )

        self.assertEqual(response.status_code, 400)
        body = response.get_json()
        self.assertIn("requested_actions", body["error"])
        self.assertIn("control characters", body["error"])
        mock_gmail.assert_not_called()

    def test_whitespace_padded_requested_action_over_max_rejected_before_gmail(self):
        padded_action = (" " * MAX_ACTION_LENGTH) + "read"

        with patch("app._gmail_service_from_token") as mock_gmail:
            response = self.client.post(
                "/query_insights",
                json={
                    "token": "test-token",
                    "query": "in:inbox",
                    "requested_actions": padded_action,
                },
            )

        self.assertEqual(response.status_code, 400)
        body = response.get_json()
        self.assertIn("requested_actions", body["error"])
        self.assertIn(str(MAX_ACTION_LENGTH), body["error"])
        mock_gmail.assert_not_called()

    def test_too_many_requested_actions_list_rejected_before_gmail(self):
        requested_actions = ["read"] * (MAX_REQUESTED_ACTIONS + 1)

        with patch("app._gmail_service_from_token") as mock_gmail:
            response = self.client.post(
                "/query_insights",
                json={
                    "token": "test-token",
                    "query": "in:inbox",
                    "requested_actions": requested_actions,
                },
            )

        self.assertEqual(response.status_code, 400)
        body = response.get_json()
        self.assertIn("requested_actions", body["error"])
        self.assertIn(str(MAX_REQUESTED_ACTIONS), body["error"])
        mock_gmail.assert_not_called()

    def test_too_many_requested_actions_string_rejected_before_gmail(self):
        requested_actions = ",".join(["read"] * (MAX_REQUESTED_ACTIONS + 1))

        with patch("app._gmail_service_from_token") as mock_gmail:
            response = self.client.post(
                "/query_insights",
                json={
                    "token": "test-token",
                    "query": "in:inbox",
                    "requested_actions": requested_actions,
                },
            )

        self.assertEqual(response.status_code, 400)
        body = response.get_json()
        self.assertIn("requested_actions", body["error"])
        self.assertIn(str(MAX_REQUESTED_ACTIONS), body["error"])
        mock_gmail.assert_not_called()

    def test_too_many_requested_actions_iterable_stops_before_sentinel(self):
        consumed = []

        def requested_actions():
            for index in range(MAX_REQUESTED_ACTIONS + 1):
                consumed.append(index)
                yield "read"
            consumed.append("sentinel")
            raise AssertionError("sentinel item should not be consumed")

        with self.assertRaises(QueryInsightsValidationError) as context:
            _normalize_requested_actions(requested_actions())

        self.assertIn(str(MAX_REQUESTED_ACTIONS), context.exception.public_message)
        self.assertEqual(consumed, list(range(MAX_REQUESTED_ACTIONS + 1)))

    def test_invalid_requested_actions_iterable_entry_at_limit_keeps_scalar_error(self):
        for invalid_entry in (None, {"read": True}, ["draft"]):
            requested_actions = ["read"] * MAX_REQUESTED_ACTIONS + [invalid_entry]

            with self.subTest(invalid_entry=invalid_entry):
                with self.assertRaises(QueryInsightsValidationError) as context:
                    _normalize_requested_actions(requested_actions)

                self.assertIn(
                    "entries must be scalar action names",
                    context.exception.public_message,
                )

    def test_requested_actions_string_empty_parts_count_toward_max(self):
        requested_actions = "," * MAX_REQUESTED_ACTIONS

        with self.assertRaises(QueryInsightsValidationError) as context:
            _normalize_requested_actions(requested_actions)

        self.assertIn(str(MAX_REQUESTED_ACTIONS), context.exception.public_message)

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

    def test_valid_comma_separated_requested_actions_are_normalized(self):
        service = object()
        with patch("app._gmail_service_from_token", return_value=service), patch(
            "app.get_emails_by_query", return_value=[{"id": "email-1"}]
        ) as mock_fetch:
            response = self.client.post(
                "/query_insights",
                json={
                    "token": "test-token",
                    "query": "from:alerts",
                    "max_results": 3,
                    "requested_actions": " READ, draft, archive_suggestion, ",
                },
            )

        self.assertEqual(response.status_code, 200)
        body = response.get_json()
        self.assertEqual(
            body["safety"],
            {
                "mode": "read_only",
                "effective_actions": ["archive_suggestion", "draft", "read"],
                "blocked_actions": [],
            },
        )
        mock_fetch.assert_called_once_with(service, query="from:alerts", max_results=3)

    def test_duplicate_requested_actions_are_normalized_once(self):
        service = object()
        with patch("app._gmail_service_from_token", return_value=service), patch(
            "app.get_emails_by_query", return_value=[]
        ), patch("app.safety_metadata", wraps=app_module.safety_metadata) as mock_safety:
            response = self.client.post(
                "/query_insights",
                json={
                    "token": "test-token",
                    "query": "in:inbox",
                    "requested_actions": ["READ", "read", "draft", "READ", "draft"],
                },
            )

        self.assertEqual(response.status_code, 200)
        body = response.get_json()
        mock_safety.assert_called_once_with(["read", "draft"])
        self.assertEqual(body["safety"]["effective_actions"], ["draft", "read"])

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

    def test_unsubscribe_requested_action_is_supported_but_blocked(self):
        with patch("app._gmail_service_from_token") as mock_gmail:
            response = self.client.post(
                "/query_insights",
                json={
                    "token": "test-token",
                    "query": "in:inbox",
                    "requested_actions": "unsubscribe",
                },
            )

        self.assertEqual(response.status_code, 400)
        body = response.get_json()
        self.assertIn("Blocked actions requested", body["error"])
        self.assertNotIn("unsupported action", body["error"])
        self.assertEqual(
            body["safety"],
            {
                "mode": "read_only",
                "effective_actions": ["read", "summarize"],
                "blocked_actions": ["unsubscribe"],
            },
        )
        mock_gmail.assert_not_called()

    def test_mailbox_mutation_requested_actions_are_supported_but_blocked(self):
        mutation_actions = [
            "mark_read",
            "mark_unread",
            "star",
            "unstar",
            "move_to_spam",
            "move_to_inbox",
            "snooze",
            "create_filter",
        ]

        with patch("app._gmail_service_from_token") as mock_gmail:
            response = self.client.post(
                "/query_insights",
                json={
                    "token": "test-token",
                    "query": "in:inbox",
                    "requested_actions": mutation_actions,
                },
            )

        self.assertEqual(response.status_code, 400)
        body = response.get_json()
        self.assertIn("Blocked actions requested", body["error"])
        self.assertNotIn("unsupported action", body["error"])
        self.assertEqual(body["safety"]["blocked_actions"], sorted(mutation_actions))
        self.assertFalse(
            set(mutation_actions).intersection(body["safety"]["effective_actions"])
        )
        mock_gmail.assert_not_called()


if __name__ == "__main__":
    unittest.main()
