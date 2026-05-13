import unittest
import sys
import types
from unittest.mock import patch

processor_stub = types.ModuleType("src.email.processor")
processor_stub.extract_insights = lambda email: email
sys.modules.setdefault("src.email.processor", processor_stub)

import app as app_module  # noqa: E402

# Keep this app import stub from leaking into tests that need the real processor.
if sys.modules.get("src.email.processor") is processor_stub:
    del sys.modules["src.email.processor"]
    email_package = sys.modules.get("src.email")
    if getattr(email_package, "processor", None) is processor_stub:
        delattr(email_package, "processor")

from src.email.query_validator import (  # noqa: E402
    MAX_ACTION_LENGTH,
    MAX_REQUESTED_ACTIONS,
    QueryInsightsValidationError,
    _normalize_requested_actions,
)


def _fixture_secret(*parts):
    return "".join(parts)


def _google_oauth_token_fixture():
    return _fixture_secret(
        "ya29.",
        "a0afh6sm",
        "abcdefghijklmnopqrstuvwxyz",
        "_0123456789",
    )


def _access_token_fixture():
    return _fixture_secret("access", "token", "value", "1234567890")


def _aws_access_key_id_fixture():
    return _fixture_secret("AKIA", "IOSFODNN", "7EXAMPLE")


def _google_api_key_fixture():
    return _fixture_secret(
        "AI",
        "za",
        "AbCdE",
        "fGhIj",
        "KlMnO",
        "pQrSt",
        "UvWxY",
        "z0123",
        "45678",
    )


class QueryInsightsValidationTests(unittest.TestCase):
    def setUp(self):
        app_module.app.config["TESTING"] = True
        self.client = app_module.app.test_client()
        self.scope_guard = patch("app._validate_gmail_token_scope", return_value=None)
        self.scope_guard.start()
        self.addCleanup(self.scope_guard.stop)

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

    def test_query_with_broad_or_sensitive_mailbox_scope_rejected(self):
        cases = [
            "in:anywhere",
            "in:drafts",
            "IN:sent from:billing",
            "is:draft",
            "is:trash",
            "label:spam",
            "from:alerts in:(sent OR inbox)",
            'in:"sent"',
            '"unterminated quote in:anywhere',
        ]

        for query in cases:
            with self.subTest(query=query):
                with patch("app._gmail_service_from_token") as mock_gmail:
                    response = self.client.post(
                        "/query_insights",
                        json={"token": "test-token", "query": query},
                    )

                self.assertEqual(response.status_code, 400)
                self.assertIn("mailbox scopes", response.get_json()["error"])
                mock_gmail.assert_not_called()

    def test_query_with_negated_broad_or_sensitive_mailbox_scope_rejected(self):
        cases = [
            "-in:trash",
            "-IN:TRASH",
            "- in:trash",
            "- label:spam",
            "-in:sent",
            "-is:draft",
            "from:foo -is:draft",
            "-in:(sent OR trash)",
            "- label:(spam OR inbox)",
            'from:alerts -in:"anywhere"',
        ]

        for query in cases:
            with self.subTest(query=query):
                with patch("app._gmail_service_from_token") as mock_gmail:
                    response = self.client.post(
                        "/query_insights",
                        json={"token": "test-token", "query": query},
                    )

                self.assertEqual(response.status_code, 400)
                self.assertIn("mailbox scopes", response.get_json()["error"])
                mock_gmail.assert_not_called()

    def test_query_scope_guard_preserves_normal_scoped_searches(self):
        service = object()
        query = 'from:alerts in:inbox after:2026/04/01 -from:spam@example.test subject:"in:anywhere"'

        with patch("app._gmail_service_from_token", return_value=service), patch(
            "app.get_emails_by_query", return_value=[]
        ) as mock_fetch:
            response = self.client.post(
                "/query_insights",
                json={"token": "test-token", "query": query, "max_results": 4},
            )

        self.assertEqual(response.status_code, 200)
        body = response.get_json()
        self.assertEqual(body["query"], query)
        mock_fetch.assert_called_once_with(service, query=query, max_results=4)

    def test_query_response_redacts_credentials_from_echo_but_fetches_raw_query(self):
        service = object()
        secret = _access_token_fixture()
        query = f'from:alerts subject:"access_token={secret}"'

        with patch("app._gmail_service_from_token", return_value=service), patch(
            "app.get_emails_by_query", return_value=[]
        ) as mock_fetch:
            response = self.client.post(
                "/query_insights",
                json={"token": "test-token", "query": query, "max_results": 4},
            )

        self.assertEqual(response.status_code, 200)
        body = response.get_json()
        self.assertEqual(
            body["query"],
            'from:alerts subject:"access_token=[REDACTED_TOKEN]"',
        )
        self.assertNotIn(secret, body["query"])
        mock_fetch.assert_called_once_with(service, query=query, max_results=4)

    def test_query_response_redacts_credentials_and_high_risk_identifiers_from_echo_but_fetches_raw_query(self):
        service = object()
        secret = _access_token_fixture()
        ssn = "123-45-6789"
        payment_card = "4242 4242 4242 4242"
        query = (
            f'from:benefits subject:"SSN {ssn} card {payment_card} '
            f'access_token={secret}"'
        )

        with patch("app._gmail_service_from_token", return_value=service), patch(
            "app.get_emails_by_query", return_value=[]
        ) as mock_fetch:
            response = self.client.post(
                "/query_insights",
                json={"token": "test-token", "query": query, "max_results": 4},
            )

        self.assertEqual(response.status_code, 200)
        body = response.get_json()
        self.assertEqual(
            body["query"],
            'from:benefits subject:"SSN [REDACTED_SSN] card '
            '[REDACTED_PAYMENT_CARD] access_token=[REDACTED_TOKEN]"',
        )
        self.assertNotIn(secret, body["query"])
        self.assertNotIn(ssn, body["query"])
        self.assertNotIn(payment_card, body["query"])
        mock_fetch.assert_called_once_with(service, query=query, max_results=4)

    def test_query_response_preserves_benign_contact_and_policy_terms_in_echo(self):
        service = object()
        query = (
            'from:maya@example.com subject:"password reset policy" '
            "after:2026/05/01 order ref-B42Q"
        )

        with patch("app._gmail_service_from_token", return_value=service), patch(
            "app.get_emails_by_query", return_value=[]
        ) as mock_fetch:
            response = self.client.post(
                "/query_insights",
                json={"token": "test-token", "query": query, "max_results": 4},
            )

        self.assertEqual(response.status_code, 200)
        body = response.get_json()
        self.assertEqual(body["query"], query)
        self.assertNotIn("[REDACTED", body["query"])
        mock_fetch.assert_called_once_with(service, query=query, max_results=4)

    def test_query_scope_guard_preserves_safe_negations_and_literals(self):
        service = object()
        cases = [
            'subject:"-in:trash"',
            "from:alerts -category:promotions",
            "in:inbox -from:spam@example.test",
        ]

        for query in cases:
            with self.subTest(query=query):
                with patch("app._gmail_service_from_token", return_value=service), patch(
                    "app.get_emails_by_query", return_value=[]
                ) as mock_fetch:
                    response = self.client.post(
                        "/query_insights",
                        json={"token": "test-token", "query": query, "max_results": 4},
                    )

                self.assertEqual(response.status_code, 200)
                body = response.get_json()
                self.assertEqual(body["query"], query)
                mock_fetch.assert_called_once_with(service, query=query, max_results=4)

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
        self.assertNotIn("[REDACTED", body["error"])
        mock_gmail.assert_not_called()

    def test_unknown_requested_actions_redacts_credential_shaped_name_in_error(self):
        credential_action = _google_oauth_token_fixture()

        with patch("app._gmail_service_from_token") as mock_gmail:
            response = self.client.post(
                "/query_insights",
                json={
                    "token": "test-token",
                    "query": "in:inbox",
                    "requested_actions": f"read,{credential_action}",
                },
            )

        self.assertEqual(response.status_code, 400)
        body = response.get_json()
        self.assertIn("unsupported action", body["error"])
        self.assertIn("[REDACTED_GOOGLE_TOKEN]", body["error"])
        self.assertNotIn(credential_action, body["error"])
        mock_gmail.assert_not_called()

    def test_unknown_requested_actions_redacts_case_sensitive_credential_shaped_names_in_error(self):
        cases = [
            (_aws_access_key_id_fixture(), "[REDACTED_AWS_KEY]"),
            (_google_api_key_fixture(), "[REDACTED_GOOGLE_API_KEY]"),
        ]

        for credential_action, placeholder in cases:
            with self.subTest(placeholder=placeholder):
                with patch("app._gmail_service_from_token") as mock_gmail:
                    response = self.client.post(
                        "/query_insights",
                        json={
                            "token": "test-token",
                            "query": "in:inbox",
                            "requested_actions": ["read", credential_action],
                        },
                    )

                self.assertEqual(response.status_code, 400)
                body = response.get_json()
                self.assertIn("unsupported action", body["error"])
                self.assertIn(placeholder, body["error"])
                self.assertNotIn(credential_action, body["error"])
                self.assertNotIn(credential_action.lower(), body["error"])
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

    def test_importance_marker_requested_action_is_supported_but_blocked(self):
        with patch("app._gmail_service_from_token") as mock_gmail:
            response = self.client.post(
                "/query_insights",
                json={
                    "token": "test-token",
                    "query": "in:inbox",
                    "requested_actions": "change_importance_marker",
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
                "blocked_actions": ["change_importance_marker"],
            },
        )
        mock_gmail.assert_not_called()

    def test_make_payment_requested_action_is_supported_but_blocked(self):
        with patch("app._gmail_service_from_token") as mock_gmail:
            response = self.client.post(
                "/query_insights",
                json={
                    "token": "test-token",
                    "query": "in:inbox",
                    "requested_actions": "make_payment",
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
                "blocked_actions": ["make_payment"],
            },
        )
        mock_gmail.assert_not_called()

    def test_payout_destination_requested_action_is_supported_but_blocked(self):
        with patch("app._gmail_service_from_token") as mock_gmail:
            response = self.client.post(
                "/query_insights",
                json={
                    "token": "test-token",
                    "query": "in:inbox",
                    "requested_actions": "change_payout_destination",
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
                "blocked_actions": ["change_payout_destination"],
            },
        )
        mock_gmail.assert_not_called()

    def test_change_security_settings_requested_action_is_supported_but_blocked(self):
        with patch("app._gmail_service_from_token") as mock_gmail:
            response = self.client.post(
                "/query_insights",
                json={
                    "token": "test-token",
                    "query": "in:inbox",
                    "requested_actions": "change_security_settings",
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
                "blocked_actions": ["change_security_settings"],
            },
        )
        mock_gmail.assert_not_called()

    def test_account_security_requested_actions_are_supported_but_blocked(self):
        requested_actions = [
            "change_recovery_email",
            "change_recovery_phone",
            "change_trusted_devices",
            "change_security_key_settings",
            "change_mfa_settings",
            "disable_account_protection",
        ]

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
        self.assertIn("Blocked actions requested", body["error"])
        self.assertNotIn("unsupported action", body["error"])
        self.assertEqual(
            body["safety"],
            {
                "mode": "read_only",
                "effective_actions": ["read", "summarize"],
                "blocked_actions": sorted(requested_actions),
            },
        )
        mock_gmail.assert_not_called()

    def test_change_network_settings_requested_action_is_supported_but_blocked(self):
        with patch("app._gmail_service_from_token") as mock_gmail:
            response = self.client.post(
                "/query_insights",
                json={
                    "token": "test-token",
                    "query": "in:inbox",
                    "requested_actions": "change_network_settings",
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
                "blocked_actions": ["change_network_settings"],
            },
        )
        mock_gmail.assert_not_called()

    def test_login_prompt_approval_requested_action_is_supported_but_blocked(self):
        with patch("app._gmail_service_from_token") as mock_gmail:
            response = self.client.post(
                "/query_insights",
                json={
                    "token": "test-token",
                    "query": "in:inbox",
                    "requested_actions": "approve_login_prompt",
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
                "blocked_actions": ["approve_login_prompt"],
            },
        )
        mock_gmail.assert_not_called()

    def test_browser_notifications_requested_action_is_supported_but_blocked(self):
        with patch("app._gmail_service_from_token") as mock_gmail:
            response = self.client.post(
                "/query_insights",
                json={
                    "token": "test-token",
                    "query": "in:inbox",
                    "requested_actions": "enable_browser_notifications",
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
                "blocked_actions": ["enable_browser_notifications"],
            },
        )
        mock_gmail.assert_not_called()

    def test_install_profile_requested_action_is_supported_but_blocked(self):
        with patch("app._gmail_service_from_token") as mock_gmail:
            response = self.client.post(
                "/query_insights",
                json={
                    "token": "test-token",
                    "query": "in:inbox",
                    "requested_actions": "install_profile",
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
                "blocked_actions": ["install_profile"],
            },
        )
        mock_gmail.assert_not_called()

    def test_email_signature_requested_action_is_supported_but_blocked(self):
        with patch("app._gmail_service_from_token") as mock_gmail:
            response = self.client.post(
                "/query_insights",
                json={
                    "token": "test-token",
                    "query": "in:inbox",
                    "requested_actions": "update_email_signature",
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
                "blocked_actions": ["update_email_signature"],
            },
        )
        mock_gmail.assert_not_called()

    def test_submit_form_requested_action_is_supported_but_blocked_with_read_through(self):
        service = object()
        with patch(
            "app._gmail_service_from_token", return_value=service
        ) as mock_gmail, patch(
            "app.get_emails_by_query", return_value=[{"id": "email-1"}]
        ) as mock_fetch:
            response = self.client.post(
                "/query_insights",
                json={
                    "token": "test-token",
                    "query": "in:inbox",
                    "requested_actions": "submit_form",
                },
            )

        self.assertEqual(response.status_code, 200)
        body = response.get_json()
        self.assertEqual(
            body["safety"],
            {
                "mode": "read_only",
                "effective_actions": ["read", "summarize"],
                "blocked_actions": ["submit_form"],
            },
        )
        self.assertEqual(body["count"], 1)
        self.assertNotIn("submit_form", body["safety"]["effective_actions"])
        mock_gmail.assert_called_once_with("test-token")
        mock_fetch.assert_called_once_with(service, query="in:inbox", max_results=25)

    def test_submit_form_requested_action_preserves_explicit_safe_read(self):
        service = object()
        with patch(
            "app._gmail_service_from_token", return_value=service
        ) as mock_gmail, patch(
            "app.get_emails_by_query", return_value=[]
        ) as mock_fetch:
            response = self.client.post(
                "/query_insights",
                json={
                    "token": "test-token",
                    "query": "in:inbox",
                    "requested_actions": "read,submit_form",
                },
            )

        self.assertEqual(response.status_code, 200)
        body = response.get_json()
        self.assertEqual(
            body["safety"],
            {
                "mode": "read_only",
                "effective_actions": ["read"],
                "blocked_actions": ["submit_form"],
            },
        )
        mock_gmail.assert_called_once_with("test-token")
        mock_fetch.assert_called_once_with(service, query="in:inbox", max_results=25)

    def test_submit_form_does_not_read_through_with_hard_blocked_action(self):
        with patch("app._gmail_service_from_token") as mock_gmail:
            response = self.client.post(
                "/query_insights",
                json={
                    "token": "test-token",
                    "query": "in:inbox",
                    "requested_actions": "submit_form,make_payment",
                },
            )

        self.assertEqual(response.status_code, 400)
        body = response.get_json()
        self.assertIn("Blocked actions requested", body["error"])
        self.assertEqual(
            body["safety"],
            {
                "mode": "read_only",
                "effective_actions": ["read", "summarize"],
                "blocked_actions": ["make_payment", "submit_form"],
            },
        )
        mock_gmail.assert_not_called()

    def test_file_transfer_requested_actions_are_supported_but_blocked(self):
        requested_actions = ["share_file", "upload_file"]

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
        self.assertIn("Blocked actions requested", body["error"])
        self.assertNotIn("unsupported action", body["error"])
        self.assertEqual(
            body["safety"],
            {
                "mode": "read_only",
                "effective_actions": ["read", "summarize"],
                "blocked_actions": sorted(requested_actions),
            },
        )
        mock_gmail.assert_not_called()

    def test_remote_access_requested_action_is_supported_but_blocked(self):
        with patch("app._gmail_service_from_token") as mock_gmail:
            response = self.client.post(
                "/query_insights",
                json={
                    "token": "test-token",
                    "query": "in:inbox",
                    "requested_actions": "start_remote_access",
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
                "blocked_actions": ["start_remote_access"],
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
            "change_importance_marker",
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
