import sys
import types
import unittest
from urllib.error import URLError
from unittest.mock import patch

processor_stub = types.ModuleType("src.email.processor")
processor_stub.extract_insights = lambda email: email
sys.modules.setdefault("src.email.processor", processor_stub)

import app as app_module  # noqa: E402
from src.auth.gmail_scope_guard import (  # noqa: E402
    GMAIL_READONLY_SCOPE,
    TOKENINFO_URL,
    TokenScopeValidationError,
    fetch_tokeninfo,
    validate_gmail_readonly_token,
)


READONLY_SCOPE = "https://www.googleapis.com/auth/gmail.readonly"
EXPECTED_AUDIENCE = "test-client-id.apps.googleusercontent.com"


def _tokeninfo_fetcher(audience=EXPECTED_AUDIENCE, scope=READONLY_SCOPE):
    def fetcher(token):
        tokeninfo = {"scope": scope}
        if audience is not None:
            tokeninfo["aud"] = audience
        return tokeninfo

    return fetcher


def _scope_fetcher(scopes):
    return lambda token: scopes


class _TokeninfoResponse:
    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, traceback):
        return False

    def read(self, limit):
        return (
            b'{"aud":"test-client-id.apps.googleusercontent.com",'
            b'"scope":"https://www.googleapis.com/auth/gmail.readonly"}'
        )


class GmailScopeGuardUnitTests(unittest.TestCase):
    def test_fetch_tokeninfo_posts_token_in_body_not_url(self):
        with patch(
            "src.auth.gmail_scope_guard.urlopen",
            return_value=_TokeninfoResponse(),
        ) as mock_urlopen:
            fetch_tokeninfo("ya29.secret-token")

        request = mock_urlopen.call_args.args[0]
        self.assertEqual(TOKENINFO_URL, request.full_url)
        self.assertNotIn("ya29.secret-token", request.full_url)
        self.assertIn(b"access_token=ya29.secret-token", request.data)

    def test_readonly_token_with_valid_audience_accepted(self):
        granted_scopes = validate_gmail_readonly_token(
            "test-token",
            expected_audience=EXPECTED_AUDIENCE,
            tokeninfo_fetcher=_tokeninfo_fetcher(
                scope=(
                    f"{READONLY_SCOPE} "
                    "https://www.googleapis.com/auth/userinfo.email "
                    "openid email profile"
                ),
            ),
        )

        self.assertIn(GMAIL_READONLY_SCOPE, granted_scopes)
        self.assertIn("openid", granted_scopes)
        self.assertIn("email", granted_scopes)
        self.assertIn("profile", granted_scopes)
        self.assertIn("userinfo.email", granted_scopes)

    def test_mismatched_audience_rejected(self):
        with self.assertRaises(TokenScopeValidationError):
            validate_gmail_readonly_token(
                "test-token",
                expected_audience=EXPECTED_AUDIENCE,
                tokeninfo_fetcher=_tokeninfo_fetcher(
                    audience="other-client-id.apps.googleusercontent.com",
                ),
            )

    def test_missing_audience_rejected(self):
        with self.assertRaises(TokenScopeValidationError):
            validate_gmail_readonly_token(
                "test-token",
                expected_audience=EXPECTED_AUDIENCE,
                tokeninfo_fetcher=_tokeninfo_fetcher(audience=None),
            )

    def test_overbroad_write_token_rejected(self):
        write_scopes = [
            "https://www.googleapis.com/auth/gmail.addons.current.action.compose",
            "https://www.googleapis.com/auth/gmail.compose",
            "https://www.googleapis.com/auth/gmail.insert",
            "https://www.googleapis.com/auth/gmail.labels",
            "https://www.googleapis.com/auth/gmail.modify",
            "https://www.googleapis.com/auth/gmail.send",
            "https://www.googleapis.com/auth/gmail.settings.basic",
            "https://www.googleapis.com/auth/gmail.settings.sharing",
            "https://mail.google.com/",
        ]

        for write_scope in write_scopes:
            with self.subTest(write_scope=write_scope):
                with self.assertRaises(TokenScopeValidationError):
                    validate_gmail_readonly_token(
                        "test-token",
                        expected_audience=EXPECTED_AUDIENCE,
                        tokeninfo_fetcher=_tokeninfo_fetcher(),
                        scope_fetcher=_scope_fetcher({
                            READONLY_SCOPE,
                            write_scope,
                        }),
                    )

    def test_unknown_future_gmail_scope_rejected_even_with_readonly(self):
        with self.assertRaises(TokenScopeValidationError):
            validate_gmail_readonly_token(
                "test-token",
                expected_audience=EXPECTED_AUDIENCE,
                tokeninfo_fetcher=_tokeninfo_fetcher(),
                scope_fetcher=_scope_fetcher({
                    READONLY_SCOPE,
                    "https://www.googleapis.com/auth/gmail.futureScope",
                }),
            )

    def test_gmail_metadata_rejected_even_with_readonly(self):
        with self.assertRaises(TokenScopeValidationError):
            validate_gmail_readonly_token(
                "test-token",
                expected_audience=EXPECTED_AUDIENCE,
                tokeninfo_fetcher=_tokeninfo_fetcher(),
                scope_fetcher=_scope_fetcher({
                    READONLY_SCOPE,
                    "https://www.googleapis.com/auth/gmail.metadata",
                }),
            )

    def test_missing_readonly_rejected(self):
        cases = [
            {"https://www.googleapis.com/auth/gmail.metadata"},
            {"https://www.googleapis.com/auth/gmail.send"},
            {"https://www.googleapis.com/auth/userinfo.email"},
        ]

        for scopes in cases:
            with self.subTest(scopes=scopes):
                with self.assertRaises(TokenScopeValidationError):
                    validate_gmail_readonly_token(
                        "test-token",
                        expected_audience=EXPECTED_AUDIENCE,
                        tokeninfo_fetcher=_tokeninfo_fetcher(),
                        scope_fetcher=_scope_fetcher(scopes),
                    )

    def test_tokeninfo_network_failure_rejected(self):
        def raise_network_failure(token):
            raise URLError("tokeninfo unavailable")

        with self.assertRaises(TokenScopeValidationError):
            validate_gmail_readonly_token(
                "test-token",
                expected_audience=EXPECTED_AUDIENCE,
                tokeninfo_fetcher=raise_network_failure,
            )


class GmailScopeGuardRouteTests(unittest.TestCase):
    def setUp(self):
        app_module.app.config["TESTING"] = True
        self.client = app_module.app.test_client()

    def test_app_scope_guard_uses_configured_oauth_client_id(self):
        with patch("app.validate_gmail_readonly_token") as mock_validate:
            app_module._validate_gmail_token_scope("ya29.secret-token")

        mock_validate.assert_called_once_with(
            "ya29.secret-token",
            expected_audience=app_module.GMAIL_CLIENT_ID,
        )

    def test_get_insights_rejected_token_avoids_service_build_and_fetch(self):
        with patch(
            "app._validate_gmail_token_scope",
            side_effect=TokenScopeValidationError("invalid scope"),
        ) as mock_scope_guard, patch(
            "app._gmail_service_from_token"
        ) as mock_service, patch(
            "app.get_emails_from_domains"
        ) as mock_fetch:
            response = self.client.post(
                "/get_insights",
                json={"token": "ya29.secret-token"},
            )

        self.assertEqual(response.status_code, 403)
        self.assertEqual(
            response.get_json(),
            {"error": "Token is not authorized for read-only Gmail access."},
        )
        self.assertNotIn("ya29.secret-token", str(response.get_json()))
        mock_scope_guard.assert_called_once_with("ya29.secret-token")
        mock_service.assert_not_called()
        mock_fetch.assert_not_called()

    def test_query_insights_rejected_token_avoids_service_build_and_fetch(self):
        with patch(
            "app._validate_gmail_token_scope",
            side_effect=TokenScopeValidationError("invalid scope"),
        ) as mock_scope_guard, patch(
            "app._gmail_service_from_token"
        ) as mock_service, patch(
            "app.get_emails_by_query"
        ) as mock_fetch:
            response = self.client.post(
                "/query_insights",
                json={"token": "ya29.secret-token", "query": "in:inbox"},
            )

        self.assertEqual(response.status_code, 403)
        self.assertEqual(
            response.get_json(),
            {"error": "Token is not authorized for read-only Gmail access."},
        )
        self.assertNotIn("ya29.secret-token", str(response.get_json()))
        mock_scope_guard.assert_called_once_with("ya29.secret-token")
        mock_service.assert_not_called()
        mock_fetch.assert_not_called()


if __name__ == "__main__":
    unittest.main()
