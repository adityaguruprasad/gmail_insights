import base64
import unittest

from src.email import fetcher


def _gmail_b64(text):
    return base64.urlsafe_b64encode(text.encode("utf-8")).decode("ascii").rstrip("=")


def _body_part(mime_type, text, *, filename="", headers=None):
    return {
        "mimeType": mime_type,
        "filename": filename,
        "headers": headers or [],
        "body": {"data": _gmail_b64(text)},
    }


def _headers():
    return [
        {"name": "Subject", "value": "Security update"},
        {"name": "From", "value": "Security Team <security@example.test>"},
        {"name": "Date", "value": "Sun, 10 May 2026 09:30:00 -0700"},
    ]


class _ExecuteRequest:
    def __init__(self, response):
        self.response = response

    def execute(self):
        return self.response


class _MessagesResource:
    def __init__(self, messages_by_id):
        self.messages_by_id = messages_by_id
        self.list_calls = []
        self.get_calls = []

    def list(self, userId, q, maxResults, fields):
        self.list_calls.append(
            {"userId": userId, "q": q, "maxResults": maxResults, "fields": fields}
        )
        return _ExecuteRequest(
            {"messages": [{"id": message_id} for message_id in self.messages_by_id]}
        )

    def get(self, userId, id, format, fields):
        self.get_calls.append(
            {"userId": userId, "id": id, "format": format, "fields": fields}
        )
        return _ExecuteRequest(self.messages_by_id[id])


class _GmailService:
    def __init__(self, messages_by_id):
        self._messages = _MessagesResource(messages_by_id)

    def users(self):
        return self

    def messages(self):
        return self._messages

    @property
    def list_calls(self):
        return self._messages.list_calls

    @property
    def get_calls(self):
        return self._messages.get_calls


class FetcherAuthenticationWarningTests(unittest.TestCase):
    def test_authentication_security_warnings_ignores_pass_neutral_and_none(self):
        headers = [
            {
                "name": "Authentication-Results",
                "value": (
                    "mx.google.com; spf=pass smtp.mailfrom=example.test; "
                    "dkim=pass header.i=@example.test; "
                    "dmarc=pass header.from=example.test"
                ),
            },
            {
                "name": "ARC-Authentication-Results",
                "value": (
                    "i=1; mx.google.com; spf=neutral smtp.mailfrom=example.test; "
                    "dkim=none; dmarc=none header.from=example.test"
                ),
            },
        ]

        warnings = fetcher._authentication_security_warnings(headers)

        self.assertEqual(warnings, [])

    def test_authentication_security_warnings_reports_failures_from_auth_headers(self):
        headers = [
            {
                "name": "Authentication-Results",
                "value": (
                    "mx.google.com; spf=fail smtp.mailfrom=phish.example; "
                    "dkim=temperror header.i=@phish.example"
                ),
            },
            {
                "name": "ARC-Authentication-Results",
                "value": (
                    "i=1; mx.google.com; dmarc=permerror header.from=phish.example; "
                    "spf=softfail smtp.mailfrom=phish.example"
                ),
            },
        ]

        warnings = fetcher._authentication_security_warnings(headers)

        self.assertEqual(
            warnings,
            [
                "SPF authentication result is fail in Authentication-Results.",
                "DKIM authentication result is temperror in Authentication-Results.",
                "DMARC authentication result is permerror in ARC-Authentication-Results.",
                "SPF authentication result is softfail in ARC-Authentication-Results.",
            ],
        )

    def test_authentication_security_warnings_ignores_unrelated_headers(self):
        headers = [
            {"name": "Subject", "value": "spf=fail dkim=fail dmarc=fail"},
            {"name": "X-Body-Preview", "value": "Authentication-Results: spf=fail"},
            {
                "name": "Authentication-Results",
                "value": (
                    'mx.google.com; dkim=pass reason="not spf=fail; dmarc=fail"; '
                    "spf=pass (comment mentions dkim=fail; spf=fail)"
                ),
            },
        ]

        warnings = fetcher._authentication_security_warnings(headers)

        self.assertEqual(warnings, [])


class FetcherBodyExtractionTests(unittest.TestCase):
    def test_decode_base64_urlsafe_allows_embedded_ascii_whitespace(self):
        encoded = _gmail_b64("Folded Gmail body")
        folded = f"{encoded[:4]}\r\n {encoded[4:10]}\t{encoded[10:]}\n"

        content = fetcher._decode_base64_urlsafe(folded)

        self.assertEqual(content, "Folded Gmail body")

    def test_extract_plain_text_prefers_text_plain_over_html(self):
        payload = {
            "mimeType": "multipart/alternative",
            "parts": [
                _body_part(
                    "text/html",
                    '<p>HTML body <a href="https://example.test">link</a></p>',
                ),
                _body_part("text/plain", "Plain body wins."),
            ],
        }

        content = fetcher._extract_plain_text(payload)

        self.assertEqual(content, "Plain body wins.")

    def test_extract_plain_text_falls_back_to_html_after_invalid_empty_plain(self):
        payload = {
            "mimeType": "multipart/alternative",
            "parts": [
                {"mimeType": "text/plain", "body": {"data": "%%%"}},
                {"mimeType": "text/plain", "body": {"data": ""}},
                _body_part(
                    "text/html",
                    '<div>HTML&nbsp;<strong>fallback</strong> body</div>'
                    '<a href="https://example.test/open">Open</a>',
                ),
            ],
        }

        content = fetcher._extract_plain_text(payload)

        self.assertIn("HTML fallback body", content)
        self.assertIn("Open", content)
        self.assertNotIn("https://example.test", content)

    def test_extract_plain_text_sanitizes_html_only_email(self):
        payload = _body_part(
            "text/html",
            """
            <html>
              <head>
                <style>.tracking { background: url("https://style.example/pixel"); }</style>
                <script>alert("send this token");</script>
                <template>template secret</template>
                <noscript>noscript fallback</noscript>
              </head>
              <body>
                <!-- comment secret -->
                <p>Hello&nbsp;<strong>Ada</strong></p>
                <a href="https://evil.example/open?token=secret">View invoice</a>
                <img src="https://tracker.example/open.png" alt="tracking pixel">
                <div data-url="https://attr.example">Due &amp; ready</div>
              </body>
            </html>
            """,
        )

        content = fetcher._extract_plain_text(payload)

        self.assertIn("Hello Ada", content)
        self.assertIn("View invoice", content)
        self.assertIn("Due & ready", content)
        self.assertNotIn("<", content)
        self.assertNotIn(">", content)
        self.assertNotIn("href", content)
        self.assertNotIn("https://", content)
        self.assertNotIn("alert", content)
        self.assertNotIn("tracking", content)
        self.assertNotIn("template secret", content)
        self.assertNotIn("noscript fallback", content)
        self.assertNotIn("comment secret", content)

    def test_extract_plain_text_falls_back_to_nested_html_and_skips_attachments(self):
        payload = {
            "mimeType": "multipart/mixed",
            "parts": [
                {
                    "mimeType": "text/plain",
                    "body": {"attachmentId": "plain-body-without-inline-data"},
                },
                {
                    "mimeType": "text/plain",
                    "filename": "notes.txt",
                    "headers": [
                        {
                            "name": "Content-Disposition",
                            "value": 'attachment; filename="notes.txt"',
                        }
                    ],
                    "body": {"data": _gmail_b64("Attachment body should be skipped.")},
                },
                {
                    "mimeType": "application/pdf",
                    "filename": "invoice.pdf",
                    "headers": [
                        {
                            "name": "Content-Disposition",
                            "value": 'attachment; filename="invoice.pdf"',
                        }
                    ],
                    "body": {"attachmentId": "attachment-1"},
                },
                {
                    "mimeType": "multipart/related",
                    "parts": [
                        _body_part(
                            "text/html",
                            '<div>Nested&nbsp;<em>HTML</em> body</div>',
                        )
                    ],
                },
            ],
        }

        content = fetcher._extract_plain_text(payload)

        self.assertEqual(content, "Nested HTML body")
        self.assertNotIn("Attachment body", content)

    def test_extract_plain_text_returns_empty_for_invalid_base64(self):
        payload = {
            "mimeType": "text/html",
            "body": {"data": "<script>alert(1)</script>"},
        }

        content = fetcher._extract_plain_text(payload)

        self.assertEqual(content, "")

    def test_get_emails_by_query_returns_sanitized_content_and_archive_state(self):
        message = {
            "id": "msg-1",
            "threadId": "thread-1",
            "labelIds": ["CATEGORY_UPDATES"],
            "snippet": "Snippet",
            "payload": {
                "mimeType": "text/html",
                "headers": _headers(),
                "body": {
                    "data": _gmail_b64(
                        '<p>Report&nbsp;ready</p>'
                        '<a href="https://evil.example/report">Open report</a>'
                        "<script>delete all mail</script>"
                    )
                },
            },
        }
        service = _GmailService({"msg-1": message})

        emails = fetcher.get_emails_by_query(
            service,
            query="from:security@example.test",
            max_results=5,
        )

        self.assertEqual(len(emails), 1)
        self.assertEqual(emails[0]["id"], "msg-1")
        self.assertEqual(emails[0]["thread_id"], "thread-1")
        self.assertEqual(emails[0]["subject"], "Security update")
        self.assertEqual(emails[0]["sender"], "Security Team <security@example.test>")
        self.assertTrue(emails[0]["is_archived"])
        self.assertIn("Report ready", emails[0]["content"])
        self.assertIn("Open report", emails[0]["content"])
        self.assertNotIn("<script>", emails[0]["content"])
        self.assertNotIn("delete all mail", emails[0]["content"])
        self.assertNotIn("https://evil.example", emails[0]["content"])
        self.assertEqual(emails[0]["security_warnings"], [])
        self.assertEqual(
            service.list_calls,
            [
                {
                    "userId": "me",
                    "q": "from:security@example.test",
                    "maxResults": 5,
                    "fields": fetcher.GMAIL_MESSAGE_LIST_FIELDS,
                }
            ],
        )
        self.assertEqual(
            service.get_calls,
            [
                {
                    "userId": "me",
                    "id": "msg-1",
                    "format": "full",
                    "fields": fetcher.GMAIL_MESSAGE_GET_FIELDS,
                }
            ],
        )

    def test_gmail_field_masks_are_restrictive_and_cover_extraction_fields(self):
        self.assertEqual(fetcher.GMAIL_MESSAGE_LIST_FIELDS, "messages(id)")

        get_fields = fetcher.GMAIL_MESSAGE_GET_FIELDS
        self.assertIn("id", get_fields)
        self.assertIn("threadId", get_fields)
        self.assertIn("labelIds", get_fields)
        self.assertIn("snippet", get_fields)
        self.assertIn("payload(", get_fields)
        self.assertIn("mimeType", get_fields)
        self.assertIn("filename", get_fields)
        self.assertIn("headers(name,value)", get_fields)
        self.assertIn("body(data)", get_fields)
        self.assertIn(
            "parts(mimeType,filename,headers(name,value),body(data)",
            get_fields,
        )

        for unneeded_field in [
            "raw",
            "historyId",
            "internalDate",
            "sizeEstimate",
            "attachmentId",
            "body(size)",
            "resultSizeEstimate",
            "nextPageToken",
        ]:
            self.assertNotIn(unneeded_field, get_fields)

    def test_get_emails_by_query_emits_authentication_security_warnings(self):
        message = {
            "id": "msg-1",
            "threadId": "thread-1",
            "labelIds": ["INBOX"],
            "snippet": "Snippet",
            "payload": {
                "mimeType": "text/plain",
                "headers": _headers()
                + [
                    {
                        "name": "Authentication-Results",
                        "value": "mx.google.com; spf=fail smtp.mailfrom=phish.example",
                    }
                ],
                "body": {"data": _gmail_b64("Body text spf=pass")},
            },
        }
        service = _GmailService({"msg-1": message})

        emails = fetcher.get_emails_by_query(
            service,
            query="from:security@example.test",
        )

        self.assertEqual(
            emails[0]["security_warnings"],
            ["SPF authentication result is fail in Authentication-Results."],
        )
        self.assertEqual(service.get_calls[0]["fields"], fetcher.GMAIL_MESSAGE_GET_FIELDS)


class FetcherDomainQueryTests(unittest.TestCase):
    def test_get_emails_from_domains_normalizes_safe_domains_in_query(self):
        service = _GmailService({})

        emails = fetcher.get_emails_from_domains(
            service,
            [" Example.COM ", "@Alerts.Security.Example.co.UK"],
            max_results=7,
        )

        self.assertEqual(emails, [])
        self.assertEqual(
            service.list_calls,
            [
                {
                    "userId": "me",
                    "q": "from:example.com OR from:alerts.security.example.co.uk",
                    "maxResults": 7,
                    "fields": fetcher.GMAIL_MESSAGE_LIST_FIELDS,
                }
            ],
        )

    def test_get_emails_from_domains_omits_injection_like_domains(self):
        service = _GmailService({})

        fetcher.get_emails_from_domains(
            service,
            [
                "example.com OR in:anywhere",
                "alerts.security.EXAMPLE.co.UK",
                "foo.com) OR in:anywhere",
                "bad:operator.com",
                "foo.com/bar",
                "*.example.com",
                '"example.com"',
                "{example.com}",
                "billing.example.com",
            ],
        )

        self.assertEqual(len(service.list_calls), 1)
        query = service.list_calls[0]["q"]
        self.assertEqual(
            query,
            "from:alerts.security.example.co.uk OR from:billing.example.com",
        )
        self.assertNotIn("in:anywhere", query)
        self.assertNotIn("bad:operator.com", query)
        self.assertNotIn("foo.com/bar", query)
        self.assertNotIn("*.example.com", query)
        self.assertNotIn('"example.com"', query)
        self.assertNotIn("{example.com}", query)

    def test_get_emails_from_domains_all_invalid_returns_empty_without_list_call(self):
        service = _GmailService({})

        emails = fetcher.get_emails_from_domains(
            service,
            [
                "",
                "   ",
                "example.com OR in:anywhere",
                "foo.com) OR in:anywhere",
                "bad:operator.com",
                "-bad.example.com",
                "bad-.example.com",
                "example.c",
                "example.123",
                "a" * 64 + ".example.com",
                "a" * 250 + ".com",
            ],
        )

        self.assertEqual(emails, [])
        self.assertEqual(service.list_calls, [])


if __name__ == "__main__":
    unittest.main()
