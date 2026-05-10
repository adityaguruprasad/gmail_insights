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

    def list(self, userId, q, maxResults):
        self.list_calls.append({"userId": userId, "q": q, "maxResults": maxResults})
        return _ExecuteRequest(
            {"messages": [{"id": message_id} for message_id in self.messages_by_id]}
        )

    def get(self, userId, id, format):
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
