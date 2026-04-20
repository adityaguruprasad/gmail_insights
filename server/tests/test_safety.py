import unittest

from src.email.safety import evaluate_requested_actions, safety_metadata, redact_sensitive_content


class SafetyPolicyTests(unittest.TestCase):
    def test_blocked_actions_are_detected(self):
        effective, blocked = evaluate_requested_actions(["read", "reply", "delete"])
        self.assertEqual(effective, ["read"])
        self.assertEqual(blocked, ["delete", "reply"])

    def test_default_actions_apply_when_empty(self):
        effective, blocked = evaluate_requested_actions(None)
        self.assertEqual(effective, ["read", "summarize"])
        self.assertEqual(blocked, [])

    def test_safety_metadata_read_only_mode(self):
        safety = safety_metadata("draft,archive_suggestion")
        self.assertEqual(safety["mode"], "read_only")
        self.assertEqual(safety["effective_actions"], ["archive_suggestion", "draft"])
        self.assertEqual(safety["blocked_actions"], [])

    def test_redaction(self):
        text = "Contact me at jane@example.com or +1 415-555-1212"
        redacted = redact_sensitive_content(text)
        self.assertNotIn("jane@example.com", redacted)
        self.assertNotIn("415-555-1212", redacted)
        self.assertIn("[REDACTED_EMAIL]", redacted)
        self.assertIn("[REDACTED_PHONE]", redacted)


if __name__ == "__main__":
    unittest.main()
