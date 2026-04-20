import re
from typing import Iterable, List, Tuple

ALLOWED_ACTIONS = {
    "read",
    "summarize",
    "classify",
    "draft",
    "archive_suggestion",
}

BLOCKED_ACTIONS = {
    "send",
    "reply",
    "delete",
    "trash",
    "forward",
    "permanent_delete",
    "modify_labels",
}

_EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
_PHONE_RE = re.compile(r"\b(?:\+?\d{1,3}[\s.-]?)?(?:\(?\d{3}\)?[\s.-]?)\d{3}[\s.-]?\d{4}\b")
_ROLE_TAG_RE = re.compile(
    r"(?im)^(\s*)(system|assistant|user|developer|tool)\s*:\s*"
)
_INSTRUCTION_PHRASE_RE = re.compile(
    r"(?i)\b("
    r"ignore\s+(all\s+)?(previous|prior|above)\s+instructions?"
    r"|disregard\s+(all\s+)?(previous|prior|above)\s+instructions?"
    r"|forget\s+(all\s+)?(previous|prior|above)\s+instructions?"
    r"|follow\s+these\s+instructions?"
    r"|act\s+as\s+(an?|the)\b"
    r"|you\s+are\s+(now\s+)?(chatgpt|assistant|system)\b"
    r")\b"
)
_INSTRUCTION_XML_TAG_RE = re.compile(
    r"(?i)</?\s*(system|assistant|user|instruction|instructions|prompt|directive|policy)\b[^>]*>"
)


def _normalize_actions(actions) -> List[str]:
    if actions is None:
        return []
    if isinstance(actions, str):
        items = [part.strip() for part in actions.split(",")]
    elif isinstance(actions, Iterable):
        items = [str(part).strip() for part in actions]
    else:
        items = [str(actions).strip()]

    return [item.lower() for item in items if item]


def evaluate_requested_actions(actions) -> Tuple[List[str], List[str]]:
    normalized = _normalize_actions(actions)
    blocked = sorted({action for action in normalized if action in BLOCKED_ACTIONS})
    effective = sorted({action for action in normalized if action in ALLOWED_ACTIONS})

    if not effective:
        effective = ["read", "summarize"]

    return effective, blocked


def safety_metadata(actions) -> dict:
    effective_actions, blocked_actions = evaluate_requested_actions(actions)
    return {
        "mode": "read_only",
        "effective_actions": effective_actions,
        "blocked_actions": blocked_actions,
    }


def redact_sensitive_content(text: str) -> str:
    if not text:
        return ""

    redacted = _EMAIL_RE.sub("[REDACTED_EMAIL]", text)
    redacted = _PHONE_RE.sub("[REDACTED_PHONE]", redacted)
    return redacted


def sanitize_untrusted_email_text(text: str) -> str:
    """Neutralize prompt-injection framing while preserving semantic text."""
    if not text:
        return ""

    sanitized = text.replace("\r\n", "\n").replace("\r", "\n")
    sanitized = _ROLE_TAG_RE.sub(r"\1[quoted-role \2] ", sanitized)
    sanitized = _INSTRUCTION_PHRASE_RE.sub(r"[quoted-instruction: \1]", sanitized)
    sanitized = _INSTRUCTION_XML_TAG_RE.sub("[quoted-xml-tag]", sanitized)
    return sanitized
