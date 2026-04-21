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
_DIRECTIVE_PATTERNS = {
    "send": [
        re.compile(r"(?i)^\s*(?:[-*]|\d+[.)])?\s*(?:please\s+)?send\s+(?:to|the|this|that|it|them|an|a)\b"),
        re.compile(
            r"(?i)\b(?:you\s+should|you\s+must|next\s+step(?:s)?|action\s+item(?:s)?|recommended\s+action(?:s)?)\b"
            r".*\bsend\s+(?:to|the|this|that|it|them|an|a)\b"
        ),
        re.compile(r"(?i)\b(?:just|now|immediately|then|next)\b.*\bsend\s+(?:to|the|this|that|it|them|an|a)\b"),
    ],
    "reply": [
        re.compile(r"(?i)^\s*(?:[-*]|\d+[.)])?\s*(?:please\s+)?reply\s+to\b"),
        re.compile(
            r"(?i)\b(?:you\s+should|you\s+must|next\s+step(?:s)?|action\s+item(?:s)?|recommended\s+action(?:s)?)\b"
            r".*\breply\s+to\b"
        ),
        re.compile(r"(?i)\b(?:just|now|immediately|then|next)\b.*\breply\s+to\b"),
    ],
    "delete": [
        re.compile(r"(?i)^\s*(?:[-*]|\d+[.)])?\s*(?:please\s+)?delete\s+(?:the|this|that|it|them|all|an|a)\b"),
        re.compile(
            r"(?i)\b(?:you\s+should|you\s+must|next\s+step(?:s)?|action\s+item(?:s)?|recommended\s+action(?:s)?)\b"
            r".*\bdelete\s+(?:the|this|that|it|them|all|an|a)\b"
        ),
    ],
    "trash": [
        re.compile(r"(?i)^\s*(?:[-*]|\d+[.)])?\s*(?:please\s+)?trash\s+(?:the|this|that|it|them|all|an|a)\b"),
        re.compile(
            r"(?i)\b(?:you\s+should|you\s+must|next\s+step(?:s)?|action\s+item(?:s)?|recommended\s+action(?:s)?)\b"
            r".*\btrash\s+(?:the|this|that|it|them|all|an|a)\b"
        ),
    ],
    "forward": [
        re.compile(r"(?i)^\s*(?:[-*]|\d+[.)])?\s*(?:please\s+)?forward\s+(?:to|the|this|that|it|them)\b"),
        re.compile(
            r"(?i)\b(?:you\s+should|you\s+must|next\s+step(?:s)?|action\s+item(?:s)?|recommended\s+action(?:s)?)\b"
            r".*\bforward\s+(?:to|the|this|that|it|them)\b"
        ),
    ],
    "modify_labels": [
        re.compile(
            r"(?i)^\s*(?:[-*]|\d+[.)])?\s*(?:please\s+)?(?:add|remove|apply|change|modify)\s+labels?\b"
        ),
        re.compile(
            r"(?i)\b(?:you\s+should|you\s+must|next\s+step(?:s)?|action\s+item(?:s)?|recommended\s+action(?:s)?)\b"
            r".*\b(?:add|remove|apply|change|modify)\s+labels?\b"
        ),
    ],
}
_ACTION_WORD_PATTERNS = {
    "send": re.compile(r"(?i)\bsend\b"),
    "reply": re.compile(r"(?i)\breply\b"),
    "delete": re.compile(r"(?i)\bdelete\b"),
    "trash": re.compile(r"(?i)\btrash\b"),
    "forward": re.compile(r"(?i)\bforward\b"),
    "modify_labels": re.compile(r"(?i)\blabels?\b"),
}


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


def _directive_actions(line: str) -> List[str]:
    return [
        action
        for action, patterns in _DIRECTIVE_PATTERNS.items()
        if any(pattern.search(line) for pattern in patterns)
    ]


def neutralize_unsafe_action_suggestions(text: str) -> Tuple[str, List[str]]:
    """Remove unsafe action-suggestion lines from model output."""
    if not text:
        return "", []

    lines = text.splitlines()
    blocked_found = set()
    blocked_line_indexes = set()

    for index, line in enumerate(lines):
        actions = _directive_actions(line)
        if actions:
            blocked_found.update(actions)
            blocked_line_indexes.add(index)

    for index in range(len(lines) - 1):
        combined = f"{lines[index]} {lines[index + 1]}"
        actions = _directive_actions(combined)
        if not actions:
            continue

        blocked_found.update(actions)
        matched_any_line = False
        for action in actions:
            action_pattern = _ACTION_WORD_PATTERNS[action]
            if action_pattern.search(lines[index]):
                blocked_line_indexes.add(index)
                matched_any_line = True
            if action_pattern.search(lines[index + 1]):
                blocked_line_indexes.add(index + 1)
                matched_any_line = True

        if not matched_any_line:
            blocked_line_indexes.update({index, index + 1})

    guarded_lines = [
        "[Unsafe action suggestion removed]" if index in blocked_line_indexes else line
        for index, line in enumerate(lines)
    ]

    return "\n".join(guarded_lines), sorted(blocked_found)
