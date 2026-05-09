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
    "mark_read",
    "mark_unread",
    "star",
    "unstar",
    "move_to_spam",
    "move_to_inbox",
    "snooze",
    "create_filter",
    "unsubscribe",
    "click_link",
    "open_link",
    "open_attachment",
    "download_attachment",
    "scan_qr_code",
    "call_phone",
    "send_sms",
    "use_verification_code",
    "accept_invite",
    "decline_invite",
    "tentative_invite",
    "create_calendar_event",
}

_EMAIL_TARGET = r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}"
_EMAIL_RE = re.compile(rf"\b{_EMAIL_TARGET}\b")
_PHONE_RE = re.compile(r"\b(?:\+?\d{1,3}[\s.-]?)?(?:\(?\d{3}\)?[\s.-]?)\d{3}[\s.-]?\d{4}\b")
_BEARER_TOKEN_RE = re.compile(
    r"(?i)\b(bearer\s+)[A-Za-z0-9._~+/=-]{16,}(?=$|[\s,;)\]}>\"'])"
)
_API_TOKEN_RE = re.compile(
    r"(?i)\b((?:api[_-]?key|api[_-]?token|access[_-]?token|auth[_-]?token)"
    r"\s*[:=]\s*)([\"']?)[A-Za-z0-9._~+/=-]{16,}\2"
)
_GOOGLE_OAUTH_TOKEN_RE = re.compile(r"\bya29\.[A-Za-z0-9._-]+\b")
_GOOGLE_REFRESH_TOKEN_RE = re.compile(r"\b1//[A-Za-z0-9._-]+\b")
_JWT_RE = re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b")
_AWS_ACCESS_KEY_ID_RE = re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b")
_SLACK_TOKEN_RE = re.compile(r"\b(?:xox[abprs]|xapp)-[A-Za-z0-9-]{10,}\b")
_GITHUB_TOKEN_RE = re.compile(r"\bgh[pousr]_[A-Za-z0-9_]{20,255}\b")
_STRIPE_SECRET_KEY_RE = re.compile(r"\bsk_(?:live|test)_[A-Za-z0-9]{16,}\b")
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
_DIRECTIVE_START = r"(?i)^\s*(?:[-*]|\d+[.)])?\s*(?:please\s+)?"
_RECOMMENDATION_KEYWORD = (
    r"(?:you\s+should|you\s+must|next\s+step(?:s)?|action\s+item(?:s)?|"
    r"recommended\s+action(?:s)?)"
)
_RECOMMENDATION_START = rf"(?i)\b{_RECOMMENDATION_KEYWORD}\b"
_RECOMMENDATION_PREFIX = rf"{_RECOMMENDATION_START}.*"
_SEND_TARGET_START = r"(?:to|the|this|that|it|them|an?\s+(?!(?:sms|text(?:\s+message)?)\b))\b"
_MAILBOX_OBJECT_NOUN = r"(?:message|messages|email|emails|thread|threads)"
_MAILBOX_OBJECT_PRONOUN = (
    rf"(?:(?:this|that)(?:\s+(?:(?:[\w-]+\s+){{0,3}})?{_MAILBOX_OBJECT_NOUN})?|it|them|all)"
)
_MAILBOX_OBJECT_DETERMINER_PHRASE = (
    rf"(?:the|an|a)\s+(?:(?:[\w-]+\s+){{0,3}})?{_MAILBOX_OBJECT_NOUN}"
)
_MAILBOX_OBJECT = (
    rf"(?:{_MAILBOX_OBJECT_PRONOUN}|{_MAILBOX_OBJECT_DETERMINER_PHRASE}|{_MAILBOX_OBJECT_NOUN})"
)
_SNOOZE_MAILBOX_OBJECT = (
    rf"(?:all\s+(?:(?:my|your|our|the|these|those)\s+)?(?:[\w-]+\s+){{0,3}}"
    rf"{_MAILBOX_OBJECT_NOUN}|{_MAILBOX_OBJECT})"
)
_LABEL_TARGET = r"(?:(?:the|an|a)\s+)?(?:(?:[\w-]+\s+){0,5})?labels?"
_LABEL_MUTATION_VERB = r"(?:add|remove|apply|change|modify)"
_DELETE_TARGET = rf"delete\s+{_MAILBOX_OBJECT}\b"
_PERMANENT_DELETE_TARGET = rf"\bpermanent(?:ly)?\s+{_DELETE_TARGET}"
# Keep generic delete from also matching the delete verb inside a permanent-delete directive.
_GENERIC_DELETE_RECOMMENDATION_LEAD_IN = rf"(?:(?!{_PERMANENT_DELETE_TARGET}).)*"
_URGENCY_SUFFIX = r"(?:right\s+now|now|asap|immediately|as\s+soon\s+as\s+possible)(?:\s+please)?"
_TARGET_END = rf"(?=\s*(?:$|[.!?,:;]|\b{_URGENCY_SUFFIX}\b\s*(?:$|[.!?,:;])))"
_DIRECT_SMS_TARGET_END = rf"(?=\s*(?:[.!?,:;]|\b{_URGENCY_SUFFIX}\b\s*(?:$|[.!?,:;])))"
_SNOOZE_TIME_SUFFIX = (
    r"(?:until\s+[\w-]+(?:\s+[\w-]+){0,3}|"
    r"for\s+(?:\d+|one|two|three|four|five|six|seven|eight|nine|ten)\s+[\w-]+(?:\s+[\w-]+){0,2}|"
    r"for\s+(?:the\s+)?weekend|"
    r"in\s+(?:the\s+)?(?:morning|afternoon|evening)|"
    r"later|tomorrow)"
)
_SNOOZE_TARGET_END = (
    rf"(?=\s*(?:$|[.!?,:;]|\b(?:{_URGENCY_SUFFIX}|{_SNOOZE_TIME_SUFFIX}|please)\b\s*(?:$|[.!?,:;])))"
)
_FILTER_CONNECTOR = r"\s+(?:for|from|that|to|matching|with|where|when)\b"
_FILTER_TARGET = (
    rf"(?:(?:a|an|the)\s+filter(?:{_FILTER_CONNECTOR}|{_TARGET_END})|"
    rf"filter(?:{_FILTER_CONNECTOR}|{_TARGET_END}))"
)
_UNSUBSCRIBE_TARGET_NOUN = (
    r"(?:senders?|newsletters?|mailing\s+lists?|lists?|subscriptions?|"
    r"messages?|emails?|threads?|services?|sites?|websites?|domains?|"
    r"brands?|notifications?|promotions?|alerts?|marketing)"
)
_UNSUBSCRIBE_URL_TARGET = (
    r"(?:https?://[^\s<>)\]]+|www\.[^\s<>)\]]+|[\w.-]+\.[A-Za-z]{2,}(?:/[^\s<>)\]]*)?)"
)
_UNSUBSCRIBE_OPT_OUT_TARGET = (
    rf"(?:{_UNSUBSCRIBE_URL_TARGET}|(?:the\s+)?(?:opt[-\s]?out\s+)?(?:url|link|page|form|site|website))"
)
_UNSUBSCRIBE_TARGET = (
    r"(?:"
    r"(?:me|us|the\s+user)\s+from\s+"
    r"(?:this|that|these|those|the|a|an)?\s*"
    r"(?:[\w.-]+\s+){0,4}"
    rf"{_UNSUBSCRIBE_TARGET_NOUN}\b"
    r"|from\s+"
    r"(?:this|that|these|those|the|a|an)?\s*"
    r"(?:[\w.-]+\s+){0,4}"
    rf"{_UNSUBSCRIBE_TARGET_NOUN}\b"
    rf"|(?:at|via|using)\s+{_UNSUBSCRIBE_OPT_OUT_TARGET}"
    r")"
)
_ACTION_SUGGESTION_START = (
    rf"(?i)^\s*(?:[-*]|\d+[.)])?\s*"
    rf"(?:(?:{_RECOMMENDATION_KEYWORD})\s*:?\s*)?"
    r"(?:(?:please|first|then|next|just|now|also)\s+){0,4}"
)
_LINK_NOUN = r"(?:link|url|website|webpage|page|site)"
_DOMAIN_LABEL = r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?"
_BARE_DOMAIN_TARGET = (
    rf"(?:{_DOMAIN_LABEL}\.)+[A-Za-z]{{2,}}(?:/[^\s<>)\]]{{1,2048}})?"
)
_EXTERNAL_URL_TARGET = (
    rf"(?:https?://[^\s<>)\]]{{1,2048}}|www\.[^\s<>)\]]{{1,2048}}|"
    rf"{_BARE_DOMAIN_TARGET})"
)
_LINK_TARGET = (
    rf"(?:{_EXTERNAL_URL_TARGET}|"
    rf"(?:(?:the|this|that|an?|your)\s+)?(?:[\w-]+\s+){{0,4}}{_LINK_NOUN})"
)
_CLICK_LINK_TARGET = rf"(?:here|{_LINK_TARGET})"
_QR_EXPLICIT_TARGET = r"(?:(?:the|this|that|an?|your)\s+)?qr\s+codes?\b"
_QR_SCAN_TARGET = r"(?:(?:the|this|that|an?|your)\s+)?(?:qr\s+)?codes?\b"
_QR_LINK_TARGET = r"(?:(?:the|this|that|an?|your)\s+)?qr\s+codes?\s+(?:links?|urls?)\b"
_QR_PURPOSE_SUFFIX = r"(?:\s+to\s+[\w-]+(?:\s+[\w-]+){0,8})?"
_ATTACHED_FILE_NOUN = (
    r"(?:file|files|pdf|pdfs|document|documents|doc|docs|spreadsheet|spreadsheets|"
    r"image|images|invoice|invoices|report|reports|form|forms)"
)
_BARE_ATTACHMENT_FILE_TARGET = (
    rf"(?:(?:the|this|that|an?|your)\s+)?(?:[\w-]+\s+){{0,2}}{_ATTACHED_FILE_NOUN}\b"
)
_EXPLICIT_ATTACHMENT_TARGET = (
    rf"(?:"
    rf"(?:(?:the|this|that|an?|your)\s+)?(?:[\w-]+\s+){{0,3}}attachments?\b|"
    rf"(?:(?:the|this|that|an?|your)\s+)?attached\s+{_ATTACHED_FILE_NOUN}\b"
    rf")"
)
_ATTACHMENT_TARGET = (
    rf"(?:"
    rf"{_EXPLICIT_ATTACHMENT_TARGET}|"
    rf"{_BARE_ATTACHMENT_FILE_TARGET}{_TARGET_END}"
    rf")"
)
# Forward exfiltration extends attachment/file nouns with email/message/thread content nouns.
_FORWARD_EXFIL_OBJECT_NOUN = (
    rf"(?:attachments?|email\s+contents?|message\s+contents?|"
    rf"thread\s+contents?|{_ATTACHED_FILE_NOUN})"
)
_FORWARD_EXFIL_OBJECT = (
    rf"(?:(?:the|this|that|an?|your)\s+)?"
    rf"(?:[\w-]+\s+){{0,3}}{_FORWARD_EXFIL_OBJECT_NOUN}\b"
)
_FORWARD_RECIPIENT_NOUN = (
    r"(?:sender|recipient|contact|customer|client|person|address|"
    r"email\s+address|accounting|security|team|owner|vendor|supplier)"
)
_FORWARD_RECIPIENT_TARGET = (
    rf"(?:{_EMAIL_TARGET}|(?:(?:the|this|that|an?)\s+)?"
    rf"(?:[\w-]+\s+){{0,4}}{_FORWARD_RECIPIENT_NOUN}\b)"
)
_FORWARD_EXFIL_TARGET = (
    rf"{_FORWARD_EXFIL_OBJECT}\s+to\s+{_FORWARD_RECIPIENT_TARGET}{_TARGET_END}"
)
_PHONE_NUMBER_TARGET = r"(?:\+?\d{1,3}[\s.-]?)?(?:\(?\d{3}\)?[\s.-]?)\d{3}[\s.-]?\d{4}"
_DIRECT_CONTACT_TARGET = (
    rf"(?:{_PHONE_NUMBER_TARGET}|"
    r"(?:(?:the|this|that)\s+)?(?:sender|contact|customer|client|person|"
    r"phone\s+number|number)\b)"
)
_SMS_PRE_TARGET_MODIFIER = (
    r"(?:(?:right\s+now|now|asap|immediately|as\s+soon\s+as\s+possible|please)\s+){0,3}"
)
_INVITE_NOUN = (
    r"(?:invites?|invitations?|calendar\s+invites?|calendar\s+invitations?|"
    r"meeting\s+invites?|meeting\s+invitations?)"
)
_INVITE_TARGET = (
    rf"(?:(?:the|this|that|an?|your)\s+)?(?:[\w-]+\s+){{0,2}}{_INVITE_NOUN}\b"
)
_CALENDAR_EVENT_TARGET = (
    r"(?:(?:a|an|the|this|that|your)\s+)?(?:calendar\s+events?|meetings?)\b"
)
_CALENDAR_SOURCE_TARGET = (
    r"(?:(?:the|this|that|an?|your)\s+)?(?:[\w-]+\s+){0,2}"
    r"(?:email|message|thread)\b"
)
_CALENDAR_LOCATION_TARGET = r"(?:(?:my|your|the)\s+)?calendar\b"
_VERIFICATION_CODE_MODIFIER = (
    r"(?:verification|one[-\s]?time|2fa|mfa|otp|login|security|"
    r"authentication|auth|confirmation|access|recovery|validation)"
)
_VERIFICATION_CODE_TARGET = (
    r"(?:(?:the|this|that|an?|your)\s+)?(?:email\s+)?"
    rf"(?:(?:{_VERIFICATION_CODE_MODIFIER})\s+code|otp|totp|hotp|pin|passcode)\b"
)
_VERIFICATION_CODE_TARGET_PREFIX = (
    r"(?:(?:the|this|that|an?|your)\s+)?(?:email\s+)?"
    rf"(?:{_VERIFICATION_CODE_MODIFIER}|totp|hotp|pin|passcode)\b"
)
_VERIFICATION_CODE_DESTINATION_SUFFIX = (
    r"(?:\s+(?:to|into|in|on|at|with)\s+"
    r"(?:(?:the|this|that|your)\s+)?"
    r"(?:website|site|webpage|page|portal|app|application|form|"
    r"login(?:\s+(?:page|screen))?|sign[-\s]?in(?:\s+(?:page|screen))?|"
    r"support|sender|recipient|person|agent|representative))?"
)
_VERIFICATION_CODE_PURPOSE_SUFFIX = (
    r"(?:\s+to\s+(?:sign\s+in|log\s+in|login|verify|authenticate|"
    r"complete\s+(?:login|sign[-\s]?in|authentication)|"
    r"access\s+(?:the\s+)?(?:account|portal|site|website|app)))?"
)
_VERIFICATION_CODE_ACTION_SUFFIX = (
    rf"(?:{_VERIFICATION_CODE_DESTINATION_SUFFIX}|{_VERIFICATION_CODE_PURPOSE_SUFFIX})"
    rf"{_TARGET_END}"
)
_NON_VERIFICATION_CODE_SEND_TARGET_START = (
    rf"(?!(?:{_VERIFICATION_CODE_TARGET}{_VERIFICATION_CODE_ACTION_SUFFIX}|"
    rf"{_VERIFICATION_CODE_TARGET_PREFIX}{_TARGET_END}))"
    rf"{_SEND_TARGET_START}"
)
_DIRECTIVE_ONLY_SPLIT_LINE_ACTIONS = {
    "modify_labels",
    "unsubscribe",
    "click_link",
    "open_link",
    "open_attachment",
    "download_attachment",
    "scan_qr_code",
    "call_phone",
    "send_sms",
    "use_verification_code",
    "accept_invite",
    "decline_invite",
    "tentative_invite",
    "create_calendar_event",
}
_DIRECTIVE_PATTERNS = {
    "send": [
        re.compile(
            rf"(?i)^\s*(?:[-*]|\d+[.)])?\s*(?:please\s+)?send\s+"
            rf"{_NON_VERIFICATION_CODE_SEND_TARGET_START}"
        ),
        re.compile(
            r"(?i)\b(?:you\s+should|you\s+must|next\s+step(?:s)?|action\s+item(?:s)?|recommended\s+action(?:s)?)\b"
            rf".*\bsend\s+{_NON_VERIFICATION_CODE_SEND_TARGET_START}"
        ),
        re.compile(
            rf"(?i)\b(?:just|now|immediately|then|next)\b.*\bsend\s+"
            rf"{_NON_VERIFICATION_CODE_SEND_TARGET_START}"
        ),
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
        re.compile(rf"{_DIRECTIVE_START}{_DELETE_TARGET}"),
        re.compile(
            rf"{_RECOMMENDATION_START}{_GENERIC_DELETE_RECOMMENDATION_LEAD_IN}\b{_DELETE_TARGET}"
        ),
    ],
    "permanent_delete": [
        re.compile(rf"{_DIRECTIVE_START}{_PERMANENT_DELETE_TARGET}"),
        re.compile(
            rf"{_RECOMMENDATION_PREFIX}{_PERMANENT_DELETE_TARGET}"
        ),
    ],
    "trash": [
        re.compile(rf"{_DIRECTIVE_START}trash\s+{_MAILBOX_OBJECT}\b"),
        re.compile(
            rf"{_RECOMMENDATION_PREFIX}\btrash\s+{_MAILBOX_OBJECT}\b"
        ),
    ],
    "forward": [
        re.compile(rf"{_DIRECTIVE_START}forward\s+(?:to|{_MAILBOX_OBJECT})\b"),
        re.compile(rf"{_DIRECTIVE_START}forward\s+{_FORWARD_EXFIL_TARGET}"),
        re.compile(
            rf"{_RECOMMENDATION_PREFIX}\bforward\s+(?:to|{_MAILBOX_OBJECT})\b"
        ),
        re.compile(
            rf"{_RECOMMENDATION_PREFIX}\bforward\s+{_FORWARD_EXFIL_TARGET}"
        ),
    ],
    "modify_labels": [
        re.compile(
            rf"{_DIRECTIVE_START}{_LABEL_MUTATION_VERB}\s+{_LABEL_TARGET}\b"
        ),
        re.compile(
            rf"{_RECOMMENDATION_PREFIX}\b{_LABEL_MUTATION_VERB}\s+{_LABEL_TARGET}\b"
        ),
        re.compile(
            rf"{_DIRECTIVE_START}label\s+{_MAILBOX_OBJECT}\s+as\s+[\w-]+(?:\s+[\w-]+){{0,5}}\b"
        ),
        re.compile(
            rf"{_RECOMMENDATION_PREFIX}\blabel\s+{_MAILBOX_OBJECT}\s+as\s+[\w-]+(?:\s+[\w-]+){{0,5}}\b"
        ),
    ],
    "mark_read": [
        re.compile(rf"{_DIRECTIVE_START}mark\s+(?:as\s+read|{_MAILBOX_OBJECT}\s+(?:as\s+)?read)\b"),
        re.compile(
            rf"{_RECOMMENDATION_PREFIX}\bmark\s+(?:as\s+read|{_MAILBOX_OBJECT}\s+(?:as\s+)?read)\b"
        ),
    ],
    "mark_unread": [
        re.compile(rf"{_DIRECTIVE_START}mark\s+(?:as\s+unread|{_MAILBOX_OBJECT}\s+(?:as\s+)?unread)\b"),
        re.compile(
            rf"{_RECOMMENDATION_PREFIX}\bmark\s+(?:as\s+unread|{_MAILBOX_OBJECT}\s+(?:as\s+)?unread)\b"
        ),
    ],
    "star": [
        re.compile(rf"{_DIRECTIVE_START}star\s+{_MAILBOX_OBJECT}\b"),
        re.compile(
            rf"{_RECOMMENDATION_PREFIX}\bstar\s+{_MAILBOX_OBJECT}\b"
        ),
    ],
    "unstar": [
        re.compile(rf"{_DIRECTIVE_START}unstar\s+{_MAILBOX_OBJECT}\b"),
        re.compile(
            rf"{_RECOMMENDATION_PREFIX}\bunstar\s+{_MAILBOX_OBJECT}\b"
        ),
    ],
    "move_to_spam": [
        re.compile(rf"{_DIRECTIVE_START}move\s+(?:{_MAILBOX_OBJECT}\s+)?to\s+spam\b{_TARGET_END}"),
        re.compile(
            rf"{_RECOMMENDATION_PREFIX}\bmove\s+(?:{_MAILBOX_OBJECT}\s+)?to\s+spam\b{_TARGET_END}"
        ),
    ],
    "move_to_inbox": [
        re.compile(rf"{_DIRECTIVE_START}move\s+(?:{_MAILBOX_OBJECT}\s+)?to\s+(?:the\s+)?inbox\b{_TARGET_END}"),
        re.compile(
            rf"{_RECOMMENDATION_PREFIX}\bmove\s+(?:{_MAILBOX_OBJECT}\s+)?to\s+(?:the\s+)?inbox\b{_TARGET_END}"
        ),
    ],
    "snooze": [
        re.compile(rf"{_DIRECTIVE_START}snooze\s+{_SNOOZE_MAILBOX_OBJECT}\b{_SNOOZE_TARGET_END}"),
        re.compile(
            rf"{_RECOMMENDATION_PREFIX}\bsnooze\s+{_SNOOZE_MAILBOX_OBJECT}\b{_SNOOZE_TARGET_END}"
        ),
    ],
    "create_filter": [
        re.compile(rf"{_DIRECTIVE_START}create\s+{_FILTER_TARGET}"),
        re.compile(
            rf"{_RECOMMENDATION_PREFIX}\bcreate\s+{_FILTER_TARGET}"
        ),
    ],
    "unsubscribe": [
        re.compile(rf"{_DIRECTIVE_START}unsubscribe\s+{_UNSUBSCRIBE_TARGET}{_TARGET_END}"),
        re.compile(
            rf"{_RECOMMENDATION_PREFIX}\bunsubscribe\s+{_UNSUBSCRIBE_TARGET}{_TARGET_END}"
        ),
    ],
    "click_link": [
        re.compile(
            rf"{_ACTION_SUGGESTION_START}(?:click|follow)\s+(?:on\s+)?"
            rf"{_CLICK_LINK_TARGET}\b"
        ),
    ],
    "open_link": [
        re.compile(
            rf"{_ACTION_SUGGESTION_START}(?:open|visit)\s+{_LINK_TARGET}\b"
        ),
    ],
    "open_attachment": [
        re.compile(rf"{_ACTION_SUGGESTION_START}open\s+{_ATTACHMENT_TARGET}"),
    ],
    "download_attachment": [
        re.compile(rf"{_ACTION_SUGGESTION_START}download\s+{_ATTACHMENT_TARGET}"),
    ],
    "scan_qr_code": [
        re.compile(
            rf"{_ACTION_SUGGESTION_START}scan\s+{_QR_SCAN_TARGET}"
            rf"{_QR_PURPOSE_SUFFIX}{_TARGET_END}"
        ),
        re.compile(
            rf"{_ACTION_SUGGESTION_START}use\s+{_QR_EXPLICIT_TARGET}"
            rf"{_QR_PURPOSE_SUFFIX}{_TARGET_END}"
        ),
        re.compile(
            rf"{_ACTION_SUGGESTION_START}(?:follow|tap)\s+{_QR_EXPLICIT_TARGET}"
            rf"{_QR_PURPOSE_SUFFIX}{_TARGET_END}"
        ),
        re.compile(
            rf"{_ACTION_SUGGESTION_START}click\s+(?:on\s+)?"
            rf"{_QR_LINK_TARGET}{_TARGET_END}"
        ),
        re.compile(
            rf"{_ACTION_SUGGESTION_START}(?:follow|open|visit)\s+"
            rf"{_QR_LINK_TARGET}{_TARGET_END}"
        ),
    ],
    "call_phone": [
        re.compile(rf"{_ACTION_SUGGESTION_START}call\s+{_DIRECT_CONTACT_TARGET}{_TARGET_END}"),
    ],
    "send_sms": [
        re.compile(rf"{_ACTION_SUGGESTION_START}(?:text|message)\s+{_DIRECT_CONTACT_TARGET}{_TARGET_END}"),
        re.compile(
            rf"{_ACTION_SUGGESTION_START}send\s+(?:an?\s+)?(?:sms|text(?:\s+message)?)\s+"
            rf"{_SMS_PRE_TARGET_MODIFIER}to\s+{_DIRECT_CONTACT_TARGET}{_TARGET_END}"
        ),
        re.compile(
            rf"{_ACTION_SUGGESTION_START}send\s+(?:an?\s+)?"
            rf"(?:sms|text(?:\s+message)?)\b{_DIRECT_SMS_TARGET_END}"
        ),
    ],
    "use_verification_code": [
        re.compile(
            rf"{_ACTION_SUGGESTION_START}(?:use|enter|submit|copy|paste|provide|share|send)\s+"
            rf"{_VERIFICATION_CODE_TARGET}{_VERIFICATION_CODE_ACTION_SUFFIX}"
        ),
        re.compile(
            rf"{_ACTION_SUGGESTION_START}(?:type|input)\s+(?:in\s+)?"
            rf"{_VERIFICATION_CODE_TARGET}{_VERIFICATION_CODE_ACTION_SUFFIX}"
        ),
        re.compile(
            rf"{_ACTION_SUGGESTION_START}(?:reply|respond)\s+with\s+"
            rf"{_VERIFICATION_CODE_TARGET}{_VERIFICATION_CODE_ACTION_SUFFIX}"
        ),
    ],
    "accept_invite": [
        re.compile(rf"{_ACTION_SUGGESTION_START}accept\s+{_INVITE_TARGET}"),
        re.compile(rf"{_ACTION_SUGGESTION_START}rsvp\s+yes\s+to\s+{_INVITE_TARGET}"),
    ],
    "decline_invite": [
        re.compile(rf"{_ACTION_SUGGESTION_START}(?:decline|reject)\s+{_INVITE_TARGET}"),
        re.compile(rf"{_ACTION_SUGGESTION_START}rsvp\s+no\s+to\s+{_INVITE_TARGET}"),
    ],
    "tentative_invite": [
        re.compile(rf"{_ACTION_SUGGESTION_START}rsvp\s+(?:maybe|tentative)\s+to\s+{_INVITE_TARGET}"),
        re.compile(
            rf"{_ACTION_SUGGESTION_START}mark\s+{_INVITE_TARGET}\s+"
            r"(?:as\s+)?tentative\b"
        ),
    ],
    "create_calendar_event": [
        re.compile(
            rf"{_ACTION_SUGGESTION_START}(?:add|create|schedule)\s+"
            rf"{_CALENDAR_EVENT_TARGET}\s+from\s+{_CALENDAR_SOURCE_TARGET}"
        ),
        re.compile(
            rf"{_ACTION_SUGGESTION_START}add\s+{_INVITE_TARGET}\s+"
            rf"to\s+{_CALENDAR_LOCATION_TARGET}{_TARGET_END}"
        ),
        re.compile(
            rf"{_ACTION_SUGGESTION_START}put\s+{_CALENDAR_EVENT_TARGET}\s+"
            rf"on\s+{_CALENDAR_LOCATION_TARGET}{_TARGET_END}"
        ),
        re.compile(
            rf"{_ACTION_SUGGESTION_START}add\s+to\s+{_CALENDAR_LOCATION_TARGET}\s+"
            rf"from\s+{_CALENDAR_SOURCE_TARGET}{_TARGET_END}"
        ),
    ],
}
_ACTION_WORD_PATTERNS = {
    "send": re.compile(r"(?i)\bsend\b"),
    "reply": re.compile(r"(?i)\breply\b"),
    "delete": re.compile(r"(?i)\bdelete\b"),
    "permanent_delete": re.compile(r"(?i)\bpermanent(?:ly)?\s+delete\b"),
    "trash": re.compile(r"(?i)\btrash\b"),
    "forward": re.compile(r"(?i)\bforward\b"),
    "mark_read": re.compile(r"(?i)\bmark\b.*\bread\b"),
    "mark_unread": re.compile(r"(?i)\bmark\b.*\bunread\b"),
    "star": re.compile(r"(?i)\bstar\b"),
    "unstar": re.compile(r"(?i)\bunstar\b"),
    "move_to_spam": re.compile(r"(?i)\bmove\b.*\bspam\b"),
    "move_to_inbox": re.compile(r"(?i)\bmove\b.*\binbox\b"),
    "snooze": re.compile(r"(?i)\bsnooze\b"),
    "create_filter": re.compile(r"(?i)\bcreate\b.*\bfilter\b"),
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

    redacted = _GOOGLE_OAUTH_TOKEN_RE.sub("[REDACTED_GOOGLE_TOKEN]", text)
    redacted = _GOOGLE_REFRESH_TOKEN_RE.sub("[REDACTED_GOOGLE_REFRESH_TOKEN]", redacted)
    redacted = _JWT_RE.sub("[REDACTED_JWT]", redacted)
    redacted = _AWS_ACCESS_KEY_ID_RE.sub("[REDACTED_AWS_KEY]", redacted)
    redacted = _SLACK_TOKEN_RE.sub("[REDACTED_SLACK_TOKEN]", redacted)
    redacted = _GITHUB_TOKEN_RE.sub("[REDACTED_GITHUB_TOKEN]", redacted)
    redacted = _STRIPE_SECRET_KEY_RE.sub("[REDACTED_STRIPE_KEY]", redacted)
    redacted = _BEARER_TOKEN_RE.sub(r"\1[REDACTED_TOKEN]", redacted)
    redacted = _API_TOKEN_RE.sub(r"\1\2[REDACTED_TOKEN]\2", redacted)
    redacted = _EMAIL_RE.sub("[REDACTED_EMAIL]", redacted)
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
    direct_actions_by_index = []

    for index, line in enumerate(lines):
        actions = _directive_actions(line)
        direct_actions_by_index.append(set(actions))
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
            if action in _DIRECTIVE_ONLY_SPLIT_LINE_ACTIONS:
                # Split-line directives for these actions rely on direct matches
                # instead of generic action words to avoid over-matching benign
                # verbs or mentions on neighboring lines.
                if (
                    action not in direct_actions_by_index[index]
                    and action not in direct_actions_by_index[index + 1]
                ):
                    blocked_line_indexes.update({index, index + 1})
                else:
                    if action in direct_actions_by_index[index]:
                        blocked_line_indexes.add(index)
                    if action in direct_actions_by_index[index + 1]:
                        blocked_line_indexes.add(index + 1)
                matched_any_line = True
                continue

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
