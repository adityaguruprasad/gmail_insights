import re
from typing import Iterable, List, Set, Tuple

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
    "report_phishing",
    "report_spam",
    "move_to_inbox",
    "snooze",
    "create_filter",
    "change_filter_settings",
    "create_forwarding_rule",
    "set_auto_reply",
    "unsubscribe",
    "click_link",
    "open_link",
    "open_attachment",
    "download_attachment",
    "run_executable",
    "enable_macros",
    "disable_security_software",
    "print_email",
    "export_data",
    "share_file",
    "upload_file",
    "load_remote_content",
    "enable_browser_notifications",
    "scan_qr_code",
    "start_remote_access",
    "call_phone",
    "send_sms",
    "create_contact",
    "update_contact",
    "update_account_contact",
    "use_verification_code",
    "approve_login_prompt",
    "accept_invite",
    "decline_invite",
    "tentative_invite",
    "create_calendar_event",
    "create_task",
    "provide_sensitive_info",
    "crypto_wallet_action",
    "make_payment",
    "update_payment_method",
    "sign_in",
    "create_external_account",
    "change_password",
    "password_manager_action",
    "authorize_app",
    "grant_mailbox_access",
    "change_security_settings",
    "change_mail_access_settings",
    "change_network_settings",
    "install_profile",
    "update_email_signature",
    "submit_form",
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
    rf"(?:(?:this|that)(?:\s+(?:(?:[\w-]+\s+){{0,3}})?{_MAILBOX_OBJECT_NOUN})?|"
    rf"(?:these|those)\s+(?:(?:[\w-]+\s+){{0,3}})?{_MAILBOX_OBJECT_NOUN}|"
    r"it|them|all)"
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
_FILTER_RULE_MUTATION_VERB = (
    r"(?:update|modify|change|edit|delete|remove|disable|deactivate|"
    r"turn\s+off|enable|activate|turn\s+on)"
)
_FILTER_OBJECT_TARGET = (
    r"(?:(?:the|an?|this|that|my|your|our)\s+)?"
    r"(?:(?:gmail|google|mail|email|inbox)\s+)?"
    r"filter(?:s|\s+settings?)?\b"
)
_FILTER_RULE_OBJECT_TARGET = (
    rf"(?:{_FILTER_OBJECT_TARGET}|"
    r"(?:(?:the|an?|this|that|my|your|our)\s+)?"
    r"(?:gmail|mail|email|inbox)\s+rules?\b)"
)
_FILTER_RULE_DETAIL_SUFFIX = (
    r"(?:\s+(?:for|from|matching|with|where|when|to|in|on|within)\s+"
    r"(?:(?:the|this|that|these|those|my|your|our|an?)\s+)?"
    r"[\w@./:+%#&=?-]+(?:\s+[\w@./:+%#&=?-]+){0,8})?"
)
_FILTER_RULE_ACTION_TARGET = (
    rf"{_FILTER_RULE_OBJECT_TARGET}{_FILTER_RULE_DETAIL_SUFFIX}{_TARGET_END}"
)
_REPORT_PHISHING_TERM = r"(?:phishing|phish)"
_REPORT_SPAM_TERM = r"(?:spam|junk|abuse)"
_REPORT_PHISHING_TARGET = (
    rf"(?:(?:{_MAILBOX_OBJECT}\s+(?:as|for)\s+)?{_REPORT_PHISHING_TERM})"
    rf"\b{_TARGET_END}"
)
_REPORT_SPAM_TARGET = (
    rf"(?:(?:{_MAILBOX_OBJECT}\s+(?:as|for)\s+)?{_REPORT_SPAM_TERM})"
    rf"\b{_TARGET_END}"
)
_MARK_REPORT_PHISHING_TARGET = (
    rf"(?:{_MAILBOX_OBJECT}\s+)?(?:as|for)\s+{_REPORT_PHISHING_TERM}\b{_TARGET_END}"
)
_MARK_REPORT_SPAM_TARGET = (
    rf"(?:{_MAILBOX_OBJECT}\s+)?(?:as|for)\s+{_REPORT_SPAM_TERM}\b{_TARGET_END}"
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
_MIDLINE_ACTION_SUGGESTION_START = (
    rf"(?i)\b{_RECOMMENDATION_KEYWORD}\b\s*:?\s*"
    r"(?:(?:please|first|then|next|just|now|also)\s+){0,4}"
)
_SEQUENCED_ACTION_SUGGESTION_START = (
    r"(?i)(?:[.!?,:;]\s*)?\b(?:then|next|also)\s+"
    r"(?:(?:please|then|next|just|now|also)\s+){0,4}"
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
_PRINT_TARGET = (
    rf"(?:{_MAILBOX_OBJECT}|{_EXPLICIT_ATTACHMENT_TARGET}|"
    rf"{_BARE_ATTACHMENT_FILE_TARGET}(?:\s+from\s+{_MAILBOX_OBJECT})?)"
)
_PRINT_PURPOSE_SUFFIX = r"(?:\s+for\s+(?:your|my|our|the)\s+records?)?"
_PRINT_ACTION_SUFFIX = rf"{_PRINT_PURPOSE_SUFFIX}(?:\s+{_URGENCY_SUFFIX})?{_TARGET_END}"
_FILE_OBJECT_NOUN = rf"(?:attachments?|{_ATTACHED_FILE_NOUN})"
_FILE_OBJECT_TARGET = (
    rf"(?:(?:the|this|that|an?|your)\s+)?"
    rf"(?:[\w-]+\s+){{0,3}}{_FILE_OBJECT_NOUN}\b"
)
_EXECUTABLE_OBJECT_NOUN = (
    r"(?:attachments?|files?|installers?|scripts?|apps?|applications?|"
    r"executables?|programs?|binaries?|setup\s+files?)"
)
_EXECUTABLE_OBJECT_TARGET = (
    rf"(?:(?:the|this|that|an?|your)\s+)?"
    rf"(?:[\w-]+\s+){{0,3}}"
    rf"{_EXECUTABLE_OBJECT_NOUN}\b"
)
_EXECUTABLE_SOURCE_SUFFIX = (
    r"(?:\s+(?:from|in)\s+(?:(?:the|this|that|an?|your)\s+)?"
    r"(?:email|message|thread|attachment))?"
)
_EXECUTABLE_FOLLOWUP_SUFFIX = (
    r"(?:\s+(?:and|then|to|for)\s+[\w-]+(?:\s+[\w-]+){0,8})?"
)
_EXECUTABLE_ACTION_SUFFIX = (
    rf"{_EXECUTABLE_SOURCE_SUFFIX}{_EXECUTABLE_FOLLOWUP_SUFFIX}{_TARGET_END}"
)
_MACRO_TARGET = r"macros?\b"
_MACRO_CONTEXT_NOUN = (
    r"(?:documents?|spreadsheets?|workbooks?|attachments?|files?|docs?|sheets?)"
)
_MACRO_CONTEXT_TARGET = (
    rf"(?:(?:the|this|that|an?|your)\s+)?"
    rf"(?:[\w-]+\s+){{0,3}}"
    rf"{_MACRO_CONTEXT_NOUN}\b"
)
_MACRO_ACTION_SUFFIX = (
    rf"(?:\s+to\s+run)?(?:\s+(?:in|for|on|within)\s+{_MACRO_CONTEXT_TARGET})?"
    r"(?:\s+(?:and|then|to)\s+[\w-]+(?:\s+[\w-]+){0,8})?"
    rf"{_TARGET_END}"
)
_OFFICE_ACTIVE_CONTENT_TARGET = r"(?:content|editing|protected\s+view\s+editing)\b"
_OFFICE_ENABLE_BUTTON_TARGET = (
    r"(?:enable\s+(?:content|editing)|enable\s+protected\s+view\s+editing)\b"
)
_OFFICE_ENABLE_BUTTON_UI_NOUN = r"(?:buttons?|prompts?|banners?)"
_OFFICE_ACTIVE_CONTENT_CONTEXT_NOUN = (
    r"(?:documents?|spreadsheets?|workbooks?|attachments?|files?|docs?|"
    r"sheets?|invoices?|reports?|forms?)"
)
_OFFICE_ACTIVE_CONTENT_CONTEXT_TARGET = (
    rf"(?:(?:the|this|that|an?|your)\s+)?"
    rf"(?:[\w-]+\s+){{0,3}}"
    rf"{_OFFICE_ACTIVE_CONTENT_CONTEXT_NOUN}\b"
)
_OFFICE_ACTIVE_CONTENT_VIEW_TARGET = (
    rf"(?:(?:the|this|that|an?|your)\s+)?"
    rf"(?:[\w-]+\s+){{0,3}}"
    rf"(?:content|{_OFFICE_ACTIVE_CONTENT_CONTEXT_NOUN})\b"
)
_OFFICE_ACTIVE_CONTENT_ACTION_SUFFIX = (
    rf"(?:\s+(?:in|for|on|within)\s+{_OFFICE_ACTIVE_CONTENT_CONTEXT_TARGET}|"
    rf"\s+to\s+(?:view|open|read|see|access|display)\s+"
    rf"{_OFFICE_ACTIVE_CONTENT_VIEW_TARGET})"
    rf"{_TARGET_END}"
)
_LOCAL_SECURITY_TARGET_PREFIX = r"(?:(?:the|your|this|that|my|our)\s+)?"
_LOCAL_SECURITY_CONTROL_TARGET = (
    rf"{_LOCAL_SECURITY_TARGET_PREFIX}"
    r"(?:anti[-\s]?virus(?:\s+(?:software|protection|scanner|scanning))?|"
    r"anti[-\s]?malware(?:\s+(?:software|protection|scanner|scanning))?|"
    r"security\s+(?:software|products?|protections?)|"
    r"endpoint\s+protection|firewall|"
    r"(?:windows|microsoft)\s+defender|gatekeeper|smart\s*screen|"
    r"real[-\s]?time\s+(?:protection|scanning|monitoring)|"
    r"(?:malware|virus)\s+(?:protection|scanning|scanner))\b"
)
_LOCAL_SECURITY_EXCLUSION_PRODUCT = (
    rf"{_LOCAL_SECURITY_TARGET_PREFIX}"
    r"(?:anti[-\s]?virus(?:\s+software)?|anti[-\s]?malware|"
    r"(?:windows|microsoft)\s+defender|malware|virus)\b"
)
_LOCAL_SECURITY_EXCLUSION_TARGET = (
    rf"{_LOCAL_SECURITY_EXCLUSION_PRODUCT}\s+"
    r"(?:exclusions?|exclusion\s+lists?|allow[-\s]?lists?|white[-\s]?lists?)\b"
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
_AUTO_FORWARD_COMMAND_LEAD = (
    r"(?:all\s+)?(?:emails?|messages?|mail)\s+automatically\b"
)
_FORWARDING_MODE = (
    r"(?:email\s+forwarding|mail\s+forwarding|mailbox\s+forwarding|"
    r"auto[-\s]?forwarding|automatic\s+forwarding|forwarding)"
)
_FORWARDING_RULE_OBJECT = (
    r"(?:(?:an?|the)\s+)?"
    r"(?:auto[-\s]?forwarding|(?:(?:mail|email|mailbox|inbox|automatic)\s+)?forwarding)"
    r"\s+rules?\b"
)
_FORWARDING_RULE_CONTEXT = (
    r"(?:(?:this|that|the|your|my|our)\s+)?"
    r"(?:inbox|mailbox|email\s+account|gmail|account)\b"
)
_FORWARDING_RULE_TARGET_SUFFIX = (
    rf"(?:\s+to\s+{_FORWARD_RECIPIENT_TARGET}|\s+for\s+{_FORWARDING_RULE_CONTEXT})?"
)
_AUTO_REPLY_OBJECT_NOUN = (
    r"(?:out[-\s]+of[-\s]+office\s+(?:repl(?:y|ies)|responses?|messages?)|"
    r"vacation\s+responders?|"
    r"automatic\s+(?:email\s+)?repl(?:y|ies)|"
    r"automated\s+(?:email\s+)?repl(?:y|ies)|"
    r"auto[-\s]?repl(?:y|ies)(?:\s+messages?)?)"
)
_AUTO_REPLY_SETTING_TARGET = (
    rf"(?:(?:an?|the|this|that|my|your|our)\s+)?"
    rf"(?:[\w-]+\s+){{0,2}}{_AUTO_REPLY_OBJECT_NOUN}\b"
)
_AUTO_REPLY_CONTEXT_SUFFIX = (
    r"(?:\s+(?:for|in|on|within)\s+"
    r"(?:(?:this|that|the|my|your|our)\s+)?"
    r"(?:account|gmail|google\s+account|email\s+account|mailbox|inbox))?"
)
_AUTO_REPLY_ACTION_TARGET = (
    rf"{_AUTO_REPLY_SETTING_TARGET}{_AUTO_REPLY_CONTEXT_SUFFIX}{_TARGET_END}"
)
_EMAIL_SIGNATURE_TARGET = (
    r"(?:(?:an?|the|this|that|my|your|our)\s+)?"
    r"(?:(?:email|gmail|account)\s+)?"
    r"(?:signature(?:s|\s+settings?)?)\b"
)
_EMAIL_SIGNATURE_DETAIL_SUFFIX = (
    r"(?:\s+(?:to\s+(?:include|use|show|display)|with|using|from|for|on|in)\s+"
    r"(?:(?:this|that|these|those|the|an?|my|your|our)\s+)?"
    r"[\w@./:+%#&=?-]+(?:\s+[\w@./:+%#&=?-]+){0,8})?"
)
_EMAIL_SIGNATURE_ACTION_TARGET = (
    rf"{_EMAIL_SIGNATURE_TARGET}{_EMAIL_SIGNATURE_DETAIL_SUFFIX}{_TARGET_END}"
)
# Exclude ambiguous software/client/account-only nouns here so OAuth/app-access
# directives stay classified under authorize_app unless the phrasing is mailbox-specific.
_MAILBOX_ACCESS_GRANTEE_NOUN = (
    r"(?:sender|recipient|contact|customer|person|user|assistant|"
    r"vendor|supplier|accounting|accountant|bookkeeper|security|team|owner|"
    r"agent|representative)"
)
_MAILBOX_ACCESS_GRANTEE_TARGET = (
    rf"(?:{_EMAIL_TARGET}|(?:(?:the|this|that|an?|my|your|our)\s+)?"
    rf"(?:[\w-]+\s+){{0,3}}{_MAILBOX_ACCESS_GRANTEE_NOUN}\b)"
)
_MAILBOX_ACCESS_RESOURCE = (
    r"(?:(?:this|that|the|my|your|our)\s+)?"
    r"(?:gmail|google\s+account|email\s+account|mailbox|inbox)\b"
)
_MAILBOX_DELEGATE_ROLE = (
    r"(?:(?:gmail|mailbox|inbox|email)\s+)?delegates?\b"
)
_MAILBOX_ACCESS_PERMISSION = (
    r"(?:(?:gmail|google\s+account|email\s+account|mailbox|inbox|"
    r"delegate|delegation)\s+access|"
    r"(?:gmail|mailbox|inbox|email)\s+delegation)\b"
)
_MAILBOX_ACCESS_CONTEXT_SUFFIX = (
    rf"(?:\s+(?:for|in|on|within)\s+{_MAILBOX_ACCESS_RESOURCE})?"
)
_FILE_UPLOAD_DESTINATION = (
    r"(?:(?:the|this|that|your)\s+)?"
    r"(?:google\s+drive|drive|dropbox|one\s*drive|onedrive|sharepoint|"
    r"icloud|client\s+portal|customer\s+portal|vendor\s+portal|"
    r"accounting\s+portal|portal|file\s+sharing\s+(?:site|service|platform)|"
    r"cloud\s+(?:storage|folder))\b"
)
_EXPORT_DATA_OBJECT_NOUN = (
    r"(?:inbox|mailbox(?:\s+backup)?|mailbox\s+data|email\s+data|"
    r"message\s+data|thread\s+data|message\s+history|email\s+history|"
    r"messages?|emails?|threads?)"
)
_EXPORT_DATA_OBJECT = (
    r"(?:(?:all|my|your|our|the|this|that|these|those|"
    r"user's|the\s+user's)\s+)?"
    rf"(?:[\w-]+\s+){{0,3}}{_EXPORT_DATA_OBJECT_NOUN}\b"
)
_EXPORT_DATA_DESTINATION = (
    r"(?:csv|archive|zip|file|google\s+drive|drive|spreadsheet|"
    r"document|json|mbox|pst|takeout|backup)\b"
)
_EXPORT_DATA_DESTINATION_SUFFIX = (
    rf"(?:\s+(?:to|into|in|on)\s+(?:(?:an?|the)\s+)?"
    rf"{_EXPORT_DATA_DESTINATION}|"
    rf"\s+as\s+(?:(?:an?|the)\s+)?{_EXPORT_DATA_DESTINATION})"
)
_OPTIONAL_EXPORT_DATA_DESTINATION_SUFFIX = (
    rf"(?:{_EXPORT_DATA_DESTINATION_SUFFIX})?"
)
_PHONE_NUMBER_TARGET = r"(?:\+?\d{1,3}[\s.-]?)?(?:\(?\d{3}\)?[\s.-]?)\d{3}[\s.-]?\d{4}"
_DIRECT_CONTACT_TARGET = (
    rf"(?:{_PHONE_NUMBER_TARGET}|"
    r"(?:(?:the|this|that)\s+)?(?:sender|contact|customer|client|person|"
    r"phone\s+number|number)\b)"
)
# Contact book targets are destinations for adding/saving entries.
_CONTACT_BOOK_TARGET = r"(?:(?:my|your|the)\s+)?(?:contacts?|address\s+book)\b"
# Contact source targets identify the thing being saved as a contact.
_CONTACT_SOURCE_TARGET = (
    rf"(?:{_PHONE_NUMBER_TARGET}|{_EMAIL_TARGET}|"
    r"(?:(?:the|this|that|an?|your)\s+)?(?:[\w-]+\s+){0,2}"
    r"(?:sender|recipient|customer|client|person|phone\s+number|number|"
    r"email\s+address|contact\s+details|contact\s+information|email|message|thread)\b)"
)
_CONTACT_DESCRIPTOR = r"(?:(?:[\w-]+\s+){0,2})"
# Contact record targets identify existing address-book records to update.
_CONTACT_RECORD_NOUN = (
    r"(?:contact\s+records?|address\s+book\s+entr(?:y|ies)|customer\s+contacts?|"
    r"client\s+contacts?|contact)"
)
_CONTACT_RECORD_TARGET = (
    rf"(?:(?:the|this|that|an?|your)\s+)?{_CONTACT_DESCRIPTOR}"
    rf"{_CONTACT_RECORD_NOUN}\b"
)
# Contact detail targets are fields/details being written to an existing contact.
_CONTACT_DETAIL_TARGET = (
    rf"(?:{_PHONE_NUMBER_TARGET}|{_EMAIL_TARGET}|"
    r"(?:(?:the|this|that|these|those|an?|your)\s+)?(?:[\w-]+\s+){0,3}"
    r"(?:phone\s+number|number|email\s+address|address|contact\s+details|"
    r"contact\s+information|details|info)\b)"
)
_CONTACT_MUTATION_END = (
    rf"(?=\s*(?:[.!?,:;]|\b{_URGENCY_SUFFIX}\b\s*(?:$|[.!?,:;])))"
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
    r"(?:(?:a|an|the|this|that|your)\s+)?(?:[\w-]+\s+){0,3}"
    r"(?:calendar\s+events?|meetings?|appointments?)\b"
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
_LOGIN_APPROVAL_SERVICE = (
    r"(?:duo|okta(?:\s+verify)?|microsoft\s+authenticator|google\s+authenticator|"
    r"authy|authenticator(?:\s+app)?|mfa\s+app|2fa\s+app)"
)
_LOGIN_APPROVAL_CONTEXT = (
    rf"(?:{_LOGIN_APPROVAL_SERVICE}|login|log[-\s]?in|sign[-\s]?in|"
    r"authentication|auth|verification|mfa|2fa|two[-\s]?factor|multi[-\s]?factor)"
)
_LOGIN_APPROVAL_REQUEST_NOUN = (
    r"(?:prompts?|requests?|notifications?|push(?:\s+notifications?)?|"
    r"approval(?:\s+requests?)?|challenges?)"
)
_LOGIN_APPROVAL_CONTEXTUAL_TARGET = (
    r"(?:(?:the|this|that|your|an?)\s+)?"
    rf"(?:(?:{_LOGIN_APPROVAL_CONTEXT})\s+){{1,3}}"
    rf"{_LOGIN_APPROVAL_REQUEST_NOUN}\b"
)
_LOGIN_APPROVAL_SERVICE_TARGET = (
    r"(?:(?:the|this|that|your|an?)\s+)?"
    rf"{_LOGIN_APPROVAL_SERVICE}\b"
)
_LOGIN_APPROVAL_SERVICE_SUFFIX = (
    rf"(?:\s+(?:in|on|from|through|via|using)\s+{_LOGIN_APPROVAL_SERVICE_TARGET})?"
)
_LOGIN_APPROVAL_PROMPT_TARGET = (
    rf"(?:{_LOGIN_APPROVAL_CONTEXTUAL_TARGET}{_LOGIN_APPROVAL_SERVICE_SUFFIX}|"
    rf"(?:(?:the|this|that|your|an?)\s+)?"
    rf"{_LOGIN_APPROVAL_REQUEST_NOUN}\b\s+"
    rf"(?:in|on|from|through|via|using)\s+{_LOGIN_APPROVAL_SERVICE_TARGET})"
)
_LOGIN_APPROVAL_RESPONSE_TARGET = (
    rf"(?:{_LOGIN_APPROVAL_PROMPT_TARGET}|{_LOGIN_APPROVAL_SERVICE_TARGET})"
)
_SIGN_IN_TARGET_NOUN = (
    r"(?:accounts?|portals?|sites?|websites?|webpages?|apps?|applications?|gmail|"
    r"login(?:\s+(?:page|screen|portal|site))?|"
    r"sign[-\s]?in(?:\s+(?:page|screen|portal|site))?)"
)
_SIGN_IN_TARGET = (
    r"(?:(?:the|this|that|your|an?)\s+)?(?:[\w-]+\s+){0,3}"
    rf"{_SIGN_IN_TARGET_NOUN}\b"
)
_SIGN_IN_SOURCE_SUFFIX = (
    r"(?:\s+from\s+(?:(?:the|this|that|an?)\s+)?(?:email|message|thread))?"
)
_SIGN_IN_ACTION_END = rf"{_SIGN_IN_SOURCE_SUFFIX}{_TARGET_END}"
_SIGN_IN_DESTINATION_SUFFIX = (
    rf"(?:\s+(?:to|into|on|onto|at|through|via|with)\s+{_SIGN_IN_TARGET})?"
)
_SIGN_IN_SESSION_VERB = r"(?:sign\s+in|log\s+in|login|authenticate)\b"
_SIGN_IN_COMPACT_VERB = r"(?:sign\s+into|log\s+into)\b"
_EXTERNAL_ACCOUNT_DESTINATION_NOUN = (
    r"(?:accounts?|services?|portals?|sites?|websites?|webpages?|apps?|"
    r"applications?|platforms?)"
)
_EXTERNAL_ACCOUNT_DESTINATION = (
    r"(?:(?:the|this|that|your|an?|new)\s+)?(?:[\w-]+\s+){0,3}"
    rf"{_EXTERNAL_ACCOUNT_DESTINATION_NOUN}\b"
)
_EXTERNAL_ACCOUNT_SOURCE = (
    rf"(?:{_LINK_TARGET}|"
    r"(?:(?:the|this|that|an?)\s+)?(?:email|message|thread))"
)
_EXTERNAL_ACCOUNT_SOURCE_SUFFIX = (
    rf"(?:\s+(?:using|via|through|from)\s+{_EXTERNAL_ACCOUNT_SOURCE})?"
)
_EXTERNAL_ACCOUNT_CONTEXT_SUFFIX = (
    rf"(?:\s+(?:on|at|in|with|for)\s+{_EXTERNAL_ACCOUNT_DESTINATION}"
    rf"{_EXTERNAL_ACCOUNT_SOURCE_SUFFIX}|"
    rf"{_EXTERNAL_ACCOUNT_SOURCE_SUFFIX})"
    rf"{_TARGET_END}"
)
_EXTERNAL_ACCOUNT_CREATION_TARGET = (
    r"(?:(?:an?|the|your|new)\s+){0,2}accounts?\b"
    rf"{_EXTERNAL_ACCOUNT_CONTEXT_SUFFIX}"
)
_EXTERNAL_ACCOUNT_REGISTRATION_TARGET = (
    rf"(?:"
    rf"(?:for\s+)?(?:(?:an?|the|your|new)\s+){{0,2}}accounts?\b"
    rf"{_EXTERNAL_ACCOUNT_CONTEXT_SUFFIX}|"
    rf"(?:for|on|at|with)\s+{_EXTERNAL_ACCOUNT_DESTINATION}"
    rf"{_EXTERNAL_ACCOUNT_SOURCE_SUFFIX}{_TARGET_END}|"
    rf"(?:using|via|through)\s+{_EXTERNAL_ACCOUNT_SOURCE}{_TARGET_END}"
    rf")"
)
_EXTERNAL_ACCOUNT_SIGNUP_TARGET = (
    rf"(?:\s+(?:for|on|at|with|to)\s+{_EXTERNAL_ACCOUNT_DESTINATION}"
    rf"{_EXTERNAL_ACCOUNT_SOURCE_SUFFIX}|"
    rf"\s+(?:using|via|through)\s+{_EXTERNAL_ACCOUNT_SOURCE})?"
    rf"{_TARGET_END}"
)
_NON_VERIFICATION_CODE_SEND_TARGET_START = (
    rf"(?!(?:{_VERIFICATION_CODE_TARGET}{_VERIFICATION_CODE_ACTION_SUFFIX}|"
    rf"{_VERIFICATION_CODE_TARGET_PREFIX}{_TARGET_END}))"
    rf"{_SEND_TARGET_START}"
)
_REMOTE_CONTENT_RESOURCE_TARGET = (
    r"(?:(?:the|this|that|all)\s+)?"
    r"(?:(?:remote|external)\s+(?:images?|content)|tracking\s+(?:pixels?|images?))\b"
)
_REMOTE_CONTENT_SENDER_TARGET = (
    r"(?:(?:the|this|that|all)\s+)?images?\s+"
    r"(?:for|from)\s+(?:(?:this|that|the)\s+)?sender\b"
)
_REMOTE_CONTENT_SENDER_SUFFIX = (
    r"(?:\s+(?:for|from)\s+(?:(?:this|that|the)\s+)?sender)?"
)
_REMOTE_CONTENT_LOAD_TARGET = (
    rf"(?:{_REMOTE_CONTENT_RESOURCE_TARGET}"
    rf"{_REMOTE_CONTENT_SENDER_SUFFIX}|{_REMOTE_CONTENT_SENDER_TARGET})"
)
_BROWSER_NOTIFICATION_CONTEXT = (
    r"(?:(?:the|this|that|your|an?)\s+)?"
    r"(?:browser|site|website|web\s+site|service|sender)\b"
)
_BROWSER_NOTIFICATION_SEND_NOUN = (
    r"(?:(?:browser|site|website|web\s+site|web|push)\s+)?notifications?\b"
)
_BROWSER_NOTIFICATION_CONTEXT_SUFFIX = (
    rf"(?:\s+(?:for|from|in|on|within)\s+{_BROWSER_NOTIFICATION_CONTEXT})?"
)
_BROWSER_NOTIFICATION_PERMISSION_TARGET = (
    rf"(?:"
    rf"(?:browser|site|website|web\s+site|web|push)\s+notifications?"
    rf"{_BROWSER_NOTIFICATION_CONTEXT_SUFFIX}|"
    rf"notifications?\s+(?:for|from|in|on|within)\s+"
    rf"{_BROWSER_NOTIFICATION_CONTEXT}"
    rf")"
)
_REMOTE_ACCESS_SESSION_NOUN = (
    r"(?:(?:remote\s+(?:desktop|support|assistance)|screen[-\s]+sharing|support)"
    r"\s+sessions?)"
)
_REMOTE_ACCESS_SESSION_TARGET = (
    r"(?:(?:the|this|that|an?|your)\s+)?"
    rf"(?:[\w-]+\s+){{0,2}}{_REMOTE_ACCESS_SESSION_NOUN}\b"
)
_REMOTE_ACCESS_DEVICE_TARGET = (
    r"(?:(?:your|my|our|the|this|that|an?)\s+)?"
    r"(?:[\w-]+\s+){0,2}(?:computer|device|desktop|laptop|machine|pc|mac|system)\b"
)
_REMOTE_ACCESS_PERMISSION_TARGET = (
    rf"(?:remote\s+access(?:\s+(?:to|of)\s+{_REMOTE_ACCESS_DEVICE_TARGET})?|"
    rf"remote\s+control(?:\s+of\s+{_REMOTE_ACCESS_DEVICE_TARGET})?)"
)
_REMOTE_ACCESS_GRANTEE_NOUN = (
    r"(?:support\s+team|customer\s+support|technical\s+support|it\s+support|"
    r"help\s*desk|sender|recipient|contact|customer|client|person|user|"
    r"technician|support|agent|representative|vendor|supplier|it)"
)
_REMOTE_ACCESS_GRANTEE_TARGET = (
    rf"(?:{_EMAIL_TARGET}|(?:(?:the|this|that|an?|your|my|our)\s+)?"
    rf"(?:[\w-]+\s+){{0,2}}{_REMOTE_ACCESS_GRANTEE_NOUN}\b)"
)
_SCREEN_SHARE_TARGET = r"(?:(?:your|my|our|the|this|that)\s+)?screens?\b"
_CRYPTO_WALLET_APP = (
    r"(?:metamask|walletconnect|coinbase\s+wallet|trust\s+wallet|phantom|"
    r"ledger|trezor)"
)
_CRYPTO_CONTEXT_DESCRIPTOR = (
    r"(?:blockchain|on[-\s]?chain|wallet|crypto|web3|ethereum|bitcoin|"
    r"token|nft)"
)
_CRYPTO_WALLET_TARGET = (
    rf"(?:{_CRYPTO_WALLET_APP}\b|"
    r"(?:(?:your|the|this|that|my|our|an?)\s+)?"
    rf"(?:(?:{_CRYPTO_CONTEXT_DESCRIPTOR})\s+)?wallets?\b)"
)
_CRYPTO_WALLET_DESTINATION = (
    r"(?:(?:the|this|that|your|an?)\s+)?"
    r"(?:site|website|webpage|page|portal|app|application|dapp|d[-\s]?app|"
    r"platform|browser)\b"
)
_CRYPTO_WALLET_CONNECTION_SUFFIX = (
    rf"(?:\s+(?:to|with|through|via|on)\s+{_CRYPTO_WALLET_DESTINATION})?"
)
_CRYPTO_TRANSACTION_DETAILED_TARGET = (
    r"(?:(?:the|this|that|your|an?)\s+)?"
    rf"(?:{_CRYPTO_CONTEXT_DESCRIPTOR}\s+){{1,2}}transactions?\b"
)
_CRYPTO_TRANSACTION_WALLET_TARGET = (
    r"(?:(?:the|this|that|your|an?)\s+)?transactions?\b\s+"
    rf"(?:in|with|using|through|via|on)\s+{_CRYPTO_WALLET_TARGET}"
)
_CRYPTO_TRANSACTION_TARGET = (
    rf"(?:{_CRYPTO_TRANSACTION_DETAILED_TARGET}|"
    rf"{_CRYPTO_TRANSACTION_WALLET_TARGET})"
)
_CRYPTO_MESSAGE_TARGET = (
    r"(?:(?:the|this|that|your|an?)\s+)?messages?\b\s+"
    rf"(?:with|using|through|via|in|on)\s+{_CRYPTO_WALLET_TARGET}"
)
_CRYPTO_TRANSACTION_CONTEXT_SUFFIX = (
    rf"(?:\s+(?:in|with|using|through|via|on)\s+{_CRYPTO_WALLET_TARGET})?"
)
_CRYPTO_WALLET_SECRET_NOUN = (
    r"(?:(?:wallet\s+)?(?:seed|recovery|secret\s+recovery)\s+phrases?|"
    r"mnemonic(?:\s+phrases?)?|"
    r"private\s+keys?)"
)
_CRYPTO_WALLET_SECRET_TARGET = (
    r"(?:(?:your|the|this|that|my|our|an?)\s+)?"
    rf"(?:[\w-]+\s+){{0,2}}{_CRYPTO_WALLET_SECRET_NOUN}\b"
)
_CRYPTO_SECRET_DESTINATION = (
    rf"(?:{_CRYPTO_WALLET_TARGET}|{_CRYPTO_WALLET_DESTINATION}|"
    r"(?:(?:the|this|that|your|an?)\s+)?"
    r"(?:support|team|agent|representative|person|company|service)\b)"
)
_CRYPTO_SECRET_DESTINATION_SUFFIX = (
    rf"(?:\s+(?:to|with|into|in|on|through|via|using|at)\s+"
    rf"{_CRYPTO_SECRET_DESTINATION})?"
)
_FINANCIAL_AMOUNT = (
    r"(?:[$\u20ac\u00a3]\s?\d[\d,]*(?:\.\d+)?|"
    r"\d+(?:\.\d+)?\s*(?:btc|bitcoin|eth|ether|ethereum|usdc|usdt|usd|eur|gbp))"
)
_PAYMENT_OBLIGATION_NOUN = (
    r"(?:invoices?|bills?|outstanding\s+balances?|balances?|amounts?\s+due|"
    r"amounts?|fees?|charges?|dues|payments?)"
)
_PAYMENT_TARGET_MODIFIER = (
    r"(?:(?!(?:to|from|for|with|about|over|into|onto|at|by|as)\b)[\w-]+\s+)"
)
_PAYMENT_OBLIGATION_TARGET = (
    rf"(?:(?:the|this|that|an?|your)\s+)?(?:{_PAYMENT_TARGET_MODIFIER}){{0,4}}"
    rf"{_PAYMENT_OBLIGATION_NOUN}\b"
)
_PAYMENT_FUNDS_NOUN = r"(?:funds?|money|payments?|amounts?|cash)"
_PAYMENT_FUNDS_TARGET = (
    rf"(?:{_FINANCIAL_AMOUNT}|(?:(?:the|this|that|an?|your)\s+)?"
    rf"(?:{_PAYMENT_TARGET_MODIFIER}){{0,3}}{_PAYMENT_FUNDS_NOUN}\b)"
)
_PAYMENT_DESTINATION_NOUN = (
    r"(?:vendors?|suppliers?|customers?|clients?|merchants?|sellers?|payees?|"
    r"accounting|finance|bookkeepers?|wallets?|banks?|accounts?)"
)
_PAYMENT_DESTINATION_TARGET = (
    rf"(?:{_EMAIL_TARGET}|(?:(?:the|this|that|an?|your)\s+)?"
    rf"(?:{_PAYMENT_TARGET_MODIFIER}){{0,4}}{_PAYMENT_DESTINATION_NOUN}\b)"
)
_PAYMENT_CHANNEL_TARGET = (
    r"(?:(?:the|this|that|your)\s+)?(?:payment\s+)?"
    r"(?:portal|website|site|app|application|form|link)\b"
)
_PAYMENT_APPROVAL_NOUN = (
    r"(?:transactions?|payments?|charges?|purchases?|wires?|transfers?|refunds?|"
    r"invoices?)"
)
_CRYPTO_PAYMENT_APPROVAL_TARGET = (
    r"(?:(?:the|this|that|an?|your)\s+)?"
    rf"(?:[\w-]+\s+){{0,2}}{_CRYPTO_CONTEXT_DESCRIPTOR}\s+transactions?\b"
)
_PURCHASE_TARGET_NOUN = r"(?:gift\s+cards?|licenses?|subscriptions?|software|products?)"
_GIFT_CARD_TARGET_MODIFIER = (
    r"(?:(?!(?:to|from|for|with|about|over|into|onto|at|by|as|on|using)\b)"
    r"[\w-]+\s+)"
)
_GIFT_CARD_VALUE_TARGET = (
    rf"(?:(?:the|this|that|an?|your)\s+)?(?:{_GIFT_CARD_TARGET_MODIFIER}){{0,3}}"
    r"(?:gift[-\s]?card\s+(?:codes?|pins?|card[-\s]?numbers?|numbers?)|"
    r"gift[-\s]?codes?)\b"
)
_GIFT_CARD_REDEMPTION_TARGET = (
    rf"(?:(?:the|this|that|an?|your)\s+)?(?:{_GIFT_CARD_TARGET_MODIFIER}){{0,3}}"
    r"(?:gift[-\s]?card(?:\s+(?:codes?|pins?|card[-\s]?numbers?|numbers?))?|"
    r"gift[-\s]?codes?)\b"
)
_GIFT_CARD_PAYMENT_TERM_RE = re.compile(r"(?i)\bgift[-\s]?(?:cards?|codes?)\b")
_GIFT_CARD_DESTINATION = (
    r"(?:(?:the|this|that|your)\s+)?"
    r"(?:portal|website|site|app|application|form|link|checkout|payment\s+page|"
    r"support|sender|recipient|person|agent|representative)\b"
)
_GIFT_CARD_ACTION_SUFFIX = (
    rf"(?:\s+(?:to|into|in|on|through|via|using|with|at)\s+"
    rf"{_GIFT_CARD_DESTINATION})?"
    rf"{_TARGET_END}"
)
_REFUND_TARGET_NOUN = (
    r"(?:customers?|clients?|buyers?|users?|accounts?|orders?|payments?|charges?|"
    r"transactions?|invoices?)"
)
_PAYMENT_METHOD_DETAIL_NOUN = (
    r"(?:payment\s+methods?|payment\s+details|payment\s+information|"
    r"credit\s+card(?:\s+(?:numbers?|details|information|info))?|"
    r"debit\s+card(?:\s+(?:numbers?|details|information|info))?|"
    r"cards?|card\s+(?:numbers?|details|information|info)|"
    r"bank\s+account(?:\s+(?:numbers?|details|information|info))?|"
    r"routing\s+numbers?|bank\s+details|"
    r"billing\s+details|billing\s+information|billing\s+info)"
)
_PAYMENT_METHOD_DETAIL_TARGET = (
    rf"(?:(?:the|this|that|an?|your)\s+)?(?:[\w-]+\s+){{0,2}}"
    rf"{_PAYMENT_METHOD_DETAIL_NOUN}\b"
)
_PAYMENT_METHOD_DESTINATION = (
    r"(?:(?:the|this|that|your)\s+)?"
    r"(?:accounts?|portals?|billing\s+(?:forms?|pages?|portals?|sites?|links?|accounts?|apps?|applications?)|"
    r"payment\s+(?:forms?|pages?|portals?|sites?|links?|accounts?|apps?|applications?)|"
    r"forms?|websites?|sites?|apps?|"
    r"applications?|links?)\b"
)
_PAYMENT_METHOD_ACTION_SUFFIX = (
    rf"(?:\s+(?:to|into|in|on|through|via|using|with)\s+"
    rf"{_PAYMENT_METHOD_DESTINATION})?"
    rf"{_TARGET_END}"
)
_APP_PASSWORD_CREDENTIAL = (
    r"(?:(?:an?|the|this|that|my|your|our|new)\s+){0,2}"
    r"(?:(?:gmail|google(?:\s+workspace)?)\s+)?app\s+passwords?\b"
)
_PASSWORD_CREDENTIAL_NOUN = r"(?:password|credentials?)"
_PASSWORD_ACCOUNT_CONTEXT = (
    r"(?:(?:this|that|the|your|an?)\s+)?"
    r"(?:account|portal|site|website|webpage|app|application|login|profile|service)\b"
)
_PASSWORD_CREDENTIAL_TARGET = (
    rf"(?!{_APP_PASSWORD_CREDENTIAL})"
    rf"(?:(?:(?:your|the|this|that|an?|new|login|account|portal|site|website|"
    rf"app|application|email|online)\s+){{0,4}}{_PASSWORD_CREDENTIAL_NOUN}\b"
    rf"(?:\s+for\s+{_PASSWORD_ACCOUNT_CONTEXT})?)"
)
_PASSWORD_ACTION_CHANNEL = (
    r"(?:(?:the|this|that|an?|your)\s+)?(?:[\w-]+\s+){0,3}"
    r"(?:link|url|website|webpage|page|site|portal|app|application|form)\b"
)
_PASSWORD_ACTION_SUFFIX = (
    rf"(?:\s+(?:using|via|through|with|on|at|in)\s+"
    rf"{_PASSWORD_ACTION_CHANNEL})?"
    rf"(?:\s+{_URGENCY_SUFFIX})?"
    r"(?=\s*(?:$|[.!?,:;]))"
)
_BROWSER_PASSWORD_APP = (
    r"(?:chrome|edge|firefox|safari|brave|browser|web\s+browser)"
)
_PASSWORD_MANAGER_STORE = (
    r"(?:(?:the|this|that|your|my|our)\s+)?"
    rf"(?:(?:{_BROWSER_PASSWORD_APP})\s+)?"
    r"(?:password|credential)\s+managers?\b"
)
_PASSWORD_MANAGER_BROWSER_LOCATION = (
    r"(?:(?:the|this|that|your|my|our)\s+)?"
    rf"{_BROWSER_PASSWORD_APP}\b"
)
_PASSWORD_MANAGER_LOCATION = (
    rf"(?:{_PASSWORD_MANAGER_STORE}|{_PASSWORD_MANAGER_BROWSER_LOCATION})"
)
_PASSWORD_MANAGER_SPECIFIC_PASSWORD_OBJECT = (
    r"(?:(?:all|the|your|my|our|this|that|these|those)\s+)?"
    rf"(?:(?:saved|stored|{_BROWSER_PASSWORD_APP})\s+){{1,3}}passwords?\b"
)
_PASSWORD_MANAGER_GENERIC_PASSWORD_OBJECT = (
    r"(?:(?:all|the|your|my|our|this|that|these|those)\s+)?passwords?\b"
)
_PASSWORD_MANAGER_CONTEXTUAL_PASSWORD_OBJECT = (
    rf"(?:{_PASSWORD_MANAGER_SPECIFIC_PASSWORD_OBJECT}|"
    rf"{_PASSWORD_MANAGER_GENERIC_PASSWORD_OBJECT}\s+"
    rf"(?:from|in|within|out\s+of)\s+{_PASSWORD_MANAGER_LOCATION})"
)
_PASSWORD_MANAGER_EXPORT_DESTINATION = (
    r"(?:csv|file|spreadsheet|document|json|archive|zip|backup|text\s+file)\b"
)
_PASSWORD_MANAGER_EXPORT_ACTION_SUFFIX = (
    rf"(?:\s+(?:from|in|within|out\s+of)\s+{_PASSWORD_MANAGER_LOCATION})?"
    rf"(?:\s+(?:to|into|in|on|as)\s+(?:(?:an?|the)\s+)?"
    rf"{_PASSWORD_MANAGER_EXPORT_DESTINATION})?"
    rf"{_TARGET_END}"
)
_PASSWORD_MANAGER_IMPORT_SOURCE = (
    r"(?:(?:the|this|that|an?|your)\s+)?"
    r"(?:attachment|attached\s+file|file|csv|spreadsheet|document|"
    r"password\s+file|export(?:ed)?\s+file)\b"
)
_PASSWORD_MANAGER_IMPORT_TARGET = (
    rf"(?:{_PASSWORD_MANAGER_SPECIFIC_PASSWORD_OBJECT}"
    rf"(?:\s+(?:from|using|via)\s+{_PASSWORD_MANAGER_IMPORT_SOURCE})?|"
    rf"{_PASSWORD_MANAGER_GENERIC_PASSWORD_OBJECT}\s+"
    rf"(?:from|using|via)\s+{_PASSWORD_MANAGER_IMPORT_SOURCE})"
)
_PASSWORD_MANAGER_SAVE_TARGET = (
    r"(?:(?:the|this|that|your|my|our|new|saved|generated|provided)\s+)?"
    r"password\b"
)
_PASSWORD_MANAGER_PROTECTION_TARGET = (
    rf"(?:{_PASSWORD_MANAGER_STORE}|"
    r"(?:(?:the|this|that|your|my|our)\s+)?"
    rf"(?:(?:{_BROWSER_PASSWORD_APP})\s+)?password\s+manager\s+protection\b"
    rf"(?:\s+(?:in|within|for|on)\s+{_PASSWORD_MANAGER_LOCATION})?|"
    r"(?:(?:the|this|that|your|my|our)\s+)?"
    rf"(?:(?:{_BROWSER_PASSWORD_APP})\s+)?password\s+protection\b"
    rf"(?:\s+(?:in|within|for|on)\s+{_PASSWORD_MANAGER_LOCATION})?)"
)
_AUTHZ_OBJECT_NOUN = (
    r"(?:apps?|applications?|integrations?|browser\s+extensions?|extensions?|"
    r"oauth\s+(?:apps?|applications?|clients?)|"
    r"third[-\s]?party\s+(?:apps?|applications?|services?))"
)
_LESS_SECURE_APP_ACCESS_CORE = (
    r"(?:(?:the|this|that|an?|my|your|our)\s+)?less\s+secure\s+apps?(?:\s+access)?"
)
_AUTHZ_OBJECT_TARGET = (
    rf"(?!{_LESS_SECURE_APP_ACCESS_CORE}\b)"
    rf"(?:(?:the|this|that|an?|your)\s+)?(?:[\w-]+\s+){{0,2}}"
    rf"{_AUTHZ_OBJECT_NOUN}\b"
)
_AUTHZ_SERVICE_TARGET = (
    r"(?:(?:the|this|that|an?|your)\s+)?(?:[\w-]+\s+){0,2}services?\b"
)
_AUTHZ_GRANTEE_TARGET = rf"(?:{_AUTHZ_OBJECT_TARGET}|{_AUTHZ_SERVICE_TARGET})"
_AUTHZ_ACCESS_RESOURCE = (
    r"(?:gmail|google\s+account|mailbox|email|inbox|account|messages?|data)"
)
_AUTHZ_ACCESS_SUFFIX = (
    rf"(?:\s+(?:to\s+access|for)\s+(?:(?:the|your)\s+)?"
    rf"{_AUTHZ_ACCESS_RESOURCE}(?:\s+access)?)?"
)
_AUTHZ_PERMISSION_TARGET = (
    r"(?:(?:the|this|that|an?|your)\s+)?"
    r"(?:oauth\s+consent(?:\s+request)?|consent\s+request|"
    r"permission\s+grant|permissions?|account\s+access|gmail\s+access|"
    r"mailbox\s+access|email\s+access)\b"
)
_AUTHZ_ACCESS_GRANT_TARGET = (
    r"(?:access|account\s+access|gmail\s+access|mailbox\s+access|"
    r"email\s+access|permissions?|permission\s+grant)\b"
)
_AUTHZ_ACCOUNT_TARGET = (
    r"(?:(?:your|the)\s+)?"
    r"(?:google\s+account|gmail|mailbox|email\s+account|account)\b"
)
_SECURITY_AUTH_FACTOR_TARGET = (
    r"(?:2fa|mfa|(?:two|multi)[-\s]?factor(?:\s+authentication)?)\b"
)
_SECURITY_KEY_TARGET = (
    r"(?:(?:the|this|that|your|my|our|an?)\s+)?"
    r"(?:[\w-]+\s+){0,2}security\s+keys?\b"
)
_SECURITY_ACCOUNT_SETTING_TARGET = (
    r"(?:(?:your|the|this|that|my|our)\s+)?"
    r"(?:account|gmail|google\s+account|email\s+account)\b"
)
_TRUSTED_DEVICE_TARGET = (
    r"(?:(?:the|this|that|your|my|our|an?)\s+)?"
    r"(?:[\w-]+\s+){0,2}(?:device|browser|computer|phone)\b"
)
_TRUSTED_DEVICE_SETTING_TARGET = (
    r"(?:(?:the|this|that|your|my|our|an?)\s+)?"
    r"(?:[\w-]+\s+){0,2}trusted\s+"
    r"(?:device|browser|computer|phone)s?\b"
)
_SECURITY_PASSKEY_TARGET = (
    r"(?:(?:the|this|that|your|my|our|an?)\s+)?passkeys?\b"
)
_SECURITY_ENROLLMENT_METHOD_TARGET = (
    r"(?:(?:the|this|that|your|my|our|an?)\s+)?"
    r"(?:link|url|page|browser|device|phone|computer)\b"
)
_SECURITY_ENROLLMENT_SUFFIX = (
    rf"(?:\s+(?:for|to|in|on|within)\s+{_SECURITY_ACCOUNT_SETTING_TARGET}|"
    rf"\s+(?:using|via|through)\s+{_SECURITY_ENROLLMENT_METHOD_TARGET})?"
)
_SECURITY_BACKUP_CODES_TARGET = (
    r"(?:(?:the|this|that|your|my|our)\s+)?backup\s+codes?\b"
)
_SECURITY_PROTECTION_TARGET = (
    r"(?:(?:the|this|that|your|my|our)\s+)?"
    r"(?:spam|phishing|spam\s+and\s+phishing|phishing\s+and\s+spam)\s+"
    r"(?:protection|filtering|filters?)\b"
)
_SECURITY_SENDER_TARGET = r"(?:(?:the|this|that)\s+)?sender\b"
_SECURITY_SAFE_SENDER_ENTRY_TARGET = (
    rf"(?:{_SECURITY_SENDER_TARGET}|{_EMAIL_TARGET}|"
    r"(?:(?:the|this|that|your|my|our)\s+)?domains?\b|"
    rf"{_BARE_DOMAIN_TARGET})"
)
_SECURITY_SAFE_SENDER_LIST_TARGET = (
    r"(?:(?:the|this|that|your|my|our)\s+)?"
    r"(?:safe\s+senders?|allow[-\s]?list|whitelist)(?:\s+list)?\b"
)
_SECURITY_FILTER_SCOPE_SUFFIX = (
    rf"(?:\s+(?:for|from|in|on|within)\s+(?:{_SECURITY_SENDER_TARGET}|"
    r"(?:(?:your|the|this|that|my|our)\s+)?"
    r"(?:account|gmail|google\s+account|email\s+account|customer|user)))?"
)
_SECURITY_ACCOUNT_SETTING_SUFFIX = (
    r"(?:\s+(?:from|for|in|on|within)\s+"
    rf"{_SECURITY_ACCOUNT_SETTING_TARGET})?"
)
_MAIL_ACCESS_ACCOUNT_CONTEXT = (
    r"(?:(?:this|that|the|my|your|our)\s+)?"
    r"(?:account|gmail|google\s+account|email\s+account)\b"
)
_MAIL_ACCESS_CONTEXT_SUFFIX = (
    rf"(?:\s+(?:for|in|on|within)\s+{_MAIL_ACCESS_ACCOUNT_CONTEXT})?"
)
_MAIL_ACCESS_PROTOCOL = r"(?:imaps?|pop(?:3s?|-3s?|\s+3)?)"
_MAIL_ACCESS_PROTOCOL_TARGET = (
    rf"(?:{_MAIL_ACCESS_PROTOCOL}\b\s+(?:access|settings?)|"
    rf"{_MAIL_ACCESS_PROTOCOL}\b(?=\s+(?:for|in|on|within)\b))"
    rf"{_MAIL_ACCESS_CONTEXT_SUFFIX}"
)
_LESS_SECURE_APP_ACCESS_TARGET = (
    rf"{_LESS_SECURE_APP_ACCESS_CORE}\b{_MAIL_ACCESS_CONTEXT_SUFFIX}"
)
_MAIL_CLIENT_ACCESS_SETTING_TARGET = (
    r"(?:"
    r"(?:insecure\s+)?mail[-\s]+client\s+access(?:\s+settings?)?|"
    r"(?:email|mail)\s+access\s+(?:protocols?|settings?)"
    r")\b"
    rf"{_MAIL_ACCESS_CONTEXT_SUFFIX}"
)
_MAIL_ACCESS_SETTING_TARGET = (
    rf"(?:{_MAIL_ACCESS_PROTOCOL_TARGET}|"
    rf"{_LESS_SECURE_APP_ACCESS_TARGET}|"
    rf"{_MAIL_CLIENT_ACCESS_SETTING_TARGET})"
)
_APP_PASSWORD_TARGET = rf"{_APP_PASSWORD_CREDENTIAL}{_MAIL_ACCESS_CONTEXT_SUFFIX}"
_NETWORK_SETTING_TARGET = (
    r"(?:(?:the|this|that|your|my|our|an?)\s+)?"
    r"(?:"
    r"dns(?:\s+(?:settings?|configuration|preferences?|servers?|resolvers?|addresses?))?|"
    r"proxy(?:\s+(?:settings?|configuration|preferences?|servers?))?|"
    r"vpn(?:\s+(?:settings?|configuration|preferences?))?|"
    r"network\s+(?:settings?|configuration|preferences?)"
    r")\b"
)
_NETWORK_SETTING_VALUE = r"[\w@./:+%#&=?-]+(?:\s+[\w@./:+%#&=?-]+){0,4}"
_NETWORK_SETTING_CONTEXT = (
    r"(?:(?:the|this|that|your|my|our|an?)\s+)?"
    r"(?:email|message|thread|site|website|webpage|page|app|application|"
    r"device|computer|phone|browser|system|network|settings)\b"
)
_NETWORK_SETTING_ACTION_SUFFIX = (
    rf"(?:\s+(?:to|as|using|via|through|with)\s+{_NETWORK_SETTING_VALUE})?"
    rf"(?:\s+(?:from|in|on|for|within)\s+{_NETWORK_SETTING_CONTEXT})?"
    rf"{_TARGET_END}"
)
_INSTALL_PROFILE_NOUN = (
    r"(?:configuration\s+profiles?|config\s+profiles?|mdm\s+profiles?|"
    r"mobile\s+device\s+management\s+profiles?|vpn\s+profiles?|profiles?|"
    r"root\s+certificates?|ca\s+certificates?|certificate\s+authority\s+certificates?|"
    r"browser\s+certificates?|trust\s+certificates?|certificates?)"
)
_INSTALL_PROFILE_TARGET = (
    r"(?:(?:the|this|that|an?|your|my|our)\s+)?"
    rf"(?:[\w-]+\s+){{0,2}}{_INSTALL_PROFILE_NOUN}\b"
)
_INSTALL_PROFILE_LOCATION = (
    r"(?:(?:the|this|that|an?|your|my|our)\s+)?"
    r"(?:email|message|thread|attachment|link|site|website|device|computer|"
    r"phone|iphone|ipad|android|mac|pc|browser|system|settings|keychain|"
    r"certificate\s+store|trust\s+store)\b"
)
_INSTALL_PROFILE_ACTION_SUFFIX = (
    rf"(?:\s+(?:from|in|on|to|into|onto|for|within)\s+"
    rf"{_INSTALL_PROFILE_LOCATION}){{0,2}}{_TARGET_END}"
)
_ACCOUNT_CONTACT_CHANNEL_NOUN = r"(?:email(?:\s+address)?|phone(?:\s+number)?)"
_ACCOUNT_CONTACT_FIELD_TARGET = (
    r"(?:(?:the|this|that|your|my|our|an?)\s+)?"
    r"(?:"
    rf"(?:recovery|backup|alternate|notification)\s+{_ACCOUNT_CONTACT_CHANNEL_NOUN}\b|"
    rf"account\s+{_ACCOUNT_CONTACT_CHANNEL_NOUN}\b|"
    rf"{_ACCOUNT_CONTACT_CHANNEL_NOUN}\s+"
    r"(?:on|for|in)\s+(?:(?:your|the|this|that|my|our)\s+)?account\b"
    r")"
)
_ACCOUNT_CONTACT_VALUE_TARGET = rf"(?:{_EMAIL_TARGET}|{_PHONE_NUMBER_TARGET})"
_ACCOUNT_CONTACT_ACCOUNT_CONTEXT = (
    r"(?:(?:your|the|this|that|my|our)\s+)?account\b"
)
_ACCOUNT_CONTACT_ACTION_SUFFIX = (
    rf"(?:\s+(?:to|with)\s+{_ACCOUNT_CONTACT_VALUE_TARGET})?"
    rf"(?:\s+(?:to|for|on|in|from)\s+{_ACCOUNT_CONTACT_ACCOUNT_CONTEXT})?"
    rf"{_TARGET_END}"
)
_FORM_OBJECT = (
    r"(?:(?:the|this|that|an?|your)\s+)?"
    r"(?:(?:[\w-]+\s+){0,3})?forms?\b"
)
_FORM_DETAIL_NOUN = r"(?:details|information|info|credentials?)"
_FORM_DETAIL_SOURCE = (
    rf"(?:(?:your|the|this|that|account|personal|contact|login)\s+){{0,3}}"
    rf"{_FORM_DETAIL_NOUN}\b"
)
_FORM_DETAILS_SUFFIX = rf"(?:\s+with\s+{_FORM_DETAIL_SOURCE})?"
_FORM_SUBMISSION_TARGET = rf"{_FORM_OBJECT}{_FORM_DETAILS_SUFFIX}{_TARGET_END}"
_SENSITIVE_INFO_PAYMENT_METHOD_NOUN = (
    r"(?:bank\s+account(?:\s+(?:numbers?|details|information|info))?|"
    r"routing\s+numbers?|"
    r"credit\s+card(?:\s+(?:numbers?|details|information|info))?|"
    r"debit\s+card(?:\s+(?:numbers?|details|information|info))?|"
    r"card\s+numbers?)"
)
_IDENTITY_DOCUMENT_NOUN_SUFFIX = (
    r"(?:\s+(?:numbers?|details|information|info|scans?|photos?|images?))?"
)
_SENSITIVE_INFO_NON_PAYMENT_NOUN = (
    r"(?:ssn|s\.s\.n|social\s+security\s+(?:numbers?|no)|"
    r"dates?\s+of\s+birth|birth\s+dates?|dob|"
    r"tax\s+(?:ids?|identification\s+numbers?)|tin|ein|"
    r"mother'?s\s+maiden\s+name|maiden\s+name|"
    rf"passports?{_IDENTITY_DOCUMENT_NOUN_SUFFIX}|"
    rf"(?:driver'?s|drivers?|driving)\s+licenses?{_IDENTITY_DOCUMENT_NOUN_SUFFIX}|"
    rf"government\s+ids?{_IDENTITY_DOCUMENT_NOUN_SUFFIX}|"
    rf"photo\s+ids?{_IDENTITY_DOCUMENT_NOUN_SUFFIX}|"
    rf"national\s+ids?{_IDENTITY_DOCUMENT_NOUN_SUFFIX}|"
    rf"identity\s+documents?{_IDENTITY_DOCUMENT_NOUN_SUFFIX}|"
    r"(?<!bank\s)account\s+numbers?|"
    r"credentials?|passwords?|passphrases?|pins?)"
)
_SENSITIVE_INFO_NOUN = (
    rf"(?:{_SENSITIVE_INFO_NON_PAYMENT_NOUN}|{_SENSITIVE_INFO_PAYMENT_METHOD_NOUN})"
)
_SENSITIVE_INFO_TARGET_PREFIX = (
    r"(?:(?:your|the|this|that|my|our|their|user's|the\s+user's)\s+)?"
    r"(?:[\w'-]+\s+){0,4}"
)
_SENSITIVE_INFO_TARGET = (
    rf"{_SENSITIVE_INFO_TARGET_PREFIX}{_SENSITIVE_INFO_NOUN}\b"
)
_SENSITIVE_INFO_NON_PAYMENT_TARGET = (
    rf"{_SENSITIVE_INFO_TARGET_PREFIX}{_SENSITIVE_INFO_NON_PAYMENT_NOUN}\b"
)
_SENSITIVE_INFO_PAYMENT_METHOD_TARGET = (
    rf"{_SENSITIVE_INFO_TARGET_PREFIX}{_SENSITIVE_INFO_PAYMENT_METHOD_NOUN}\b"
)
_SENSITIVE_INFO_DESTINATION = (
    r"(?:(?:the|this|that|your|their|an?)\s+)?"
    r"(?:[\w-]+\s+){0,3}"
    r"(?:portal|form|site|website|webpage|page|link|url|sender|recipient|"
    r"support|team|agent|representative|person|company|service|app|"
    r"application|bank|agency)\b"
)
_SENSITIVE_INFO_PAYMENT_CONTEXT_DESTINATION = (
    r"(?:(?:the|this|that|your|their|an?)\s+)?"
    r"(?:billing|payment)\s+"
    r"(?:forms?|pages?|portals?|sites?|links?|accounts?|apps?|applications?)\b"
)
_SENSITIVE_INFO_DESTINATION_SUFFIX = (
    rf"(?:\s+(?:to|with|into|in|on|through|via|using|at)\s+"
    rf"{_SENSITIVE_INFO_DESTINATION})?"
)
_SENSITIVE_INFO_PAYMENT_METHOD_DESTINATION_SUFFIX = (
    rf"(?!(?:\s+(?:to|with|into|in|on|through|via|using|at)\s+"
    rf"{_SENSITIVE_INFO_PAYMENT_CONTEXT_DESTINATION}))"
    rf"(?:\s+(?:to|with|into|in|on|through|via|using|at)\s+"
    rf"{_SENSITIVE_INFO_DESTINATION})?"
)
_SENSITIVE_INFO_ACTION_TARGET = (
    rf"{_SENSITIVE_INFO_TARGET}{_SENSITIVE_INFO_DESTINATION_SUFFIX}{_TARGET_END}"
)
_SENSITIVE_INFO_PAYMENT_OVERLAP_ACTION_TARGET = (
    rf"(?:{_SENSITIVE_INFO_NON_PAYMENT_TARGET}{_SENSITIVE_INFO_DESTINATION_SUFFIX}|"
    rf"{_SENSITIVE_INFO_PAYMENT_METHOD_TARGET}"
    rf"{_SENSITIVE_INFO_PAYMENT_METHOD_DESTINATION_SUFFIX}){_TARGET_END}"
)
_TASK_ITEM_NOUN = r"(?:tasks?|to[-\s]?dos?|to[-\s]?do\s+items?|reminders?)"
_TASK_ITEM_TARGET = (
    rf"(?:(?:an?|the|this|that|my|your)\s+)?(?:[\w-]+\s+){{0,3}}"
    rf"{_TASK_ITEM_NOUN}\b"
)
_TASK_CONTAINER_NOUN = r"(?:task\s+list|to[-\s]?do\s+list|reminder\s+list)"
_TASK_CONTAINER_TARGET = (
    rf"(?:(?:my|your|the|this|that)\s+)?(?:[\w-]+\s+){{0,2}}"
    rf"{_TASK_CONTAINER_NOUN}\b"
)
_TASK_PURPOSE_SUFFIX = r"(?:\s+(?:to|for)\s+[\w-]+(?:\s+[\w-]+){0,8})?"
_TASK_SOURCE_SUFFIX = rf"(?:\s+from\s+{_MAILBOX_OBJECT})?"
_DIRECTIVE_ONLY_SPLIT_LINE_ACTIONS = {
    "modify_labels",
    "unsubscribe",
    "report_phishing",
    "report_spam",
    "click_link",
    "open_link",
    "open_attachment",
    "download_attachment",
    "run_executable",
    "enable_macros",
    "disable_security_software",
    "print_email",
    "export_data",
    "share_file",
    "upload_file",
    "load_remote_content",
    "enable_browser_notifications",
    "scan_qr_code",
    "start_remote_access",
    "call_phone",
    "send_sms",
    "create_contact",
    "update_contact",
    "update_account_contact",
    "use_verification_code",
    "approve_login_prompt",
    "accept_invite",
    "decline_invite",
    "tentative_invite",
    "create_calendar_event",
    "create_task",
    "provide_sensitive_info",
    "crypto_wallet_action",
    "make_payment",
    "update_payment_method",
    "sign_in",
    "create_external_account",
    "change_password",
    "password_manager_action",
    "authorize_app",
    "grant_mailbox_access",
    "change_security_settings",
    "change_mail_access_settings",
    "change_network_settings",
    "install_profile",
    "update_email_signature",
    "submit_form",
    "create_forwarding_rule",
    "set_auto_reply",
    "change_filter_settings",
}
_DIRECTIVE_SPAN_SPLIT_LINE_ACTIONS = {
    "run_executable",
    "enable_macros",
    "disable_security_software",
    "sign_in",
    "create_external_account",
    "change_password",
    "password_manager_action",
    "authorize_app",
    "grant_mailbox_access",
    "change_security_settings",
    "change_mail_access_settings",
    "change_network_settings",
    "install_profile",
    "update_account_contact",
    "approve_login_prompt",
    "update_email_signature",
    "create_task",
    "provide_sensitive_info",
    "crypto_wallet_action",
    "make_payment",
    "create_forwarding_rule",
    "print_email",
    "export_data",
    "set_auto_reply",
    "start_remote_access",
    "enable_browser_notifications",
    "change_filter_settings",
}
_DIRECTIVE_PATTERNS = {
    "provide_sensitive_info": [
        re.compile(
            rf"{_ACTION_SUGGESTION_START}(?:provide|enter|submit)\s+"
            rf"{_SENSITIVE_INFO_PAYMENT_OVERLAP_ACTION_TARGET}"
        ),
        re.compile(
            rf"{_ACTION_SUGGESTION_START}(?:share|disclose|send|upload)\s+"
            rf"{_SENSITIVE_INFO_ACTION_TARGET}"
        ),
        re.compile(
            rf"{_ACTION_SUGGESTION_START}(?:reply|respond)\s+with\s+"
            rf"{_SENSITIVE_INFO_ACTION_TARGET}"
        ),
    ],
    "crypto_wallet_action": [
        re.compile(
            rf"{_ACTION_SUGGESTION_START}(?:connect|link)\s+"
            rf"{_CRYPTO_WALLET_TARGET}{_CRYPTO_WALLET_CONNECTION_SUFFIX}"
            rf"{_TARGET_END}"
        ),
        re.compile(
            rf"{_MIDLINE_ACTION_SUGGESTION_START}(?:connect|link)\s+"
            rf"{_CRYPTO_WALLET_TARGET}{_CRYPTO_WALLET_CONNECTION_SUFFIX}"
            rf"{_TARGET_END}"
        ),
        re.compile(
            rf"{_ACTION_SUGGESTION_START}unlock\s+"
            rf"{_CRYPTO_WALLET_TARGET}{_TARGET_END}"
        ),
        re.compile(
            rf"{_MIDLINE_ACTION_SUGGESTION_START}unlock\s+"
            rf"{_CRYPTO_WALLET_TARGET}{_TARGET_END}"
        ),
        re.compile(
            rf"{_ACTION_SUGGESTION_START}(?:sign|approve|authorize|confirm)\s+"
            rf"{_CRYPTO_TRANSACTION_TARGET}{_CRYPTO_TRANSACTION_CONTEXT_SUFFIX}"
            rf"{_TARGET_END}"
        ),
        re.compile(
            rf"{_MIDLINE_ACTION_SUGGESTION_START}(?:sign|approve|authorize|confirm)\s+"
            rf"{_CRYPTO_TRANSACTION_TARGET}{_CRYPTO_TRANSACTION_CONTEXT_SUFFIX}"
            rf"{_TARGET_END}"
        ),
        re.compile(
            rf"{_ACTION_SUGGESTION_START}sign\s+"
            rf"{_CRYPTO_MESSAGE_TARGET}{_TARGET_END}"
        ),
        re.compile(
            rf"{_MIDLINE_ACTION_SUGGESTION_START}sign\s+"
            rf"{_CRYPTO_MESSAGE_TARGET}{_TARGET_END}"
        ),
        re.compile(
            rf"{_ACTION_SUGGESTION_START}"
            rf"(?:import|enter|input|type|paste|submit|provide|reveal|share|send|disclose)\s+"
            rf"{_CRYPTO_WALLET_SECRET_TARGET}{_CRYPTO_SECRET_DESTINATION_SUFFIX}"
            rf"{_TARGET_END}"
        ),
        re.compile(
            rf"{_MIDLINE_ACTION_SUGGESTION_START}"
            rf"(?:import|enter|input|type|paste|submit|provide|reveal|share|send|disclose)\s+"
            rf"{_CRYPTO_WALLET_SECRET_TARGET}{_CRYPTO_SECRET_DESTINATION_SUFFIX}"
            rf"{_TARGET_END}"
        ),
    ],
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
        re.compile(
            rf"{_DIRECTIVE_START}forward\s+"
            rf"(?!{_AUTO_FORWARD_COMMAND_LEAD})(?:to|{_MAILBOX_OBJECT})\b"
        ),
        re.compile(rf"{_DIRECTIVE_START}forward\s+{_FORWARD_EXFIL_TARGET}"),
        re.compile(
            rf"{_RECOMMENDATION_PREFIX}\bforward\s+"
            rf"(?!{_AUTO_FORWARD_COMMAND_LEAD})(?:to|{_MAILBOX_OBJECT})\b"
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
    "report_phishing": [
        re.compile(rf"{_ACTION_SUGGESTION_START}report\s+{_REPORT_PHISHING_TARGET}"),
        re.compile(
            rf"{_ACTION_SUGGESTION_START}(?:mark|flag)\s+"
            rf"{_MARK_REPORT_PHISHING_TARGET}"
        ),
    ],
    "report_spam": [
        re.compile(rf"{_ACTION_SUGGESTION_START}report\s+{_REPORT_SPAM_TARGET}"),
        re.compile(
            rf"{_ACTION_SUGGESTION_START}(?:mark|flag)\s+"
            rf"{_MARK_REPORT_SPAM_TARGET}"
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
    "change_filter_settings": [
        re.compile(
            rf"{_ACTION_SUGGESTION_START}{_FILTER_RULE_MUTATION_VERB}\s+"
            rf"{_FILTER_RULE_ACTION_TARGET}"
        ),
        re.compile(
            rf"{_MIDLINE_ACTION_SUGGESTION_START}{_FILTER_RULE_MUTATION_VERB}\s+"
            rf"{_FILTER_RULE_ACTION_TARGET}"
        ),
    ],
    "create_forwarding_rule": [
        re.compile(
            rf"{_ACTION_SUGGESTION_START}(?:set\s+up|enable|configure)\s+"
            rf"{_FORWARDING_MODE}(?:\s+to\s+{_FORWARD_RECIPIENT_TARGET})?"
            rf"{_TARGET_END}"
        ),
        re.compile(
            rf"{_ACTION_SUGGESTION_START}(?:create|add|configure|set\s+up|enable)\s+"
            rf"{_FORWARDING_RULE_OBJECT}{_FORWARDING_RULE_TARGET_SUFFIX}{_TARGET_END}"
        ),
        re.compile(
            rf"{_ACTION_SUGGESTION_START}forward\s+{_AUTO_FORWARD_COMMAND_LEAD}"
            rf"(?:\s+to\s+{_FORWARD_RECIPIENT_TARGET})?{_TARGET_END}"
        ),
        re.compile(
            rf"{_MIDLINE_ACTION_SUGGESTION_START}(?:set\s+up|enable|configure)\s+"
            rf"{_FORWARDING_MODE}(?:\s+to\s+{_FORWARD_RECIPIENT_TARGET})?"
            rf"{_TARGET_END}"
        ),
        re.compile(
            rf"{_MIDLINE_ACTION_SUGGESTION_START}"
            rf"(?:create|add|configure|set\s+up|enable)\s+"
            rf"{_FORWARDING_RULE_OBJECT}{_FORWARDING_RULE_TARGET_SUFFIX}{_TARGET_END}"
        ),
        re.compile(
            rf"{_MIDLINE_ACTION_SUGGESTION_START}forward\s+"
            rf"{_AUTO_FORWARD_COMMAND_LEAD}"
            rf"(?:\s+to\s+{_FORWARD_RECIPIENT_TARGET})?{_TARGET_END}"
        ),
    ],
    "set_auto_reply": [
        re.compile(
            rf"{_ACTION_SUGGESTION_START}"
            rf"(?:set(?:\s+up)?|turn\s+on|switch\s+on|enable|activate|configure|create)\s+"
            rf"{_AUTO_REPLY_ACTION_TARGET}"
        ),
        re.compile(
            rf"{_MIDLINE_ACTION_SUGGESTION_START}"
            rf"(?:set(?:\s+up)?|turn\s+on|switch\s+on|enable|activate|configure|create)\s+"
            rf"{_AUTO_REPLY_ACTION_TARGET}"
        ),
    ],
    "update_email_signature": [
        re.compile(
            rf"{_ACTION_SUGGESTION_START}"
            rf"(?:set|update|change|add|create|remove|delete|enable|disable|"
            rf"modify|configure|replace|edit|reset|append\s+to)\s+"
            rf"{_EMAIL_SIGNATURE_ACTION_TARGET}"
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
    "run_executable": [
        re.compile(
            rf"{_ACTION_SUGGESTION_START}(?:run|execute|launch)\s+"
            rf"{_EXECUTABLE_OBJECT_TARGET}{_EXECUTABLE_ACTION_SUFFIX}"
        ),
        re.compile(
            rf"{_ACTION_SUGGESTION_START}open\s+and\s+(?:run|execute)\s+"
            rf"{_EXECUTABLE_OBJECT_TARGET}{_EXECUTABLE_ACTION_SUFFIX}"
        ),
        re.compile(
            rf"{_ACTION_SUGGESTION_START}open\s+{_EXECUTABLE_OBJECT_TARGET}\s+"
            rf"and\s+(?:run|execute)(?:\s+it)?{_TARGET_END}"
        ),
    ],
    "enable_macros": [
        re.compile(
            rf"{_ACTION_SUGGESTION_START}(?:enable|allow|turn\s+on)\s+"
            rf"{_MACRO_TARGET}{_MACRO_ACTION_SUFFIX}"
        ),
        re.compile(
            rf"{_ACTION_SUGGESTION_START}(?:enable|allow|turn\s+on)\s+"
            rf"{_MACRO_CONTEXT_TARGET}\s+{_MACRO_TARGET}{_TARGET_END}"
        ),
        re.compile(
            rf"{_ACTION_SUGGESTION_START}(?:enable|allow|turn\s+on)\s+"
            rf"{_OFFICE_ACTIVE_CONTENT_TARGET}"
            rf"{_OFFICE_ACTIVE_CONTENT_ACTION_SUFFIX}"
        ),
        re.compile(
            rf"{_ACTION_SUGGESTION_START}(?:click|press|select|choose)\s+"
            rf"(?:the\s+)?{_OFFICE_ENABLE_BUTTON_TARGET}"
            rf"(?:\s+{_OFFICE_ENABLE_BUTTON_UI_NOUN})?"
            rf"{_OFFICE_ACTIVE_CONTENT_ACTION_SUFFIX}"
        ),
    ],
    "disable_security_software": [
        re.compile(
            rf"{_ACTION_SUGGESTION_START}"
            rf"(?:disable|deactivate|turn\s+off|switch\s+off|shut\s+off)\s+"
            rf"{_LOCAL_SECURITY_CONTROL_TARGET}{_TARGET_END}"
        ),
        re.compile(
            rf"{_ACTION_SUGGESTION_START}"
            rf"(?:uninstall|remove|stop|kill|terminate)\s+"
            rf"{_LOCAL_SECURITY_CONTROL_TARGET}{_TARGET_END}"
        ),
        re.compile(
            rf"{_ACTION_SUGGESTION_START}(?:bypass|override)\s+"
            rf"{_LOCAL_SECURITY_CONTROL_TARGET}{_TARGET_END}"
        ),
        re.compile(
            rf"{_ACTION_SUGGESTION_START}(?:allow[-\s]?list|white[-\s]?list)\s+"
            rf"{_FILE_OBJECT_TARGET}\s+(?:in|with|on|for)\s+"
            rf"{_LOCAL_SECURITY_CONTROL_TARGET}{_TARGET_END}"
        ),
        re.compile(
            rf"{_ACTION_SUGGESTION_START}add\s+{_FILE_OBJECT_TARGET}\s+to\s+"
            rf"{_LOCAL_SECURITY_EXCLUSION_TARGET}{_TARGET_END}"
        ),
        re.compile(
            rf"{_ACTION_SUGGESTION_START}exclude\s+{_FILE_OBJECT_TARGET}\s+"
            rf"from\s+{_LOCAL_SECURITY_CONTROL_TARGET}{_TARGET_END}"
        ),
    ],
    "print_email": [
        re.compile(
            rf"{_ACTION_SUGGESTION_START}print\s+"
            rf"{_PRINT_TARGET}{_PRINT_ACTION_SUFFIX}"
        ),
    ],
    "export_data": [
        re.compile(
            rf"{_ACTION_SUGGESTION_START}(?:export|download|back\s+up|backup)\s+"
            rf"{_EXPORT_DATA_OBJECT}{_OPTIONAL_EXPORT_DATA_DESTINATION_SUFFIX}"
            rf"{_TARGET_END}"
        ),
        re.compile(
            rf"{_ACTION_SUGGESTION_START}(?:save|copy)\s+"
            rf"{_EXPORT_DATA_OBJECT}{_EXPORT_DATA_DESTINATION_SUFFIX}"
            rf"{_TARGET_END}"
        ),
    ],
    "share_file": [
        re.compile(
            rf"{_ACTION_SUGGESTION_START}share\s+{_FILE_OBJECT_TARGET}\s+"
            rf"(?:with|to)\s+{_FORWARD_RECIPIENT_TARGET}{_TARGET_END}"
        ),
        re.compile(
            rf"{_ACTION_SUGGESTION_START}(?:grant|give)\s+access\s+"
            rf"to\s+{_FILE_OBJECT_TARGET}{_TARGET_END}"
        ),
        re.compile(
            rf"{_ACTION_SUGGESTION_START}(?:grant|give)\s+"
            rf"{_FORWARD_RECIPIENT_TARGET}\s+access\s+to\s+"
            rf"{_FILE_OBJECT_TARGET}{_TARGET_END}"
        ),
    ],
    "upload_file": [
        re.compile(
            rf"{_ACTION_SUGGESTION_START}upload\s+{_FILE_OBJECT_TARGET}\s+"
            rf"(?:to|into|onto|on)\s+{_FILE_UPLOAD_DESTINATION}{_TARGET_END}"
        ),
        re.compile(
            rf"{_ACTION_SUGGESTION_START}save\s+{_FILE_OBJECT_TARGET}\s+"
            rf"(?:to|into|in|on)\s+{_FILE_UPLOAD_DESTINATION}{_TARGET_END}"
        ),
        re.compile(
            rf"{_ACTION_SUGGESTION_START}add\s+{_FILE_OBJECT_TARGET}\s+"
            rf"to\s+{_FILE_UPLOAD_DESTINATION}{_TARGET_END}"
        ),
    ],
    "load_remote_content": [
        re.compile(
            rf"{_ACTION_SUGGESTION_START}(?:load|show|display|download|fetch)\s+"
            rf"{_REMOTE_CONTENT_LOAD_TARGET}{_TARGET_END}"
        ),
        re.compile(
            rf"{_ACTION_SUGGESTION_START}enable\s+"
            rf"{_REMOTE_CONTENT_LOAD_TARGET}{_TARGET_END}"
        ),
    ],
    "enable_browser_notifications": [
        re.compile(
            rf"{_ACTION_SUGGESTION_START}(?:enable|allow|permit|turn\s+on)\s+"
            rf"{_BROWSER_NOTIFICATION_PERMISSION_TARGET}{_TARGET_END}"
        ),
        re.compile(
            rf"{_ACTION_SUGGESTION_START}subscribe\s+to\s+"
            rf"{_BROWSER_NOTIFICATION_PERMISSION_TARGET}{_TARGET_END}"
        ),
        re.compile(
            rf"{_ACTION_SUGGESTION_START}(?:allow|permit)\s+"
            rf"{_BROWSER_NOTIFICATION_CONTEXT}\s+to\s+"
            rf"(?:send(?:\s+you)?|push|deliver)\s+"
            rf"{_BROWSER_NOTIFICATION_SEND_NOUN}{_TARGET_END}"
        ),
    ],
    "start_remote_access": [
        re.compile(
            rf"{_ACTION_SUGGESTION_START}(?:start|join)\s+"
            rf"{_REMOTE_ACCESS_SESSION_TARGET}{_TARGET_END}"
        ),
        re.compile(
            rf"{_ACTION_SUGGESTION_START}connect\s+to\s+"
            rf"{_REMOTE_ACCESS_SESSION_TARGET}{_TARGET_END}"
        ),
        re.compile(
            rf"{_ACTION_SUGGESTION_START}share\s+{_SCREEN_SHARE_TARGET}\s+"
            rf"(?:with|to)\s+{_REMOTE_ACCESS_GRANTEE_TARGET}{_TARGET_END}"
        ),
        re.compile(
            rf"{_ACTION_SUGGESTION_START}(?:grant|give|provide)\s+"
            rf"{_REMOTE_ACCESS_GRANTEE_TARGET}\s+"
            rf"{_REMOTE_ACCESS_PERMISSION_TARGET}{_TARGET_END}"
        ),
        re.compile(
            rf"{_ACTION_SUGGESTION_START}(?:grant|give|provide)\s+"
            rf"{_REMOTE_ACCESS_PERMISSION_TARGET}\s+(?:to|for)\s+"
            rf"{_REMOTE_ACCESS_GRANTEE_TARGET}{_TARGET_END}"
        ),
        re.compile(
            rf"{_ACTION_SUGGESTION_START}(?:allow|enable)\s+"
            rf"{_REMOTE_ACCESS_PERMISSION_TARGET}{_TARGET_END}"
        ),
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
    "create_contact": [
        re.compile(
            rf"{_ACTION_SUGGESTION_START}create\s+(?:an?\s+)?"
            rf"{_CONTACT_DESCRIPTOR}contact{_CONTACT_MUTATION_END}"
        ),
        re.compile(
            rf"{_ACTION_SUGGESTION_START}(?:add|save)\s+{_CONTACT_SOURCE_TARGET}\s+"
            rf"(?:to\s+{_CONTACT_BOOK_TARGET}|as\s+(?:an?\s+)?"
            rf"{_CONTACT_DESCRIPTOR}contact){_TARGET_END}"
        ),
        re.compile(
            rf"{_ACTION_SUGGESTION_START}create\s+(?:an?\s+)?"
            rf"{_CONTACT_DESCRIPTOR}contact\s+"
            rf"from\s+{_CONTACT_SOURCE_TARGET}{_TARGET_END}"
        ),
    ],
    "update_contact": [
        re.compile(
            rf"{_ACTION_SUGGESTION_START}(?:update|edit)\s+"
            rf"{_CONTACT_RECORD_TARGET}{_CONTACT_MUTATION_END}"
        ),
        re.compile(
            rf"{_ACTION_SUGGESTION_START}(?:update|edit)\s+{_CONTACT_RECORD_TARGET}\s+"
            rf"(?:with|using)\s+{_CONTACT_DETAIL_TARGET}{_TARGET_END}"
        ),
        re.compile(
            rf"{_ACTION_SUGGESTION_START}add\s+{_CONTACT_DETAIL_TARGET}\s+"
            rf"to\s+{_CONTACT_RECORD_TARGET}{_TARGET_END}"
        ),
    ],
    "update_account_contact": [
        re.compile(
            rf"{_ACTION_SUGGESTION_START}(?:update|change|add|set|replace|remove|delete)\s+"
            rf"{_ACCOUNT_CONTACT_FIELD_TARGET}{_ACCOUNT_CONTACT_ACTION_SUFFIX}"
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
    "approve_login_prompt": [
        re.compile(
            rf"{_ACTION_SUGGESTION_START}(?:approve|accept|allow|confirm)\s+"
            rf"{_LOGIN_APPROVAL_PROMPT_TARGET}{_TARGET_END}"
        ),
        re.compile(
            rf"{_MIDLINE_ACTION_SUGGESTION_START}(?:approve|accept|allow|confirm)\s+"
            rf"{_LOGIN_APPROVAL_PROMPT_TARGET}{_TARGET_END}"
        ),
        re.compile(
            rf"{_ACTION_SUGGESTION_START}(?:tap|click|press|select|choose)\s+"
            rf"(?:yes|approve|allow|accept|confirm)\s+"
            rf"(?:on|in|within)\s+{_LOGIN_APPROVAL_RESPONSE_TARGET}{_TARGET_END}"
        ),
        re.compile(
            rf"{_MIDLINE_ACTION_SUGGESTION_START}(?:tap|click|press|select|choose)\s+"
            rf"(?:yes|approve|allow|accept|confirm)\s+"
            rf"(?:on|in|within)\s+{_LOGIN_APPROVAL_RESPONSE_TARGET}{_TARGET_END}"
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
            rf"{_ACTION_SUGGESTION_START}add\s+{_CALENDAR_EVENT_TARGET}\s+"
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
    "create_task": [
        re.compile(
            rf"{_ACTION_SUGGESTION_START}(?:add|create|set)\s+"
            rf"{_TASK_ITEM_TARGET}{_TASK_PURPOSE_SUFFIX}{_TASK_SOURCE_SUFFIX}"
            rf"{_TARGET_END}"
        ),
        re.compile(
            rf"{_ACTION_SUGGESTION_START}add\s+{_MAILBOX_OBJECT}\s+to\s+"
            rf"{_TASK_CONTAINER_TARGET}{_TARGET_END}"
        ),
        re.compile(
            rf"{_ACTION_SUGGESTION_START}remind\s+(?:me|us|the\s+user)\s+"
            rf"(?:to|about)\s+[\w-]+(?:\s+[\w-]+){{0,8}}{_TARGET_END}"
        ),
    ],
    "make_payment": [
        re.compile(
            rf"{_ACTION_SUGGESTION_START}pay\s+{_PAYMENT_FUNDS_TARGET}"
            rf"(?:\s+to\s+{_PAYMENT_DESTINATION_TARGET})?{_TARGET_END}"
        ),
        re.compile(
            rf"{_ACTION_SUGGESTION_START}pay\s+"
            rf"(?:{_PAYMENT_OBLIGATION_TARGET}|{_PAYMENT_DESTINATION_TARGET})"
            rf"{_TARGET_END}"
        ),
        re.compile(
            rf"{_ACTION_SUGGESTION_START}send\s+{_PAYMENT_FUNDS_TARGET}\s+"
            rf"to\s+{_PAYMENT_DESTINATION_TARGET}{_TARGET_END}"
        ),
        re.compile(
            rf"{_ACTION_SUGGESTION_START}(?:wire|transfer)\s+"
            rf"{_PAYMENT_FUNDS_TARGET}\s+to\s+{_PAYMENT_DESTINATION_TARGET}"
            rf"{_TARGET_END}"
        ),
        re.compile(
            rf"{_ACTION_SUGGESTION_START}submit\s+{_PAYMENT_OBLIGATION_TARGET}"
            rf"(?:\s+(?:via|through|using|on|in|to)\s+"
            rf"{_PAYMENT_CHANNEL_TARGET})?{_TARGET_END}"
        ),
        re.compile(
            rf"{_ACTION_SUGGESTION_START}(?:approve|authorize)\s+"
            rf"(?!{_CRYPTO_PAYMENT_APPROVAL_TARGET})"
            rf"(?:(?:the|this|that|an?|your)\s+)?(?:[\w-]+\s+){{0,3}}"
            rf"{_PAYMENT_APPROVAL_NOUN}\b{_TARGET_END}"
        ),
        re.compile(
            rf"{_SEQUENCED_ACTION_SUGGESTION_START}(?:approve|authorize)\s+"
            rf"(?!{_CRYPTO_PAYMENT_APPROVAL_TARGET})"
            rf"(?:(?:the|this|that|an?|your)\s+)?(?:[\w-]+\s+){{0,3}}"
            rf"{_PAYMENT_APPROVAL_NOUN}\b{_TARGET_END}"
        ),
        re.compile(
            rf"{_ACTION_SUGGESTION_START}(?:buy|purchase)\s+"
            rf"(?:(?:the|this|that|an?|your)\s+)?(?:[\w-]+\s+){{0,3}}"
            rf"{_PURCHASE_TARGET_NOUN}\b{_TARGET_END}"
        ),
        re.compile(
            rf"{_ACTION_SUGGESTION_START}(?:redeem|use|activate)\s+"
            rf"{_GIFT_CARD_REDEMPTION_TARGET}{_GIFT_CARD_ACTION_SUFFIX}"
        ),
        re.compile(
            rf"{_ACTION_SUGGESTION_START}(?:enter|submit|provide|share|send)\s+"
            rf"{_GIFT_CARD_VALUE_TARGET}{_GIFT_CARD_ACTION_SUFFIX}"
        ),
        re.compile(
            rf"{_ACTION_SUGGESTION_START}refund\s+"
            rf"(?:(?:the|this|that|an?|your)\s+)?(?:[\w-]+\s+){{0,3}}"
            rf"{_REFUND_TARGET_NOUN}\b{_TARGET_END}"
        ),
    ],
    "update_payment_method": [
        re.compile(
            rf"{_ACTION_SUGGESTION_START}(?:update|add)\s+"
            rf"{_PAYMENT_METHOD_DETAIL_TARGET}{_PAYMENT_METHOD_ACTION_SUFFIX}"
        ),
        re.compile(
            rf"{_ACTION_SUGGESTION_START}(?:enter|provide|submit)\s+"
            rf"{_PAYMENT_METHOD_DETAIL_TARGET}\s+"
            rf"(?:to|into|in|on|through|via|using|with)\s+"
            rf"{_PAYMENT_METHOD_DESTINATION}{_TARGET_END}"
        ),
    ],
    "sign_in": [
        re.compile(
            rf"{_ACTION_SUGGESTION_START}{_SIGN_IN_SESSION_VERB}"
            rf"{_SIGN_IN_DESTINATION_SUFFIX}{_SIGN_IN_ACTION_END}"
        ),
        re.compile(
            rf"{_ACTION_SUGGESTION_START}{_SIGN_IN_COMPACT_VERB}\s+"
            rf"{_SIGN_IN_TARGET}{_SIGN_IN_ACTION_END}"
        ),
        re.compile(
            rf"{_ACTION_SUGGESTION_START}authenticate\s+"
            rf"{_SIGN_IN_TARGET}{_SIGN_IN_ACTION_END}"
        ),
        re.compile(
            rf"{_ACTION_SUGGESTION_START}(?:verify|access)\s+"
            rf"{_SIGN_IN_TARGET}{_SIGN_IN_ACTION_END}"
        ),
    ],
    "create_external_account": [
        re.compile(
            rf"{_ACTION_SUGGESTION_START}(?:sign\s+up|sign-up|signup)"
            rf"{_EXTERNAL_ACCOUNT_SIGNUP_TARGET}"
        ),
        re.compile(
            rf"{_MIDLINE_ACTION_SUGGESTION_START}(?:sign\s+up|sign-up|signup)"
            rf"{_EXTERNAL_ACCOUNT_SIGNUP_TARGET}"
        ),
        re.compile(
            rf"{_ACTION_SUGGESTION_START}create\s+"
            rf"{_EXTERNAL_ACCOUNT_CREATION_TARGET}"
        ),
        re.compile(
            rf"{_MIDLINE_ACTION_SUGGESTION_START}create\s+"
            rf"{_EXTERNAL_ACCOUNT_CREATION_TARGET}"
        ),
        re.compile(
            rf"{_ACTION_SUGGESTION_START}register\s+"
            rf"{_EXTERNAL_ACCOUNT_REGISTRATION_TARGET}"
        ),
        re.compile(
            rf"{_MIDLINE_ACTION_SUGGESTION_START}register\s+"
            rf"{_EXTERNAL_ACCOUNT_REGISTRATION_TARGET}"
        ),
    ],
    "change_password": [
        re.compile(
            rf"{_ACTION_SUGGESTION_START}(?:reset|change|update|set|recover|create)\s+"
            rf"{_PASSWORD_CREDENTIAL_TARGET}{_PASSWORD_ACTION_SUFFIX}"
        ),
    ],
    "password_manager_action": [
        re.compile(
            rf"{_ACTION_SUGGESTION_START}(?:export|download|copy)\s+"
            rf"{_PASSWORD_MANAGER_CONTEXTUAL_PASSWORD_OBJECT}"
            rf"{_PASSWORD_MANAGER_EXPORT_ACTION_SUFFIX}"
        ),
        re.compile(
            rf"{_MIDLINE_ACTION_SUGGESTION_START}(?:export|download|copy)\s+"
            rf"{_PASSWORD_MANAGER_CONTEXTUAL_PASSWORD_OBJECT}"
            rf"{_PASSWORD_MANAGER_EXPORT_ACTION_SUFFIX}"
        ),
        re.compile(
            rf"{_ACTION_SUGGESTION_START}(?:show|reveal)\s+"
            rf"{_PASSWORD_MANAGER_CONTEXTUAL_PASSWORD_OBJECT}{_TARGET_END}"
        ),
        re.compile(
            rf"{_MIDLINE_ACTION_SUGGESTION_START}(?:show|reveal)\s+"
            rf"{_PASSWORD_MANAGER_CONTEXTUAL_PASSWORD_OBJECT}{_TARGET_END}"
        ),
        re.compile(
            rf"{_ACTION_SUGGESTION_START}import\s+"
            rf"{_PASSWORD_MANAGER_IMPORT_TARGET}{_TARGET_END}"
        ),
        re.compile(
            rf"{_MIDLINE_ACTION_SUGGESTION_START}import\s+"
            rf"{_PASSWORD_MANAGER_IMPORT_TARGET}{_TARGET_END}"
        ),
        re.compile(
            rf"{_ACTION_SUGGESTION_START}save\s+"
            rf"{_PASSWORD_MANAGER_SAVE_TARGET}\s+"
            rf"(?:to|into|in|with|using|on)\s+{_PASSWORD_MANAGER_LOCATION}"
            rf"{_TARGET_END}"
        ),
        re.compile(
            rf"{_MIDLINE_ACTION_SUGGESTION_START}save\s+"
            rf"{_PASSWORD_MANAGER_SAVE_TARGET}\s+"
            rf"(?:to|into|in|with|using|on)\s+{_PASSWORD_MANAGER_LOCATION}"
            rf"{_TARGET_END}"
        ),
        re.compile(
            rf"{_ACTION_SUGGESTION_START}"
            rf"(?:disable|deactivate|turn\s+off|switch\s+off)\s+"
            rf"{_PASSWORD_MANAGER_PROTECTION_TARGET}{_TARGET_END}"
        ),
        re.compile(
            rf"{_MIDLINE_ACTION_SUGGESTION_START}"
            rf"(?:disable|deactivate|turn\s+off|switch\s+off)\s+"
            rf"{_PASSWORD_MANAGER_PROTECTION_TARGET}{_TARGET_END}"
        ),
    ],
    "authorize_app": [
        re.compile(
            rf"{_ACTION_SUGGESTION_START}(?:authorize|approve)\s+"
            rf"{_AUTHZ_OBJECT_TARGET}{_AUTHZ_ACCESS_SUFFIX}{_TARGET_END}"
        ),
        re.compile(
            rf"{_ACTION_SUGGESTION_START}(?:authorize|approve)\s+"
            rf"{_AUTHZ_PERMISSION_TARGET}{_TARGET_END}"
        ),
        re.compile(
            rf"{_ACTION_SUGGESTION_START}grant\s+"
            rf"{_AUTHZ_ACCESS_GRANT_TARGET}\s+to\s+"
            rf"{_AUTHZ_GRANTEE_TARGET}{_AUTHZ_ACCESS_SUFFIX}{_TARGET_END}"
        ),
        re.compile(
            rf"{_ACTION_SUGGESTION_START}grant\s+"
            rf"{_AUTHZ_GRANTEE_TARGET}\s+{_AUTHZ_ACCESS_GRANT_TARGET}"
            rf"{_AUTHZ_ACCESS_SUFFIX}{_TARGET_END}"
        ),
        re.compile(
            rf"{_ACTION_SUGGESTION_START}allow\s+"
            rf"{_AUTHZ_GRANTEE_TARGET}\s+to\s+access\s+"
            rf"(?:(?:the|your)\s+)?{_AUTHZ_ACCESS_RESOURCE}{_TARGET_END}"
        ),
        re.compile(
            rf"{_ACTION_SUGGESTION_START}connect\s+"
            rf"{_AUTHZ_ACCOUNT_TARGET}\s+to\s+{_AUTHZ_GRANTEE_TARGET}"
            rf"{_TARGET_END}"
        ),
        re.compile(
            rf"{_ACTION_SUGGESTION_START}connect\s+"
            rf"{_AUTHZ_GRANTEE_TARGET}\s+to\s+{_AUTHZ_ACCOUNT_TARGET}"
            rf"{_TARGET_END}"
        ),
        re.compile(
            rf"{_ACTION_SUGGESTION_START}(?:install|enable)\s+"
            rf"{_AUTHZ_OBJECT_TARGET}{_TARGET_END}"
        ),
    ],
    "grant_mailbox_access": [
        re.compile(
            rf"{_ACTION_SUGGESTION_START}add\s+"
            rf"{_MAILBOX_ACCESS_GRANTEE_TARGET}\s+as\s+(?:an?\s+)?"
            rf"{_MAILBOX_DELEGATE_ROLE}{_MAILBOX_ACCESS_CONTEXT_SUFFIX}"
            rf"{_TARGET_END}"
        ),
        re.compile(
            rf"{_ACTION_SUGGESTION_START}set\s+up\s+"
            rf"{_MAILBOX_ACCESS_GRANTEE_TARGET}\s+as\s+(?:an?\s+)?"
            rf"{_MAILBOX_DELEGATE_ROLE}{_MAILBOX_ACCESS_CONTEXT_SUFFIX}"
            rf"{_TARGET_END}"
        ),
        re.compile(
            rf"{_ACTION_SUGGESTION_START}(?:grant|give|share|delegate)\s+"
            rf"{_MAILBOX_ACCESS_PERMISSION}\s+(?:to|with)\s+"
            rf"{_MAILBOX_ACCESS_GRANTEE_TARGET}{_MAILBOX_ACCESS_CONTEXT_SUFFIX}"
            rf"{_TARGET_END}"
        ),
        re.compile(
            rf"{_ACTION_SUGGESTION_START}(?:grant|give)\s+"
            rf"{_MAILBOX_ACCESS_GRANTEE_TARGET}\s+"
            rf"{_MAILBOX_ACCESS_PERMISSION}{_MAILBOX_ACCESS_CONTEXT_SUFFIX}"
            rf"{_TARGET_END}"
        ),
        re.compile(
            rf"{_ACTION_SUGGESTION_START}provide\s+"
            rf"{_MAILBOX_ACCESS_GRANTEE_TARGET}\s+with\s+"
            rf"{_MAILBOX_ACCESS_PERMISSION}{_MAILBOX_ACCESS_CONTEXT_SUFFIX}"
            rf"{_TARGET_END}"
        ),
        re.compile(
            rf"{_ACTION_SUGGESTION_START}allow\s+"
            rf"{_MAILBOX_ACCESS_GRANTEE_TARGET}\s+to\s+access\s+"
            rf"{_MAILBOX_ACCESS_RESOURCE}{_TARGET_END}"
        ),
        re.compile(
            rf"{_ACTION_SUGGESTION_START}(?:grant|give)\s+"
            rf"{_MAILBOX_ACCESS_GRANTEE_TARGET}\s+access\s+to\s+"
            rf"{_MAILBOX_ACCESS_RESOURCE}{_TARGET_END}"
        ),
    ],
    "change_security_settings": [
        re.compile(
            rf"{_ACTION_SUGGESTION_START}(?:trust|remember)\s+"
            rf"{_TRUSTED_DEVICE_TARGET}{_TARGET_END}"
        ),
        re.compile(
            rf"{_ACTION_SUGGESTION_START}add\s+{_TRUSTED_DEVICE_TARGET}\s+"
            rf"as\s+{_TRUSTED_DEVICE_SETTING_TARGET}{_TARGET_END}"
        ),
        re.compile(
            rf"{_ACTION_SUGGESTION_START}mark\s+{_TRUSTED_DEVICE_TARGET}\s+"
            rf"as\s+trusted{_TARGET_END}"
        ),
        re.compile(
            rf"{_ACTION_SUGGESTION_START}(?:register|create|add|set\s+up|enroll)\s+"
            rf"{_SECURITY_PASSKEY_TARGET}{_SECURITY_ENROLLMENT_SUFFIX}"
            rf"{_TARGET_END}"
        ),
        re.compile(
            rf"{_ACTION_SUGGESTION_START}enroll\s+{_TRUSTED_DEVICE_TARGET}\s+"
            rf"for\s+{_SECURITY_PASSKEY_TARGET}{_TARGET_END}"
        ),
        re.compile(
            rf"{_ACTION_SUGGESTION_START}(?:add|register|enroll|create|set\s+up)\s+"
            rf"{_SECURITY_KEY_TARGET}{_SECURITY_ENROLLMENT_SUFFIX}"
            rf"{_TARGET_END}"
        ),
        re.compile(
            rf"{_ACTION_SUGGESTION_START}(?:disable|deactivate|turn\s+off)\s+"
            rf"{_SECURITY_AUTH_FACTOR_TARGET}{_TARGET_END}"
        ),
        re.compile(
            rf"{_ACTION_SUGGESTION_START}remove\s+"
            rf"{_SECURITY_KEY_TARGET}{_SECURITY_ACCOUNT_SETTING_SUFFIX}"
            rf"{_TARGET_END}"
        ),
        re.compile(
            rf"{_ACTION_SUGGESTION_START}(?:reset|regenerate|replace)\s+"
            rf"{_SECURITY_BACKUP_CODES_TARGET}{_TARGET_END}"
        ),
        re.compile(
            rf"{_ACTION_SUGGESTION_START}(?:disable|deactivate|turn\s+off|lower|reduce|weaken)\s+"
            rf"{_SECURITY_PROTECTION_TARGET}{_SECURITY_FILTER_SCOPE_SUFFIX}"
            rf"{_TARGET_END}"
        ),
        re.compile(
            rf"{_ACTION_SUGGESTION_START}(?:whitelist|allow[-\s]?list)\s+"
            rf"{_SECURITY_SAFE_SENDER_ENTRY_TARGET}{_TARGET_END}"
        ),
        re.compile(
            rf"{_ACTION_SUGGESTION_START}add\s+{_SECURITY_SAFE_SENDER_ENTRY_TARGET}\s+"
            rf"to\s+{_SECURITY_SAFE_SENDER_LIST_TARGET}{_TARGET_END}"
        ),
    ],
    "change_mail_access_settings": [
        re.compile(
            rf"{_ACTION_SUGGESTION_START}"
            rf"(?:enable|disable|allow|authorize|approve|change|update|modify|configure|"
            rf"turn\s+on|turn\s+off|switch\s+on|switch\s+off)\s+"
            rf"{_MAIL_ACCESS_SETTING_TARGET}{_TARGET_END}"
        ),
        re.compile(
            rf"{_ACTION_SUGGESTION_START}"
            rf"(?:create|generate|set(?:\s+up)?|update|change|reset|replace|"
            rf"recover|remove|delete|revoke|disable|make|request|obtain)\s+"
            rf"{_APP_PASSWORD_TARGET}{_TARGET_END}"
        ),
    ],
    "change_network_settings": [
        re.compile(
            rf"{_ACTION_SUGGESTION_START}"
            rf"(?:change|update|modify|configure|set(?:\s+up)?|reset|enable|disable|"
            rf"turn\s+on|turn\s+off|switch\s+on|switch\s+off)\s+"
            rf"{_NETWORK_SETTING_TARGET}{_NETWORK_SETTING_ACTION_SUFFIX}"
        ),
        re.compile(
            rf"{_MIDLINE_ACTION_SUGGESTION_START}"
            rf"(?:change|update|modify|configure|set(?:\s+up)?|reset|enable|disable|"
            rf"turn\s+on|turn\s+off|switch\s+on|switch\s+off)\s+"
            rf"{_NETWORK_SETTING_TARGET}{_NETWORK_SETTING_ACTION_SUFFIX}"
        ),
    ],
    "install_profile": [
        re.compile(
            rf"{_ACTION_SUGGESTION_START}(?:install|add|trust)\s+"
            rf"{_INSTALL_PROFILE_TARGET}{_INSTALL_PROFILE_ACTION_SUFFIX}"
        ),
    ],
    "submit_form": [
        re.compile(
            rf"{_ACTION_SUGGESTION_START}submit\s+"
            rf"{_FORM_SUBMISSION_TARGET}"
        ),
        re.compile(
            rf"{_ACTION_SUGGESTION_START}fill\s+out\s+"
            rf"{_FORM_SUBMISSION_TARGET}"
        ),
        re.compile(
            rf"{_ACTION_SUGGESTION_START}complete\s+"
            rf"{_FORM_SUBMISSION_TARGET}"
        ),
        re.compile(
            rf"{_ACTION_SUGGESTION_START}(?:enter|provide)\s+"
            rf"{_FORM_DETAIL_SOURCE}\s+(?:in|into|on|through|via)\s+"
            rf"{_FORM_OBJECT}{_TARGET_END}"
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
    actions = [
        action
        for action, patterns in _DIRECTIVE_PATTERNS.items()
        if any(pattern.search(line) for pattern in patterns)
    ]
    actions = _suppress_overlapping_crypto_wallet_payment_actions(line, actions)
    return _suppress_overlapping_gift_card_payment_actions(line, actions)


def _directive_match_spans(line: str, action: str) -> List[Tuple[int, int]]:
    return [
        match.span()
        for pattern in _DIRECTIVE_PATTERNS[action]
        for match in [pattern.search(line)]
        if match
    ]


def _spans_overlap(first: Tuple[int, int], second: Tuple[int, int]) -> bool:
    return first[0] < second[1] and second[0] < first[1]


def _suppress_overlapping_crypto_wallet_payment_actions(
    line: str, actions: List[str]
) -> List[str]:
    action_set = set(actions)
    if not {"crypto_wallet_action", "make_payment"}.issubset(action_set):
        return actions

    crypto_spans = _directive_match_spans(line, "crypto_wallet_action")
    payment_spans = _directive_match_spans(line, "make_payment")
    if any(
        _spans_overlap(payment_span, crypto_span)
        for payment_span in payment_spans
        for crypto_span in crypto_spans
    ):
        return [action for action in actions if action != "make_payment"]

    return actions


def _suppress_overlapping_gift_card_payment_actions(
    line: str, actions: List[str]
) -> List[str]:
    if "make_payment" not in actions:
        return actions

    gift_card_payment_spans = [
        (start, end)
        for start, end in _directive_match_spans(line, "make_payment")
        if _GIFT_CARD_PAYMENT_TERM_RE.search(line[start:end])
    ]
    if not gift_card_payment_spans:
        return actions

    overlapping_actions = {
        "provide_sensitive_info",
        "send",
        "update_payment_method",
    }
    suppressed = set()
    for action in overlapping_actions.intersection(actions):
        if any(
            _spans_overlap(action_span, payment_span)
            for action_span in _directive_match_spans(line, action)
            for payment_span in gift_card_payment_spans
        ):
            suppressed.add(action)

    if not suppressed:
        return actions

    return [action for action in actions if action not in suppressed]


def _suppress_crypto_wallet_payment_overlap(
    lines: List[str],
    index: int,
    direct_actions_by_index: List[Set[str]],
    combined: str,
) -> None:
    crypto_spans = _directive_match_spans(combined, "crypto_wallet_action")
    if not crypto_spans:
        return

    line_offsets = (
        (index, 0),
        (index + 1, len(lines[index]) + 1),
    )
    for line_index, offset in line_offsets:
        if "make_payment" not in direct_actions_by_index[line_index]:
            continue

        payment_spans = [
            (start + offset, end + offset)
            for start, end in _directive_match_spans(lines[line_index], "make_payment")
        ]
        if any(
            _spans_overlap(payment_span, crypto_span)
            for payment_span in payment_spans
            for crypto_span in crypto_spans
        ):
            direct_actions_by_index[line_index].discard("make_payment")


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
            blocked_line_indexes.add(index)

    for index in range(len(lines) - 1):
        combined = f"{lines[index]} {lines[index + 1]}"
        actions = _directive_actions(combined)
        if not actions:
            continue

        if "crypto_wallet_action" in actions:
            _suppress_crypto_wallet_payment_overlap(
                lines, index, direct_actions_by_index, combined
            )
        blocked_found.update(actions)
        matched_any_line = False
        for action in actions:
            if action in _DIRECTIVE_ONLY_SPLIT_LINE_ACTIONS:
                line_boundary = len(lines[index]) + 1
                if (
                    action in _DIRECTIVE_SPAN_SPLIT_LINE_ACTIONS
                    and any(
                        end > line_boundary
                        for _, end in _directive_match_spans(combined, action)
                    )
                ):
                    blocked_line_indexes.update({index, index + 1})
                    matched_any_line = True
                    continue

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

    for actions in direct_actions_by_index:
        blocked_found.update(actions)

    guarded_lines = [
        "[Unsafe action suggestion removed]" if index in blocked_line_indexes else line
        for index, line in enumerate(lines)
    ]

    return "\n".join(guarded_lines), sorted(blocked_found)
