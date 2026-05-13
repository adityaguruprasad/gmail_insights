import re
from typing import Iterable, List, Set, Tuple
from urllib.parse import quote_plus, unquote, unquote_plus, urlsplit

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
    "change_importance_marker",
    "star",
    "unstar",
    "move_to_spam",
    "report_phishing",
    "report_spam",
    "move_to_inbox",
    "snooze",
    "change_thread_mute_state",
    "create_filter",
    "change_filter_settings",
    "change_blocked_senders",
    "create_forwarding_rule",
    "set_auto_reply",
    "unsubscribe",
    "click_link",
    "open_link",
    "open_attachment",
    "download_attachment",
    "run_executable",
    "run_shell_command",
    "install_software",
    "enable_macros",
    "disable_security_software",
    "print_email",
    "export_data",
    "share_file",
    "upload_file",
    "load_remote_content",
    "enable_browser_notifications",
    "change_browser_sync_settings",
    "scan_qr_code",
    "start_remote_access",
    "call_phone",
    "send_sms",
    "create_contact",
    "update_contact",
    "update_account_contact",
    "change_recovery_email",
    "change_recovery_phone",
    "use_verification_code",
    "approve_login_prompt",
    "manage_backup_codes",
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
    "change_trusted_devices",
    "change_session_settings",
    "change_security_key_settings",
    "manage_passkeys",
    "change_mfa_settings",
    "disable_account_protection",
    "change_mail_access_settings",
    "change_network_settings",
    "install_profile",
    "update_email_signature",
    "change_send_as_settings",
    "submit_form",
}

_EMAIL_TARGET = r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}"
_EMAIL_RE = re.compile(rf"\b{_EMAIL_TARGET}\b")
_PHONE_RE = re.compile(r"\b(?:\+?\d{1,3}[\s.-]?)?(?:\(?\d{3}\)?[\s.-]?)\d{3}[\s.-]?\d{4}\b")
_BEARER_TOKEN_RE = re.compile(
    r"(?i)\b(bearer\s+)[A-Za-z0-9._~+/=-]{16,}(?=$|[\s,;)\]}>\"'])"
)
_BASIC_AUTH_CREDENTIAL_TARGET = (
    r"(?:[A-Za-z0-9+/]{4}){4,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?"
)
_BASIC_AUTH_CONTEXT_PREFIX = (
    r"(?:"
    r"[\"']?\b(?:proxy-)?authorization\b[\"']?\s*[:=]|"
    r"\b(?:proxy-)?authorization\s+(?:header|value)\s*[:=]?|"
    r"\b(?:proxy\s+)?auth(?:entication)?\s+(?:header|value)\s*[:=]?"
    r")"
)
_BASIC_AUTH_RE = re.compile(
    rf"(?i)(?P<prefix>{_BASIC_AUTH_CONTEXT_PREFIX}\s*[\"']?\s*basic\s+[\"']?)"
    rf"(?P<credential>{_BASIC_AUTH_CREDENTIAL_TARGET})"
    r"(?P<suffix>[\"']?)"
    r"(?=$|[\s,;.!?)\]}>\"'])"
)
_API_TOKEN_RE = re.compile(
    r"(?i)\b((?:api[_-]?key|api[_-]?token|access[_-]?token|auth[_-]?token)"
    r"\s*[:=]\s*)([\"']?)[A-Za-z0-9._~+/=-]{16,}\2"
)
_PASSWORD_SECRET_PLACEHOLDER = "[REDACTED_PASSWORD]"
_PASSWORD_SECRET_CONTEXT = (
    r"(?:"
    r"(?:(?:temporary|temp|initial|new|current|account|login|portal|admin|"
    r"user|database|db|ssh|sftp|ftp|vpn|wi[-\s]?fi)\s+)?"
    r"(?:password|passphrase)|"
    r"passwd|pwd"
    r")"
)
_PASSWORD_SECRET_CONTEXT_BOUNDARY = (
    r"(?!\s+(?:"
    r"policy|policies|reset|rules?|requirements?|change|manager|protection|"
    r"metrics?|instructions?|creation|links?|guide|docs?|field|forms?"
    r")\b)"
)
_PASSWORD_SECRET_VALUE = r"[^&;#?\s\"'<>]{6,128}"
_PASSWORD_SECRET_AFTER_CONTEXT_RE = re.compile(
    rf"(?<![A-Za-z0-9_])(?P<context>{_PASSWORD_SECRET_CONTEXT})"
    rf"(?![A-Za-z0-9_]){_PASSWORD_SECRET_CONTEXT_BOUNDARY}"
    rf"(?P<between>\s*(?:(?:is|are|was)\s+|[:=]\s*|-\s+))"
    rf"(?P<quote>[\"'])?"
    rf"(?P<password>{_PASSWORD_SECRET_VALUE})"
    rf"(?(quote)(?P=quote))",
    re.IGNORECASE,
)
_PASSWORD_SECRET_BEFORE_CONTEXT_RE = re.compile(
    rf"(?<![A-Za-z0-9_])"
    rf"(?P<quote>[\"'])?"
    rf"(?P<password>{_PASSWORD_SECRET_VALUE})"
    rf"(?(quote)(?P=quote))"
    rf"(?P<between>\s+(?:is|as|for)\s+(?:your|my|our|the|this|a|an)?\s*)"
    rf"(?P<context>{_PASSWORD_SECRET_CONTEXT})"
    rf"(?![A-Za-z0-9_]){_PASSWORD_SECRET_CONTEXT_BOUNDARY}",
    re.IGNORECASE,
)
_PASSWORD_SECRET_TRAILING_PUNCTUATION = ".,;:)]}"
_APP_PASSWORD_PLACEHOLDER = "[REDACTED_APP_PASSWORD]"
_APP_PASSWORD_CONTEXT = (
    r"(?:"
    r"(?:(?:gmail|google(?:\s+workspace)?|mail|email)\s+)?app\s+password|"
    r"application[-\s]?specific\s+password"
    r")"
)
_APP_PASSWORD_VALUE = (
    r"(?<![A-Za-z0-9])(?:[A-Za-z]{4}[\s-]+){3}[A-Za-z]{4}(?![A-Za-z0-9])"
)
_APP_PASSWORD_AFTER_CONTEXT_RE = re.compile(
    rf"\b(?P<context>{_APP_PASSWORD_CONTEXT})\b"
    rf"(?P<between>\s*(?:is|:|=|-)?\s*)"
    rf"(?P<app_password>{_APP_PASSWORD_VALUE})",
    re.IGNORECASE,
)
_APP_PASSWORD_BEFORE_CONTEXT_RE = re.compile(
    rf"(?P<app_password>{_APP_PASSWORD_VALUE})"
    rf"(?P<between>\s+(?:is|as|for)\s+(?:your|the|this|a|an)?\s*)"
    rf"(?P<context>{_APP_PASSWORD_CONTEXT})\b",
    re.IGNORECASE,
)
_WALLET_SEED_PHRASE_PLACEHOLDER = "[REDACTED_WALLET_SEED_PHRASE]"
_WALLET_SEED_CONTEXT = (
    r"(?:"
    r"(?:wallet\s+)?seed\s+(?:phrases?|words?)|"
    r"(?:wallet\s+)?(?:secret\s+)?recovery\s+(?:phrases?|words?)|"
    r"(?:wallet\s+)?backup\s+(?:phrases?|words?)|"
    r"(?:wallet\s+)?mnemonics?(?:\s+phrases?)?"
    r")"
)
_WALLET_SEED_WORD = r"[A-Za-z]{3,8}"
_WALLET_SEED_WORD_COUNTS = (24, 21, 18, 15, 12)
_WALLET_SEED_WORD_COUNT_PATTERNS = "|".join(
    rf"(?:{_WALLET_SEED_WORD}\s+){{{word_count - 1}}}{_WALLET_SEED_WORD}"
    for word_count in _WALLET_SEED_WORD_COUNTS
)
_WALLET_SEED_PHRASE_VALUE = (
    rf"(?<![A-Za-z])(?:{_WALLET_SEED_WORD_COUNT_PATTERNS})(?![A-Za-z])"
)
_WALLET_SEED_AFTER_CONTEXT_RE = re.compile(
    rf"\b(?P<context>{_WALLET_SEED_CONTEXT})\b"
    rf"(?P<between>\s*(?:is|are|:|=|-)?\s*)"
    rf"(?P<quote>[\"'])?"
    rf"(?P<seed_phrase>{_WALLET_SEED_PHRASE_VALUE})"
    rf"(?(quote)(?P=quote))",
    re.IGNORECASE,
)
_WALLET_SEED_BEFORE_CONTEXT_RE = re.compile(
    rf"(?P<quote>[\"'])?"
    rf"(?P<seed_phrase>{_WALLET_SEED_PHRASE_VALUE})"
    rf"(?(quote)(?P=quote))"
    rf"(?P<between>\s+(?:is|are|as|for)\s+(?:your|my|the|this|a|an)?\s*)"
    rf"(?P<context>{_WALLET_SEED_CONTEXT})\b",
    re.IGNORECASE,
)
_BANK_ROUTING_PLACEHOLDER = "[REDACTED_ROUTING_NUMBER]"
_BANK_ACCOUNT_PLACEHOLDER = "[REDACTED_BANK_ACCOUNT]"
_PASSPORT_NUMBER_PLACEHOLDER = "[REDACTED_PASSPORT_NUMBER]"
_DRIVER_LICENSE_NUMBER_PLACEHOLDER = "[REDACTED_DRIVER_LICENSE_NUMBER]"
_GOVERNMENT_ID_NUMBER_PLACEHOLDER = "[REDACTED_GOVERNMENT_ID_NUMBER]"
_DATE_OF_BIRTH_PLACEHOLDER = "[REDACTED_DATE_OF_BIRTH]"
_BANK_CONTEXT_BOUNDARY = r"(?![A-Za-z0-9_])"
_BANK_VALUE_AFTER_CONTEXT_SEPARATOR = r"\s*(?:(?:is|are)\s+)?(?:[:,=#-]\s*)?"
_BANK_VALUE_BEFORE_CONTEXT_SEPARATOR = (
    r"(?:\s+|\s*[-:=,]\s*|\s*\(\s*)"
    r"(?:(?:is|are|as|for)\s+)?"
    r"(?:(?:your|my|our|the|this|that|a|an)\s+)?"
)
_BANK_ROUTING_CONTEXT = (
    r"(?:"
    r"aba\s+routing(?:\s+(?:numbers?|nos?\.?|#))?|"
    r"routing\s+(?:numbers?|nos?\.?|#)|"
    r"bank\s+routing(?:\s+(?:numbers?|nos?\.?|#))?|"
    r"ach\s+routing(?:\s+(?:numbers?|nos?\.?|#))?|"
    r"wire\s+routing(?:\s+(?:numbers?|nos?\.?|#))?"
    r")"
)
_BANK_ACCOUNT_CONTEXT = (
    r"(?:"
    r"account\s+(?:numbers?|nos?\.?|#)|"
    r"acct\.?\s*(?:numbers?|nos?\.?|#)|"
    r"bank\s+account(?:\s+(?:numbers?|nos?\.?|#))?|"
    r"checking\s+account(?:\s+(?:numbers?|nos?\.?|#))?|"
    r"savings\s+account(?:\s+(?:numbers?|nos?\.?|#))?|"
    r"ach\s+account(?:\s+(?:numbers?|nos?\.?|#))?|"
    r"wire\s+account(?:\s+(?:numbers?|nos?\.?|#))?"
    r")"
)
_BANK_ROUTING_VALUE = (
    r"(?<![A-Za-z0-9])(?<!\d[ -])"
    r"\d(?:[ -]?\d){8}"
    r"(?![ -]?\d)(?![A-Za-z0-9])"
)
_BANK_ACCOUNT_VALUE = (
    r"(?<![A-Za-z0-9])(?<!\d[ -])"
    r"\d(?:[ -]?\d){3,16}"
    r"(?![ -]?\d)(?![A-Za-z0-9])"
)
_IDENTITY_DOCUMENT_CONTEXT_BOUNDARY = r"(?![A-Za-z0-9_])"
_IDENTITY_DOCUMENT_VALUE_AFTER_CONTEXT_SEPARATOR = (
    r"\s*(?:(?:is|are|was)\s+)?(?:[:,=#-]\s*)?"
)
_IDENTITY_DOCUMENT_VALUE_BEFORE_CONTEXT_SEPARATOR = (
    r"(?:\s+|\s*[-:=,]\s*)"
    r"(?:(?:is|are|was|as|for)\s+)?"
    r"(?:(?:your|my|our|the|this|that|a|an)\s+)?"
)
_IDENTITY_DOCUMENT_NUMBER_VALUE = (
    r"(?<![A-Za-z0-9-])"
    r"(?=[A-Za-z0-9-]{5,24}(?![A-Za-z0-9-]))"
    r"(?=[A-Za-z0-9-]*\d)"
    r"(?!\d{4}-\d{2}-\d{2}(?![A-Za-z0-9-]))"
    r"[A-Za-z0-9](?:[A-Za-z0-9-]{3,22}[A-Za-z0-9])"
    r"(?![A-Za-z0-9-])"
)
_PASSPORT_NUMBER_CONTEXT = (
    r"(?:"
    r"passport\s+(?:numbers?|nos?\.?|#|ids?)|"
    r"passport(?=\s*[:=#-])"
    r")"
)
_DRIVER_LICENSE_NUMBER_CONTEXT = (
    r"(?:"
    r"(?:driver'?s|drivers?|driving)\s+licen[cs]e\s+"
    r"(?:numbers?|nos?\.?|#|ids?)|"
    r"(?:driver'?s|drivers?|driving)\s+licen[cs]e(?=\s*[:=#-])"
    r")"
)
_GOVERNMENT_ID_NUMBER_CONTEXT = (
    r"(?:"
    r"government\s+ids?(?:\s+(?:numbers?|nos?\.?|#))?|"
    r"government\s+identification\s+(?:numbers?|nos?\.?|#)"
    r")"
)
_DATE_OF_BIRTH_CONTEXT = (
    r"(?:"
    r"dates?[-\s]+of[-\s]+birth|"
    r"birth[-\s]+dates?|"
    r"dob"
    r")"
)
_DATE_OF_BIRTH_CONTEXT_BOUNDARY = r"(?![A-Za-z0-9_])"
_DATE_OF_BIRTH_VALUE_AFTER_CONTEXT_SEPARATOR = (
    r"\s*(?:"
    r"(?:(?:value|field|metadata|entry)\s+)?(?:is|are|was)\s+|"
    r"(?:value|field|metadata|entry)\s+appeared\s*[:=#-]\s*|"
    r"[:,=#-]\s*|"
    r"\s+"
    r")"
)
_DATE_OF_BIRTH_VALUE_BEFORE_CONTEXT_SEPARATOR = (
    r"(?:\s+|\s*[-:=,]\s*)"
    r"(?:(?:is|are|was|as|for)\s+)?"
    r"(?:(?:your|my|our|the|this|that|a|an)\s+)?"
)
_DATE_OF_BIRTH_YEAR = r"(?:19|20)\d{2}"
_DATE_OF_BIRTH_MONTH_NUMBER = r"(?:0?[1-9]|1[0-2])"
_DATE_OF_BIRTH_DAY = r"(?:0?[1-9]|[12]\d|3[01])"
_DATE_OF_BIRTH_MONTH_NAME = (
    r"(?:Jan(?:uary)?|Feb(?:ruary)?|Mar(?:ch)?|Apr(?:il)?|May|"
    r"Jun(?:e)?|Jul(?:y)?|Aug(?:ust)?|Sep(?:t(?:ember)?)?|"
    r"Oct(?:ober)?|Nov(?:ember)?|Dec(?:ember)?)"
)
_DATE_OF_BIRTH_VALUE = (
    rf"(?<![A-Za-z0-9])(?:"
    rf"{_DATE_OF_BIRTH_YEAR}[-/]{_DATE_OF_BIRTH_MONTH_NUMBER}[-/]{_DATE_OF_BIRTH_DAY}|"
    rf"{_DATE_OF_BIRTH_MONTH_NUMBER}[-/]{_DATE_OF_BIRTH_DAY}[-/]{_DATE_OF_BIRTH_YEAR}|"
    rf"{_DATE_OF_BIRTH_MONTH_NAME}\.?\s+{_DATE_OF_BIRTH_DAY},?\s+{_DATE_OF_BIRTH_YEAR}|"
    rf"{_DATE_OF_BIRTH_DAY}\s+{_DATE_OF_BIRTH_MONTH_NAME}\.?,?\s+{_DATE_OF_BIRTH_YEAR}"
    rf")(?![A-Za-z0-9])"
)
_BANK_ROUTING_AFTER_CONTEXT_RE = re.compile(
    rf"(?<![A-Za-z0-9_])(?P<context>{_BANK_ROUTING_CONTEXT})"
    rf"{_BANK_CONTEXT_BOUNDARY}"
    rf"(?P<between>{_BANK_VALUE_AFTER_CONTEXT_SEPARATOR})"
    rf"(?P<quote>[\"'])?"
    rf"(?P<routing_number>{_BANK_ROUTING_VALUE})"
    rf"(?(quote)(?P=quote))",
    re.IGNORECASE,
)
_BANK_ROUTING_BEFORE_CONTEXT_RE = re.compile(
    rf"(?P<quote>[\"'])?"
    rf"(?P<routing_number>{_BANK_ROUTING_VALUE})"
    rf"(?(quote)(?P=quote))"
    rf"(?P<between>{_BANK_VALUE_BEFORE_CONTEXT_SEPARATOR})"
    rf"(?P<context>{_BANK_ROUTING_CONTEXT})"
    rf"{_BANK_CONTEXT_BOUNDARY}",
    re.IGNORECASE,
)
_BANK_ACCOUNT_AFTER_CONTEXT_RE = re.compile(
    rf"(?<![A-Za-z0-9_])(?P<context>{_BANK_ACCOUNT_CONTEXT})"
    rf"{_BANK_CONTEXT_BOUNDARY}"
    rf"(?P<between>{_BANK_VALUE_AFTER_CONTEXT_SEPARATOR})"
    rf"(?P<quote>[\"'])?"
    rf"(?P<account_number>{_BANK_ACCOUNT_VALUE})"
    rf"(?(quote)(?P=quote))",
    re.IGNORECASE,
)
_BANK_ACCOUNT_BEFORE_CONTEXT_RE = re.compile(
    rf"(?P<quote>[\"'])?"
    rf"(?P<account_number>{_BANK_ACCOUNT_VALUE})"
    rf"(?(quote)(?P=quote))"
    rf"(?P<between>{_BANK_VALUE_BEFORE_CONTEXT_SEPARATOR})"
    rf"(?P<context>{_BANK_ACCOUNT_CONTEXT})"
    rf"{_BANK_CONTEXT_BOUNDARY}",
    re.IGNORECASE,
)
_PASSPORT_NUMBER_AFTER_CONTEXT_RE = re.compile(
    rf"(?<![A-Za-z0-9_])(?P<context>{_PASSPORT_NUMBER_CONTEXT})"
    rf"{_IDENTITY_DOCUMENT_CONTEXT_BOUNDARY}"
    rf"(?P<between>{_IDENTITY_DOCUMENT_VALUE_AFTER_CONTEXT_SEPARATOR})"
    rf"(?P<quote>[\"'])?"
    rf"(?P<passport_number>{_IDENTITY_DOCUMENT_NUMBER_VALUE})"
    rf"(?(quote)(?P=quote))",
    re.IGNORECASE,
)
_PASSPORT_NUMBER_BEFORE_CONTEXT_RE = re.compile(
    rf"(?P<quote>[\"'])?"
    rf"(?P<passport_number>{_IDENTITY_DOCUMENT_NUMBER_VALUE})"
    rf"(?(quote)(?P=quote))"
    rf"(?P<between>{_IDENTITY_DOCUMENT_VALUE_BEFORE_CONTEXT_SEPARATOR})"
    rf"(?P<context>{_PASSPORT_NUMBER_CONTEXT})"
    rf"{_IDENTITY_DOCUMENT_CONTEXT_BOUNDARY}",
    re.IGNORECASE,
)
_DRIVER_LICENSE_NUMBER_AFTER_CONTEXT_RE = re.compile(
    rf"(?<![A-Za-z0-9_])(?P<context>{_DRIVER_LICENSE_NUMBER_CONTEXT})"
    rf"{_IDENTITY_DOCUMENT_CONTEXT_BOUNDARY}"
    rf"(?P<between>{_IDENTITY_DOCUMENT_VALUE_AFTER_CONTEXT_SEPARATOR})"
    rf"(?P<quote>[\"'])?"
    rf"(?P<driver_license_number>{_IDENTITY_DOCUMENT_NUMBER_VALUE})"
    rf"(?(quote)(?P=quote))",
    re.IGNORECASE,
)
_DRIVER_LICENSE_NUMBER_BEFORE_CONTEXT_RE = re.compile(
    rf"(?P<quote>[\"'])?"
    rf"(?P<driver_license_number>{_IDENTITY_DOCUMENT_NUMBER_VALUE})"
    rf"(?(quote)(?P=quote))"
    rf"(?P<between>{_IDENTITY_DOCUMENT_VALUE_BEFORE_CONTEXT_SEPARATOR})"
    rf"(?P<context>{_DRIVER_LICENSE_NUMBER_CONTEXT})"
    rf"{_IDENTITY_DOCUMENT_CONTEXT_BOUNDARY}",
    re.IGNORECASE,
)
_GOVERNMENT_ID_NUMBER_AFTER_CONTEXT_RE = re.compile(
    rf"(?<![A-Za-z0-9_])(?P<context>{_GOVERNMENT_ID_NUMBER_CONTEXT})"
    rf"{_IDENTITY_DOCUMENT_CONTEXT_BOUNDARY}"
    rf"(?P<between>{_IDENTITY_DOCUMENT_VALUE_AFTER_CONTEXT_SEPARATOR})"
    rf"(?P<quote>[\"'])?"
    rf"(?P<government_id_number>{_IDENTITY_DOCUMENT_NUMBER_VALUE})"
    rf"(?(quote)(?P=quote))",
    re.IGNORECASE,
)
_GOVERNMENT_ID_NUMBER_BEFORE_CONTEXT_RE = re.compile(
    rf"(?P<quote>[\"'])?"
    rf"(?P<government_id_number>{_IDENTITY_DOCUMENT_NUMBER_VALUE})"
    rf"(?(quote)(?P=quote))"
    rf"(?P<between>{_IDENTITY_DOCUMENT_VALUE_BEFORE_CONTEXT_SEPARATOR})"
    rf"(?P<context>{_GOVERNMENT_ID_NUMBER_CONTEXT})"
    rf"{_IDENTITY_DOCUMENT_CONTEXT_BOUNDARY}",
    re.IGNORECASE,
)
_DATE_OF_BIRTH_AFTER_CONTEXT_RE = re.compile(
    rf"(?<![A-Za-z0-9_])(?P<context>{_DATE_OF_BIRTH_CONTEXT})"
    rf"{_DATE_OF_BIRTH_CONTEXT_BOUNDARY}"
    rf"(?P<between>{_DATE_OF_BIRTH_VALUE_AFTER_CONTEXT_SEPARATOR})"
    rf"(?P<quote>[\"'])?"
    rf"(?P<date_of_birth>{_DATE_OF_BIRTH_VALUE})"
    rf"(?(quote)(?P=quote))",
    re.IGNORECASE,
)
_DATE_OF_BIRTH_BEFORE_CONTEXT_RE = re.compile(
    rf"(?P<quote>[\"'])?"
    rf"(?P<date_of_birth>{_DATE_OF_BIRTH_VALUE})"
    rf"(?(quote)(?P=quote))"
    rf"(?P<between>{_DATE_OF_BIRTH_VALUE_BEFORE_CONTEXT_SEPARATOR})"
    rf"(?P<context>{_DATE_OF_BIRTH_CONTEXT})"
    rf"{_DATE_OF_BIRTH_CONTEXT_BOUNDARY}",
    re.IGNORECASE,
)
_GOOGLE_OAUTH_TOKEN_RE = re.compile(r"\bya29\.[A-Za-z0-9._-]+\b")
_GOOGLE_REFRESH_TOKEN_RE = re.compile(r"\b1//[A-Za-z0-9._-]+\b")
_JWT_RE = re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b")
_JWT_VALUE_RE = re.compile(
    r"^eyJ[A-Za-z0-9_-]{5,}={0,2}\.[A-Za-z0-9_-]{5,}={0,2}\."
    r"[A-Za-z0-9_-]{5,}={0,2}$"
)
_OAUTH_CLIENT_SECRET_PLACEHOLDER = "[REDACTED_OAUTH_CLIENT_SECRET]"
_OAUTH_CLIENT_SECRET_NAME = (
    r"(?:client[_-]?secret|oauth[_-]?client[_-]?secret|"
    r"google[_-]?client[_-]?secret)"
)
_OAUTH_CLIENT_SECRET_VALUE = (
    r"[A-Za-z0-9_~+/%=-][A-Za-z0-9._~+/%=-]{6,}"
    r"[A-Za-z0-9_~+/%=-]"
)
_OAUTH_CLIENT_SECRET_ASSIGNMENT_RE = re.compile(
    rf"(?P<prefix>(?<![A-Za-z0-9_])(?P<key_quote>[\"'])?"
    rf"{_OAUTH_CLIENT_SECRET_NAME}(?(key_quote)(?P=key_quote))"
    rf"(?![A-Za-z0-9_])\s*[:=]\s*)"
    rf"(?P<quote>[\"'])?"
    rf"(?P<oauth_client_secret>{_OAUTH_CLIENT_SECRET_VALUE})"
    rf"(?(quote)(?P=quote))",
    re.IGNORECASE,
)
_OIDC_ID_TOKEN_VALUE = (
    r"eyJ[A-Za-z0-9_-]{5,}={0,2}\.[A-Za-z0-9_-]{5,}={0,2}\."
    r"[A-Za-z0-9_-]{5,}={0,2}"
)
_OIDC_ID_TOKEN_ASSIGNMENT_RE = re.compile(
    rf"(?P<prefix>(?<![A-Za-z0-9_])(?P<key_quote>[\"'])?"
    rf"id[_-]?token(?(key_quote)(?P=key_quote))"
    rf"(?![A-Za-z0-9_])\s*[:=]\s*)"
    rf"(?P<quote>[\"'])?"
    rf"(?P<id_token>{_OIDC_ID_TOKEN_VALUE})"
    rf"(?(quote)(?P=quote))",
    re.IGNORECASE,
)
_AWS_ACCESS_KEY_ID_RE = re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b")
_AWS_SECRET_ACCESS_KEY_PLACEHOLDER = "[REDACTED_AWS_SECRET_ACCESS_KEY]"
_AWS_SECRET_ACCESS_KEY_CONTEXT = (
    r"(?:"
    r"aws[_\-\s]*secret[_\-\s]*access[_\-\s]*key|"
    r"secret[_\-\s]*access[_\-\s]*key"
    r")"
)
_AWS_SECRET_ACCESS_KEY_VALUE = r"[A-Za-z0-9/+=]{40}(?![A-Za-z0-9/+=])"
_AWS_SECRET_ACCESS_KEY_AFTER_CONTEXT_RE = re.compile(
    rf"(?<![A-Za-z0-9_])"
    rf"(?P<context_quote>[\"'])?"
    rf"(?P<context>{_AWS_SECRET_ACCESS_KEY_CONTEXT})"
    rf"(?(context_quote)(?P=context_quote))"
    rf"(?![A-Za-z0-9_])"
    rf"(?P<between>\s*(?:(?:is|are|was)\s+|[:=]\s*|-\s*|\s+))"
    rf"(?P<quote>[\"'])?"
    rf"(?P<aws_secret_access_key>{_AWS_SECRET_ACCESS_KEY_VALUE})"
    rf"(?(quote)(?P=quote))",
    re.IGNORECASE,
)
_SESSION_TOKEN_PLACEHOLDER = "[REDACTED_SESSION_TOKEN]"
_SESSION_TOKEN_CONTEXT = (
    r"(?:"
    r"aws[_\-\s]*session[_\-\s]*token|"
    r"x[-_\s]*amz[-_\s]*security[-_\s]*token|"
    r"session[_\-\s]*token|"
    r"security[_\-\s]*token"
    r")"
)
_SESSION_TOKEN_VALUE = (
    r"(?=[A-Za-z0-9._~+/%=-]{16,}(?![A-Za-z0-9._~+/%=-]))"
    r"[A-Za-z0-9_~+/%=-][A-Za-z0-9._~+/%=-]*[A-Za-z0-9_~+/%=-]"
)
_SESSION_TOKEN_AFTER_CONTEXT_RE = re.compile(
    rf"(?<![A-Za-z0-9_])"
    rf"(?P<context_quote>[\"'])?"
    rf"(?P<context>{_SESSION_TOKEN_CONTEXT})"
    rf"(?(context_quote)(?P=context_quote))"
    rf"(?![A-Za-z0-9_])"
    rf"(?P<between>\s*(?:(?:is|are|was)\s+|[:=]\s*|-\s*|\s+))"
    rf"(?P<quote>[\"'])?"
    rf"(?P<session_token>{_SESSION_TOKEN_VALUE})"
    rf"(?(quote)(?P=quote))",
    re.IGNORECASE,
)
_WEBHOOK_SIGNING_SECRET_PLACEHOLDER = "[REDACTED_WEBHOOK_SIGNING_SECRET]"
_WEBHOOK_SIGNING_SECRET_CONTEXT = (
    r"(?:"
    r"(?:webhook|request|event|endpoint|slack|stripe)[_\-\s]+signing[_\-\s]+secret|"
    r"(?:webhook|endpoint)[_\-\s]+secret|"
    r"signing[_-]+secret"
    r")"
)
_WEBHOOK_SIGNING_SECRET_VALUE = (
    r"(?=[A-Za-z0-9._~+/%=-]{16,}(?![A-Za-z0-9._~+/%=-]))"
    r"(?=[A-Za-z0-9._~+/%=-]*(?:\d|[._~+/%=-]))"
    r"[A-Za-z0-9_~+/%=-][A-Za-z0-9._~+/%=-]*[A-Za-z0-9_~+/%=-]"
)
_WEBHOOK_SIGNING_SECRET_BENIGN_HYPHEN_PREFIX = (
    r"(?:rotation|rotated|rotating|policy|policies|documentation|docs?|documents?|documented)"
    r"(?=$|[-_\s.]|\b)"
)
_WEBHOOK_SIGNING_SECRET_AFTER_CONTEXT_RE = re.compile(
    rf"(?<![A-Za-z0-9_])"
    rf"(?P<context_quote>[\"'])?"
    rf"(?P<context>{_WEBHOOK_SIGNING_SECRET_CONTEXT})"
    rf"(?(context_quote)(?P=context_quote))"
    rf"(?![A-Za-z0-9_])"
    rf"(?P<between>\s*(?:(?:is|are|was)\s+|[:=]\s*|"
    rf"-\s*(?!{_WEBHOOK_SIGNING_SECRET_BENIGN_HYPHEN_PREFIX})))"
    rf"(?P<quote>[\"'])?"
    rf"(?P<webhook_signing_secret>{_WEBHOOK_SIGNING_SECRET_VALUE})"
    rf"(?(quote)(?P=quote))",
    re.IGNORECASE,
)
_OPENAI_API_KEY_PLACEHOLDER = "[REDACTED_OPENAI_API_KEY]"
_OPENAI_API_KEY_RE = re.compile(
    r"(?<![A-Za-z0-9_-])"
    r"sk-(?:proj-[A-Za-z0-9_-]{32,}|(?!ant-)[A-Za-z0-9]{32,})"
    r"(?![A-Za-z0-9_-])"
)
_ANTHROPIC_API_KEY_PLACEHOLDER = "[REDACTED_ANTHROPIC_API_KEY]"
_ANTHROPIC_API_KEY_RE = re.compile(
    r"(?<![A-Za-z0-9_-])sk-ant-[A-Za-z0-9_-]{32,}(?![A-Za-z0-9_-])"
)
_GOOGLE_API_KEY_PLACEHOLDER = "[REDACTED_GOOGLE_API_KEY]"
_GOOGLE_API_KEY_RE = re.compile(
    r"(?<![A-Za-z0-9_-])AIza[A-Za-z0-9_-]{35}(?![A-Za-z0-9_-])"
)
_SENDGRID_API_KEY_PLACEHOLDER = "[REDACTED_SENDGRID_API_KEY]"
_SENDGRID_API_KEY_RE = re.compile(
    r"(?<![A-Za-z0-9_-])"
    r"SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}"
    r"(?![A-Za-z0-9_-])"
)
_SLACK_TOKEN_RE = re.compile(r"\b(?:xox[abprs]|xapp)-[A-Za-z0-9-]{10,}\b")
_GITHUB_TOKEN_RE = re.compile(
    r"\b(?:gh[pousr]_[A-Za-z0-9_]{20,255}|github_pat_[A-Za-z0-9_]{22,255})\b"
)
_STRIPE_SECRET_KEY_RE = re.compile(r"\bsk_(?:live|test)_[A-Za-z0-9]{16,}\b")
_PAYMENT_CARD_RE = re.compile(
    r"(?<![A-Za-z0-9])(?<!\d[ -])"
    r"(?P<payment_card>\d(?:[ -]?\d){12,18})"
    r"(?![ -]?\d)(?![A-Za-z0-9])"
)
_US_SSN_RE = re.compile(r"(?<![A-Za-z0-9])\d{3}-\d{2}-\d{4}(?![A-Za-z0-9])")
_PRIVATE_KEY_PLACEHOLDER = "[REDACTED_PRIVATE_KEY]"
_PRIVATE_KEY_TYPE = (
    r"(?:PRIVATE KEY|RSA PRIVATE KEY|EC PRIVATE KEY|DSA PRIVATE KEY|"
    r"OPENSSH PRIVATE KEY|PGP PRIVATE KEY BLOCK)"
)
_PRIVATE_KEY_BEGIN = rf"-----BEGIN {_PRIVATE_KEY_TYPE}-----"
_PRIVATE_KEY_BLOCK_RE = re.compile(
    rf"-----BEGIN (?P<private_key_type>{_PRIVATE_KEY_TYPE})-----"
    r".*?"
    r"-----END (?P=private_key_type)-----",
    re.DOTALL | re.IGNORECASE,
)
_PRIVATE_KEY_ASSIGNMENT_NAME = r"private[_-]?key"
_PRIVATE_KEY_INLINE_ASSIGNMENT_RE = re.compile(
    rf"(?P<prefix>(?:\"{_PRIVATE_KEY_ASSIGNMENT_NAME}\"|"
    rf"'{_PRIVATE_KEY_ASSIGNMENT_NAME}'|"
    rf"{_PRIVATE_KEY_ASSIGNMENT_NAME})\s*[:=]\s*)"
    rf"(?P<quote>[\"'])(?P<value>[^\r\n\"']*{_PRIVATE_KEY_BEGIN}[^\r\n\"']*)"
    rf"(?P=quote)",
    re.IGNORECASE,
)
_OTP_CONTEXT = (
    r"(?:"
    r"verification\s+(?:code|passcode|pin)|"
    r"one[-\s]?time\s+(?:code|passcode|password|pin)|"
    r"otp(?:\s+code)?|"
    r"login\s+(?:code|passcode|pin)|"
    r"sign[-\s]?in\s+(?:code|passcode|pin)|"
    r"security\s+(?:code|passcode|pin)|"
    r"2fa\s+(?:code|passcode|pin)|"
    r"two[-\s]?factor\s+(?:code|passcode|pin)|"
    r"password\s+reset\s+(?:code|passcode|pin)"
    r")"
)
_ALPHANUMERIC_OTP_CODE = (
    r"(?=[A-Za-z0-9]{4,8}(?![A-Za-z0-9]))"
    r"(?=[A-Za-z0-9]*[A-Za-z])"
    r"(?=[A-Za-z0-9]*\d)"
    r"[A-Za-z0-9]{4,8}"
)
_OTP_CODE_VALUE = (
    rf"(?<![A-Za-z0-9])(?:\d{{4,8}}|{_ALPHANUMERIC_OTP_CODE})(?![A-Za-z0-9])"
)
_OTP_PURPOSE_CONTEXT = (
    r"(?:"
    r"verify(?:\s+your\s+(?:account|email|identity))?|"
    r"sign\s*in|"
    r"log\s*in|"
    r"complete\s+(?:your\s+)?login|"
    r"authenticate|"
    r"reset(?:\s+your)?\s+password"
    r")"
)
_OTP_CODE_AFTER_CONTEXT_RE = re.compile(
    rf"\b(?P<context>{_OTP_CONTEXT})\b"
    rf"(?P<between>"
    rf"\s*(?:is|are|:|=|-|\#)?\s*|"
    rf"\s+(?:to|for)\s+{_OTP_PURPOSE_CONTEXT}\s*(?:is|:|=|-)?\s*"
    rf")"
    rf"(?P<code>{_OTP_CODE_VALUE})",
    re.IGNORECASE,
)
_OTP_CODE_BEFORE_CONTEXT_RE = re.compile(
    rf"(?P<code>{_OTP_CODE_VALUE})"
    rf"(?P<between>\s+(?:is|as|for)\s+(?:your|the|this|a|an)?\s*)"
    rf"(?P<context>{_OTP_CONTEXT})\b",
    re.IGNORECASE,
)
_OTP_CODE_AFTER_ACTION_RE = re.compile(
    rf"\b(?P<lead>(?:use|enter|type|copy|submit)\s+)"
    rf"(?P<code>{_OTP_CODE_VALUE})"
    rf"(?P<trail>\s+(?:to|for)\s+{_OTP_PURPOSE_CONTEXT}\b)",
    re.IGNORECASE,
)
_MFA_BACKUP_CODE_PLACEHOLDER = "[REDACTED_MFA_BACKUP_CODE]"
_MFA_BACKUP_FACTOR_CONTEXT = (
    r"(?:mfa|2fa|two[-\s]?factor|multi[-\s]?factor|authenticator(?:\s+app)?)"
)
_MFA_BACKUP_CODE_CONTEXT = (
    r"(?:"
    rf"(?:(?:{_MFA_BACKUP_FACTOR_CONTEXT})\s+)?"
    r"(?:backup|recovery|scratch|emergency)\s+"
    r"(?:codes?|passcodes?|pins?)|"
    r"(?:backup|recovery|scratch|emergency)\s+"
    rf"(?:{_MFA_BACKUP_FACTOR_CONTEXT})\s+"
    r"(?:codes?|passcodes?|pins?)"
    r")"
)
_MFA_BACKUP_DIGIT_CODE = (
    r"(?:"
    r"\d{8,12}|"
    r"\d{4}[- ]\d{4}(?:[- ]\d{2,4})?|"
    r"\d{5}[- ]\d{5}|"
    r"\d{6}[- ]\d{6}|"
    r"\d{3}[- ]\d{3}[- ]\d{2,6}"
    r")"
)
_MFA_BACKUP_ALPHANUMERIC_CODE = (
    r"(?=[A-Za-z0-9-]{9,20}(?![A-Za-z0-9-]))"
    r"(?=[A-Za-z0-9-]*[A-Za-z])"
    r"[A-Za-z0-9]{4,6}(?:-[A-Za-z0-9]{4,6}){1,2}"
)
_MFA_BACKUP_CODE_VALUE = (
    rf"(?<![A-Za-z0-9-])"
    rf"(?:{_MFA_BACKUP_DIGIT_CODE}|{_MFA_BACKUP_ALPHANUMERIC_CODE})"
    rf"(?![A-Za-z0-9-])"
)
_MFA_BACKUP_CODE_VALUE_RE = re.compile(_MFA_BACKUP_CODE_VALUE, re.IGNORECASE)
_MFA_BACKUP_CODE_LIST_SEPARATOR = (
    r"(?:\s*(?:,|;|/|\||\band\b|\bor\b)\s*|\s+)"
)
_MFA_BACKUP_CODE_LIST_ITEM = rf"[\"']?{_MFA_BACKUP_CODE_VALUE}[\"']?"
_MFA_BACKUP_CODE_LIST = (
    rf"{_MFA_BACKUP_CODE_LIST_ITEM}"
    rf"(?:{_MFA_BACKUP_CODE_LIST_SEPARATOR}{_MFA_BACKUP_CODE_LIST_ITEM}){{0,9}}"
)
_MFA_BACKUP_CODE_AFTER_CONTEXT_RE = re.compile(
    rf"(?<![A-Za-z0-9_])(?P<context>{_MFA_BACKUP_CODE_CONTEXT})"
    rf"(?![A-Za-z0-9_])"
    rf"(?P<between>\s*(?:(?:is|are|was|were)\b\s*)?(?:[:,=#-]\s*)?)"
    rf"(?P<codes>{_MFA_BACKUP_CODE_LIST})",
    re.IGNORECASE,
)
_MFA_BACKUP_CODE_BEFORE_CONTEXT_RE = re.compile(
    rf"(?P<quote>[\"'])?"
    rf"(?P<code>{_MFA_BACKUP_CODE_VALUE})"
    rf"(?(quote)(?P=quote))"
    rf"(?P<between>\s+(?:is|are|as|for)\s+"
    rf"(?:your|my|our|the|this|that|a|an)?\s*)"
    rf"(?P<context>{_MFA_BACKUP_CODE_CONTEXT})"
    rf"(?![A-Za-z0-9_])",
    re.IGNORECASE,
)
_AUTHENTICATOR_SECRET_PLACEHOLDER = "[REDACTED_AUTHENTICATOR_SECRET]"
_AUTHENTICATOR_FACTOR_CONTEXT = (
    r"(?:"
    r"totp|hotp|otp|mfa|2fa|two[-\s]?factor|multi[-\s]?factor|"
    r"authenticator(?:\s+app)?|google\s+authenticator|"
    r"microsoft\s+authenticator|authy"
    r")"
)
_AUTHENTICATOR_SECRET_CONTEXT = (
    r"(?:"
    rf"{_AUTHENTICATOR_FACTOR_CONTEXT}\s+"
    r"(?:secret(?:\s+key)?|seed|setup\s+(?:key|code)|"
    r"manual\s+entry\s+(?:key|code))|"
    r"(?:setup|manual\s+entry|enrollment|provisioning)\s+"
    r"(?:key|code|secret)\s+for\s+(?:your\s+)?"
    rf"{_AUTHENTICATOR_FACTOR_CONTEXT}|"
    r"(?:secret|seed|setup\s+(?:key|code)|manual\s+entry\s+(?:key|code))"
    r"\s+(?:for|from)\s+(?:your\s+)?"
    rf"{_AUTHENTICATOR_FACTOR_CONTEXT}"
    r")"
)
_AUTHENTICATOR_SECRET_CONTIGUOUS_VALUE = r"[A-Z2-7]{16,128}={0,6}"
_AUTHENTICATOR_SECRET_GROUPED_VALUE = (
    r"[A-Z2-7]{4}(?:[ -]+[A-Z2-7]{4}){3,31}"
)
_AUTHENTICATOR_SECRET_VALUE = (
    rf"(?<![A-Za-z0-9])(?:{_AUTHENTICATOR_SECRET_CONTIGUOUS_VALUE}|"
    rf"{_AUTHENTICATOR_SECRET_GROUPED_VALUE})(?![A-Za-z0-9])"
)
_AUTHENTICATOR_SECRET_AFTER_CONTEXT_RE = re.compile(
    rf"(?<![A-Za-z0-9_])(?P<context>{_AUTHENTICATOR_SECRET_CONTEXT})"
    rf"(?![A-Za-z0-9_])"
    rf"(?P<between>\s*(?:(?:is|are|was)\s+|[:=]\s*|-\s*))"
    rf"(?P<quote>[\"'])?"
    rf"(?P<authenticator_secret>{_AUTHENTICATOR_SECRET_VALUE})"
    rf"(?(quote)(?P=quote))",
    re.IGNORECASE,
)
_AUTHENTICATOR_SECRET_BEFORE_CONTEXT_RE = re.compile(
    rf"(?P<quote>[\"'])?"
    rf"(?P<authenticator_secret>{_AUTHENTICATOR_SECRET_VALUE})"
    rf"(?(quote)(?P=quote))"
    rf"(?P<between>\s+(?:is|are|as|for)\s+"
    rf"(?:your|my|our|the|this|that|a|an)?\s*)"
    rf"(?P<context>{_AUTHENTICATOR_SECRET_CONTEXT})"
    rf"(?![A-Za-z0-9_])",
    re.IGNORECASE,
)
_SENSITIVE_LINK_URL_TARGET = (
    r"(?:https?://[^\s<>\]\"']{1,2048}|www\.[^\s<>\]\"']{1,2048})"
)
_CREDENTIAL_QUERY_VALUE_PLACEHOLDER = "[REDACTED_CREDENTIAL_QUERY_VALUE]"
_OAUTH_AUTHORIZATION_CODE_PLACEHOLDER = "[REDACTED_OAUTH_AUTHORIZATION_CODE]"
_REFRESH_TOKEN_PLACEHOLDER = "[REDACTED_REFRESH_TOKEN]"
_PASSKEY_CREDENTIAL_ID_PLACEHOLDER = "[REDACTED_PASSKEY_CREDENTIAL_ID]"
_PASSKEY_CHALLENGE_ID_PLACEHOLDER = "[REDACTED_PASSKEY_CHALLENGE_ID]"
_PASSKEY_REGISTRATION_URL_PLACEHOLDER = "[REDACTED_PASSKEY_REGISTRATION_URL]"
_PASSKEY_ASSERTION_URL_PLACEHOLDER = "[REDACTED_PASSKEY_ASSERTION_URL]"
_SAML_RESPONSE_PLACEHOLDER = "[REDACTED_SAML_RESPONSE]"
_SAML_REQUEST_PLACEHOLDER = "[REDACTED_SAML_REQUEST]"
_SAML_XML_PLACEHOLDER = "[REDACTED_SAML_XML]"
_WEBHOOK_URL_PLACEHOLDER = "[REDACTED_WEBHOOK_URL]"
_URL_USERINFO_CREDENTIAL_PLACEHOLDER = "[REDACTED_URL_CREDENTIAL]"
_COOKIE_SECRET_PLACEHOLDER = "[REDACTED_COOKIE_SECRET]"
_SIGNED_CLOUD_STORAGE_SIGNATURE_PLACEHOLDER = (
    "[REDACTED_SIGNED_CLOUD_STORAGE_SIGNATURE]"
)
_SIGNED_CLOUD_STORAGE_CREDENTIAL_PLACEHOLDER = (
    "[REDACTED_SIGNED_CLOUD_STORAGE_CREDENTIAL]"
)
_URL_USERINFO_CREDENTIAL_SCHEMES = {
    "ftp",
    "ftps",
    "http",
    "https",
    "imap",
    "imaps",
    "smtp",
    "smtps",
    "pop3",
    "pop3s",
    "sftp",
    "ssh",
}


def _normalized_query_param_name(name: str) -> str:
    return unquote_plus(name).lower().replace("-", "_")


def _query_param_name_aliases(name: str) -> Set[str]:
    normalized = _normalized_query_param_name(name)
    return {normalized, normalized.replace("_", "")}


def _expand_query_param_names(names: Iterable[str]) -> Set[str]:
    expanded = set()
    for name in names:
        expanded.update(_query_param_name_aliases(name))

    return expanded


_COOKIE_SECRET_NAMES = _expand_query_param_names(
    {
        "session",
        "sessionid",
        "session_id",
        "session_token",
        "session_cookie",
        "sid",
        "auth",
        "auth_token",
        "token",
        "access_token",
        "refresh_token",
        "csrf",
        "csrf_token",
        "xsrf",
        "xsrf_token",
        "jwt",
        "id_token",
        "remember_me",
    }
)
_COOKIE_NAME = r"[A-Za-z0-9][A-Za-z0-9_.-]{0,128}"
_COOKIE_SECRET_VALUE = r"[^;,\s\"'<>]{1,4096}"
_COOKIE_QUOTED_SECRET_VALUE = r"[^\"'\r\n<>]{1,4096}"
_COOKIE_MAYBE_QUOTED_SECRET_VALUE = (
    rf"(?P<quote>[\"'])?"
    rf"(?P<cookie_secret>"
    rf"(?(quote){_COOKIE_QUOTED_SECRET_VALUE}|{_COOKIE_SECRET_VALUE})"
    rf")"
    rf"(?(quote)(?P=quote))"
)
_COOKIE_SECRET_LIKE_VALUE = (
    r"(?=[A-Za-z0-9._~+/%=-]{6,4096}(?![A-Za-z0-9._~+/%=-]))"
    r"(?=[A-Za-z0-9._~+/%=-]*(?:\d|[._~+/%=-]))"
    r"[A-Za-z0-9][A-Za-z0-9._~+/%=-]*"
)
_COOKIE_BENIGN_PROSE_VALUE_PREFIXES = (
    "expiration",
    "expired",
    "expires",
    "first-party",
    "opt-in",
    "opt-out",
    "persistent",
    "preference",
    "rotated",
    "rotation",
    "same-site",
    "samesite",
    "session-only",
    "temporary",
    "third-party",
)
_COOKIE_PAIR_RE = re.compile(
    rf"(?<![A-Za-z0-9_.-])(?P<name>{_COOKIE_NAME})"
    rf"\s*=\s*{_COOKIE_MAYBE_QUOTED_SECRET_VALUE}",
    re.IGNORECASE,
)
_SET_COOKIE_HEADER_RE = re.compile(
    r"(?i)(?P<label>(?<![A-Za-z0-9_-])Set-Cookie\s*:\s*)"
    r"(?P<cookies>[^\r\n]{0,4096})"
)
_COOKIE_HEADER_RE = re.compile(
    r"(?i)(?P<label>(?<![A-Za-z0-9_-])Cookie\s*:\s*)"
    r"(?P<cookies>[^\r\n]{0,4096})"
)
_COOKIE_PROSE_ASSIGNMENT_RE = re.compile(
    rf"(?<![A-Za-z0-9_.-])(?P<name>{_COOKIE_NAME})(?![A-Za-z0-9_.-])"
    rf"(?P<between>\s+cookies?\s*(?:[:=]\s*|-\s+))"
    rf"{_COOKIE_MAYBE_QUOTED_SECRET_VALUE}",
    re.IGNORECASE,
)
_COOKIE_PROSE_VALUE_RE = re.compile(
    rf"(?<![A-Za-z0-9_.-])(?P<name>{_COOKIE_NAME})(?![A-Za-z0-9_.-])"
    rf"(?P<between>\s+cookies?\s+(?P<prose_verb>(?:is|are|was|were)\s+)?)"
    rf"(?P<quote>[\"'])?"
    rf"(?P<cookie_secret>{_COOKIE_SECRET_LIKE_VALUE})"
    rf"(?(quote)(?P=quote))",
    re.IGNORECASE,
)
_COOKIE_SECRET_TRAILING_PUNCTUATION = ".,)]}"


_CREDENTIAL_QUERY_PARAM_NAMES = _expand_query_param_names(
    {
        "api_key",
        "api_token",
        "token",
        "auth",
        "auth_token",
        "secret",
        "client_secret",
        "aws_secret_access_key",
        "secret_access_key",
        "aws_session_token",
        "security_token",
        "x_amz_credential",
        "x_amz_security_token",
        "x_amz_signature",
        "password",
        "passwd",
        "passphrase",
        "totp_secret",
        "otp_secret",
        "mfa_secret",
        "code_verifier",
        "access_token",
        "refresh_token",
        "id_token",
        "session",
        "session_id",
        "session_token",
        "session_cookie",
        "cookie",
        "csrf",
        "csrf_token",
        "xsrf",
        "xsrf_token",
        "ticket",
        "key",
        "jwt",
    }
)
_CONTEXTUAL_CREDENTIAL_QUERY_PARAM_NAMES = _expand_query_param_names(
    {
        "token",
        "reset_token",
        "password_reset_token",
        "verification_token",
        "verify_token",
        "confirmation_token",
        "confirm_token",
        "invite_token",
        "invitation_token",
        "code",
        "reset_code",
        "password_reset_code",
        "verification_code",
        "verify_code",
        "confirmation_code",
        "confirm_code",
        "invite_code",
        "invitation_code",
        "magic_code",
        "login_code",
        "sign_in_code",
        "signin_code",
        "key",
        "reset_key",
        "verification_key",
        "confirmation_key",
        "invite_key",
        "invitation_key",
        "ticket",
        "invite_ticket",
        "invitation_ticket",
        "signature",
        "sig",
        "state",
        "otp",
        "otp_code",
        "one_time_code",
        "one_time_password",
    }
)
_OAUTH_CLIENT_SECRET_QUERY_PARAM_NAMES = _expand_query_param_names(
    {
        "client_secret",
        "oauth_client_secret",
        "google_client_secret",
    }
)
_OIDC_ID_TOKEN_QUERY_PARAM_NAMES = _expand_query_param_names(
    {
        "id_token",
    }
)
_OAUTH_AUTHORIZATION_CODE_PARAM_NAMES = _expand_query_param_names(
    {
        "code",
        "auth_code",
        "authorization_code",
        "oauth_code",
    }
)
_OAUTH_AUTHORIZATION_CODE_QUERY_CONTEXT_PARAM_NAMES = _expand_query_param_names(
    {
        "client_id",
        "code_challenge",
        "code_verifier",
        "grant_type",
        "redirect_uri",
        "response_type",
    }
)
_PASSKEY_CREDENTIAL_QUERY_PARAM_NAMES = _expand_query_param_names(
    {
        "credential",
        "credential_id",
        "credential_identifier",
        "passkey_credential",
        "passkey_credential_id",
        "public_key_credential",
        "public_key_credential_id",
        "raw_id",
        "webauthn_credential",
        "webauthn_credential_id",
    }
)
_PASSKEY_CHALLENGE_QUERY_PARAM_NAMES = _expand_query_param_names(
    {
        "challenge",
        "challenge_id",
        "passkey_challenge",
        "webauthn_challenge",
        "webauthn_challenge_id",
    }
)
_SAML_RESPONSE_QUERY_PARAM_NAMES = _expand_query_param_names({"saml_response"})
_SAML_REQUEST_QUERY_PARAM_NAMES = _expand_query_param_names({"saml_request"})
_GCS_SIGNED_URL_SIGNATURE_QUERY_PARAM_NAMES = _expand_query_param_names(
    {"x_goog_signature"}
)
_GCS_SIGNED_URL_CREDENTIAL_QUERY_PARAM_NAMES = _expand_query_param_names(
    {"x_goog_credential", "x_goog_security_token"}
)
_AZURE_SAS_SIGNATURE_QUERY_PARAM_NAMES = _expand_query_param_names({"sig"})
_AZURE_SAS_CONTEXT_PARAM_NAMES = _expand_query_param_names(
    {
        "sv",
        "ss",
        "srt",
        "sp",
        "se",
        "sr",
        "st",
        "spr",
        "sip",
        "si",
        "skoid",
        "sktid",
        "skt",
        "ske",
        "sks",
        "skv",
    }
)
_AZURE_STORAGE_HOST_RE = re.compile(
    r"(?i)(?:^|\.)"
    r"(?:blob|dfs|file|queue|table)\.core\.windows\.net$"
)
_CREDENTIAL_QUERY_URL_RE = re.compile(
    r"(?P<url>(?:https?://|www\.)[^\s<>\"']{1,2048})",
    re.IGNORECASE,
)
_OTPAUTH_URL_RE = re.compile(
    r"(?P<url>otpauth://[^\s<>\"']{1,2048})",
    re.IGNORECASE,
)
_URL_USERINFO_CREDENTIAL_URL_RE = re.compile(
    r"(?P<url>"
    r"(?:https?://|imaps?://|smtps?://|pop3s?://|ftps?://|sftp://|ssh://)"
    r"[^\s<>\"']{1,2048})",
    re.IGNORECASE,
)
_WEBHOOK_URL_SAFE_PATH_SEGMENT_RE = re.compile(r"[A-Za-z0-9._~@%-]+")
_QUERY_PARAM_SEPARATOR_RE = re.compile(r"([&;])")
_REDACTION_PLACEHOLDER_SUFFIX_RE = re.compile(r"\[REDACTED_[A-Z0-9_]+\]$")
_OAUTH_AUTHORIZATION_CODE_URL_CONTEXT_RE = re.compile(
    r"(?i)(?<![A-Za-z])(?:"
    r"oauth(?:2|[-_/]?2(?:\.0)?)?(?:[-_/]?callback)?|"
    r"oidc|openid|"
    r"authorize|authorization|consent|"
    r"callback(?:url)?|redirect(?:uri|url)?"
    r")(?![A-Za-z])"
)
_CREDENTIAL_LINK_CODE_URL_CONTEXT_RE = re.compile(
    r"(?i)(?<![A-Za-z])(?:"
    r"password[-_/ ]?reset|reset|reset[-_/ ]?(?:password|pwd)|"
    r"forgot(?:ten)?[-_/ ]?password|"
    r"verify|verification|"
    r"confirm[-_/ ]?(?:account|email|identity)|"
    r"(?:account|email|identity)[-_/ ]?confirm(?:ation)?|"
    r"magic(?:[-_/ ]?(?:login|sign[-_ ]?in|link))?|"
    r"log[-_ ]?in|login|sign[-_ ]?in|signin|"
    r"(?:accept[-_/ ]?)?(?:invite|invitation)|"
    r"(?:invite|invitation)[-_/ ]?accept|"
    r"auth(?:enticate|entication)?|"
    r"callback(?:url)?|redirect(?:uri|url)?|"
    r"oauth(?:2|[-_/]?2(?:\.0)?)?"
    r")(?![A-Za-z])"
)
_SENSITIVE_EMAIL_LINK_URL_CONTEXT_RE = re.compile(
    r"(?i)(?<![A-Za-z])(?:"
    r"password[-_/ ]?reset|reset[-_/ ]?(?:password|pwd)|"
    r"forgot(?:ten)?[-_/ ]?password|"
    r"verify|verification|"
    r"confirm(?:ation)?|"
    r"confirm[-_/ ]?(?:account|email|identity)|"
    r"(?:account|email|identity)[-_/ ]?confirm(?:ation)?|"
    r"magic(?:[-_/ ]?(?:login|sign[-_ ]?in|link|code))?|"
    r"(?:accept[-_/ ]?)?(?:invite|invitation)|"
    r"(?:invite|invitation)[-_/ ]?accept"
    r")(?![A-Za-z])"
)
_SENSITIVE_LINK_TOKEN_LIKE_PATH_SEGMENT_RE = re.compile(
    r"(?i)(?=.{12,256}$)(?=.*[A-Za-z])(?=.*\d)[A-Za-z0-9._~%+=-]+"
)
_PASSKEY_WEBAUTHN_CONTEXT = (
    r"(?:"
    r"passkeys?|"
    r"web[-_\s/]*authn(?:[-_\s/]+credentials?)?|"
    r"webauthn(?:[-_\s/]+credentials?)?|"
    r"fido(?:2)?|ctap(?:2)?|"
    r"security[-_\s/]+keys?|"
    r"platform[-_\s/]+authenticators?|"
    r"resident[-_\s/]+credentials?|"
    r"discoverable[-_\s/]+credentials?|"
    r"public[-_\s/]+key[-_\s/]+credentials?"
    r")"
)
_PASSKEY_WEBAUTHN_URL_CONTEXT_RE = re.compile(
    rf"(?i)(?<![A-Za-z]){_PASSKEY_WEBAUTHN_CONTEXT}(?![A-Za-z])"
)
_PASSKEY_REGISTRATION_URL_PURPOSE = (
    r"(?:"
    r"register|registration|enroll(?:ment)?|attestation|"
    r"create|creation|credential[-_\s/]+creation|make[-_\s/]*credential"
    r")"
)
_PASSKEY_ASSERTION_URL_PURPOSE = (
    r"(?:"
    r"assert(?:ion)?|authenticate|authentication|login|"
    r"sign[-_\s/]*in|signin|credential[-_\s/]+request|get[-_\s/]*assertion"
    r")"
)
_PASSKEY_REGISTRATION_URL_PURPOSE_RE = re.compile(
    rf"(?i)(?<![A-Za-z]){_PASSKEY_REGISTRATION_URL_PURPOSE}(?![A-Za-z])"
)
_PASSKEY_ASSERTION_URL_PURPOSE_RE = re.compile(
    rf"(?i)(?<![A-Za-z]){_PASSKEY_ASSERTION_URL_PURPOSE}(?![A-Za-z])"
)
_PASSKEY_ARTIFACT_VALUE = (
    r"(?=[A-Za-z0-9_~+/\-=%]{8,}(?![A-Za-z0-9_~+/\-=%]))"
    r"(?=[A-Za-z0-9_~+/\-=%]*[A-Za-z])"
    r"(?=[A-Za-z0-9_~+/\-=%]*\d)"
    r"[A-Za-z0-9][A-Za-z0-9_~+/\-=%]*"
)
_PASSKEY_CREDENTIAL_ID_LABEL = (
    r"(?:"
    r"credential[-_\s]?(?:id|identifier)|credentialid|"
    r"raw[-_\s]?id|rawid|"
    r"public[-_\s]?key[-_\s]?credential[-_\s]?id"
    r")"
)
_PASSKEY_CHALLENGE_ID_LABEL = (
    r"(?:"
    r"challenge(?:[-_\s]?(?:id|identifier))?|challengeid|"
    r"public[-_\s]?key[-_\s]?challenge"
    r")"
)
_PASSKEY_ARTIFACT_CONTEXT_WINDOW = r"[^\n.!?]{0,80}?"
_PASSKEY_CREDENTIAL_ID_AFTER_CONTEXT_RE = re.compile(
    rf"\b(?P<context>{_PASSKEY_WEBAUTHN_CONTEXT})\b"
    rf"(?P<between>{_PASSKEY_ARTIFACT_CONTEXT_WINDOW})"
    rf"\b(?P<label>{_PASSKEY_CREDENTIAL_ID_LABEL})\b"
    rf"(?P<separator>\s*(?:(?:is|are|was)\s+|[:=#-]\s*))"
    rf"(?P<quote>[\"'])?"
    rf"(?P<credential_id>{_PASSKEY_ARTIFACT_VALUE})"
    rf"(?(quote)(?P=quote))",
    re.IGNORECASE,
)
_PASSKEY_CREDENTIAL_ID_BEFORE_CONTEXT_RE = re.compile(
    rf"\b(?P<label>{_PASSKEY_CREDENTIAL_ID_LABEL})\b"
    rf"(?P<separator>\s*(?:(?:is|are|was)\s+|[:=#-]\s*))"
    rf"(?P<quote>[\"'])?"
    rf"(?P<credential_id>{_PASSKEY_ARTIFACT_VALUE})"
    rf"(?(quote)(?P=quote))"
    rf"(?P<between>{_PASSKEY_ARTIFACT_CONTEXT_WINDOW})"
    rf"\b(?P<context>{_PASSKEY_WEBAUTHN_CONTEXT})\b",
    re.IGNORECASE,
)
_PASSKEY_CHALLENGE_ID_AFTER_CONTEXT_RE = re.compile(
    rf"\b(?P<context>{_PASSKEY_WEBAUTHN_CONTEXT})\b"
    rf"(?P<between>{_PASSKEY_ARTIFACT_CONTEXT_WINDOW})"
    rf"\b(?P<label>{_PASSKEY_CHALLENGE_ID_LABEL})\b"
    rf"(?P<separator>\s*(?:(?:is|are|was)\s+|[:=#-]\s*))"
    rf"(?P<quote>[\"'])?"
    rf"(?P<challenge_id>{_PASSKEY_ARTIFACT_VALUE})"
    rf"(?(quote)(?P=quote))",
    re.IGNORECASE,
)
_PASSKEY_CHALLENGE_ID_BEFORE_CONTEXT_RE = re.compile(
    rf"\b(?P<label>{_PASSKEY_CHALLENGE_ID_LABEL})\b"
    rf"(?P<separator>\s*(?:(?:is|are|was)\s+|[:=#-]\s*))"
    rf"(?P<quote>[\"'])?"
    rf"(?P<challenge_id>{_PASSKEY_ARTIFACT_VALUE})"
    rf"(?(quote)(?P=quote))"
    rf"(?P<between>{_PASSKEY_ARTIFACT_CONTEXT_WINDOW})"
    rf"\b(?P<context>{_PASSKEY_WEBAUTHN_CONTEXT})\b",
    re.IGNORECASE,
)
_PASSKEY_REGISTRATION_URL_LABEL = (
    rf"(?:{_PASSKEY_REGISTRATION_URL_PURPOSE}"
    r"[-_\s]+(?:url|link|endpoint|uri|page|request)|"
    r"(?:url|link|endpoint|uri|page|request)\s+"
    rf"(?:for|to)\s+{_PASSKEY_REGISTRATION_URL_PURPOSE})"
)
_PASSKEY_ASSERTION_URL_LABEL = (
    rf"(?:{_PASSKEY_ASSERTION_URL_PURPOSE}"
    r"[-_\s]+(?:url|link|endpoint|uri|page|request)|"
    r"(?:url|link|endpoint|uri|page|request)\s+"
    rf"(?:for|to)\s+{_PASSKEY_ASSERTION_URL_PURPOSE})"
)
_PASSKEY_REGISTRATION_URL_AFTER_CONTEXT_RE = re.compile(
    rf"\b(?P<context>{_PASSKEY_WEBAUTHN_CONTEXT})\b"
    rf"(?P<between>{_PASSKEY_ARTIFACT_CONTEXT_WINDOW})"
    rf"\b(?P<label>{_PASSKEY_REGISTRATION_URL_LABEL})\b"
    rf"(?P<separator>\s*(?:(?:is|are|was|at)\s+|[:=#-]\s*|here\s+)?\s*)"
    rf"(?P<url>{_SENSITIVE_LINK_URL_TARGET})",
    re.IGNORECASE,
)
_PASSKEY_REGISTRATION_URL_BEFORE_CONTEXT_RE = re.compile(
    rf"\b(?P<label>{_PASSKEY_REGISTRATION_URL_LABEL})\b"
    rf"(?P<between>{_PASSKEY_ARTIFACT_CONTEXT_WINDOW})"
    rf"\b(?P<context>{_PASSKEY_WEBAUTHN_CONTEXT})\b"
    rf"(?P<separator>\s*(?:(?:is|are|was|at)\s+|[:=#-]\s*|here\s+)?\s*)"
    rf"(?P<url>{_SENSITIVE_LINK_URL_TARGET})",
    re.IGNORECASE,
)
_PASSKEY_ASSERTION_URL_AFTER_CONTEXT_RE = re.compile(
    rf"\b(?P<context>{_PASSKEY_WEBAUTHN_CONTEXT})\b"
    rf"(?P<between>{_PASSKEY_ARTIFACT_CONTEXT_WINDOW})"
    rf"\b(?P<label>{_PASSKEY_ASSERTION_URL_LABEL})\b"
    rf"(?P<separator>\s*(?:(?:is|are|was|at)\s+|[:=#-]\s*|here\s+)?\s*)"
    rf"(?P<url>{_SENSITIVE_LINK_URL_TARGET})",
    re.IGNORECASE,
)
_PASSKEY_ASSERTION_URL_BEFORE_CONTEXT_RE = re.compile(
    rf"\b(?P<label>{_PASSKEY_ASSERTION_URL_LABEL})\b"
    rf"(?P<between>{_PASSKEY_ARTIFACT_CONTEXT_WINDOW})"
    rf"\b(?P<context>{_PASSKEY_WEBAUTHN_CONTEXT})\b"
    rf"(?P<separator>\s*(?:(?:is|are|was|at)\s+|[:=#-]\s*|here\s+)?\s*)"
    rf"(?P<url>{_SENSITIVE_LINK_URL_TARGET})",
    re.IGNORECASE,
)
_OAUTH_AUTHORIZATION_CODE_CONTEXT = (
    r"(?:"
    r"authorization\s+code|"
    r"oauth(?:\s*2(?:\.0)?)?\s+(?:authorization\s+)?code|"
    r"oidc\s+(?:authorization\s+)?code|"
    r"auth\s+code|"
    r"auth[_-]?code|"
    r"authorization[_-]?code|"
    r"oauth[_-]?code|"
    r"oidc[_-]?code"
    r")"
)
_OAUTH_AUTHORIZATION_CODE_VALUE = (
    r"(?=[A-Za-z0-9_~+/\-=%]{12,})"
    r"(?=[A-Za-z0-9_~+/\-=%]*[A-Za-z])"
    r"(?=[A-Za-z0-9_~+/\-=%]*\d)"
    r"[A-Za-z0-9][A-Za-z0-9_~+/\-=%]*"
)
_OAUTH_CONTEXT_VALUE_SEPARATOR = r"(?:\s+(?:is|are|was)\s+|\s*[:=]\s*|\s*-\s+)"
_OAUTH_AUTHORIZATION_CODE_AFTER_CONTEXT_RE = re.compile(
    rf"\b(?P<context>{_OAUTH_AUTHORIZATION_CODE_CONTEXT})\b"
    rf"(?P<between>{_OAUTH_CONTEXT_VALUE_SEPARATOR})"
    rf"(?P<quote>[\"'])?"
    rf"(?P<authorization_code>{_OAUTH_AUTHORIZATION_CODE_VALUE})"
    rf"(?(quote)(?P=quote))",
    re.IGNORECASE,
)
_OAUTH_DEVICE_USER_CODE_CONTEXT = (
    r"(?:"
    r"(?:oauth(?:\s*2(?:\.0)?)?\s+)?device\s+code|"
    r"(?:oauth(?:\s*2(?:\.0)?)?\s+)?user\s+code|"
    r"device[_-]?code|"
    r"user[_-]?code"
    r")"
)
_OAUTH_DEVICE_USER_CODE_VALUE = (
    r"(?=[A-Za-z0-9_~+/\-=%]{12,})"
    r"(?=[A-Za-z0-9_~+/\-=%]*[A-Za-z])"
    r"(?=[A-Za-z0-9_~+/\-=%]*\d)"
    r"[A-Za-z0-9][A-Za-z0-9_~+/\-=%]*"
)
_OAUTH_DEVICE_USER_CODE_AFTER_CONTEXT_RE = re.compile(
    rf"\b(?P<context>{_OAUTH_DEVICE_USER_CODE_CONTEXT})\b"
    rf"(?P<between>{_OAUTH_CONTEXT_VALUE_SEPARATOR})"
    rf"(?P<quote>[\"'])?"
    rf"(?P<authorization_code>{_OAUTH_DEVICE_USER_CODE_VALUE})"
    rf"(?(quote)(?P=quote))",
    re.IGNORECASE,
)
_REFRESH_TOKEN_CONTEXT = (
    r"(?:"
    r"(?:oauth(?:\s*2(?:\.0)?)?\s+)?refresh\s+tokens?|"
    r"refresh[_-]?tokens?|"
    r"offline\s+access\s+tokens?|"
    r"offline[_-]?access[_-]?tokens?"
    r")"
)
_REFRESH_TOKEN_VALUE = (
    r"(?=[A-Za-z0-9._~+/%=-]{16,})"
    r"(?=[A-Za-z0-9._~+/%=-]*[A-Za-z])"
    r"(?=[A-Za-z0-9._~+/%=-]*\d)"
    r"[A-Za-z0-9_~+/%=-][A-Za-z0-9._~+/%=-]*[A-Za-z0-9_~+/%=-]"
    r"(?![A-Za-z0-9_~+/%=-])"
)
_REFRESH_TOKEN_AFTER_CONTEXT_RE = re.compile(
    rf"\b(?P<context>{_REFRESH_TOKEN_CONTEXT})\b"
    rf"(?P<between>{_OAUTH_CONTEXT_VALUE_SEPARATOR})"
    rf"(?P<quote>[\"'])?"
    rf"(?P<refresh_token>{_REFRESH_TOKEN_VALUE})"
    rf"(?(quote)(?P=quote))",
    re.IGNORECASE,
)
_SAML_FORM_FIELD_NAME = r"SAML[-_]?Response|SAML[-_]?Request"
_SAML_FORM_FIELD_VALUE = (
    r"(?=[A-Za-z0-9+/_~%=-]{24,}(?![A-Za-z0-9+/_~%=-]))"
    r"[A-Za-z0-9%][A-Za-z0-9+/_~%=-]*"
)
_SAML_FORM_FIELD_RE = re.compile(
    rf"(?P<prefix>(?<![A-Za-z0-9_])(?P<key_quote>[\"'])?"
    rf"(?P<field>{_SAML_FORM_FIELD_NAME})(?(key_quote)(?P=key_quote))"
    rf"(?![A-Za-z0-9_])\s*[:=]\s*)"
    rf"(?P<quote>[\"'])?"
    rf"(?P<saml_value>{_SAML_FORM_FIELD_VALUE})"
    rf"(?(quote)(?P=quote))",
    re.IGNORECASE,
)
_SAML_XML_BLOCK_RE = re.compile(
    r"<\s*(?P<saml_xml_tag>"
    r"(?:(?:saml|samlp|saml2|saml2p):)?(?:Assertion|Response|AuthnRequest)"
    r")\b[^>]*>.*?</\s*(?P=saml_xml_tag)\s*>",
    re.IGNORECASE | re.DOTALL,
)
_SAML_XML_MARKER_RE = re.compile(
    r"(?i)\b(?:saml|samlp|saml2|saml2p)\b|urn:oasis:names:tc:SAML"
)
_SENSITIVE_LINK_CONTEXT = (
    r"(?:"
    r"password\s+reset|"
    r"reset\s+(?:your\s+)?password|"
    r"forgot(?:ten)?\s+password|"
    r"magic\s+(?:sign[-\s]?in|login)\s+link|"
    r"magic\s+link|"
    r"sign[-\s]?in\s+link|"
    r"login\s+link|"
    r"account\s+verification|"
    r"email\s+verification|"
    r"verify\s+(?:your\s+)?(?:account|email|identity)|"
    r"confirm\s+(?:your\s+)?(?:account|email|identity)|"
    r"(?:link|url)\s+to\s+(?:sign\s*in|log\s*in)"
    r")"
)
_SENSITIVE_LINK_AFTER_CONTEXT_RE = re.compile(
    rf"\b(?P<context>{_SENSITIVE_LINK_CONTEXT})\b"
    rf"(?P<between>"
    rf"(?:\s+(?:link|url|button|page))?\s*(?:is|:|=|-|at|here|below)?\s*"
    rf")"
    rf"(?P<url>{_SENSITIVE_LINK_URL_TARGET})",
    re.IGNORECASE,
)
_SENSITIVE_LINK_BEFORE_CONTEXT_RE = re.compile(
    rf"(?P<url>{_SENSITIVE_LINK_URL_TARGET})"
    rf"(?P<between>\s+(?:is|as|for|to|will)\s+(?:your|the|this|a|an)?\s*)"
    rf"(?P<context>{_SENSITIVE_LINK_CONTEXT})\b",
    re.IGNORECASE,
)
_SENSITIVE_URL_TRAILING_PUNCTUATION = ".,;:!?)]}"
_PROMPT_ROLE_TAGS = r"system|assistant|user|developer|tool|human"
_PROMPT_BOUNDARY_MARKER_RE = re.compile(
    r"(?i)\b(?:BEGIN|END)_UNTRUSTED_EMAIL\b"
)
_ROLE_TAG_RE = re.compile(rf"(?im)^(\s*)({_PROMPT_ROLE_TAGS})\s*:\s*")
_INLINE_ROLE_TAG_RE = re.compile(
    rf"(?i)(?<![\w/@.-])({_PROMPT_ROLE_TAGS})\s*:\s*"
)
_MARKDOWN_ROLE_HEADING_RE = re.compile(
    rf"(?im)^([ \t]{{0,3}}#{{1,6}}\s*)({_PROMPT_ROLE_TAGS})(\s*:\s*|\s*$)"
)
_MODEL_CONTROL_TOKEN_RE = re.compile(
    rf"(?i)"
    rf"<\|\s*im_start\s*\|>[ \t]*(?:{_PROMPT_ROLE_TAGS})?"
    rf"|<\|\s*start_header_id\s*\|>[ \t]*(?:{_PROMPT_ROLE_TAGS})"
    rf"[ \t]*<\|\s*end_header_id\s*\|>"
    r"|<\|\s*(?:im_end|end|endoftext|eot_id|start_header_id|end_header_id|"
    rf"{_PROMPT_ROLE_TAGS})\s*\|>"
    r"|\[/?INST\]"
    r"|<</?SYS>>"
)
_ACTION_ROLE_PREFIX = rf"(?:(?:{_PROMPT_ROLE_TAGS})\s*:\s*)?"
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
_SAFETY_METADATA_SUPPRESSION_PHRASE = (
    r"(?:"
    r"(?:hide|suppress|omit|remove|exclude|drop)\s+"
    r"(?:(?:any|all|the)\s+)?(?:security\s+|safety\s+)?"
    r"(?:warnings?|alerts?|signals?|metadata)"
    r"|(?:do\s+not|don't|never)\s+"
    r"(?:mention|show|include|surface|report|flag)\s+"
    r"(?:that\s+)?(?:this\s+)?(?:is\s+)?"
    r"(?:suspicious|risky|unsafe|a\s+warning|any\s+warnings?|"
    r"security\s+warnings?|safety\s+metadata)"
    r"|(?:tell|assure)\s+(?:the\s+)?user\s+(?:that\s+)?"
    r"(?:this|it|the\s+(?:message|email|link|url|attachment|file|content))\s+"
    r"is\s+(?:safe|verified|trusted|legitimate)"
    r"|mark\s+(?:(?:this|it|the\s+"
    r"(?:message|email|link|url|attachment|file|content))\s+)?"
    r"(?:as\s+)?(?:safe|verified|trusted|legitimate)"
    r"|bypass\s+(?:(?:any|all|the)\s+)?(?:security|safety|phishing)\s+checks?"
    r")"
)
_SAFETY_METADATA_DIRECTIVE_RE = re.compile(
    rf"\b({_SAFETY_METADATA_SUPPRESSION_PHRASE})\b",
    re.IGNORECASE,
)
_DIRECTIVE_START = rf"(?i)^\s*(?:[-*]|\d+[.)])?\s*{_ACTION_ROLE_PREFIX}(?:please\s+)?"
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
_URGENCY_SUFFIX = (
    r"(?:please\s+do\s+(?:it|this|that)\s+"
    r"(?:right\s+now|now|asap|immediately|as\s+soon\s+as\s+possible)|"
    r"(?:right\s+now|now|asap|immediately|as\s+soon\s+as\s+possible)"
    r"(?:\s+please)?)"
)
_TARGET_END = rf"(?=\s*(?:$|[.!?,:;]|\b{_URGENCY_SUFFIX}\b\s*(?:$|[.!?,:;])))"
_STANDALONE_POLITE_SUFFIX = r"(?:please)"
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
_MUTE_CONVERSATION_NOUN = (
    r"(?:messages?|emails?|threads?|conversations?|email\s+conversations?)"
)
_MUTE_CONVERSATION_OBJECT = (
    r"(?:(?:the|this|that|these|those|an?|all)\s+)?"
    rf"(?:(?:[\w-]+\s+){{0,3}}{_MUTE_CONVERSATION_NOUN})\b"
)
_MUTE_NOTIFICATION_NOUN = r"(?:notifications?|alerts?)"
_FILTER_CONNECTOR = r"\s+(?:for|from|that|to|matching|with|where|when)\b"
_FILTER_TARGET = (
    rf"(?:(?:a|an|the)\s+filter(?:{_FILTER_CONNECTOR}|{_TARGET_END})|"
    rf"filter(?:{_FILTER_CONNECTOR}|{_TARGET_END}))"
)
_FILTER_RULE_MUTATION_VERB = (
    r"(?:update|modify|change|edit|adjust|tweak|reset|rename|replace|rewrite|"
    r"delete|remove|disable|deactivate|turn\s+off|enable|activate|turn\s+on|"
    r"pause|unpause)"
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
_IMPORTANCE_MARKER_TARGET = (
    rf"(?:(?:{_MAILBOX_OBJECT}\s+(?:as\s+)?)?"
    rf"(?:not\s+important|unimportant|important))\b{_TARGET_END}"
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
    rf"{_ACTION_ROLE_PREFIX}"
    rf"(?:(?:{_RECOMMENDATION_KEYWORD})\s*:?\s*)?"
    r"(?:(?:please|first|then|next|just|now|also)\s+){0,4}"
)
_MIDLINE_ACTION_SUGGESTION_START = (
    rf"(?i)\b{_RECOMMENDATION_KEYWORD}\b\s*:?\s*"
    r"(?:(?:please|first|then|next|just|now|also)\s+){0,4}"
)
_INSIGHT_SECTION_PREFIX = (
    r"(?:(?:summary|action\s+items?|draft\s+assistance|archive\s+suggestion|"
    r"security\s+warnings?)\s*:?\s*)?"
)
_SAFETY_METADATA_DIRECTIVE_LINE_RE = re.compile(
    rf"^\s*(?:[-*]|\d+[.)])?\s*"
    rf"{_ACTION_ROLE_PREFIX}"
    rf"(?:(?:{_RECOMMENDATION_KEYWORD})\s*:?\s*)?"
    rf"{_INSIGHT_SECTION_PREFIX}"
    r"(?:(?:please|first|then|next|just|now|also)\s+){0,4}"
    rf"{_SAFETY_METADATA_SUPPRESSION_PHRASE}\b",
    re.IGNORECASE,
)
_SECURITY_WARNING_ABSENCE_CLAIM_RE = re.compile(
    r"\b(?:no|none|zero|not\s+any|without)\s+"
    r"(?:security\s+|safety\s+)?warnings?\b"
    r"|\b(?:there\s+are\s+no|there\s+aren't\s+any|"
    r"does(?:\s+not|n't)\s+(?:have|include|contain))\s+"
    r"(?:security\s+|safety\s+)?warnings?\b"
    r"|\b(?:security\s+|safety\s+)?warnings?\s*"
    r"(?::|-|are|is)?\s*(?:none|no|zero)\b",
    re.IGNORECASE,
)
_RISKY_CONTENT_SAFE_CLAIM_RE = re.compile(
    r"\b(?:the\s+|this\s+)?"
    r"(?:message|email|sender|link|url|attachment|file|content|request)\s+"
    r"(?:is|looks|appears|seems)\s+"
    r"(?:completely\s+|totally\s+|fully\s+)?"
    r"(?:safe|verified|trusted|legitimate|not\s+suspicious|not\s+risky|not\s+unsafe)\b"
    r"|\b(?:safe|verified|trusted|legitimate)\s+"
    r"(?:message|email|sender|link|url|attachment|file|content|request)\b",
    re.IGNORECASE,
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
_BLOCKED_SENDER_ENTRY_NOUN = (
    r"(?:senders?|contacts?|email\s+addresses?|addresses?|domains?)"
)
_BLOCKED_SENDER_ENTRY_TARGET = (
    rf"(?:{_EMAIL_TARGET}(?:\s+(?:email\s+)?address)?|"
    rf"{_BARE_DOMAIN_TARGET}(?:\s+domain)?|"
    r"(?:(?:the|this|that|an?|your|my|our)\s+)?"
    rf"(?:[\w-]+\s+){{0,2}}{_BLOCKED_SENDER_ENTRY_NOUN}\b)"
)
_BLOCKED_SENDER_LIST_TARGET = (
    r"(?:(?:the|this|that|your|my|our)\s+)?"
    r"(?:(?:blocked\s+senders?|blocked\s+contacts?|"
    r"blocked\s+(?:email\s+)?addresses?|blocked\s+domains?|"
    r"block(?:ed)?[-\s]?list)(?:\s+list)?)\b"
)
_LINK_TARGET = (
    rf"(?:{_EXTERNAL_URL_TARGET}|"
    rf"(?:(?:the|this|that|an?|your)\s+)?(?:[\w-]+\s+){{0,4}}{_LINK_NOUN})"
)
_LINK_BUTTON_NOUN = r"(?:buttons?|cta|call[-\s]?to[-\s]?action(?:\s+buttons?)?)"
_LINK_BUTTON_TARGET = (
    rf"(?:(?:the|this|that|an?|your)\s+)?"
    rf"(?:[\w-]+\s+){{0,4}}{_LINK_BUTTON_NOUN}\b"
)
_LINK_ACTION_SUFFIX = (
    r"(?:\s+(?:in|from|on|within)\s+"
    r"(?:(?:the|this|that)\s+)?(?:email|message|thread))?"
    r"(?:\s+(?:to|for|and|with)\s+[\w-]+(?:\s+[\w-]+){0,8})?"
)
_LINK_ACTION_END = rf"{_LINK_ACTION_SUFFIX}{_TARGET_END}"
_CLICK_LINK_TARGET = rf"(?:here|{_LINK_TARGET}|{_LINK_BUTTON_TARGET})"
_QR_CONTEXT_MODIFIER = (
    r"(?:(?:authenticator|mfa|2fa|two[-\s]?factor|multi[-\s]?factor|"
    r"totp|login|sign[-\s]?in|verification)\s+){0,3}"
)
_QR_EXPLICIT_TARGET = (
    rf"(?:(?:the|this|that|an?|your)\s+)?{_QR_CONTEXT_MODIFIER}qr\s+codes?\b"
)
_QR_SCAN_TARGET = (
    rf"(?:(?:the|this|that|an?|your)\s+)?{_QR_CONTEXT_MODIFIER}(?:qr\s+)?codes?\b"
)
_QR_LINK_TARGET = (
    rf"(?:(?:the|this|that|an?|your)\s+)?{_QR_CONTEXT_MODIFIER}"
    r"qr\s+codes?\s+(?:links?|urls?)\b"
)
_QR_PURPOSE_SUFFIX = r"(?:\s+to\s+[\w-]+(?:\s+[\w-]+){0,8})?"
_ATTACHED_FILE_NOUN = (
    r"(?:file|files|pdf|pdfs|document|documents|doc|docs|spreadsheet|spreadsheets|"
    r"image|images|invoice|invoices|report|reports|form|forms)"
)
_BARE_ATTACHMENT_FILE_TARGET = (
    rf"(?:(?:the|this|that|an?|your)\s+)?(?:[\w-]+\s+){{0,2}}{_ATTACHED_FILE_NOUN}\b"
)
_ATTACHMENT_TARGET_END = (
    rf"(?=\s*(?:$|[.!?,:;]|\b(?:{_URGENCY_SUFFIX}|{_STANDALONE_POLITE_SUFFIX})\b\s*(?:$|[.!?,:;])))"
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
    rf"{_BARE_ATTACHMENT_FILE_TARGET}{_ATTACHMENT_TARGET_END}"
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
_SHELL_COMMAND_NOUN = (
    r"(?:commands?(?![-\s]?line\b)|shell\s+commands?|terminal\s+commands?|"
    r"powershell\s+commands?|cmd\s+commands?)"
)
_SHELL_COMMAND_REFERENCE = (
    rf"(?:(?:the|this|that|a|an|your|their|following|above|below)\s+)?"
    rf"(?:[\w-]+\s+){{0,2}}{_SHELL_COMMAND_NOUN}\b"
)
_SHELL_COMMAND_DESTINATION = (
    r"(?:(?:the|your|a|this|that)\s+)?"
    r"(?:terminal|shell|console|command\s+prompt|cmd(?:\.exe)?|"
    r"windows\s+terminal|power\s*shell|powershell|bash|zsh)\b"
)
_SHELL_COMMAND_SOURCE = (
    r"(?:(?:the|this|that|an?|your)\s+)?(?:email|message|thread)\b"
)
_SHELL_COMMAND_SOURCE_SUFFIX = (
    rf"(?:\s+(?:from|in|copied\s+from)\s+{_SHELL_COMMAND_SOURCE})?"
)
_SHELL_COMMAND_DESTINATION_SUFFIX = (
    rf"(?:\s+(?:in|into|on|at|using|with)\s+{_SHELL_COMMAND_DESTINATION})?"
)
_SHELL_COMMAND_ACTION_SUFFIX = (
    rf"{_SHELL_COMMAND_SOURCE_SUFFIX}{_SHELL_COMMAND_DESTINATION_SUFFIX}"
    rf"(?:\s+(?:and|then|to|for)\s+[\w-]+(?:\s+[\w-]+){{0,8}})?"
    rf"{_TARGET_END}"
)
_SHELL_COMMAND_COPY_SUFFIX = (
    rf"{_SHELL_COMMAND_SOURCE_SUFFIX}\s+(?:into|in|to|at|on)\s+"
    rf"{_SHELL_COMMAND_DESTINATION}{_TARGET_END}"
)
_SHELL_COMMAND_SNIPPET_COMMAND = (
    r"(?:curl|wget|bash|sh|zsh|powershell|pwsh|cmd|python3?|ruby|perl|node|"
    r"npx|npm|pnpm|yarn|pip3?|brew|apt(?:-get)?|yum|dnf|apk|choco(?:latey)?|"
    r"winget|scoop|git|ssh|scp|rsync|chmod|chown|rm|mv|cp|mkdir|tar|unzip|"
    r"docker|kubectl|openssl)"
)
_SHELL_COMMAND_SNIPPET_TOKEN = r"[\w@./:+%#&=?,-]+"
_SHELL_COMMAND_SNIPPET = (
    rf"(?:sudo\s+)?{_SHELL_COMMAND_SNIPPET_COMMAND}"
    rf"(?:(?:\s+{_SHELL_COMMAND_SNIPPET_TOKEN})|"
    rf"(?:\s*(?:&&|\|\||\||;|>)\s*{_SHELL_COMMAND_SNIPPET_TOKEN})){{0,12}}"
)
_INSTALL_SOFTWARE_NOUN = (
    r"(?:software|apps?|applications?|packages?|clients?|agents?|"
    r"tools?|command[-\s]?line\s+tools?|cli(?:\s+tools?)?|updates?|"
    r"browser\s+extensions?|extensions?)"
)
_INSTALL_SOFTWARE_TARGET = (
    rf"(?:(?:the|this|that|an?|your)\s+)?"
    rf"(?:[\w-]+\s+){{0,3}}{_INSTALL_SOFTWARE_NOUN}\b"
)
_INSTALL_SOFTWARE_SOURCE = (
    r"(?:(?:the|this|that|an?|your)\s+)?"
    r"(?:email|message|thread|attachment|link|url|website|webpage|page|site|"
    r"app\s+store|store)\b"
)
_INSTALL_SOFTWARE_SOURCE_SUFFIX = (
    rf"(?:\s+(?:from|in|on|via|through|using|with)\s+"
    rf"{_INSTALL_SOFTWARE_SOURCE})?"
)
_INSTALL_SOFTWARE_ACTION_SUFFIX = (
    rf"{_INSTALL_SOFTWARE_SOURCE_SUFFIX}{_TARGET_END}"
)
_PACKAGE_MANAGER_INSTALL_COMMAND = (
    r"(?:"
    r"(?:npm|pnpm)\s+(?:install|i)|"
    r"yarn\s+(?:add|install)|"
    r"pip3?\s+install|"
    r"python3?\s+-m\s+pip\s+install|"
    r"gem\s+install|"
    r"cargo\s+install|"
    r"go\s+install|"
    r"brew\s+install|"
    r"apt(?:-get)?\s+install|"
    r"yum\s+install|"
    r"dnf\s+install|"
    r"apk\s+add|"
    r"choco(?:latey)?\s+install|"
    r"winget\s+install|"
    r"scoop\s+install"
    r")"
)
_PACKAGE_MANAGER_COMMAND_ARGS = r"(?:\s+[\w@./:+%#&=?-]+){0,8}"
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
_SEND_AS_VALUE_NOUN = (
    r"(?:vendor|supplier|accounting|accountant|bookkeeper|billing|sender|"
    r"contact|recipient|person|team|address|email\s+address)"
)
_SEND_AS_VALUE_TARGET = (
    rf"(?:{_EMAIL_TARGET}|(?:(?:the|this|that|an?|my|your|our)\s+)?"
    rf"(?:[\w-]+\s+){{0,3}}{_SEND_AS_VALUE_NOUN}\b)"
)
_SEND_AS_OBJECT_TARGET = (
    r"(?:(?:an?|the|this|that|my|your|our)\s+)?"
    r"(?:(?:old|new)\s+)?"
    r"(?:(?:gmail|google|email|mail|sender)\s+)?"
    r"send[-\s]?as\s+(?:alias(?:es)?|address(?:es)?|settings?)\b"
)
_DEFAULT_FROM_TARGET = (
    r"(?:(?:the|this|that|my|your|our)\s+)?"
    r"default\s+(?:from\s+address|sender(?:\s+address)?)\b"
)
_REPLY_TO_TARGET = (
    r"(?:(?:the|this|that|my|your|our)\s+)?"
    r"reply[-\s]?to\s+address\b"
)
_SEND_AS_SETTING_ACTION_SUFFIX = (
    rf"(?:\s+(?:to|as|with|using)\s+{_SEND_AS_VALUE_TARGET})?"
    rf"{_TARGET_END}"
)
_SEND_AS_IDENTITY_SETTING_TARGET = (
    rf"(?:{_SEND_AS_OBJECT_TARGET}|{_DEFAULT_FROM_TARGET}|{_REPLY_TO_TARGET})"
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
_BROWSER_SYNC_APP = r"(?:chrome|edge|firefox|safari|brave|browser|web\s+browser)"
_BROWSER_SYNC_SCOPE = rf"(?:{_BROWSER_SYNC_APP}|cloud)"
_BROWSER_SYNC_SETTING_TARGET = (
    rf"(?:"
    rf"(?:{_BROWSER_SYNC_APP}|cloud)\s+sync(?:ing)?|"
    rf"{_BROWSER_SYNC_SCOPE}\s+profile\s+sync(?:ing)?|"
    rf"profile\s+sync(?:ing)?\s+(?:in|within|on|for)\s+"
    rf"(?:(?:the|your)\s+)?{_BROWSER_SYNC_APP}"
    rf")"
)
_BROWSER_SYNC_DESTINATION = (
    r"(?:(?:the|this|that|your|my|our|an?)\s+)?"
    r"(?:accounts?|cloud|browsers?|devices?|profiles?|settings)\b"
)
_BROWSER_SYNC_PROFILE_TARGET = (
    r"(?:(?:your|the|this|that|my|our)\s+)?"
    rf"{_BROWSER_SYNC_SCOPE}\s+profiles?\b"
    rf"(?:\s+(?:with|to|into|in|on|within|for)\s+"
    rf"{_BROWSER_SYNC_DESTINATION})?"
)
_BROWSER_SYNC_SIGN_IN_TARGET = (
    r"(?:(?:your|the|this|that)\s+)?"
    rf"(?:{_BROWSER_SYNC_APP}\s+sync|"
    rf"{_BROWSER_SYNC_SCOPE}\s+profiles?|"
    rf"{_BROWSER_SYNC_APP}\s+to\s+sync(?:\s+"
    r"(?:passwords?|bookmarks?|sessions?|settings?|profiles?|"
    r"browser\s+profiles?|browser\s+data|data))?)"
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
_AUTOMATION_CONNECTOR_NOUN = (
    r"(?:zapier|make(?:\.com)?|ifttt|slack|"
    r"(?:slack\s+)?bots?|"
    r"ai\s+(?:assistants?|agents?|bots?)|"
    r"automation\s+(?:connectors?|workflows?|bots?|agents?|assistants?|"
    r"integrations?|services?|platforms?|tools?)|"
    r"workflow\s+(?:automations?|connectors?|integrations?|bots?|agents?|"
    r"assistants?|services?|platforms?|tools?))"
)
_AUTOMATION_CONNECTOR_TARGET = (
    rf"(?:(?:the|this|that|an?|your)\s+)?(?:[\w-]+\s+){{0,2}}"
    rf"{_AUTOMATION_CONNECTOR_NOUN}\b"
)
_AUTHZ_OBJECT_NOUN = (
    rf"(?:apps?|applications?|integrations?|browser\s+extensions?|extensions?|"
    rf"oauth\s+(?:apps?|applications?|clients?)|"
    rf"third[-\s]?party\s+(?:apps?|applications?|services?)|"
    rf"{_AUTOMATION_CONNECTOR_NOUN})"
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
_AUTHZ_CONSENT_UI_MODIFIER = (
    r"(?:google|gmail|oauth|app|application|third[-\s]?party|account|"
    r"sign[-\s]?in|login)"
)
_AUTHZ_CONSENT_UI_TARGET = (
    r"(?:(?:the|this|that|your|an?)\s+)?"
    rf"(?:(?:{_AUTHZ_CONSENT_UI_MODIFIER})\s+){{0,4}}"
    r"(?:"
    r"(?:oauth\s+)?consent\s+(?:screen|prompt|dialog|dialogue|page|request)|"
    r"permissions?\s+(?:screen|prompt|dialog|dialogue|page|request)|"
    r"(?:access|authorization)\s+(?:prompt|dialog|dialogue|page|request)"
    r")\b"
)
_AUTHZ_CONSENT_APPROVAL_BUTTON = (
    r"(?:allow|approve|accept|authorize|grant\s+access)"
)
_AUTHZ_ACCESS_GRANT_TARGET = (
    r"(?:access|account\s+access|gmail\s+access|mailbox\s+access|"
    r"email\s+access|permissions?|permission\s+grant)\b"
)
_AUTHZ_ACCOUNT_TARGET = (
    r"(?:(?:your|the|this|that|my|our)\s+)?"
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
_PASSKEY_WEBAUTHN_TARGET = (
    r"(?:(?:the|this|that|your|my|our|an?|all|new|saved|stored)\s+)?"
    r"(?:[\w-]+\s+){0,3}"
    rf"{_PASSKEY_WEBAUTHN_CONTEXT}\b"
)
_PASSKEY_WEBAUTHN_ARTIFACT_TARGET = (
    r"(?:(?:the|this|that|your|my|our|an?)\s+)?"
    r"(?:[\w-]+\s+){0,2}"
    rf"(?:{_PASSKEY_WEBAUTHN_CONTEXT}\s+)?"
    rf"(?:{_PASSKEY_CREDENTIAL_ID_LABEL}|{_PASSKEY_CHALLENGE_ID_LABEL}|"
    rf"{_PASSKEY_REGISTRATION_URL_LABEL}|{_PASSKEY_ASSERTION_URL_LABEL})\b"
)
_PASSKEY_WEBAUTHN_LOCATION = (
    r"(?:(?:the|this|that|your|my|our|an?)\s+)?"
    r"(?:account|gmail|google\s+account|email\s+account|"
    r"browser|device|phone|computer|laptop|platform\s+authenticator|"
    r"security\s+key|password\s+manager|icloud\s+keychain|chrome|"
    r"file|csv|json|backup|archive|cloud|drive|link|url|page|"
    r"app|application|site|website|portal)\b"
)
_PASSKEY_WEBAUTHN_ACTION_SUFFIX = (
    rf"(?:\s+(?:for|from|in|on|within|to|into|onto|with|using|via|through|as)\s+"
    rf"{_PASSKEY_WEBAUTHN_LOCATION})?"
    rf"{_TARGET_END}"
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
    r"(?:(?:the|this|that|your|my|our|an?|all)\s+)?"
    r"(?:"
    r"(?:(?:2fa\s*/\s*mfa|mfa\s*/\s*2fa|2fa|mfa|"
    r"two[-\s]?factor|multi[-\s]?factor)"
    r"(?:\s+authentication)?\s+)?backup\s+codes?|"
    r"(?:account\s+)?recovery\s+codes?"
    r")\b"
)
_SECURITY_BACKUP_CODES_LOCATION = (
    r"(?:(?:the|this|that|your|my|our|an?)\s+)?"
    r"(?:account|gmail|google\s+account|email\s+account|"
    r"security\s+settings?|account\s+settings?|settings|"
    r"page|portal|app|application|browser|device|"
    r"file|document|pdf|csv|spreadsheet|text\s+file|notes?|folder|"
    r"password\s+manager|authenticator(?:\s+app)?|2fa\s+app|mfa\s+app|"
    r"link|url|website|webpage|site|cloud|drive|"
    r"safe\s+place|secure\s+place|offline\s+copy|records?|safekeeping)\b"
)
_SECURITY_BACKUP_CODES_SUFFIX = (
    rf"(?:\s+(?:from|for|in|on|within|to|into|onto|as|using|via|through)\s+"
    rf"{_SECURITY_BACKUP_CODES_LOCATION}|"
    rf"\s+(?:somewhere\s+(?:safe|secure)|securely))?"
    rf"{_TARGET_END}"
)
_SECURITY_BACKUP_CODE_DISCLOSURE_TARGET = (
    r"(?:(?:the|this|that|your|my|our|an?|all)\s+)?"
    r"(?:(?:2fa\s*/\s*mfa|mfa\s*/\s*2fa|2fa|mfa|"
    r"two[-\s]?factor|multi[-\s]?factor)"
    r"(?:\s+authentication)?\s+)?backup\s+codes?\b"
)
_SECURITY_BACKUP_CODES_DISCLOSURE_DESTINATION = (
    r"(?:(?:the|this|that|your|their|an?)\s+)?"
    r"(?:[\w-]+\s+){0,3}"
    r"(?:portal|form|site|website|webpage|page|link|url|sender|recipient|"
    r"support|team|agent|representative|person|company|service|app|"
    r"application)\b|"
    r"[\w@./:+%#&=?-]+(?:\s+[\w@./:+%#&=?-]+){0,4}"
)
_SECURITY_BACKUP_CODES_DISCLOSURE_SUFFIX = (
    rf"(?:\s+(?:to|with|into|in|on|through|via|using|at)\s+"
    rf"{_SECURITY_BACKUP_CODES_DISCLOSURE_DESTINATION})?"
    rf"(?:\s+(?:to|for)\s+[\w-]+(?:\s+[\w-]+){{0,8}})?"
    rf"{_TARGET_END}"
)
_SECURITY_BACKUP_CODES_DISCLOSURE_TARGET = (
    rf"{_SECURITY_BACKUP_CODE_DISCLOSURE_TARGET}"
    rf"{_SECURITY_BACKUP_CODES_DISCLOSURE_SUFFIX}"
)
_SECURITY_QUESTION_TARGET = (
    r"(?:(?:the|this|that|your|my|our|an?)\s+)?"
    r"(?:(?:account\s+)?security|(?:account\s+)?recovery)\s+questions?\b"
)
_SECURITY_QUESTION_MUTATION_SUFFIX = (
    rf"(?:\s+(?:to|for|in|on|within)\s+{_SECURITY_ACCOUNT_SETTING_TARGET}|"
    rf"\s+(?:using|via|through)\s+{_SECURITY_ENROLLMENT_METHOD_TARGET})?"
    rf"{_TARGET_END}"
)
_SECURITY_QUESTION_ANSWER_SUFFIX = (
    r"(?:\s+(?:with|using|as)\s+"
    r"[\w'@./:+%#&=?-]+(?:\s+[\w'@./:+%#&=?-]+){0,8})?"
    rf"{_TARGET_END}"
)
_SECURITY_PROTECTION_TARGET = (
    r"(?:(?:the|this|that|your|my|our)\s+)?"
    r"(?:spam|phishing|spam\s+and\s+phishing|phishing\s+and\s+spam)\s+"
    r"(?:protection|filtering|filters?)\b"
)
_SECURITY_SENDER_TARGET = r"(?:(?:the|this|that)\s+)?sender\b"
# Safe-sender entries are domains only; _BARE_DOMAIN_TARGET also accepts URL paths.
_SECURITY_SAFE_SENDER_DOMAIN_TARGET = (
    rf"(?:{_DOMAIN_LABEL}\.)+[A-Za-z]{{2,}}"
    r"(?=$|\s|[!?,:;]|\.(?=$|\s))"
)
_SECURITY_SAFE_SENDER_ENTRY_TARGET = (
    rf"(?:{_SECURITY_SENDER_TARGET}|{_EMAIL_TARGET}|"
    r"(?:(?:the|this|that|your|my|our)\s+)?domains?\b|"
    rf"{_SECURITY_SAFE_SENDER_DOMAIN_TARGET})"
)
_SECURITY_SAFE_SENDER_LIST_TARGET = (
    r"(?:(?:the|this|that|your|my|our)\s+)?"
    r"(?:safe[-\s]+senders?|allow[-\s]?list|white[-\s]?list)(?:\s+list)?\b"
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
_TRUSTED_DEVICE_ACTION_SUFFIX = (
    rf"(?:\s+(?:from|for|in|on|within)\s+{_SECURITY_ACCOUNT_SETTING_TARGET})?"
    rf"{_TARGET_END}"
)
_SESSION_SETTING_SESSION_MODIFIER = (
    r"(?:all|other|active|suspicious|unknown|unrecognized|current|account|"
    r"login|log[-\s]?in|sign[-\s]?in)"
)
_SESSION_SETTING_SESSION_TARGET = (
    r"(?:(?:the|this|that|your|my|our)\s+)?"
    rf"(?:{_SESSION_SETTING_SESSION_MODIFIER}\s+){{0,4}}sessions?\b"
)
_SESSION_SETTING_DEVICE_TARGET = (
    r"(?:(?:all|other|active|suspicious|unknown|unrecognized)\s+)?"
    r"(?:devices?|browsers?|computers?|phones?)\b"
)
_SESSION_SETTING_ACCOUNT_TARGET = (
    r"(?:(?:the|this|that|your|my|our)\s+)?"
    r"(?:gmail|google\s+account|email\s+account|account)\b"
)
_SESSION_SETTING_SIGN_OUT_TARGET = (
    rf"(?:{_SESSION_SETTING_SESSION_TARGET}|{_SESSION_SETTING_DEVICE_TARGET}|"
    rf"{_SESSION_SETTING_ACCOUNT_TARGET})"
)
_SESSION_SETTING_ACCOUNT_SUFFIX = (
    rf"(?:\s+(?:from|for|in|on|within)\s+{_SECURITY_ACCOUNT_SETTING_TARGET})?"
)
_SESSION_SETTING_ACTION_SUFFIX = (
    rf"{_SESSION_SETTING_ACCOUNT_SUFFIX}{_TARGET_END}"
)
_SECURITY_KEY_SETTING_TARGET = (
    rf"(?:{_SECURITY_KEY_TARGET}|{_SECURITY_PASSKEY_TARGET}|"
    r"(?:(?:the|this|that|your|my|our)\s+)?"
    r"(?:security\s+key|passkey)\s+settings?\b)"
)
_SECURITY_KEY_ACTION_SUFFIX = (
    rf"(?:{_SECURITY_ENROLLMENT_SUFFIX}|{_SECURITY_ACCOUNT_SETTING_SUFFIX})"
    rf"{_TARGET_END}"
)
_SECURITY_MFA_SETTING_TARGET = (
    r"(?:(?:the|this|that|your|my|our)\s+)?"
    rf"(?:{_SECURITY_AUTH_FACTOR_TARGET}|"
    r"(?:two|2)[-\s]?step\s+verification|"
    r"login\s+verification|sign[-\s]?in\s+verification)"
    r"(?:\s+(?:settings?|methods?|factors?|devices?))?\b"
)
_SECURITY_MFA_ACTION_SUFFIX = (
    rf"(?:\s+(?:for|from|in|on|within)\s+{_SECURITY_ACCOUNT_SETTING_TARGET})?"
    rf"{_TARGET_END}"
)
_AUTHENTICATOR_PROVISIONING_SOURCE = (
    r"(?:(?:the|this|that|an?|your)\s+)?"
    r"(?:"
    r"otpauth\s+(?:uris?|urls?)|"
    r"(?:totp|otp|mfa)\s+secrets?|"
    r"authenticator\s+(?:uris?|urls?|links?|"
    r"provisioning\s+(?:uris?|urls?|links?)|"
    r"enrollment\s+(?:uris?|urls?|links?))|"
    r"mfa\s+enrollment\s+(?:uris?|urls?|links?)|"
    r"provisioning\s+(?:uris?|urls?|links?)"
    r")\b"
)
_AUTHENTICATOR_APP_TARGET = (
    rf"(?:(?:the|this|that|your|an?)\s+)?{_LOGIN_APPROVAL_SERVICE}\b"
)
_AUTHENTICATOR_PROVISIONING_ACTION_SUFFIX = (
    rf"(?:\s+(?:to|into|in|on|with|using|via|through)\s+"
    rf"{_AUTHENTICATOR_APP_TARGET})?"
    rf"{_TARGET_END}"
)
_ACCOUNT_PROTECTION_TARGET = (
    r"(?:(?:the|this|that|your|my|our)\s+)?"
    r"(?:(?:google|gmail|account)\s+)?"
    r"(?:advanced\s+protection(?:\s+program)?|"
    r"account\s+(?:security\s+)?protection|"
    r"login\s+protection|sign[-\s]?in\s+protection)\b"
)
_ACCOUNT_PROTECTION_ACTION_SUFFIX = (
    rf"(?:\s+(?:for|from|in|on|within)\s+{_SECURITY_ACCOUNT_SETTING_TARGET})?"
    rf"{_TARGET_END}"
)
_MAIL_ACCESS_ACCOUNT_CONTEXT = (
    r"(?:(?:this|that|the|my|your|our)\s+)?"
    r"(?:account|gmail|google\s+account|email\s+account)\b"
)
_MAIL_ACCESS_CONTEXT_SUFFIX = (
    rf"(?:\s+(?:for|in|on|within)\s+{_MAIL_ACCESS_ACCOUNT_CONTEXT})?"
)
_MAIL_ACCESS_PROTOCOL = r"(?:imaps?|pop(?:3s?|-3s?|\s+3s?)?)"
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
_ACCOUNT_CONTACT_CHANNEL_QUALIFIER = (
    r"(?:primary|secondary|2fa|mfa|(?:two|multi)[-\s]?factor|"
    r"login|sign[-\s]?in|verification)"
)
_ACCOUNT_CONTACT_FIELD_TARGET = (
    r"(?:(?:the|this|that|your|my|our|an?)\s+)?"
    r"(?:"
    rf"(?:recovery|backup|alternate|notification|"
    rf"{_ACCOUNT_CONTACT_CHANNEL_QUALIFIER})\s+"
    rf"{_ACCOUNT_CONTACT_CHANNEL_NOUN}\b|"
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
_ACCOUNT_RECOVERY_EMAIL_TARGET = (
    r"(?:(?:the|this|that|your|my|our|an?)\s+)?"
    r"(?:recovery|backup|alternate)\s+email(?:\s+address)?\b"
)
_ACCOUNT_RECOVERY_PHONE_TARGET = (
    r"(?:(?:the|this|that|your|my|our|an?)\s+)?"
    r"(?:recovery|backup|alternate)\s+phone(?:\s+number)?\b"
)
_ACCOUNT_RECOVERY_EMAIL_ACTION_SUFFIX = (
    rf"(?:\s+(?:to|with)\s+{_EMAIL_TARGET})?"
    rf"(?:\s+(?:to|for|on|in|from)\s+{_ACCOUNT_CONTACT_ACCOUNT_CONTEXT})?"
    rf"{_TARGET_END}"
)
_ACCOUNT_RECOVERY_PHONE_ACTION_SUFFIX = (
    rf"(?:\s+(?:to|with)\s+{_PHONE_NUMBER_TARGET})?"
    rf"(?:\s+(?:to|for|on|in|from)\s+{_ACCOUNT_CONTACT_ACCOUNT_CONTEXT})?"
    rf"{_TARGET_END}"
)
_FORM_DOCUMENT_NOUN = r"(?:forms?|surveys?|questionnaires?|applications?)"
_FORM_OBJECT = (
    r"(?:(?:the|this|that|an?|your)\s+)?"
    rf"(?:(?:[\w-]+\s+){{0,3}})?{_FORM_DOCUMENT_NOUN}\b"
)
_FORM_DETAIL_NOUN = r"(?:details|information|info|credentials?)"
_FORM_DETAIL_SOURCE = (
    rf"(?:(?:your|the|this|that|account|personal|contact|login)\s+){{0,3}}"
    rf"{_FORM_DETAIL_NOUN}\b"
)
_FORM_DETAILS_SUFFIX = rf"(?:\s+with\s+{_FORM_DETAIL_SOURCE})?"
_FORM_SUBMISSION_LOCATION_NOUN = (
    r"(?:links?|urls?|websites?|sites?|webpages?|pages?|portals?|"
    r"forms?|surveys?|questionnaires?|applications?)"
)
_FORM_SUBMISSION_LOCATION = (
    r"(?:(?:the|this|that|an?|your)\s+)?"
    rf"(?:(?:[\w-]+\s+){{0,3}})?{_FORM_SUBMISSION_LOCATION_NOUN}\b"
)
_FORM_SUBMISSION_DESTINATION = (
    rf"(?:{_EXTERNAL_URL_TARGET}|{_FORM_SUBMISSION_LOCATION})"
)
_FORM_SUBMISSION_LOCATION_SUFFIX = (
    rf"(?:\s+(?:via|through|using|on|at|in|into)\s+"
    rf"{_FORM_SUBMISSION_DESTINATION})?"
)
_FORM_SUBMISSION_FOLLOWUP_SUFFIX = (
    rf"(?:\s+and\s+(?:submit|send)\s+(?:it|them)"
    rf"(?:\s+(?:via|through|using|on|at|in|into)\s+"
    rf"{_FORM_SUBMISSION_DESTINATION})?)?"
)
_FORM_SUBMISSION_TARGET = (
    rf"{_FORM_OBJECT}{_FORM_DETAILS_SUFFIX}{_FORM_SUBMISSION_LOCATION_SUFFIX}"
    rf"{_FORM_SUBMISSION_FOLLOWUP_SUFFIX}{_TARGET_END}"
)
_FORM_SUBMISSION_CHANNEL_TARGET = (
    rf"(?:via|through|using|on|at|in|into)\s+"
    rf"{_FORM_SUBMISSION_DESTINATION}{_TARGET_END}"
)
_FORM_SUBMISSION_VERB = (
    r"(?:submit|fill[-\s]+(?:out|in)|complete|send|sign(?:\s+and\s+submit)?)"
)
_FORM_ACTION_SUGGESTION_START = (
    rf"(?i)^\s*(?:[-*]|\d+[.)])?\s*"
    rf"{_ACTION_ROLE_PREFIX}"
    rf"(?:(?:{_RECOMMENDATION_KEYWORD})\s*:?\s*)?"
    rf"{_INSIGHT_SECTION_PREFIX}"
    r"(?:(?:please|first|then|next|just|now|also)\s+){0,4}"
)
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
_AUTH_SECRET_NOUN = (
    r"(?:passwords?|credentials?|passphrases?|"
    r"api[-_\s]?keys?|api[-_\s]?tokens?|access[-_\s]?keys?|access[-_\s]?tokens?|"
    r"auth(?:entication)?[-_\s]?tokens?|oauth(?:\s+2(?:\.0)?)?\s+tokens?|"
    r"refresh[-_\s]?tokens?|bearer[-_\s]?tokens?|"
    r"(?:personal\s+access\s+)?tokens?|pats?|"
    r"session\s+cookies?|cookies?|jwt(?:s|\s+tokens?)?|"
    r"client\s+secrets?|app\s+secrets?|api\s+secrets?|"
    r"signing\s+secrets?|webhook\s+secrets?|"
    r"recovery\s+keys?|"
    r"(?:login|authentication|auth|account|security|session)\s+secrets?)"
)
_AUTH_SECRET_TARGET = (
    r"(?:(?:your|the|this|that|my|our|their|user's|the\s+user's|all)\s+)?"
    rf"(?:[\w'-]+\s+){{0,4}}{_AUTH_SECRET_NOUN}\b"
)
_AUTH_SECRET_DESTINATION = (
    rf"(?:{_SENSITIVE_INFO_DESTINATION}|"
    r"[\w@./:+%#&=?-]+(?:\s+[\w@./:+%#&=?-]+){0,4})"
)
_AUTH_SECRET_DISCLOSURE_SUFFIX = (
    rf"(?:\s+(?:to|with|into|in|on|through|via|using|at)\s+"
    rf"{_AUTH_SECRET_DESTINATION})?"
    rf"(?:\s+(?:to|for)\s+[\w-]+(?:\s+[\w-]+){{0,8}})?"
    rf"{_TARGET_END}"
)
_AUTH_SECRET_DISCLOSURE_TARGET = (
    rf"{_AUTH_SECRET_TARGET}{_AUTH_SECRET_DISCLOSURE_SUFFIX}"
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
    "change_importance_marker",
    "unsubscribe",
    "report_phishing",
    "report_spam",
    "click_link",
    "open_link",
    "open_attachment",
    "download_attachment",
    "run_executable",
    "run_shell_command",
    "install_software",
    "enable_macros",
    "disable_security_software",
    "print_email",
    "export_data",
    "share_file",
    "upload_file",
    "load_remote_content",
    "enable_browser_notifications",
    "change_browser_sync_settings",
    "scan_qr_code",
    "start_remote_access",
    "call_phone",
    "send_sms",
    "create_contact",
    "update_contact",
    "update_account_contact",
    "change_recovery_email",
    "change_recovery_phone",
    "use_verification_code",
    "approve_login_prompt",
    "manage_backup_codes",
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
    "change_trusted_devices",
    "change_session_settings",
    "change_security_key_settings",
    "manage_passkeys",
    "change_mfa_settings",
    "disable_account_protection",
    "change_mail_access_settings",
    "change_network_settings",
    "install_profile",
    "update_email_signature",
    "change_send_as_settings",
    "submit_form",
    "create_forwarding_rule",
    "set_auto_reply",
    "change_filter_settings",
    "change_blocked_senders",
    "change_thread_mute_state",
}
_DIRECTIVE_SPAN_SPLIT_LINE_ACTIONS = {
    "change_importance_marker",
    "run_executable",
    "run_shell_command",
    "install_software",
    "enable_macros",
    "disable_security_software",
    "sign_in",
    "create_external_account",
    "change_password",
    "password_manager_action",
    "authorize_app",
    "grant_mailbox_access",
    "change_security_settings",
    "change_trusted_devices",
    "change_session_settings",
    "change_security_key_settings",
    "manage_passkeys",
    "change_mfa_settings",
    "disable_account_protection",
    "change_mail_access_settings",
    "change_network_settings",
    "install_profile",
    "update_account_contact",
    "change_recovery_email",
    "change_recovery_phone",
    "approve_login_prompt",
    "manage_backup_codes",
    "update_email_signature",
    "change_send_as_settings",
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
    "change_browser_sync_settings",
    "change_filter_settings",
    "change_blocked_senders",
    "change_thread_mute_state",
    "submit_form",
}
_DIRECTIVE_PATTERNS = {
    "provide_sensitive_info": [
        re.compile(
            rf"{_ACTION_SUGGESTION_START}"
            rf"(?:enter|input|paste|provide|reveal|share|send|submit|"
            rf"type|upload|disclose)\s+{_AUTH_SECRET_DISCLOSURE_TARGET}"
        ),
        re.compile(
            rf"{_MIDLINE_ACTION_SUGGESTION_START}"
            rf"(?:enter|input|paste|provide|reveal|share|send|submit|"
            rf"type|upload|disclose)\s+{_AUTH_SECRET_DISCLOSURE_TARGET}"
        ),
        re.compile(
            rf"{_ACTION_SUGGESTION_START}(?:reply|respond)\s+with\s+"
            rf"{_AUTH_SECRET_DISCLOSURE_TARGET}"
        ),
        re.compile(
            rf"{_MIDLINE_ACTION_SUGGESTION_START}(?:reply|respond)\s+with\s+"
            rf"{_AUTH_SECRET_DISCLOSURE_TARGET}"
        ),
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
            rf"(?:import|enter|input|type|paste|submit|provide|reveal|share|send|upload|disclose)\s+"
            rf"{_CRYPTO_WALLET_SECRET_TARGET}{_CRYPTO_SECRET_DESTINATION_SUFFIX}"
            rf"{_TARGET_END}"
        ),
        re.compile(
            rf"{_MIDLINE_ACTION_SUGGESTION_START}"
            rf"(?:import|enter|input|type|paste|submit|provide|reveal|share|send|upload|disclose)\s+"
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
    "change_importance_marker": [
        re.compile(
            rf"{_ACTION_SUGGESTION_START}(?:mark|flag)\s+"
            rf"{_IMPORTANCE_MARKER_TARGET}"
        ),
        re.compile(
            rf"{_MIDLINE_ACTION_SUGGESTION_START}(?:mark|flag)\s+"
            rf"{_IMPORTANCE_MARKER_TARGET}"
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
    "change_thread_mute_state": [
        re.compile(
            rf"{_ACTION_SUGGESTION_START}(?:mute|unmute)\s+"
            rf"{_MUTE_CONVERSATION_OBJECT}{_TARGET_END}"
        ),
        re.compile(
            rf"{_MIDLINE_ACTION_SUGGESTION_START}(?:mute|unmute)\s+"
            rf"{_MUTE_CONVERSATION_OBJECT}{_TARGET_END}"
        ),
        re.compile(
            rf"{_ACTION_SUGGESTION_START}"
            rf"(?:silence|unsilence|mute|unmute|disable|enable|"
            rf"turn\s+off|turn\s+on)\s+"
            rf"{_MUTE_NOTIFICATION_NOUN}\s+for\s+"
            rf"{_MUTE_CONVERSATION_OBJECT}{_TARGET_END}"
        ),
        re.compile(
            rf"{_MIDLINE_ACTION_SUGGESTION_START}"
            rf"(?:silence|unsilence|mute|unmute|disable|enable|"
            rf"turn\s+off|turn\s+on)\s+"
            rf"{_MUTE_NOTIFICATION_NOUN}\s+for\s+"
            rf"{_MUTE_CONVERSATION_OBJECT}{_TARGET_END}"
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
    "change_blocked_senders": [
        re.compile(
            rf"{_ACTION_SUGGESTION_START}(?:block|unblock)\s+"
            rf"{_BLOCKED_SENDER_ENTRY_TARGET}{_TARGET_END}"
        ),
        re.compile(
            rf"{_MIDLINE_ACTION_SUGGESTION_START}(?:block|unblock)\s+"
            rf"{_BLOCKED_SENDER_ENTRY_TARGET}{_TARGET_END}"
        ),
        re.compile(
            rf"{_ACTION_SUGGESTION_START}add\s+"
            rf"{_BLOCKED_SENDER_ENTRY_TARGET}\s+to\s+"
            rf"{_BLOCKED_SENDER_LIST_TARGET}{_TARGET_END}"
        ),
        re.compile(
            rf"{_MIDLINE_ACTION_SUGGESTION_START}add\s+"
            rf"{_BLOCKED_SENDER_ENTRY_TARGET}\s+to\s+"
            rf"{_BLOCKED_SENDER_LIST_TARGET}{_TARGET_END}"
        ),
        re.compile(
            rf"{_ACTION_SUGGESTION_START}(?:put|place)\s+"
            rf"{_BLOCKED_SENDER_ENTRY_TARGET}\s+(?:on|onto|in|into)\s+"
            rf"{_BLOCKED_SENDER_LIST_TARGET}{_TARGET_END}"
        ),
        re.compile(
            rf"{_MIDLINE_ACTION_SUGGESTION_START}(?:put|place)\s+"
            rf"{_BLOCKED_SENDER_ENTRY_TARGET}\s+(?:on|onto|in|into)\s+"
            rf"{_BLOCKED_SENDER_LIST_TARGET}{_TARGET_END}"
        ),
        re.compile(
            rf"{_ACTION_SUGGESTION_START}(?:remove|delete)\s+"
            rf"{_BLOCKED_SENDER_ENTRY_TARGET}\s+from\s+"
            rf"{_BLOCKED_SENDER_LIST_TARGET}{_TARGET_END}"
        ),
        re.compile(
            rf"{_MIDLINE_ACTION_SUGGESTION_START}(?:remove|delete)\s+"
            rf"{_BLOCKED_SENDER_ENTRY_TARGET}\s+from\s+"
            rf"{_BLOCKED_SENDER_LIST_TARGET}{_TARGET_END}"
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
    "change_send_as_settings": [
        re.compile(
            rf"{_ACTION_SUGGESTION_START}add\s+{_SEND_AS_VALUE_TARGET}\s+"
            rf"as\s+(?:an?\s+)?send[-\s]?as\s+(?:alias(?:es)?|address(?:es)?)"
            rf"{_TARGET_END}"
        ),
        re.compile(
            rf"{_MIDLINE_ACTION_SUGGESTION_START}add\s+{_SEND_AS_VALUE_TARGET}\s+"
            rf"as\s+(?:an?\s+)?send[-\s]?as\s+(?:alias(?:es)?|address(?:es)?)"
            rf"{_TARGET_END}"
        ),
        re.compile(
            rf"{_ACTION_SUGGESTION_START}set\s+{_SEND_AS_VALUE_TARGET}\s+"
            rf"as\s+{_DEFAULT_FROM_TARGET}{_TARGET_END}"
        ),
        re.compile(
            rf"{_MIDLINE_ACTION_SUGGESTION_START}set\s+{_SEND_AS_VALUE_TARGET}\s+"
            rf"as\s+{_DEFAULT_FROM_TARGET}{_TARGET_END}"
        ),
        re.compile(
            rf"{_ACTION_SUGGESTION_START}make\s+{_SEND_AS_VALUE_TARGET}\s+"
            rf"(?:as\s+)?{_DEFAULT_FROM_TARGET}{_TARGET_END}"
        ),
        re.compile(
            rf"{_MIDLINE_ACTION_SUGGESTION_START}make\s+{_SEND_AS_VALUE_TARGET}\s+"
            rf"(?:as\s+)?{_DEFAULT_FROM_TARGET}{_TARGET_END}"
        ),
        re.compile(
            rf"{_ACTION_SUGGESTION_START}use\s+{_SEND_AS_VALUE_TARGET}\s+"
            rf"as\s+{_REPLY_TO_TARGET}{_TARGET_END}"
        ),
        re.compile(
            rf"{_MIDLINE_ACTION_SUGGESTION_START}use\s+{_SEND_AS_VALUE_TARGET}\s+"
            rf"as\s+{_REPLY_TO_TARGET}{_TARGET_END}"
        ),
        re.compile(
            rf"{_ACTION_SUGGESTION_START}(?:set|change|update)\s+"
            rf"{_REPLY_TO_TARGET}\s+to\s+{_SEND_AS_VALUE_TARGET}"
            rf"{_TARGET_END}"
        ),
        re.compile(
            rf"{_MIDLINE_ACTION_SUGGESTION_START}(?:set|change|update)\s+"
            rf"{_REPLY_TO_TARGET}\s+to\s+{_SEND_AS_VALUE_TARGET}"
            rf"{_TARGET_END}"
        ),
        re.compile(
            rf"{_ACTION_SUGGESTION_START}(?:set|change|update|configure)\s+"
            rf"{_SEND_AS_IDENTITY_SETTING_TARGET}"
            rf"{_SEND_AS_SETTING_ACTION_SUFFIX}"
        ),
        re.compile(
            rf"{_MIDLINE_ACTION_SUGGESTION_START}(?:set|change|update|configure)\s+"
            rf"{_SEND_AS_IDENTITY_SETTING_TARGET}"
            rf"{_SEND_AS_SETTING_ACTION_SUFFIX}"
        ),
        re.compile(
            rf"{_ACTION_SUGGESTION_START}(?:remove|delete)\s+"
            rf"{_SEND_AS_OBJECT_TARGET}{_TARGET_END}"
        ),
        re.compile(
            rf"{_MIDLINE_ACTION_SUGGESTION_START}(?:remove|delete)\s+"
            rf"{_SEND_AS_OBJECT_TARGET}{_TARGET_END}"
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
            rf"{_ACTION_SUGGESTION_START}"
            rf"(?:click|follow|tap|press|select|choose)\s+(?:on\s+)?"
            rf"{_CLICK_LINK_TARGET}\b{_LINK_ACTION_END}"
        ),
    ],
    "open_link": [
        re.compile(
            rf"{_ACTION_SUGGESTION_START}(?:open|visit)\s+{_LINK_TARGET}\b"
        ),
        re.compile(
            rf"{_ACTION_SUGGESTION_START}(?:navigate|browse|go)\s+to\s+"
            rf"{_LINK_TARGET}\b{_LINK_ACTION_END}"
        ),
        re.compile(
            rf"{_ACTION_SUGGESTION_START}launch\s+{_LINK_TARGET}\b"
            rf"{_LINK_ACTION_END}"
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
    "run_shell_command": [
        re.compile(
            rf"{_ACTION_SUGGESTION_START}(?:run|execute)\s+"
            rf"{_SHELL_COMMAND_REFERENCE}{_SHELL_COMMAND_ACTION_SUFFIX}"
        ),
        re.compile(
            rf"{_ACTION_SUGGESTION_START}(?:run|execute)\s+"
            rf"(?:the\s+)?following\s+command\s*:?\s+"
            rf"{_SHELL_COMMAND_SNIPPET}{_TARGET_END}"
        ),
        re.compile(
            rf"{_ACTION_SUGGESTION_START}(?:run|execute)\s+"
            rf"{_SHELL_COMMAND_SNIPPET}{_TARGET_END}"
        ),
        re.compile(
            rf"{_ACTION_SUGGESTION_START}"
            rf"(?:paste|copy\s+and\s+paste|copy)\s+"
            rf"{_SHELL_COMMAND_REFERENCE}{_SHELL_COMMAND_COPY_SUFFIX}"
        ),
        re.compile(
            rf"{_ACTION_SUGGESTION_START}"
            rf"(?:paste|copy\s+and\s+paste|copy)\s+"
            rf"(?:this|that|it){_SHELL_COMMAND_COPY_SUFFIX}"
        ),
        re.compile(
            rf"{_ACTION_SUGGESTION_START}type\s+"
            rf"{_SHELL_COMMAND_REFERENCE}{_SHELL_COMMAND_COPY_SUFFIX}"
        ),
    ],
    "install_software": [
        re.compile(
            rf"{_ACTION_SUGGESTION_START}"
            rf"(?:install|download\s+and\s+install|download\s+then\s+install|"
            rf"download,\s*then\s+install)\s+"
            rf"{_INSTALL_SOFTWARE_TARGET}{_INSTALL_SOFTWARE_ACTION_SUFFIX}"
        ),
        re.compile(
            rf"{_ACTION_SUGGESTION_START}(?:run|execute)\s+"
            rf"{_PACKAGE_MANAGER_INSTALL_COMMAND}"
            rf"{_PACKAGE_MANAGER_COMMAND_ARGS}"
            rf"{_INSTALL_SOFTWARE_SOURCE_SUFFIX}{_TARGET_END}"
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
    "change_browser_sync_settings": [
        re.compile(
            rf"{_ACTION_SUGGESTION_START}"
            rf"(?:enable|activate|turn\s+on|switch\s+on)\s+"
            rf"{_BROWSER_SYNC_SETTING_TARGET}{_TARGET_END}"
        ),
        re.compile(
            rf"{_ACTION_SUGGESTION_START}(?:sync|synchronize)\s+"
            rf"{_BROWSER_SYNC_PROFILE_TARGET}{_TARGET_END}"
        ),
        re.compile(
            rf"{_ACTION_SUGGESTION_START}"
            rf"(?:sign\s+in|log\s+in|login|authenticate)\b\s+"
            rf"(?:to|into|on|with)\s+"
            rf"{_BROWSER_SYNC_SIGN_IN_TARGET}{_TARGET_END}"
        ),
        re.compile(
            rf"{_ACTION_SUGGESTION_START}(?:sign\s+into|log\s+into)\s+"
            rf"{_BROWSER_SYNC_SIGN_IN_TARGET}{_TARGET_END}"
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
    "change_recovery_email": [
        re.compile(
            rf"{_ACTION_SUGGESTION_START}"
            rf"(?:update|change|add|set|replace|remove|delete)\s+"
            rf"{_ACCOUNT_RECOVERY_EMAIL_TARGET}"
            rf"{_ACCOUNT_RECOVERY_EMAIL_ACTION_SUFFIX}"
        ),
        re.compile(
            rf"{_MIDLINE_ACTION_SUGGESTION_START}"
            rf"(?:update|change|add|set|replace|remove|delete)\s+"
            rf"{_ACCOUNT_RECOVERY_EMAIL_TARGET}"
            rf"{_ACCOUNT_RECOVERY_EMAIL_ACTION_SUFFIX}"
        ),
        re.compile(
            rf"{_ACTION_SUGGESTION_START}(?:set|use|add)\s+"
            rf"{_EMAIL_TARGET}\s+as\s+{_ACCOUNT_RECOVERY_EMAIL_TARGET}"
            rf"{_TARGET_END}"
        ),
        re.compile(
            rf"{_MIDLINE_ACTION_SUGGESTION_START}(?:set|use|add)\s+"
            rf"{_EMAIL_TARGET}\s+as\s+{_ACCOUNT_RECOVERY_EMAIL_TARGET}"
            rf"{_TARGET_END}"
        ),
    ],
    "change_recovery_phone": [
        re.compile(
            rf"{_ACTION_SUGGESTION_START}"
            rf"(?:update|change|add|set|replace|remove|delete)\s+"
            rf"{_ACCOUNT_RECOVERY_PHONE_TARGET}"
            rf"{_ACCOUNT_RECOVERY_PHONE_ACTION_SUFFIX}"
        ),
        re.compile(
            rf"{_MIDLINE_ACTION_SUGGESTION_START}"
            rf"(?:update|change|add|set|replace|remove|delete)\s+"
            rf"{_ACCOUNT_RECOVERY_PHONE_TARGET}"
            rf"{_ACCOUNT_RECOVERY_PHONE_ACTION_SUFFIX}"
        ),
        re.compile(
            rf"{_ACTION_SUGGESTION_START}(?:set|use|add)\s+"
            rf"{_PHONE_NUMBER_TARGET}\s+as\s+{_ACCOUNT_RECOVERY_PHONE_TARGET}"
            rf"{_TARGET_END}"
        ),
        re.compile(
            rf"{_MIDLINE_ACTION_SUGGESTION_START}(?:set|use|add)\s+"
            rf"{_PHONE_NUMBER_TARGET}\s+as\s+{_ACCOUNT_RECOVERY_PHONE_TARGET}"
            rf"{_TARGET_END}"
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
    "manage_backup_codes": [
        re.compile(
            rf"{_ACTION_SUGGESTION_START}"
            rf"(?:share|send|provide|enter|paste|upload|submit|reveal|disclose)\s+"
            rf"{_SECURITY_BACKUP_CODES_DISCLOSURE_TARGET}"
        ),
        re.compile(
            rf"{_MIDLINE_ACTION_SUGGESTION_START}"
            rf"(?:share|send|provide|enter|paste|upload|submit|reveal|disclose)\s+"
            rf"{_SECURITY_BACKUP_CODES_DISCLOSURE_TARGET}"
        ),
        re.compile(
            rf"{_ACTION_SUGGESTION_START}"
            rf"(?:generate|create|get|view|show|reveal|download|export|"
            rf"save|copy|print|regenerate|reset|replace)\s+"
            rf"{_SECURITY_BACKUP_CODES_TARGET}{_SECURITY_BACKUP_CODES_SUFFIX}"
        ),
        re.compile(
            rf"{_MIDLINE_ACTION_SUGGESTION_START}"
            rf"(?:generate|create|get|view|show|reveal|download|export|"
            rf"save|copy|print|regenerate|reset|replace)\s+"
            rf"{_SECURITY_BACKUP_CODES_TARGET}{_SECURITY_BACKUP_CODES_SUFFIX}"
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
            rf"{_ACTION_SUGGESTION_START}(?:click|press|tap|select|choose)\s+"
            rf"(?:the\s+)?{_AUTHZ_CONSENT_APPROVAL_BUTTON}(?:\s+button)?\s+"
            rf"(?:on|in|within)\s+{_AUTHZ_CONSENT_UI_TARGET}{_TARGET_END}"
        ),
        re.compile(
            rf"{_MIDLINE_ACTION_SUGGESTION_START}"
            rf"(?:click|press|tap|select|choose)\s+"
            rf"(?:the\s+)?{_AUTHZ_CONSENT_APPROVAL_BUTTON}(?:\s+button)?\s+"
            rf"(?:on|in|within)\s+{_AUTHZ_CONSENT_UI_TARGET}{_TARGET_END}"
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
        re.compile(
            rf"{_ACTION_SUGGESTION_START}(?:set\s+up|create|configure|enable)\s+"
            rf"{_AUTOMATION_CONNECTOR_TARGET}\s+"
            rf"(?:with|for|to|on|in|using)\s+"
            rf"{_MAILBOX_ACCESS_RESOURCE}{_TARGET_END}"
        ),
    ],
    "manage_passkeys": [
        re.compile(
            rf"{_ACTION_SUGGESTION_START}"
            rf"(?:add|register|enroll|create|set\s+up|enable|save|store)\s+"
            rf"{_PASSKEY_WEBAUTHN_TARGET}{_PASSKEY_WEBAUTHN_ACTION_SUFFIX}"
        ),
        re.compile(
            rf"{_MIDLINE_ACTION_SUGGESTION_START}"
            rf"(?:add|register|enroll|create|set\s+up|enable|save|store)\s+"
            rf"{_PASSKEY_WEBAUTHN_TARGET}{_PASSKEY_WEBAUTHN_ACTION_SUFFIX}"
        ),
        re.compile(
            rf"{_ACTION_SUGGESTION_START}"
            rf"(?:remove|delete|revoke|disable|deactivate|turn\s+off|"
            rf"reset|replace|recover)\s+"
            rf"{_PASSKEY_WEBAUTHN_TARGET}{_PASSKEY_WEBAUTHN_ACTION_SUFFIX}"
        ),
        re.compile(
            rf"{_MIDLINE_ACTION_SUGGESTION_START}"
            rf"(?:remove|delete|revoke|disable|deactivate|turn\s+off|"
            rf"reset|replace|recover)\s+"
            rf"{_PASSKEY_WEBAUTHN_TARGET}{_PASSKEY_WEBAUTHN_ACTION_SUFFIX}"
        ),
        re.compile(
            rf"{_ACTION_SUGGESTION_START}"
            rf"(?:sync|synchronize|export|download|copy|back\s+up|backup|"
            rf"import|migrate|transfer)\s+"
            rf"{_PASSKEY_WEBAUTHN_TARGET}{_PASSKEY_WEBAUTHN_ACTION_SUFFIX}"
        ),
        re.compile(
            rf"{_MIDLINE_ACTION_SUGGESTION_START}"
            rf"(?:sync|synchronize|export|download|copy|back\s+up|backup|"
            rf"import|migrate|transfer)\s+"
            rf"{_PASSKEY_WEBAUTHN_TARGET}{_PASSKEY_WEBAUTHN_ACTION_SUFFIX}"
        ),
        re.compile(
            rf"{_ACTION_SUGGESTION_START}"
            rf"(?:change|update|configure|manage)\s+"
            rf"{_PASSKEY_WEBAUTHN_TARGET}{_PASSKEY_WEBAUTHN_ACTION_SUFFIX}"
        ),
        re.compile(
            rf"{_MIDLINE_ACTION_SUGGESTION_START}"
            rf"(?:change|update|configure|manage)\s+"
            rf"{_PASSKEY_WEBAUTHN_TARGET}{_PASSKEY_WEBAUTHN_ACTION_SUFFIX}"
        ),
        re.compile(
            rf"{_ACTION_SUGGESTION_START}enroll\s+{_TRUSTED_DEVICE_TARGET}\s+"
            rf"for\s+{_PASSKEY_WEBAUTHN_TARGET}{_TARGET_END}"
        ),
        re.compile(
            rf"{_MIDLINE_ACTION_SUGGESTION_START}enroll\s+"
            rf"{_TRUSTED_DEVICE_TARGET}\s+for\s+"
            rf"{_PASSKEY_WEBAUTHN_TARGET}{_TARGET_END}"
        ),
        re.compile(
            rf"{_ACTION_SUGGESTION_START}"
            rf"(?:share|send|provide|enter|paste|upload|submit|reveal|"
            rf"disclose|expose|copy)\s+"
            rf"{_PASSKEY_WEBAUTHN_ARTIFACT_TARGET}{_PASSKEY_WEBAUTHN_ACTION_SUFFIX}"
        ),
        re.compile(
            rf"{_MIDLINE_ACTION_SUGGESTION_START}"
            rf"(?:share|send|provide|enter|paste|upload|submit|reveal|"
            rf"disclose|expose|copy)\s+"
            rf"{_PASSKEY_WEBAUTHN_ARTIFACT_TARGET}{_PASSKEY_WEBAUTHN_ACTION_SUFFIX}"
        ),
    ],
    "change_trusted_devices": [
        re.compile(
            rf"{_ACTION_SUGGESTION_START}(?:trust|remember)\s+"
            rf"{_TRUSTED_DEVICE_TARGET}{_TARGET_END}"
        ),
        re.compile(
            rf"{_MIDLINE_ACTION_SUGGESTION_START}(?:trust|remember)\s+"
            rf"{_TRUSTED_DEVICE_TARGET}{_TARGET_END}"
        ),
        re.compile(
            rf"{_ACTION_SUGGESTION_START}add\s+{_TRUSTED_DEVICE_TARGET}\s+"
            rf"as\s+{_TRUSTED_DEVICE_SETTING_TARGET}{_TARGET_END}"
        ),
        re.compile(
            rf"{_MIDLINE_ACTION_SUGGESTION_START}add\s+"
            rf"{_TRUSTED_DEVICE_TARGET}\s+as\s+"
            rf"{_TRUSTED_DEVICE_SETTING_TARGET}{_TARGET_END}"
        ),
        re.compile(
            rf"{_ACTION_SUGGESTION_START}mark\s+{_TRUSTED_DEVICE_TARGET}\s+"
            rf"as\s+trusted{_TARGET_END}"
        ),
        re.compile(
            rf"{_MIDLINE_ACTION_SUGGESTION_START}mark\s+"
            rf"{_TRUSTED_DEVICE_TARGET}\s+as\s+trusted{_TARGET_END}"
        ),
        re.compile(
            rf"{_ACTION_SUGGESTION_START}(?:add|register|enroll|set\s+up|create)\s+"
            rf"{_TRUSTED_DEVICE_SETTING_TARGET}{_TRUSTED_DEVICE_ACTION_SUFFIX}"
        ),
        re.compile(
            rf"{_MIDLINE_ACTION_SUGGESTION_START}"
            rf"(?:add|register|enroll|set\s+up|create)\s+"
            rf"{_TRUSTED_DEVICE_SETTING_TARGET}{_TRUSTED_DEVICE_ACTION_SUFFIX}"
        ),
        re.compile(
            rf"{_ACTION_SUGGESTION_START}"
            rf"(?:remove|delete|revoke|untrust|forget)\s+"
            rf"{_TRUSTED_DEVICE_SETTING_TARGET}{_TRUSTED_DEVICE_ACTION_SUFFIX}"
        ),
        re.compile(
            rf"{_MIDLINE_ACTION_SUGGESTION_START}"
            rf"(?:remove|delete|revoke|untrust|forget)\s+"
            rf"{_TRUSTED_DEVICE_SETTING_TARGET}{_TRUSTED_DEVICE_ACTION_SUFFIX}"
        ),
        re.compile(
            rf"{_ACTION_SUGGESTION_START}"
            rf"(?:remove|delete|revoke|untrust|forget)\s+"
            rf"{_TRUSTED_DEVICE_TARGET}\s+from\s+"
            rf"{_TRUSTED_DEVICE_SETTING_TARGET}{_TARGET_END}"
        ),
        re.compile(
            rf"{_MIDLINE_ACTION_SUGGESTION_START}"
            rf"(?:remove|delete|revoke|untrust|forget)\s+"
            rf"{_TRUSTED_DEVICE_TARGET}\s+from\s+"
            rf"{_TRUSTED_DEVICE_SETTING_TARGET}{_TARGET_END}"
        ),
        re.compile(
            rf"{_ACTION_SUGGESTION_START}(?:change|update|configure|manage)\s+"
            rf"{_TRUSTED_DEVICE_SETTING_TARGET}{_TRUSTED_DEVICE_ACTION_SUFFIX}"
        ),
        re.compile(
            rf"{_MIDLINE_ACTION_SUGGESTION_START}"
            rf"(?:change|update|configure|manage)\s+"
            rf"{_TRUSTED_DEVICE_SETTING_TARGET}{_TRUSTED_DEVICE_ACTION_SUFFIX}"
        ),
    ],
    "change_session_settings": [
        re.compile(
            rf"{_ACTION_SUGGESTION_START}(?:sign|log)\s+out\s+"
            rf"(?:(?:of|from)\s+)?{_SESSION_SETTING_SIGN_OUT_TARGET}"
            rf"{_SESSION_SETTING_ACTION_SUFFIX}"
        ),
        re.compile(
            rf"{_MIDLINE_ACTION_SUGGESTION_START}(?:sign|log)\s+out\s+"
            rf"(?:(?:of|from)\s+)?{_SESSION_SETTING_SIGN_OUT_TARGET}"
            rf"{_SESSION_SETTING_ACTION_SUFFIX}"
        ),
        re.compile(
            rf"{_ACTION_SUGGESTION_START}(?:revoke|terminate|end)\s+"
            rf"{_SESSION_SETTING_SESSION_TARGET}{_SESSION_SETTING_ACTION_SUFFIX}"
        ),
        re.compile(
            rf"{_MIDLINE_ACTION_SUGGESTION_START}(?:revoke|terminate|end)\s+"
            rf"{_SESSION_SETTING_SESSION_TARGET}{_SESSION_SETTING_ACTION_SUFFIX}"
        ),
    ],
    "change_security_key_settings": [
        re.compile(
            rf"{_ACTION_SUGGESTION_START}"
            rf"(?:add|register|enroll|create|set\s+up|enable)\s+"
            rf"{_SECURITY_KEY_SETTING_TARGET}{_SECURITY_KEY_ACTION_SUFFIX}"
        ),
        re.compile(
            rf"{_MIDLINE_ACTION_SUGGESTION_START}"
            rf"(?:add|register|enroll|create|set\s+up|enable)\s+"
            rf"{_SECURITY_KEY_SETTING_TARGET}{_SECURITY_KEY_ACTION_SUFFIX}"
        ),
        re.compile(
            rf"{_ACTION_SUGGESTION_START}enroll\s+{_TRUSTED_DEVICE_TARGET}\s+"
            rf"for\s+{_SECURITY_PASSKEY_TARGET}{_TARGET_END}"
        ),
        re.compile(
            rf"{_MIDLINE_ACTION_SUGGESTION_START}enroll\s+"
            rf"{_TRUSTED_DEVICE_TARGET}\s+for\s+"
            rf"{_SECURITY_PASSKEY_TARGET}{_TARGET_END}"
        ),
        re.compile(
            rf"{_ACTION_SUGGESTION_START}"
            rf"(?:remove|delete|revoke|disable|deactivate|turn\s+off)\s+"
            rf"{_SECURITY_KEY_SETTING_TARGET}{_SECURITY_KEY_ACTION_SUFFIX}"
        ),
        re.compile(
            rf"{_MIDLINE_ACTION_SUGGESTION_START}"
            rf"(?:remove|delete|revoke|disable|deactivate|turn\s+off)\s+"
            rf"{_SECURITY_KEY_SETTING_TARGET}{_SECURITY_KEY_ACTION_SUFFIX}"
        ),
        re.compile(
            rf"{_ACTION_SUGGESTION_START}"
            rf"(?:change|update|configure|manage|replace|reset)\s+"
            rf"{_SECURITY_KEY_SETTING_TARGET}{_SECURITY_KEY_ACTION_SUFFIX}"
        ),
        re.compile(
            rf"{_MIDLINE_ACTION_SUGGESTION_START}"
            rf"(?:change|update|configure|manage|replace|reset)\s+"
            rf"{_SECURITY_KEY_SETTING_TARGET}{_SECURITY_KEY_ACTION_SUFFIX}"
        ),
    ],
    "change_mfa_settings": [
        re.compile(
            rf"{_ACTION_SUGGESTION_START}"
            rf"(?:add|import|enter|input|paste|use)\s+"
            rf"{_AUTHENTICATOR_PROVISIONING_SOURCE}"
            rf"{_AUTHENTICATOR_PROVISIONING_ACTION_SUFFIX}"
        ),
        re.compile(
            rf"{_MIDLINE_ACTION_SUGGESTION_START}"
            rf"(?:add|import|enter|input|paste|use)\s+"
            rf"{_AUTHENTICATOR_PROVISIONING_SOURCE}"
            rf"{_AUTHENTICATOR_PROVISIONING_ACTION_SUFFIX}"
        ),
        re.compile(
            rf"{_ACTION_SUGGESTION_START}"
            rf"(?:enable|disable|deactivate|turn\s+on|turn\s+off|"
            rf"switch\s+on|switch\s+off|add|remove|delete|change|update|"
            rf"configure|set(?:\s+up)?|reset|replace|enroll)\s+"
            rf"{_SECURITY_MFA_SETTING_TARGET}{_SECURITY_MFA_ACTION_SUFFIX}"
        ),
        re.compile(
            rf"{_MIDLINE_ACTION_SUGGESTION_START}"
            rf"(?:enable|disable|deactivate|turn\s+on|turn\s+off|"
            rf"switch\s+on|switch\s+off|add|remove|delete|change|update|"
            rf"configure|set(?:\s+up)?|reset|replace|enroll)\s+"
            rf"{_SECURITY_MFA_SETTING_TARGET}{_SECURITY_MFA_ACTION_SUFFIX}"
        ),
    ],
    "disable_account_protection": [
        re.compile(
            rf"{_ACTION_SUGGESTION_START}"
            rf"(?:disable|deactivate|turn\s+off|switch\s+off|remove|"
            rf"lower|reduce|weaken)\s+"
            rf"{_ACCOUNT_PROTECTION_TARGET}{_ACCOUNT_PROTECTION_ACTION_SUFFIX}"
        ),
        re.compile(
            rf"{_MIDLINE_ACTION_SUGGESTION_START}"
            rf"(?:disable|deactivate|turn\s+off|switch\s+off|remove|"
            rf"lower|reduce|weaken)\s+"
            rf"{_ACCOUNT_PROTECTION_TARGET}{_ACCOUNT_PROTECTION_ACTION_SUFFIX}"
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
            rf"{_ACTION_SUGGESTION_START}"
            rf"(?:add|change|configure|create|edit|replace|reset|"
            rf"set(?:\s+up)?|update)\s+"
            rf"{_SECURITY_QUESTION_TARGET}{_SECURITY_QUESTION_MUTATION_SUFFIX}"
        ),
        re.compile(
            rf"{_ACTION_SUGGESTION_START}answer\s+"
            rf"{_SECURITY_QUESTION_TARGET}{_SECURITY_QUESTION_ANSWER_SUFFIX}"
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
            rf"{_FORM_ACTION_SUGGESTION_START}{_FORM_SUBMISSION_VERB}\s+"
            rf"{_FORM_SUBMISSION_TARGET}"
        ),
        re.compile(
            rf"{_MIDLINE_ACTION_SUGGESTION_START}{_FORM_SUBMISSION_VERB}\s+"
            rf"{_FORM_SUBMISSION_TARGET}"
        ),
        re.compile(
            rf"{_FORM_ACTION_SUGGESTION_START}submit\s+"
            rf"{_FORM_SUBMISSION_CHANNEL_TARGET}"
        ),
        re.compile(
            rf"{_MIDLINE_ACTION_SUGGESTION_START}submit\s+"
            rf"{_FORM_SUBMISSION_CHANNEL_TARGET}"
        ),
        re.compile(
            rf"{_FORM_ACTION_SUGGESTION_START}(?:enter|provide)\s+"
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


def _replace_match_group(match: re.Match, group_name: str, replacement: str) -> str:
    return (
        match.string[match.start() : match.start(group_name)]
        + replacement
        + match.string[match.end(group_name) : match.end()]
    )


def _redact_otp_code(match: re.Match) -> str:
    return _replace_match_group(match, "code", "[REDACTED_OTP]")


def _redact_mfa_backup_code(match: re.Match) -> str:
    return _replace_match_group(
        match,
        "code",
        _MFA_BACKUP_CODE_PLACEHOLDER,
    )


def _redact_mfa_backup_code_list(match: re.Match) -> str:
    return _replace_match_group(
        match,
        "codes",
        _MFA_BACKUP_CODE_VALUE_RE.sub(
            _MFA_BACKUP_CODE_PLACEHOLDER,
            match.group("codes"),
        ),
    )


def _redact_oauth_authorization_code(match: re.Match) -> str:
    return _replace_match_group(
        match,
        "authorization_code",
        _OAUTH_AUTHORIZATION_CODE_PLACEHOLDER,
    )


def _split_url_trailing_punctuation(url: str) -> Tuple[str, str]:
    trailing_punctuation = ""
    while url and url[-1] in _SENSITIVE_URL_TRAILING_PUNCTUATION:
        if url[-1] == "]" and _REDACTION_PLACEHOLDER_SUFFIX_RE.search(url):
            break
        trailing_punctuation = url[-1] + trailing_punctuation
        url = url[:-1]

    return url, trailing_punctuation


def _redact_sensitive_link(match: re.Match) -> str:
    url, trailing_punctuation = _split_url_trailing_punctuation(match.group("url"))
    redacted_url, changed = _redact_url_query_and_fragment(url)
    replacement = (
        redacted_url
        if changed and not _url_has_token_like_path_segment(url)
        else "[REDACTED_SENSITIVE_LINK]"
    )

    return (
        match.string[match.start() : match.start("url")]
        + replacement
        + trailing_punctuation
        + match.string[match.end("url") : match.end()]
    )


def _url_authority_end(url: str, authority_start: int) -> int:
    delimiter_indexes = [
        index
        for delimiter in "/?#"
        if (index := url.find(delimiter, authority_start)) >= 0
    ]
    return min(delimiter_indexes, default=len(url))


def _redact_url_userinfo_credential_value(url: str) -> Tuple[str, bool]:
    scheme_end = url.find("://")
    if scheme_end < 0:
        return url, False

    scheme = url[:scheme_end].lower()
    if scheme not in _URL_USERINFO_CREDENTIAL_SCHEMES:
        return url, False

    try:
        parsed = urlsplit(url)
    except ValueError:
        return url, False

    if parsed.scheme.lower() != scheme or not parsed.netloc:
        return url, False

    authority_start = scheme_end + 3
    authority_end = _url_authority_end(url, authority_start)
    authority = url[authority_start:authority_end]
    userinfo, at_separator, hostinfo = authority.rpartition("@")
    if not at_separator or not hostinfo:
        return url, False

    username, credential_separator, credential = userinfo.partition(":")
    if (
        not credential_separator
        or not credential
        or credential == _URL_USERINFO_CREDENTIAL_PLACEHOLDER
    ):
        return url, False

    redacted_authority = (
        f"{username}{credential_separator}"
        f"{_URL_USERINFO_CREDENTIAL_PLACEHOLDER}@{hostinfo}"
    )
    return (
        url[:authority_start] + redacted_authority + url[authority_end:],
        True,
    )


def _redact_url_userinfo_credentials_in_url(match: re.Match) -> str:
    url, trailing_punctuation = _split_url_trailing_punctuation(match.group("url"))
    redacted_url, changed = _redact_url_userinfo_credential_value(url)
    if not changed:
        return match.group(0)

    redacted_url = redacted_url + trailing_punctuation
    return (
        match.string[match.start() : match.start("url")]
        + redacted_url
        + match.string[match.end("url") : match.end()]
    )


def _redact_url_userinfo_credentials(text: str) -> str:
    return _URL_USERINFO_CREDENTIAL_URL_RE.sub(
        _redact_url_userinfo_credentials_in_url,
        text,
    )


def _is_sensitive_cookie_name(name: str) -> bool:
    return bool(_query_param_name_aliases(name).intersection(_COOKIE_SECRET_NAMES))


def _split_cookie_secret_trailing_punctuation(value: str) -> Tuple[str, str]:
    trailing_punctuation = ""
    while value and value[-1] in _COOKIE_SECRET_TRAILING_PUNCTUATION:
        trailing_punctuation = value[-1] + trailing_punctuation
        value = value[:-1]

    return value, trailing_punctuation


def _is_benign_cookie_prose_value(match: re.Match) -> bool:
    if not match.groupdict().get("prose_verb"):
        return False

    value = match.group("cookie_secret").lower().strip(".,)]}\"'")
    return value.startswith(_COOKIE_BENIGN_PROSE_VALUE_PREFIXES)


def _redact_cookie_secret(match: re.Match) -> str:
    if not _is_sensitive_cookie_name(match.group("name")):
        return match.group(0)
    if _is_benign_cookie_prose_value(match):
        return match.group(0)

    secret, trailing_punctuation = _split_cookie_secret_trailing_punctuation(
        match.group("cookie_secret"),
    )
    if not secret:
        return match.group(0)

    return _replace_match_group(
        match,
        "cookie_secret",
        _COOKIE_SECRET_PLACEHOLDER + trailing_punctuation,
    )


def _redact_cookie_pairs(text: str) -> str:
    return _COOKIE_PAIR_RE.sub(_redact_cookie_secret, text)


def _redact_cookie_header(match: re.Match) -> str:
    return _replace_match_group(
        match,
        "cookies",
        _redact_cookie_pairs(match.group("cookies")),
    )


def _redact_cookie_artifacts(text: str) -> str:
    redacted = _SET_COOKIE_HEADER_RE.sub(_redact_cookie_header, text)
    redacted = _COOKIE_HEADER_RE.sub(_redact_cookie_header, redacted)
    redacted = _COOKIE_PROSE_ASSIGNMENT_RE.sub(_redact_cookie_secret, redacted)
    return _COOKIE_PROSE_VALUE_RE.sub(_redact_cookie_secret, redacted)


def _query_param_names(query: str) -> Set[str]:
    names = set()

    for part in _QUERY_PARAM_SEPARATOR_RE.split(query):
        if part in {"&", ";"}:
            continue

        name, separator, _ = part.partition("=")
        if separator:
            names.add(_normalized_query_param_name(name))

    return names


def _fragment_query_param_names(fragment: str) -> Set[str]:
    if "?" not in fragment:
        return _query_param_names(fragment)

    _, _, query = fragment.partition("?")
    return _query_param_names(query)


def _fragment_route_context(fragment: str) -> str:
    route, separator, _ = fragment.partition("?")
    return route if separator else ""


def _fragment_path_context(fragment: str) -> str:
    return _fragment_route_context(fragment) or (
        fragment if fragment.startswith("/") else ""
    )


def _path_has_token_like_segment(path: str) -> bool:
    for raw_segment in path.split("/"):
        segment = unquote(raw_segment)
        if _SENSITIVE_LINK_TOKEN_LIKE_PATH_SEGMENT_RE.fullmatch(segment):
            return True

    return False


def _url_has_token_like_path_segment(url: str) -> bool:
    candidate = url
    if candidate.lower().startswith("www."):
        candidate = f"https://{candidate}"

    try:
        parsed = urlsplit(candidate)
    except ValueError:
        return False

    if parsed.scheme.lower() not in {"http", "https"} or not parsed.netloc:
        return False

    return _path_has_token_like_segment(
        parsed.path,
    ) or _path_has_token_like_segment(_fragment_path_context(parsed.fragment))


def _url_structural_context(
    parsed_url,
    query_param_names: Set[str],
    fragment_param_names: Set[str],
) -> str:
    return unquote_plus(
        " ".join(
            [
                parsed_url.netloc,
                parsed_url.path,
                _fragment_route_context(parsed_url.fragment),
                *query_param_names,
                *fragment_param_names,
            ]
        )
    )


def _has_oauth_authorization_code_url_context(url: str) -> bool:
    candidate = url
    if candidate.lower().startswith("www."):
        candidate = f"https://{candidate}"

    try:
        parsed = urlsplit(candidate)
    except ValueError:
        return False

    query_param_names = _query_param_names(parsed.query)
    fragment_param_names = _fragment_query_param_names(parsed.fragment)
    structural_context = _url_structural_context(
        parsed,
        query_param_names,
        fragment_param_names,
    )

    if _OAUTH_AUTHORIZATION_CODE_URL_CONTEXT_RE.search(structural_context):
        return True

    if (
        {"code", "state"}.issubset(query_param_names)
        or {"code", "state"}.issubset(fragment_param_names)
    ):
        return True

    context_param_names = query_param_names | fragment_param_names
    return bool(
        context_param_names.intersection(
            _OAUTH_AUTHORIZATION_CODE_QUERY_CONTEXT_PARAM_NAMES
        )
    )


def _has_credential_link_code_url_context(url: str) -> bool:
    candidate = url
    if candidate.lower().startswith("www."):
        candidate = f"https://{candidate}"

    try:
        parsed = urlsplit(candidate)
    except ValueError:
        return False

    query_param_names = _query_param_names(parsed.query)
    fragment_param_names = _fragment_query_param_names(parsed.fragment)
    structural_context = _url_structural_context(
        parsed,
        query_param_names,
        fragment_param_names,
    )

    return bool(_CREDENTIAL_LINK_CODE_URL_CONTEXT_RE.search(structural_context))


def _has_sensitive_email_link_url_context(url: str) -> bool:
    candidate = url
    if candidate.lower().startswith("www."):
        candidate = f"https://{candidate}"

    try:
        parsed = urlsplit(candidate)
    except ValueError:
        return False

    query_param_names = _query_param_names(parsed.query)
    fragment_param_names = _fragment_query_param_names(parsed.fragment)
    structural_context = _url_structural_context(
        parsed,
        query_param_names,
        fragment_param_names,
    )

    return bool(_SENSITIVE_EMAIL_LINK_URL_CONTEXT_RE.search(structural_context))


def _has_signed_cloud_storage_url_context(url: str) -> bool:
    candidate = url
    if candidate.lower().startswith("www."):
        candidate = f"https://{candidate}"

    try:
        parsed = urlsplit(candidate)
    except ValueError:
        return False

    if parsed.scheme.lower() not in {"http", "https"} or not parsed.netloc:
        return False

    hostname = (parsed.hostname or "").lower()
    if not _AZURE_STORAGE_HOST_RE.search(hostname):
        return False

    query_param_names = _query_param_names(parsed.query)
    fragment_param_names = _fragment_query_param_names(parsed.fragment)
    param_names = query_param_names | fragment_param_names
    return bool(
        param_names.intersection(_AZURE_SAS_SIGNATURE_QUERY_PARAM_NAMES)
        and param_names.intersection(_AZURE_SAS_CONTEXT_PARAM_NAMES)
    )


def _passkey_webauthn_url_components(url: str):
    candidate = url
    if candidate.lower().startswith("www."):
        candidate = f"https://{candidate}"

    try:
        parsed = urlsplit(candidate)
    except ValueError:
        return None

    query_param_names = _query_param_names(parsed.query)
    fragment_param_names = _fragment_query_param_names(parsed.fragment)
    structural_context = _url_structural_context(
        parsed,
        query_param_names,
        fragment_param_names,
    )

    return structural_context, query_param_names | fragment_param_names


def _has_passkey_webauthn_url_context(url: str) -> bool:
    components = _passkey_webauthn_url_components(url)
    if components is None:
        return False

    structural_context, _ = components
    return bool(_PASSKEY_WEBAUTHN_URL_CONTEXT_RE.search(structural_context))


def _passkey_webauthn_url_purpose(url: str):
    components = _passkey_webauthn_url_components(url)
    if components is None:
        return None

    structural_context, context_param_names = components
    if not _PASSKEY_WEBAUTHN_URL_CONTEXT_RE.search(structural_context):
        return None

    passkey_param_names = (
        _PASSKEY_CREDENTIAL_QUERY_PARAM_NAMES | _PASSKEY_CHALLENGE_QUERY_PARAM_NAMES
    )
    if not context_param_names.intersection(passkey_param_names):
        return None

    if _PASSKEY_REGISTRATION_URL_PURPOSE_RE.search(structural_context):
        return "registration"
    if _PASSKEY_ASSERTION_URL_PURPOSE_RE.search(structural_context):
        return "assertion"

    return None


def _is_oauth_authorization_code_query_param(
    name: str,
    oauth_authorization_code_context: bool,
) -> bool:
    normalized_name = _normalized_query_param_name(name)
    if normalized_name not in _OAUTH_AUTHORIZATION_CODE_PARAM_NAMES:
        return False

    return normalized_name != "code" or oauth_authorization_code_context


def _is_credential_link_code_query_param(
    name: str,
    credential_link_code_context: bool,
) -> bool:
    return (
        _normalized_query_param_name(name) == "code"
        and credential_link_code_context
    )


def _is_contextual_credential_query_param(
    name: str,
    contextual_credential_context: bool,
) -> bool:
    return (
        contextual_credential_context
        and _normalized_query_param_name(name)
        in _CONTEXTUAL_CREDENTIAL_QUERY_PARAM_NAMES
    )


def _passkey_webauthn_query_param_placeholder(name: str):
    normalized_name = _normalized_query_param_name(name)
    if normalized_name in _PASSKEY_CREDENTIAL_QUERY_PARAM_NAMES:
        return _PASSKEY_CREDENTIAL_ID_PLACEHOLDER
    if normalized_name in _PASSKEY_CHALLENGE_QUERY_PARAM_NAMES:
        return _PASSKEY_CHALLENGE_ID_PLACEHOLDER

    return None


def _saml_query_param_placeholder(name: str):
    normalized_name = _normalized_query_param_name(name)
    if normalized_name in _SAML_RESPONSE_QUERY_PARAM_NAMES:
        return _SAML_RESPONSE_PLACEHOLDER
    if normalized_name in _SAML_REQUEST_QUERY_PARAM_NAMES:
        return _SAML_REQUEST_PLACEHOLDER

    return None


def _signed_cloud_storage_query_param_placeholder(
    name: str,
    signed_cloud_storage_context: bool,
):
    normalized_name = _normalized_query_param_name(name)
    if normalized_name in _GCS_SIGNED_URL_SIGNATURE_QUERY_PARAM_NAMES:
        return _SIGNED_CLOUD_STORAGE_SIGNATURE_PLACEHOLDER
    if normalized_name in _GCS_SIGNED_URL_CREDENTIAL_QUERY_PARAM_NAMES:
        return _SIGNED_CLOUD_STORAGE_CREDENTIAL_PLACEHOLDER
    if (
        signed_cloud_storage_context
        and normalized_name in _AZURE_SAS_SIGNATURE_QUERY_PARAM_NAMES
    ):
        return _SIGNED_CLOUD_STORAGE_SIGNATURE_PLACEHOLDER

    return None


def _is_redacted_or_raw_jwt(value: str) -> bool:
    decoded_value = unquote_plus(value)
    return decoded_value == "[REDACTED_JWT]" or bool(
        _JWT_VALUE_RE.fullmatch(decoded_value)
    )


def _credential_query_param_placeholder(name: str, value: str):
    normalized_name = _normalized_query_param_name(name)
    if saml_placeholder := _saml_query_param_placeholder(name):
        return saml_placeholder
    if normalized_name in _OAUTH_CLIENT_SECRET_QUERY_PARAM_NAMES:
        return _OAUTH_CLIENT_SECRET_PLACEHOLDER
    if normalized_name in _OIDC_ID_TOKEN_QUERY_PARAM_NAMES and _is_redacted_or_raw_jwt(
        value,
    ):
        return "[REDACTED_JWT]"
    if normalized_name in _CREDENTIAL_QUERY_PARAM_NAMES:
        return _CREDENTIAL_QUERY_VALUE_PLACEHOLDER

    return None


def _redact_credential_query_string(
    query: str,
    oauth_authorization_code_context: bool = False,
    credential_link_code_context: bool = False,
    passkey_webauthn_context: bool = False,
    sensitive_email_link_context: bool = False,
    signed_cloud_storage_context: bool = False,
) -> Tuple[str, bool]:
    changed = False
    redacted_parts = []
    contextual_credential_context = (
        oauth_authorization_code_context
        or credential_link_code_context
        or sensitive_email_link_context
    )

    for part in _QUERY_PARAM_SEPARATOR_RE.split(query):
        if part in {"&", ";"}:
            redacted_parts.append(part)
            continue

        name, separator, value = part.partition("=")
        passkey_placeholder = (
            _passkey_webauthn_query_param_placeholder(name)
            if passkey_webauthn_context
            else None
        )
        signed_cloud_storage_placeholder = (
            _signed_cloud_storage_query_param_placeholder(
                name,
                signed_cloud_storage_context,
            )
        )
        credential_placeholder = (
            _credential_query_param_placeholder(name, value)
            if separator and value
            else None
        )
        if (
            separator
            and value
            and _is_oauth_authorization_code_query_param(
                name,
                oauth_authorization_code_context,
            )
        ):
            redacted_parts.append(
                f"{name}{separator}{_OAUTH_AUTHORIZATION_CODE_PLACEHOLDER}"
            )
            changed = True
        elif (
            separator
            and value
            and _is_credential_link_code_query_param(
                name,
                credential_link_code_context,
            )
        ):
            redacted_parts.append(
                f"{name}{separator}{_CREDENTIAL_QUERY_VALUE_PLACEHOLDER}"
            )
            changed = True
        elif separator and value and passkey_placeholder:
            redacted_parts.append(f"{name}{separator}{passkey_placeholder}")
            changed = True
        elif separator and value and signed_cloud_storage_placeholder:
            redacted_parts.append(
                f"{name}{separator}{signed_cloud_storage_placeholder}"
            )
            changed = True
        elif separator and value and credential_placeholder:
            redacted_parts.append(f"{name}{separator}{credential_placeholder}")
            changed = True
        # Unconditional credential params are handled above. This contextual
        # set only applies in OAuth, credential-link, or sensitive email-link
        # contexts because names like code, state, and signature are common.
        elif (
            separator
            and value
            and _is_contextual_credential_query_param(
                name,
                contextual_credential_context,
            )
        ):
            redacted_parts.append(
                f"{name}{separator}{_CREDENTIAL_QUERY_VALUE_PLACEHOLDER}"
            )
            changed = True
        elif separator and value:
            redacted_value, value_changed = _redact_url_encoded_otpauth_payload(value)
            redacted_parts.append(f"{name}{separator}{redacted_value}")
            changed = changed or value_changed
        else:
            redacted_parts.append(part)

    return "".join(redacted_parts), changed


def _redact_credential_fragment(
    fragment: str,
    oauth_authorization_code_context: bool = False,
    credential_link_code_context: bool = False,
    passkey_webauthn_context: bool = False,
    sensitive_email_link_context: bool = False,
    signed_cloud_storage_context: bool = False,
) -> Tuple[str, bool]:
    if "?" not in fragment:
        return _redact_credential_query_string(
            fragment,
            oauth_authorization_code_context,
            credential_link_code_context,
            passkey_webauthn_context,
            sensitive_email_link_context,
            signed_cloud_storage_context,
        )

    route, _, query = fragment.partition("?")
    redacted_query, changed = _redact_credential_query_string(
        query,
        oauth_authorization_code_context,
        credential_link_code_context,
        passkey_webauthn_context,
        sensitive_email_link_context,
        signed_cloud_storage_context,
    )
    return f"{route}?{redacted_query}", changed


def _redact_url_query_and_fragment(url: str) -> Tuple[str, bool]:
    oauth_authorization_code_context = _has_oauth_authorization_code_url_context(url)
    credential_link_code_context = _has_credential_link_code_url_context(url)
    passkey_webauthn_context = _has_passkey_webauthn_url_context(url)
    sensitive_email_link_context = _has_sensitive_email_link_url_context(url)
    signed_cloud_storage_context = _has_signed_cloud_storage_url_context(url)
    query_start = url.find("?")
    if query_start >= 0:
        fragment_start = url.find("#", query_start + 1)
        if fragment_start < 0:
            query = url[query_start + 1 :]
            redacted_query, changed = _redact_credential_query_string(
                query,
                oauth_authorization_code_context,
                credential_link_code_context,
                passkey_webauthn_context,
                sensitive_email_link_context,
                signed_cloud_storage_context,
            )
            redacted_url = url[: query_start + 1] + redacted_query
        else:
            query = url[query_start + 1 : fragment_start]
            fragment = url[fragment_start + 1 :]
            redacted_query, query_changed = _redact_credential_query_string(
                query,
                oauth_authorization_code_context,
                credential_link_code_context,
                passkey_webauthn_context,
                sensitive_email_link_context,
                signed_cloud_storage_context,
            )
            redacted_fragment, fragment_changed = _redact_credential_fragment(
                fragment,
                oauth_authorization_code_context,
                credential_link_code_context,
                passkey_webauthn_context,
                sensitive_email_link_context,
                signed_cloud_storage_context,
            )
            changed = query_changed or fragment_changed
            redacted_url = (
                url[: query_start + 1]
                + redacted_query
                + "#"
                + redacted_fragment
            )
    else:
        fragment_start = url.find("#")
        if fragment_start < 0:
            return url, False

        fragment = url[fragment_start + 1 :]
        redacted_fragment, changed = _redact_credential_fragment(
            fragment,
            oauth_authorization_code_context,
            credential_link_code_context,
            passkey_webauthn_context,
            sensitive_email_link_context,
            signed_cloud_storage_context,
        )
        redacted_url = url[: fragment_start + 1] + redacted_fragment

    return redacted_url, changed


def _redact_credential_query_params_in_url(match: re.Match) -> str:
    url, trailing_punctuation = _split_url_trailing_punctuation(match.group("url"))

    candidate = url
    if candidate.lower().startswith("www."):
        candidate = f"https://{candidate}"

    try:
        parsed = urlsplit(candidate)
    except ValueError:
        return match.group(0)

    if parsed.scheme.lower() not in {"http", "https"} or not parsed.netloc:
        return match.group(0)

    redacted_url, changed = _redact_url_query_and_fragment(url)

    if not changed:
        return match.group(0)

    if (
        _has_sensitive_email_link_url_context(url)
        and _url_has_token_like_path_segment(url)
    ):
        redacted_url = "[REDACTED_SENSITIVE_LINK]"

    redacted_url = redacted_url + trailing_punctuation
    return (
        match.string[match.start() : match.start("url")]
        + redacted_url
        + match.string[match.end("url") : match.end()]
    )


def _redact_otpauth_uri_query_params_in_url(match: re.Match) -> str:
    url, trailing_punctuation = _split_url_trailing_punctuation(match.group("url"))

    try:
        parsed = urlsplit(url)
    except ValueError:
        return match.group(0)

    if parsed.scheme.lower() != "otpauth":
        return match.group(0)

    redacted_url, changed = _redact_url_query_and_fragment(url)
    if not changed:
        return match.group(0)

    redacted_url = redacted_url + trailing_punctuation
    return (
        match.string[match.start() : match.start("url")]
        + redacted_url
        + match.string[match.end("url") : match.end()]
    )


def _redact_authenticator_provisioning_uris(text: str) -> str:
    return _OTPAUTH_URL_RE.sub(_redact_otpauth_uri_query_params_in_url, text)


def _redact_url_encoded_otpauth_payload(value: str) -> Tuple[str, bool]:
    decoded_value = unquote_plus(value)
    if "otpauth://" not in decoded_value.lower():
        return value, False

    redacted_value = _redact_authenticator_provisioning_uris(decoded_value)
    if redacted_value == decoded_value:
        return value, False

    return quote_plus(redacted_value), True


def _redact_credential_query_params(text: str) -> str:
    return _CREDENTIAL_QUERY_URL_RE.sub(_redact_credential_query_params_in_url, text)


def _redact_short_lived_login_credentials(text: str) -> str:
    redacted = _SENSITIVE_LINK_AFTER_CONTEXT_RE.sub(_redact_sensitive_link, text)
    redacted = _SENSITIVE_LINK_BEFORE_CONTEXT_RE.sub(_redact_sensitive_link, redacted)
    redacted = _OTP_CODE_AFTER_ACTION_RE.sub(_redact_otp_code, redacted)
    redacted = _OTP_CODE_AFTER_CONTEXT_RE.sub(_redact_otp_code, redacted)
    return _OTP_CODE_BEFORE_CONTEXT_RE.sub(_redact_otp_code, redacted)


def _redact_mfa_backup_codes(text: str) -> str:
    redacted = _MFA_BACKUP_CODE_AFTER_CONTEXT_RE.sub(
        _redact_mfa_backup_code_list,
        text,
    )
    return _MFA_BACKUP_CODE_BEFORE_CONTEXT_RE.sub(
        _redact_mfa_backup_code,
        redacted,
    )


def _redact_authenticator_secret(match: re.Match) -> str:
    return _replace_match_group(
        match,
        "authenticator_secret",
        _AUTHENTICATOR_SECRET_PLACEHOLDER,
    )


def _redact_authenticator_enrollment_secrets(text: str) -> str:
    redacted = _AUTHENTICATOR_SECRET_AFTER_CONTEXT_RE.sub(
        _redact_authenticator_secret,
        text,
    )
    return _AUTHENTICATOR_SECRET_BEFORE_CONTEXT_RE.sub(
        _redact_authenticator_secret,
        redacted,
    )


def _redact_oauth_authorization_codes(text: str) -> str:
    redacted = _OAUTH_AUTHORIZATION_CODE_AFTER_CONTEXT_RE.sub(
        _redact_oauth_authorization_code,
        text,
    )
    return _OAUTH_DEVICE_USER_CODE_AFTER_CONTEXT_RE.sub(
        _redact_oauth_authorization_code,
        redacted,
    )


def _redact_refresh_token(match: re.Match) -> str:
    return _replace_match_group(
        match,
        "refresh_token",
        _REFRESH_TOKEN_PLACEHOLDER,
    )


def _redact_refresh_tokens(text: str) -> str:
    return _REFRESH_TOKEN_AFTER_CONTEXT_RE.sub(_redact_refresh_token, text)


def _redact_oauth_oidc_authorization_artifacts(text: str) -> str:
    redacted = _redact_oauth_authorization_codes(text)
    return _redact_refresh_tokens(redacted)


def _redact_saml_form_field(match: re.Match) -> str:
    placeholder = _saml_query_param_placeholder(match.group("field"))
    if placeholder is None:
        return match.group(0)

    return _replace_match_group(match, "saml_value", placeholder)


def _redact_saml_xml_block(match: re.Match) -> str:
    tag = match.group("saml_xml_tag")
    local_name = tag.rsplit(":", 1)[-1].lower()

    if ":" in tag or local_name in {"assertion", "authnrequest"}:
        return _SAML_XML_PLACEHOLDER

    if _SAML_XML_MARKER_RE.search(match.group(0)):
        return _SAML_XML_PLACEHOLDER

    return match.group(0)


def _redact_saml_sso_artifacts(text: str) -> str:
    redacted = _SAML_XML_BLOCK_RE.sub(_redact_saml_xml_block, text)
    return _SAML_FORM_FIELD_RE.sub(_redact_saml_form_field, redacted)


def _split_password_trailing_punctuation(password: str) -> Tuple[str, str]:
    trailing_punctuation = ""
    while password and password[-1] in _PASSWORD_SECRET_TRAILING_PUNCTUATION:
        trailing_punctuation = password[-1] + trailing_punctuation
        password = password[:-1]

    return password, trailing_punctuation


def _looks_like_password_secret(password: str) -> bool:
    if not 6 <= len(password) <= 128:
        return False
    if password.startswith("[REDACTED_"):
        return False
    if not any(char.isalpha() for char in password):
        return False

    return any(not char.isalnum() for char in password) or any(
        char.isdigit() for char in password
    )


def _redact_password_secret(match: re.Match) -> str:
    password, trailing_punctuation = _split_password_trailing_punctuation(
        match.group("password"),
    )
    if not _looks_like_password_secret(password):
        return match.group(0)

    return (
        match.string[match.start() : match.start("password")]
        + _PASSWORD_SECRET_PLACEHOLDER
        + trailing_punctuation
        + match.string[match.end("password") : match.end()]
    )


def _redact_password_secrets(text: str) -> str:
    redacted = _PASSWORD_SECRET_AFTER_CONTEXT_RE.sub(_redact_password_secret, text)
    return _PASSWORD_SECRET_BEFORE_CONTEXT_RE.sub(
        _redact_password_secret,
        redacted,
    )


def _redact_oauth_client_secret(match: re.Match) -> str:
    return _replace_match_group(
        match,
        "oauth_client_secret",
        _OAUTH_CLIENT_SECRET_PLACEHOLDER,
    )


def _redact_oidc_id_token(match: re.Match) -> str:
    return _replace_match_group(match, "id_token", "[REDACTED_JWT]")


def _redact_oauth_oidc_assignments(text: str) -> str:
    redacted = _OAUTH_CLIENT_SECRET_ASSIGNMENT_RE.sub(
        _redact_oauth_client_secret,
        text,
    )
    return _OIDC_ID_TOKEN_ASSIGNMENT_RE.sub(_redact_oidc_id_token, redacted)


def _redact_aws_secret_access_key(match: re.Match) -> str:
    return _replace_match_group(
        match,
        "aws_secret_access_key",
        _AWS_SECRET_ACCESS_KEY_PLACEHOLDER,
    )


def _redact_aws_secret_access_keys(text: str) -> str:
    return _AWS_SECRET_ACCESS_KEY_AFTER_CONTEXT_RE.sub(
        _redact_aws_secret_access_key,
        text,
    )


def _redact_session_token(match: re.Match) -> str:
    return _replace_match_group(
        match,
        "session_token",
        _SESSION_TOKEN_PLACEHOLDER,
    )


def _redact_session_tokens(text: str) -> str:
    return _SESSION_TOKEN_AFTER_CONTEXT_RE.sub(_redact_session_token, text)


def _redact_webhook_signing_secret(match: re.Match) -> str:
    return _replace_match_group(
        match,
        "webhook_signing_secret",
        _WEBHOOK_SIGNING_SECRET_PLACEHOLDER,
    )


def _redact_webhook_signing_secrets(text: str) -> str:
    return _WEBHOOK_SIGNING_SECRET_AFTER_CONTEXT_RE.sub(
        _redact_webhook_signing_secret,
        text,
    )


def _webhook_url_path_segments(path: str) -> List[str]:
    return [unquote(segment) for segment in path.split("/") if segment]


def _is_webhook_secret_path_segment(segment: str, min_length: int = 8) -> bool:
    if len(segment) < min_length:
        return False
    if not _WEBHOOK_URL_SAFE_PATH_SEGMENT_RE.fullmatch(segment):
        return False
    return any(char.isalnum() for char in segment)


def _is_slack_webhook_url(hostname: str, path_segments: List[str]) -> bool:
    return (
        hostname == "hooks.slack.com"
        and len(path_segments) >= 4
        and path_segments[0].lower() == "services"
        and _is_webhook_secret_path_segment(path_segments[1])
        and _is_webhook_secret_path_segment(path_segments[2])
        and _is_webhook_secret_path_segment(path_segments[3], min_length=12)
    )


def _is_discord_webhook_url(hostname: str, path_segments: List[str]) -> bool:
    return (
        hostname in {"discord.com", "discordapp.com"}
        and len(path_segments) >= 4
        and [segment.lower() for segment in path_segments[:2]] == ["api", "webhooks"]
        and path_segments[2].isdigit()
        and len(path_segments[2]) >= 8
        and _is_webhook_secret_path_segment(path_segments[3], min_length=16)
    )


def _is_office_webhook_url(hostname: str, path_segments: List[str]) -> bool:
    if hostname != "webhook.office.com" and not hostname.endswith(
        ".webhook.office.com"
    ):
        return False
    if len(path_segments) < 4:
        return False

    lowered_segments = [segment.lower() for segment in path_segments]
    if lowered_segments[0] not in {"webhook", "webhookb2"}:
        return False
    if "incomingwebhook" not in lowered_segments:
        return False

    incoming_index = lowered_segments.index("incomingwebhook")
    secret_segments = path_segments[incoming_index + 1 :]
    return any(
        _is_webhook_secret_path_segment(segment, min_length=16)
        for segment in secret_segments
    )


def _is_provider_webhook_url(url: str) -> bool:
    candidate = url
    if candidate.lower().startswith("www."):
        candidate = f"https://{candidate}"

    try:
        parsed = urlsplit(candidate)
    except ValueError:
        return False

    if parsed.scheme.lower() not in {"http", "https"} or not parsed.netloc:
        return False

    hostname = (parsed.hostname or "").lower()
    path_segments = _webhook_url_path_segments(parsed.path)
    return (
        _is_slack_webhook_url(hostname, path_segments)
        or _is_discord_webhook_url(hostname, path_segments)
        or _is_office_webhook_url(hostname, path_segments)
    )


def _redact_provider_webhook_url(match: re.Match) -> str:
    url, trailing_punctuation = _split_url_trailing_punctuation(match.group("url"))
    if not _is_provider_webhook_url(url):
        return match.group(0)

    return (
        match.string[match.start() : match.start("url")]
        + _WEBHOOK_URL_PLACEHOLDER
        + trailing_punctuation
        + match.string[match.end("url") : match.end()]
    )


def _redact_provider_webhook_urls(text: str) -> str:
    return _CREDENTIAL_QUERY_URL_RE.sub(_redact_provider_webhook_url, text)


def _redact_passkey_credential_id(match: re.Match) -> str:
    return _replace_match_group(
        match,
        "credential_id",
        _PASSKEY_CREDENTIAL_ID_PLACEHOLDER,
    )


def _redact_passkey_challenge_id(match: re.Match) -> str:
    return _replace_match_group(
        match,
        "challenge_id",
        _PASSKEY_CHALLENGE_ID_PLACEHOLDER,
    )


def _redact_passkey_url_match(match: re.Match, placeholder: str) -> str:
    _, trailing_punctuation = _split_url_trailing_punctuation(match.group("url"))

    return (
        match.string[match.start() : match.start("url")]
        + placeholder
        + trailing_punctuation
        + match.string[match.end("url") : match.end()]
    )


def _redact_passkey_registration_url(match: re.Match) -> str:
    return _redact_passkey_url_match(
        match,
        _PASSKEY_REGISTRATION_URL_PLACEHOLDER,
    )


def _redact_passkey_assertion_url(match: re.Match) -> str:
    return _redact_passkey_url_match(
        match,
        _PASSKEY_ASSERTION_URL_PLACEHOLDER,
    )


def _redact_structural_passkey_webauthn_url(match: re.Match) -> str:
    url, trailing_punctuation = _split_url_trailing_punctuation(match.group("url"))

    purpose = _passkey_webauthn_url_purpose(url)
    if purpose == "registration":
        placeholder = _PASSKEY_REGISTRATION_URL_PLACEHOLDER
    elif purpose == "assertion":
        placeholder = _PASSKEY_ASSERTION_URL_PLACEHOLDER
    else:
        return match.group(0)

    return (
        match.string[match.start() : match.start("url")]
        + placeholder
        + trailing_punctuation
        + match.string[match.end("url") : match.end()]
    )


def _redact_passkey_webauthn_artifacts(text: str) -> str:
    redacted = _PASSKEY_REGISTRATION_URL_AFTER_CONTEXT_RE.sub(
        _redact_passkey_registration_url,
        text,
    )
    redacted = _PASSKEY_REGISTRATION_URL_BEFORE_CONTEXT_RE.sub(
        _redact_passkey_registration_url,
        redacted,
    )
    redacted = _PASSKEY_ASSERTION_URL_AFTER_CONTEXT_RE.sub(
        _redact_passkey_assertion_url,
        redacted,
    )
    redacted = _PASSKEY_ASSERTION_URL_BEFORE_CONTEXT_RE.sub(
        _redact_passkey_assertion_url,
        redacted,
    )
    redacted = _CREDENTIAL_QUERY_URL_RE.sub(
        _redact_structural_passkey_webauthn_url,
        redacted,
    )
    redacted = _PASSKEY_CREDENTIAL_ID_AFTER_CONTEXT_RE.sub(
        _redact_passkey_credential_id,
        redacted,
    )
    redacted = _PASSKEY_CREDENTIAL_ID_BEFORE_CONTEXT_RE.sub(
        _redact_passkey_credential_id,
        redacted,
    )
    redacted = _PASSKEY_CHALLENGE_ID_AFTER_CONTEXT_RE.sub(
        _redact_passkey_challenge_id,
        redacted,
    )
    return _PASSKEY_CHALLENGE_ID_BEFORE_CONTEXT_RE.sub(
        _redact_passkey_challenge_id,
        redacted,
    )


def _redact_app_password(match: re.Match) -> str:
    return _replace_match_group(match, "app_password", _APP_PASSWORD_PLACEHOLDER)


def _redact_app_passwords(text: str) -> str:
    redacted = _APP_PASSWORD_AFTER_CONTEXT_RE.sub(_redact_app_password, text)
    return _APP_PASSWORD_BEFORE_CONTEXT_RE.sub(_redact_app_password, redacted)


def _redact_wallet_seed_phrase(match: re.Match) -> str:
    return _replace_match_group(
        match,
        "seed_phrase",
        _WALLET_SEED_PHRASE_PLACEHOLDER,
    )


def _redact_wallet_seed_phrases(text: str) -> str:
    redacted = _WALLET_SEED_AFTER_CONTEXT_RE.sub(_redact_wallet_seed_phrase, text)
    return _WALLET_SEED_BEFORE_CONTEXT_RE.sub(_redact_wallet_seed_phrase, redacted)


def _redact_bank_routing_number(match: re.Match) -> str:
    return _replace_match_group(
        match,
        "routing_number",
        _BANK_ROUTING_PLACEHOLDER,
    )


def _redact_bank_account_number(match: re.Match) -> str:
    return _replace_match_group(
        match,
        "account_number",
        _BANK_ACCOUNT_PLACEHOLDER,
    )


def _redact_bank_credentials(text: str) -> str:
    redacted = _BANK_ROUTING_AFTER_CONTEXT_RE.sub(_redact_bank_routing_number, text)
    redacted = _BANK_ROUTING_BEFORE_CONTEXT_RE.sub(
        _redact_bank_routing_number,
        redacted,
    )
    redacted = _BANK_ACCOUNT_AFTER_CONTEXT_RE.sub(
        _redact_bank_account_number,
        redacted,
    )
    return _BANK_ACCOUNT_BEFORE_CONTEXT_RE.sub(
        _redact_bank_account_number,
        redacted,
    )


def _redact_passport_number(match: re.Match) -> str:
    return _replace_match_group(
        match,
        "passport_number",
        _PASSPORT_NUMBER_PLACEHOLDER,
    )


def _redact_driver_license_number(match: re.Match) -> str:
    return _replace_match_group(
        match,
        "driver_license_number",
        _DRIVER_LICENSE_NUMBER_PLACEHOLDER,
    )


def _redact_government_id_number(match: re.Match) -> str:
    return _replace_match_group(
        match,
        "government_id_number",
        _GOVERNMENT_ID_NUMBER_PLACEHOLDER,
    )


def _redact_date_of_birth(match: re.Match) -> str:
    return _replace_match_group(
        match,
        "date_of_birth",
        _DATE_OF_BIRTH_PLACEHOLDER,
    )


def _redact_identity_document_numbers(text: str) -> str:
    redacted = _PASSPORT_NUMBER_AFTER_CONTEXT_RE.sub(
        _redact_passport_number,
        text,
    )
    redacted = _PASSPORT_NUMBER_BEFORE_CONTEXT_RE.sub(
        _redact_passport_number,
        redacted,
    )
    redacted = _DRIVER_LICENSE_NUMBER_AFTER_CONTEXT_RE.sub(
        _redact_driver_license_number,
        redacted,
    )
    redacted = _DRIVER_LICENSE_NUMBER_BEFORE_CONTEXT_RE.sub(
        _redact_driver_license_number,
        redacted,
    )
    redacted = _GOVERNMENT_ID_NUMBER_AFTER_CONTEXT_RE.sub(
        _redact_government_id_number,
        redacted,
    )
    return _GOVERNMENT_ID_NUMBER_BEFORE_CONTEXT_RE.sub(
        _redact_government_id_number,
        redacted,
    )


def _redact_date_of_birth_values(text: str) -> str:
    redacted = _DATE_OF_BIRTH_AFTER_CONTEXT_RE.sub(_redact_date_of_birth, text)
    return _DATE_OF_BIRTH_BEFORE_CONTEXT_RE.sub(_redact_date_of_birth, redacted)


def _redact_private_key_assignment(match: re.Match) -> str:
    return (
        f"{match.group('prefix')}{match.group('quote')}"
        f"{_PRIVATE_KEY_PLACEHOLDER}{match.group('quote')}"
    )


def _redact_private_keys(text: str) -> str:
    redacted = _PRIVATE_KEY_INLINE_ASSIGNMENT_RE.sub(
        _redact_private_key_assignment, text
    )
    return _PRIVATE_KEY_BLOCK_RE.sub(_PRIVATE_KEY_PLACEHOLDER, redacted)


def _passes_luhn_checksum(digits: str) -> bool:
    if not digits.isdigit() or not 13 <= len(digits) <= 19:
        return False

    total = 0
    for index, char in enumerate(reversed(digits)):
        digit = int(char)
        if index % 2 == 1:
            digit *= 2
            if digit > 9:
                digit -= 9
        total += digit

    return total % 10 == 0


def _redact_payment_card(match: re.Match) -> str:
    candidate = match.group("payment_card")
    digits = candidate.replace(" ", "").replace("-", "")
    if _passes_luhn_checksum(digits):
        return "[REDACTED_PAYMENT_CARD]"
    return candidate


def _is_redacted_url_userinfo_email_username(match: re.Match) -> bool:
    suffix = f":{_URL_USERINFO_CREDENTIAL_PLACEHOLDER}@"
    if not match.string.startswith(suffix, match.end()):
        return False

    scheme_end = match.string.rfind("://", 0, match.start())
    if scheme_end < 0:
        return False

    scheme_start = scheme_end
    while (
        scheme_start > 0
        and (
            match.string[scheme_start - 1].isalnum()
            or match.string[scheme_start - 1] in "+-."
        )
    ):
        scheme_start -= 1

    scheme = match.string[scheme_start:scheme_end].lower()
    if scheme not in _URL_USERINFO_CREDENTIAL_SCHEMES:
        return False

    authority_prefix = match.string[scheme_end + 3 : match.start()]
    return not any(char in authority_prefix for char in "/?#@ \t\r\n<>\"'")


def _redact_email_address(match: re.Match) -> str:
    if _is_redacted_url_userinfo_email_username(match):
        return match.group(0)

    return "[REDACTED_EMAIL]"


def _redact_email_addresses(text: str) -> str:
    return _EMAIL_RE.sub(_redact_email_address, text)


def redact_credential_content(text: str) -> str:
    """Redact credential-like secrets while preserving ordinary contact metadata."""
    if not text:
        return ""

    redacted = _redact_private_keys(text)
    redacted = _redact_saml_sso_artifacts(redacted)
    redacted = _redact_oauth_oidc_assignments(redacted)
    redacted = _redact_oauth_oidc_authorization_artifacts(redacted)
    redacted = _redact_cookie_artifacts(redacted)
    redacted = _GOOGLE_OAUTH_TOKEN_RE.sub("[REDACTED_GOOGLE_TOKEN]", redacted)
    redacted = _GOOGLE_REFRESH_TOKEN_RE.sub("[REDACTED_GOOGLE_REFRESH_TOKEN]", redacted)
    redacted = _JWT_RE.sub("[REDACTED_JWT]", redacted)
    redacted = _AWS_ACCESS_KEY_ID_RE.sub("[REDACTED_AWS_KEY]", redacted)
    redacted = _redact_aws_secret_access_keys(redacted)
    redacted = _redact_session_tokens(redacted)
    redacted = _redact_webhook_signing_secrets(redacted)
    redacted = _redact_provider_webhook_urls(redacted)
    # Provider-shaped keys run before generic api_key redaction to keep specific placeholders.
    redacted = _OPENAI_API_KEY_RE.sub(_OPENAI_API_KEY_PLACEHOLDER, redacted)
    redacted = _ANTHROPIC_API_KEY_RE.sub(_ANTHROPIC_API_KEY_PLACEHOLDER, redacted)
    redacted = _GOOGLE_API_KEY_RE.sub(_GOOGLE_API_KEY_PLACEHOLDER, redacted)
    redacted = _SENDGRID_API_KEY_RE.sub(_SENDGRID_API_KEY_PLACEHOLDER, redacted)
    redacted = _SLACK_TOKEN_RE.sub("[REDACTED_SLACK_TOKEN]", redacted)
    redacted = _GITHUB_TOKEN_RE.sub("[REDACTED_GITHUB_TOKEN]", redacted)
    redacted = _STRIPE_SECRET_KEY_RE.sub("[REDACTED_STRIPE_KEY]", redacted)
    redacted = _BASIC_AUTH_RE.sub(
        r"\g<prefix>[REDACTED_BASIC_AUTH]\g<suffix>",
        redacted,
    )
    redacted = _BEARER_TOKEN_RE.sub(r"\1[REDACTED_TOKEN]", redacted)
    redacted = _redact_password_secrets(redacted)
    redacted = _redact_short_lived_login_credentials(redacted)
    redacted = _redact_mfa_backup_codes(redacted)
    redacted = _redact_authenticator_enrollment_secrets(redacted)
    redacted = _redact_authenticator_provisioning_uris(redacted)
    redacted = _redact_passkey_webauthn_artifacts(redacted)
    redacted = _redact_credential_query_params(redacted)
    redacted = _redact_url_userinfo_credentials(redacted)
    redacted = _API_TOKEN_RE.sub(r"\1\2[REDACTED_TOKEN]\2", redacted)
    redacted = _redact_app_passwords(redacted)
    redacted = _redact_wallet_seed_phrases(redacted)
    return redacted


def redact_response_metadata_content(text: str) -> str:
    """Redact high-risk API metadata while preserving ordinary contact metadata."""
    if not text:
        return ""

    redacted = redact_credential_content(text)
    redacted = _redact_bank_credentials(redacted)
    redacted = _PAYMENT_CARD_RE.sub(_redact_payment_card, redacted)
    redacted = _US_SSN_RE.sub("[REDACTED_SSN]", redacted)
    redacted = _redact_date_of_birth_values(redacted)
    return _redact_identity_document_numbers(redacted)


def redact_sensitive_content(text: str) -> str:
    """Redact all supported sensitive content, not only credentials."""
    if not text:
        return ""

    redacted = redact_response_metadata_content(text)
    redacted = _redact_email_addresses(redacted)
    redacted = _PHONE_RE.sub("[REDACTED_PHONE]", redacted)
    return redacted


def sanitize_untrusted_email_text(text: str) -> str:
    """Neutralize prompt-injection framing while preserving semantic text."""
    if not text:
        return ""

    sanitized = text.replace("\r\n", "\n").replace("\r", "\n")
    sanitized = _redact_saml_sso_artifacts(sanitized)
    sanitized = _redact_oauth_oidc_authorization_artifacts(sanitized)
    sanitized = _redact_cookie_artifacts(sanitized)
    sanitized = _redact_provider_webhook_urls(sanitized)
    sanitized = _redact_authenticator_enrollment_secrets(sanitized)
    sanitized = _PROMPT_BOUNDARY_MARKER_RE.sub(
        "[quoted-prompt-boundary]",
        sanitized,
    )
    sanitized = _MODEL_CONTROL_TOKEN_RE.sub(
        "[quoted-model-control-token]",
        sanitized,
    )
    sanitized = _MARKDOWN_ROLE_HEADING_RE.sub(r"\1[quoted-role \2]\3", sanitized)
    sanitized = _ROLE_TAG_RE.sub(r"\1[quoted-role \2] ", sanitized)
    sanitized = _INLINE_ROLE_TAG_RE.sub(
        lambda match: f"[quoted-role {match.group(1)}] ",
        sanitized,
    )
    sanitized = _INSTRUCTION_PHRASE_RE.sub(r"[quoted-instruction: \1]", sanitized)
    sanitized = _SAFETY_METADATA_DIRECTIVE_RE.sub(
        lambda match: f"[quoted-safety-directive: {match.group(1)}]",
        sanitized,
    )
    sanitized = _INSTRUCTION_XML_TAG_RE.sub("[quoted-xml-tag]", sanitized)
    return sanitized


def neutralize_safety_metadata_misrepresentation(
    text: str,
    has_security_warnings: bool = False,
) -> Tuple[str, List[str]]:
    """Remove output lines that hide or contradict security-warning metadata."""
    if not text:
        return "", []

    findings = set()
    guarded_lines = []

    for line in text.splitlines():
        block_line = False

        if _SAFETY_METADATA_DIRECTIVE_LINE_RE.search(line):
            findings.add("security_warning_suppression")
            block_line = True

        if has_security_warnings and not block_line:
            if _SECURITY_WARNING_ABSENCE_CLAIM_RE.search(line):
                findings.add("security_warning_misrepresentation")
                block_line = True
            elif _RISKY_CONTENT_SAFE_CLAIM_RE.search(line):
                findings.add("security_warning_misrepresentation")
                block_line = True

        if block_line:
            guarded_lines.append("[Security warning manipulation removed]")
        else:
            guarded_lines.append(line)

    return "\n".join(guarded_lines), sorted(findings)


def _directive_actions(line: str) -> List[str]:
    actions = [
        action
        for action, patterns in _DIRECTIVE_PATTERNS.items()
        if any(pattern.search(line) for pattern in patterns)
    ]
    actions = _suppress_overlapping_crypto_wallet_payment_actions(line, actions)
    actions = _suppress_overlapping_gift_card_payment_actions(line, actions)
    actions = _suppress_overlapping_password_manager_secret_actions(line, actions)
    actions = _suppress_overlapping_account_security_actions(line, actions)
    actions = _suppress_overlapping_form_send_actions(line, actions)
    return _suppress_overlapping_install_software_actions(line, actions)


def _directive_match_spans(line: str, action: str) -> List[Tuple[int, int]]:
    return [
        match.span()
        for pattern in _DIRECTIVE_PATTERNS[action]
        for match in [pattern.search(line)]
        if match
    ]


def _spans_overlap(first: Tuple[int, int], second: Tuple[int, int]) -> bool:
    return first[0] < second[1] and second[0] < first[1]


def _all_spans_overlap_any(
    spans: List[Tuple[int, int]], candidates: List[Tuple[int, int]]
) -> bool:
    return bool(spans) and all(
        any(_spans_overlap(span, candidate) for candidate in candidates)
        for span in spans
    )


def _suppress_overlapping_account_security_actions(
    line: str, actions: List[str]
) -> List[str]:
    suppressed = set()

    recovery_actions = {"change_recovery_email", "change_recovery_phone"}
    recovery_specific_spans = [
        span
        for action in recovery_actions.intersection(actions)
        for span in _directive_match_spans(line, action)
    ]
    if (
        "update_account_contact" in actions
        and recovery_specific_spans
        and _all_spans_overlap_any(
            _directive_match_spans(line, "update_account_contact"),
            recovery_specific_spans,
        )
    ):
        suppressed.add("update_account_contact")

    account_security_actions = {
        "change_trusted_devices",
        "change_security_key_settings",
        "manage_passkeys",
        "change_mfa_settings",
        "disable_account_protection",
    }
    account_security_specific_spans = [
        span
        for action in account_security_actions.intersection(actions)
        for span in _directive_match_spans(line, action)
    ]
    if (
        "change_security_settings" in actions
        and account_security_specific_spans
        and _all_spans_overlap_any(
            _directive_match_spans(line, "change_security_settings"),
            account_security_specific_spans,
        )
    ):
        suppressed.add("change_security_settings")

    if {"change_security_key_settings", "manage_passkeys"}.issubset(actions):
        passkey_spans = _directive_match_spans(line, "manage_passkeys")
        if passkey_spans and _all_spans_overlap_any(
            _directive_match_spans(line, "change_security_key_settings"),
            passkey_spans,
        ):
            suppressed.add("change_security_key_settings")

    if not suppressed:
        return actions

    return [action for action in actions if action not in suppressed]


def _suppress_overlapping_form_send_actions(line: str, actions: List[str]) -> List[str]:
    if not {"send", "submit_form"}.issubset(actions):
        return actions

    submit_form_spans = _directive_match_spans(line, "submit_form")
    send_spans = _directive_match_spans(line, "send")
    if any(
        _spans_overlap(send_span, submit_form_span)
        for send_span in send_spans
        for submit_form_span in submit_form_spans
    ):
        return [action for action in actions if action != "send"]

    return actions


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


def _suppress_overlapping_password_manager_secret_actions(
    line: str, actions: List[str]
) -> List[str]:
    action_set = set(actions)
    if not {"password_manager_action", "provide_sensitive_info"}.issubset(action_set):
        return actions

    password_manager_spans = _directive_match_spans(line, "password_manager_action")
    sensitive_info_spans = _directive_match_spans(line, "provide_sensitive_info")
    if any(
        _spans_overlap(sensitive_info_span, password_manager_span)
        for sensitive_info_span in sensitive_info_spans
        for password_manager_span in password_manager_spans
    ):
        return [action for action in actions if action != "provide_sensitive_info"]

    return actions


def _suppress_overlapping_install_software_actions(
    line: str, actions: List[str]
) -> List[str]:
    if "install_software" not in actions:
        return actions

    more_specific_actions = {
        "authorize_app",
        "run_executable",
        "enable_macros",
        "install_profile",
    }
    overlapping_actions = more_specific_actions.intersection(actions)

    install_spans = _directive_match_spans(line, "install_software")
    if overlapping_actions and any(
        _spans_overlap(install_span, specific_span)
        for install_span in install_spans
        for action in overlapping_actions
        for specific_span in _directive_match_spans(line, action)
    ):
        return [action for action in actions if action != "install_software"]

    if "run_shell_command" in actions and any(
        _spans_overlap(install_span, shell_span)
        for install_span in install_spans
        for shell_span in _directive_match_spans(line, "run_shell_command")
    ):
        return [action for action in actions if action != "run_shell_command"]

    return actions


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


def _suppress_split_line_account_contact_overlaps(
    lines: List[str],
    index: int,
    direct_actions_by_index: List[Set[str]],
    combined: str,
) -> None:
    line_boundary = len(lines[index]) + 1
    account_contact_spans = [
        span
        for span in _directive_match_spans(combined, "update_account_contact")
        if span[0] < line_boundary < span[1]
    ]
    if not account_contact_spans:
        return

    line_offsets = (
        (index, 0),
        (index + 1, line_boundary),
    )
    for line_index, offset in line_offsets:
        if "change_mfa_settings" not in direct_actions_by_index[line_index]:
            continue

        mfa_spans = [
            (start + offset, end + offset)
            for start, end in _directive_match_spans(
                lines[line_index],
                "change_mfa_settings",
            )
        ]
        if any(
            _spans_overlap(mfa_span, account_contact_span)
            for mfa_span in mfa_spans
            for account_contact_span in account_contact_spans
        ):
            direct_actions_by_index[line_index].discard("change_mfa_settings")


def _suppress_split_line_form_send_overlaps(
    lines: List[str],
    index: int,
    direct_actions_by_index: List[Set[str]],
    combined: str,
) -> None:
    submit_form_spans = _directive_match_spans(combined, "submit_form")
    if not submit_form_spans:
        return

    line_boundary = len(lines[index]) + 1
    line_offsets = (
        (index, 0),
        (index + 1, line_boundary),
    )
    for line_index, offset in line_offsets:
        if "send" not in direct_actions_by_index[line_index]:
            continue

        send_spans = [
            (start + offset, end + offset)
            for start, end in _directive_match_spans(lines[line_index], "send")
        ]
        if any(
            _spans_overlap(send_span, submit_form_span)
            for send_span in send_spans
            for submit_form_span in submit_form_spans
        ):
            direct_actions_by_index[line_index].discard("send")


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
        if "update_account_contact" in actions:
            _suppress_split_line_account_contact_overlaps(
                lines, index, direct_actions_by_index, combined
            )
        if "submit_form" in actions:
            _suppress_split_line_form_send_overlaps(
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
