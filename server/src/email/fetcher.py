import base64
import re
from email import policy
from email.parser import Parser
from html.parser import HTMLParser
from typing import Dict, List, Optional, Tuple
from urllib.parse import urlsplit

GMAIL_MESSAGE_LIST_FIELDS = "messages(id)"
GMAIL_MESSAGE_PART_FIELDS_MAX_DEPTH = 12
_GMAIL_MESSAGE_PART_BASE_FIELDS = "mimeType,filename,headers(name,value),body(data)"


def _gmail_message_part_fields(depth: int = GMAIL_MESSAGE_PART_FIELDS_MAX_DEPTH) -> str:
    if depth <= 0:
        return _GMAIL_MESSAGE_PART_BASE_FIELDS

    return (
        f"{_GMAIL_MESSAGE_PART_BASE_FIELDS},"
        f"parts({_gmail_message_part_fields(depth - 1)})"
    )


GMAIL_MESSAGE_GET_FIELDS = (
    "id,threadId,labelIds,snippet,"
    f"payload({_gmail_message_part_fields()})"
)
_AUTHENTICATION_RESULT_HEADER_LABELS = {
    "authentication-results": "Authentication-Results",
    "arc-authentication-results": "ARC-Authentication-Results",
}
_AUTHENTICATION_WARNING_RESULTS = {"fail", "softfail", "temperror", "permerror"}
_AUTHENTICATION_MECHANISM_LABELS = {
    "spf": "SPF",
    "dkim": "DKIM",
    "dmarc": "DMARC",
}
_AUTHENTICATION_RESULT_RE = re.compile(
    r"^\s*(spf|dkim|dmarc)\s*=\s*([a-z]+)\b",
    re.IGNORECASE,
)


def _decode_base64_urlsafe(data: Optional[str]) -> str:
    if not data:
        return ""

    try:
        encoded = data.encode("ascii").translate(None, b" \t\n\r\f\v")
        padding = b"=" * (-len(encoded) % 4)
        decoded = base64.b64decode(
            encoded + padding,
            altchars=b"-_",
            validate=True,
        )
        return decoded.decode("utf-8", errors="replace")
    except Exception:
        return ""


_HTML_CONTENT_TAGS_TO_DROP = {"script", "style", "template", "noscript"}
_HTML_BLOCK_TAGS = {
    "address",
    "article",
    "aside",
    "blockquote",
    "br",
    "caption",
    "dd",
    "div",
    "dl",
    "dt",
    "figcaption",
    "figure",
    "footer",
    "h1",
    "h2",
    "h3",
    "h4",
    "h5",
    "h6",
    "header",
    "hr",
    "li",
    "main",
    "nav",
    "ol",
    "p",
    "pre",
    "section",
    "table",
    "tbody",
    "td",
    "tfoot",
    "th",
    "thead",
    "tr",
    "ul",
}
_DANGEROUS_LINK_SCHEMES = {"javascript", "data", "file", "tel", "sms", "mailto"}
_REMOTE_IMAGE_WARNING = (
    "HTML message contains remote images that may load tracking or remote content."
)
_EXECUTABLE_ATTACHMENT_EXTENSIONS = {
    ".exe",
    ".msi",
    ".bat",
    ".cmd",
    ".com",
    ".scr",
    ".ps1",
    ".vbs",
    ".js",
    ".jar",
    ".apk",
    ".dmg",
    ".pkg",
    ".sh",
}
_MACRO_ENABLED_ATTACHMENT_EXTENSIONS = {".docm", ".xlsm", ".pptm"}
_ARCHIVE_ATTACHMENT_EXTENSIONS = {
    ".zip",
    ".rar",
    ".7z",
    ".gz",
    ".tgz",
    ".bz2",
    ".xz",
    ".iso",
}
_BENIGN_DOCUMENT_MEDIA_ATTACHMENT_EXTENSIONS = {
    ".csv",
    ".doc",
    ".docx",
    ".gif",
    ".jpeg",
    ".jpg",
    ".mov",
    ".mp3",
    ".mp4",
    ".odp",
    ".ods",
    ".odt",
    ".pdf",
    ".png",
    ".ppt",
    ".pptx",
    ".rtf",
    ".txt",
    ".wav",
    ".xls",
    ".xlsx",
}
_DISPLAY_URL_STRIP_CHARS = " \t\r\n\f\v<>()[]{}\"'`"
_DISPLAY_URL_TRAILING_PUNCTUATION = ".,;:!?"


class _HTMLToPlainTextParser(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self._chunks: List[str] = []
        self._drop_depth = 0

    def handle_starttag(self, tag, attrs):
        tag = tag.lower()
        if tag in _HTML_CONTENT_TAGS_TO_DROP:
            self._drop_depth += 1
            return

        if self._drop_depth:
            return

        if tag in _HTML_BLOCK_TAGS:
            self._chunks.append("\n")

    def handle_endtag(self, tag):
        tag = tag.lower()
        if tag in _HTML_CONTENT_TAGS_TO_DROP:
            if self._drop_depth:
                self._drop_depth -= 1
            return

        if self._drop_depth:
            return

        if tag in _HTML_BLOCK_TAGS:
            self._chunks.append("\n")

    def handle_data(self, data):
        if not self._drop_depth:
            self._chunks.append(data)

    def handle_comment(self, data):
        return

    def get_text(self) -> str:
        text = "".join(self._chunks)
        text = text.replace("\r\n", "\n").replace("\r", "\n")
        text = text.replace("\xa0", " ")
        text = re.sub(r"[^\S\n]+", " ", text)
        text = re.sub(r" *\n *", "\n", text)
        text = re.sub(r"\n{3,}", "\n\n", text)
        return text.strip()


def _html_to_plain_text(content: str) -> str:
    if not content:
        return ""

    parser = _HTMLToPlainTextParser()
    try:
        parser.feed(content)
        parser.close()
    except Exception:
        return ""

    return parser.get_text()


def _normalized_hostname(hostname: Optional[str]) -> Optional[str]:
    if not hostname:
        return None

    normalized = hostname.strip().lower().rstrip(".")
    if normalized.startswith("www."):
        normalized = normalized[4:]

    return normalized or None


def _http_url_host(
    value: Optional[str],
    *,
    allow_www_shorthand: bool = False,
) -> Optional[str]:
    if not value:
        return None

    candidate = value.strip()
    if candidate.startswith("//"):
        candidate = f"https:{candidate}"
    elif allow_www_shorthand and candidate.lower().startswith("www."):
        candidate = f"https://{candidate}"

    try:
        parsed = urlsplit(candidate)
    except ValueError:
        return None

    if parsed.scheme.lower() not in {"http", "https"}:
        return None

    return _normalized_hostname(parsed.hostname)


def _display_url_host(text: str) -> Optional[str]:
    candidate = " ".join((text or "").split())
    candidate = candidate.strip(_DISPLAY_URL_STRIP_CHARS).rstrip(
        _DISPLAY_URL_TRAILING_PUNCTUATION
    )
    if not candidate or any(char.isspace() for char in candidate):
        return None

    lower_candidate = candidate.lower()
    if not (
        lower_candidate.startswith("http://")
        or lower_candidate.startswith("https://")
        or lower_candidate.startswith("www.")
    ):
        return None

    return _http_url_host(candidate, allow_www_shorthand=True)


def _url_scheme(value: Optional[str]) -> str:
    if not value:
        return ""

    candidate = value.strip()
    colon_index = candidate.find(":")
    if colon_index <= 0:
        return ""

    scheme = candidate[:colon_index].lower()
    if not scheme:
        return ""

    for char in scheme:
        if not (char.isalnum() or char in {"+", "-", "."}):
            return ""

    return scheme


class _HTMLLinkSafetyParser(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self._warnings: List[str] = []
        self._seen_warnings = set()
        self._drop_depth = 0
        self._anchor_stack: List[Dict] = []

    def _add_warning(self, warning: str) -> None:
        if warning in self._seen_warnings:
            return

        self._seen_warnings.add(warning)
        self._warnings.append(warning)

    def _check_anchor(self, anchor: Dict) -> None:
        display_host = _display_url_host("".join(anchor["chunks"]))
        href_host = _http_url_host(anchor.get("href"))
        if display_host and href_host and display_host != href_host:
            self._add_warning(
                f"Link text host {display_host} points to different host {href_host}."
            )

    def handle_starttag(self, tag, attrs):
        tag = tag.lower()
        if tag in _HTML_CONTENT_TAGS_TO_DROP:
            self._drop_depth += 1
            return

        if self._drop_depth:
            return

        attrs_by_name = {
            str(name).lower(): (value or "")
            for name, value in attrs
            if name is not None
        }

        if tag == "a":
            href = attrs_by_name.get("href", "")
            scheme = _url_scheme(href)
            if scheme in _DANGEROUS_LINK_SCHEMES:
                self._add_warning(
                    f"Link uses potentially unsafe {scheme}: URL scheme."
                )
            self._anchor_stack.append({"href": href, "chunks": []})
        elif tag == "img" and _http_url_host(attrs_by_name.get("src")):
            self._add_warning(_REMOTE_IMAGE_WARNING)

    def handle_endtag(self, tag):
        tag = tag.lower()
        if tag in _HTML_CONTENT_TAGS_TO_DROP:
            if self._drop_depth:
                self._drop_depth -= 1
            return

        if self._drop_depth:
            return

        if tag != "a" or not self._anchor_stack:
            return

        self._check_anchor(self._anchor_stack.pop())

    def handle_data(self, data):
        if self._drop_depth:
            return

        for anchor in self._anchor_stack:
            anchor["chunks"].append(data)

    def handle_comment(self, data):
        return

    def get_warnings(self) -> List[str]:
        while self._anchor_stack:
            self._check_anchor(self._anchor_stack.pop())

        return self._warnings


def _html_link_security_warnings(content: str) -> List[str]:
    if not content:
        return []

    parser = _HTMLLinkSafetyParser()
    try:
        parser.feed(content)
        parser.close()
    except Exception:
        return []

    return parser.get_warnings()


def _base_mime_type(mime_type: str) -> str:
    return mime_type.split(";", 1)[0].strip().lower()


def _is_attachment_part(part: Dict) -> bool:
    if part.get("filename"):
        return True

    disposition = _header_value(part.get("headers", []) or [], "Content-Disposition", "")
    disposition_type = disposition.split(";", 1)[0].strip().lower()
    return disposition_type == "attachment"


def _dedupe_preserving_order(values: List[str]) -> List[str]:
    deduped: List[str] = []
    seen = set()

    for value in values:
        if value in seen:
            continue

        seen.add(value)
        deduped.append(value)

    return deduped


def _header_parameter(headers: List[Dict], key: str, parameter: str) -> str:
    value = _header_value(headers, key, "")
    if not value:
        return ""

    unfolded_value = str(value).replace("\r", " ").replace("\n", " ")
    try:
        message = Parser(policy=policy.default).parsestr(
            f"{key}: {unfolded_value}\n\n"
        )
        parsed_header = message[key]
    except Exception:
        return ""

    if parsed_header is None:
        return ""

    params = getattr(parsed_header, "params", {}) or {}
    return str(params.get(parameter, "") or "")


def _attachment_filename(part: Dict) -> str:
    headers = part.get("headers", []) or []
    filename = (
        str(part.get("filename") or "")
        or _header_parameter(headers, "Content-Disposition", "filename")
        or _header_parameter(headers, "Content-Type", "name")
    )
    return " ".join(filename.replace("\r", " ").replace("\n", " ").split())


def _attachment_extensions(filename: str) -> List[str]:
    normalized = filename.strip().lower().rstrip(" .")
    basename = re.split(r"[\\/]", normalized)[-1]
    if "." not in basename:
        return []

    return [f".{extension}" for extension in basename.split(".")[1:] if extension]


def _attachment_extension(filename: str) -> str:
    extensions = _attachment_extensions(filename)
    if not extensions:
        return ""

    return extensions[-1]


def _deceptive_double_attachment_extensions(
    filename: str,
) -> Optional[Tuple[str, str]]:
    extensions = _attachment_extensions(filename)
    if len(extensions) < 2:
        return None

    previous_extension, extension = extensions[-2], extensions[-1]
    if (
        extension not in _EXECUTABLE_ATTACHMENT_EXTENSIONS
        and extension not in _MACRO_ENABLED_ATTACHMENT_EXTENSIONS
    ):
        return None

    if (
        previous_extension not in _BENIGN_DOCUMENT_MEDIA_ATTACHMENT_EXTENSIONS
        and previous_extension not in _ARCHIVE_ATTACHMENT_EXTENSIONS
    ):
        return None

    return previous_extension, extension


def _attachment_security_warning(filename: str) -> Optional[str]:
    double_extensions = _deceptive_double_attachment_extensions(filename)
    if double_extensions:
        previous_extension, extension = double_extensions
        return (
            f"Attachment {filename} uses a deceptive double extension "
            f"({previous_extension}{extension}) and may contain active content."
        )

    extension = _attachment_extension(filename)
    if extension in _MACRO_ENABLED_ATTACHMENT_EXTENSIONS:
        return (
            f"Attachment {filename} is macro-enabled and may contain active content."
        )

    if extension in _EXECUTABLE_ATTACHMENT_EXTENSIONS:
        return (
            f"Attachment {filename} uses executable or script file extension "
            f"{extension} and may contain active content."
        )

    if extension in _ARCHIVE_ATTACHMENT_EXTENSIONS:
        return (
            f"Attachment {filename} is an archive file and may conceal other files."
        )

    return None


def _attachment_security_warnings(payload: Dict) -> List[str]:
    if not payload:
        return []

    warnings: List[str] = []
    if _is_attachment_part(payload):
        filename = _attachment_filename(payload)
        if filename:
            warning = _attachment_security_warning(filename)
            if warning:
                warnings.append(warning)

    for part in payload.get("parts", []) or []:
        warnings.extend(_attachment_security_warnings(part))

    return _dedupe_preserving_order(warnings)


def _find_decoded_mime_part(payload: Dict, mime_type: str) -> Optional[str]:
    if not payload or _is_attachment_part(payload):
        return None

    if _base_mime_type(payload.get("mimeType", "")) == mime_type:
        data = payload.get("body", {}).get("data")
        if data is None:
            return None
        decoded = _decode_base64_urlsafe(data)
        if decoded:
            return decoded
        return None

    for part in payload.get("parts", []) or []:
        decoded = _find_decoded_mime_part(part, mime_type)
        if decoded is not None:
            return decoded

    return None


def _find_decoded_mime_parts(payload: Dict, mime_type: str) -> List[str]:
    if not payload or _is_attachment_part(payload):
        return []

    decoded_parts: List[str] = []
    if _base_mime_type(payload.get("mimeType", "")) == mime_type:
        data = payload.get("body", {}).get("data")
        if data is not None:
            decoded = _decode_base64_urlsafe(data)
            if decoded:
                decoded_parts.append(decoded)

    for part in payload.get("parts", []) or []:
        decoded_parts.extend(_find_decoded_mime_parts(part, mime_type))

    return decoded_parts


def _extract_plain_text(payload: Dict) -> str:
    if not payload:
        return ""

    plain_text = _find_decoded_mime_part(payload, "text/plain")
    if plain_text is not None:
        return plain_text

    html_text = _find_decoded_mime_part(payload, "text/html")
    if html_text is not None:
        return _html_to_plain_text(html_text)

    return ""


def _html_security_warnings(payload: Dict) -> List[str]:
    warnings: List[str] = []
    seen = set()

    for html_text in _find_decoded_mime_parts(payload, "text/html"):
        for warning in _html_link_security_warnings(html_text):
            if warning in seen:
                continue

            seen.add(warning)
            warnings.append(warning)

    return warnings


def _header_value(headers: List[Dict], key: str, default: str = "") -> str:
    for item in headers:
        if item.get("name", "").lower() == key.lower():
            return item.get("value", default)
    return default


def _header_values(headers: List[Dict], key: str) -> List[str]:
    return [
        str(item.get("value", ""))
        for item in headers or []
        if str(item.get("name", "")).lower() == key.lower()
    ]


def _normalize_email_domain(domain: str) -> Optional[str]:
    normalized = domain.strip().lower().rstrip(".")
    if normalized.startswith("www."):
        normalized = normalized[4:]

    return _normalize_safe_domain(normalized)


def _email_header_value_domains(header_name: str, value: str) -> List[str]:
    unfolded_value = str(value).replace("\r", " ").replace("\n", " ")
    if not unfolded_value.strip():
        return []

    try:
        message = Parser(policy=policy.default).parsestr(
            f"{header_name}: {unfolded_value}\n\n"
        )
        parsed_header = message[header_name]
    except Exception:
        return []

    if parsed_header is None or getattr(parsed_header, "defects", ()):
        return []

    domains: List[str] = []
    for address in getattr(parsed_header, "addresses", ()):
        if not getattr(address, "username", "") or not getattr(address, "domain", ""):
            continue

        domain = _normalize_email_domain(str(address.domain))
        if domain:
            domains.append(domain)

    return domains


def _email_header_domains(headers: List[Dict], key: str) -> List[str]:
    values = _header_values(headers, key)
    if not values:
        return []

    domains: List[str] = []
    seen = set()
    for value in values:
        for domain in _email_header_value_domains(key, value):
            if domain in seen:
                continue

            seen.add(domain)
            domains.append(domain)

    return domains


def _reply_to_security_warnings(headers: List[Dict]) -> List[str]:
    from_domains = _email_header_domains(headers, "From")
    if not from_domains:
        return []

    sender_domain = from_domains[0]
    warnings: List[str] = []
    for reply_to_domain in _email_header_domains(headers, "Reply-To"):
        if reply_to_domain == sender_domain:
            continue

        warnings.append(
            f"Reply-To domain {reply_to_domain} differs from "
            f"sender domain {sender_domain}."
        )

    return warnings


def _authentication_result_clauses(value: str) -> List[str]:
    clauses: List[str] = []
    current: List[str] = []
    comment_depth = 0
    in_quote = False
    escaped = False

    for char in value:
        current.append(char)

        if in_quote:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == '"':
                in_quote = False
            continue

        if char == '"':
            in_quote = True
        elif char == "(":
            comment_depth += 1
        elif char == ")" and comment_depth:
            comment_depth -= 1
        elif char == ";" and not comment_depth:
            current.pop()
            clauses.append("".join(current))
            current = []

    clauses.append("".join(current))
    return clauses


def _authentication_security_warnings(headers: List[Dict]) -> List[str]:
    warnings: List[str] = []
    seen = set()

    for item in headers or []:
        header_name = str(item.get("name", ""))
        normalized_header_name = header_name.lower()
        header_label = _AUTHENTICATION_RESULT_HEADER_LABELS.get(normalized_header_name)
        if header_label is None:
            continue

        value = str(item.get("value", ""))
        unfolded_value = " ".join(value.replace("\r", " ").replace("\n", " ").split())
        for clause in _authentication_result_clauses(unfolded_value):
            result_match = _AUTHENTICATION_RESULT_RE.match(clause)
            if not result_match:
                continue

            mechanism = result_match.group(1).lower()
            result = result_match.group(2).lower()
            if result not in _AUTHENTICATION_WARNING_RESULTS:
                continue

            warning_key = (normalized_header_name, mechanism, result)
            if warning_key in seen:
                continue
            seen.add(warning_key)

            warnings.append(
                f"{_AUTHENTICATION_MECHANISM_LABELS[mechanism]} authentication "
                f"result is {result} in {header_label}."
            )

    return warnings


def get_emails_by_query(service, query: str, max_results: int = 100) -> List[Dict]:
    results = (
        service.users()
        .messages()
        .list(
            userId="me",
            q=query,
            maxResults=max_results,
            fields=GMAIL_MESSAGE_LIST_FIELDS,
        )
        .execute()
    )
    messages = results.get("messages", [])

    emails: List[Dict] = []
    for message in messages:
        msg = (
            service.users()
            .messages()
            .get(
                userId="me",
                id=message["id"],
                format="full",
                fields=GMAIL_MESSAGE_GET_FIELDS,
            )
            .execute()
        )

        payload = msg.get("payload", {})
        headers = payload.get("headers", [])
        label_ids = msg.get("labelIds", [])

        emails.append(
            {
                "id": msg.get("id"),
                "thread_id": msg.get("threadId"),
                "subject": _header_value(headers, "Subject", "(No Subject)"),
                "sender": _header_value(headers, "From", "Unknown Sender"),
                "date": _header_value(headers, "Date", ""),
                "snippet": msg.get("snippet", ""),
                "label_ids": label_ids,
                "is_archived": "INBOX" not in label_ids,
                "security_warnings": _dedupe_preserving_order(
                    _authentication_security_warnings(headers)
                    + _reply_to_security_warnings(headers)
                    + _html_security_warnings(payload)
                    + _attachment_security_warnings(payload)
                ),
                "content": _extract_plain_text(payload),
            }
        )

    return emails


_DOMAIN_LABEL_RE = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")
_FINAL_DOMAIN_LABEL_RE = re.compile(r"^[a-z]{2,}$")


def _normalize_safe_domain(domain: str) -> Optional[str]:
    normalized = domain.strip().lower()
    if normalized.startswith("@"):
        normalized = normalized[1:]

    if not normalized or len(normalized) > 253:
        return None

    labels = normalized.split(".")
    if len(labels) < 2 or not _FINAL_DOMAIN_LABEL_RE.fullmatch(labels[-1]):
        return None

    for label in labels:
        if not 1 <= len(label) <= 63 or not _DOMAIN_LABEL_RE.fullmatch(label):
            return None

    return normalized


def get_emails_from_domains(service, domains, max_results: int = 100):
    valid_domains = [
        normalized
        for domain in domains
        if domain and (normalized := _normalize_safe_domain(domain))
    ]
    if not valid_domains:
        return []

    query = " OR ".join([f"from:{domain}" for domain in valid_domains])
    return get_emails_by_query(service, query=query, max_results=max_results)
