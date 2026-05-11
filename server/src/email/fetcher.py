import base64
import re
from html.parser import HTMLParser
from typing import Dict, List, Optional

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


def _base_mime_type(mime_type: str) -> str:
    return mime_type.split(";", 1)[0].strip().lower()


def _is_attachment_part(part: Dict) -> bool:
    if part.get("filename"):
        return True

    disposition = _header_value(part.get("headers", []) or [], "Content-Disposition", "")
    disposition_type = disposition.split(";", 1)[0].strip().lower()
    return disposition_type == "attachment"


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


def _header_value(headers: List[Dict], key: str, default: str = "") -> str:
    for item in headers:
        if item.get("name", "").lower() == key.lower():
            return item.get("value", default)
    return default


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
                "security_warnings": _authentication_security_warnings(headers),
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
