import base64
from typing import Dict, List, Optional


def _decode_base64_urlsafe(data: Optional[str]) -> str:
    if not data:
        return ""

    padding = '=' * (-len(data) % 4)
    try:
        return base64.urlsafe_b64decode(data + padding).decode("utf-8", errors="replace")
    except Exception:
        return ""


def _extract_plain_text(payload: Dict) -> str:
    if not payload:
        return ""

    mime_type = payload.get("mimeType", "")
    body = payload.get("body", {})

    if mime_type == "text/plain":
        return _decode_base64_urlsafe(body.get("data"))

    parts = payload.get("parts", []) or []
    for part in parts:
        part_mime_type = part.get("mimeType", "")
        if part_mime_type == "text/plain":
            return _decode_base64_urlsafe(part.get("body", {}).get("data"))

        nested_parts = part.get("parts")
        if nested_parts:
            nested_text = _extract_plain_text(part)
            if nested_text:
                return nested_text

    return _decode_base64_urlsafe(body.get("data"))


def _header_value(headers: List[Dict], key: str, default: str = "") -> str:
    for item in headers:
        if item.get("name", "").lower() == key.lower():
            return item.get("value", default)
    return default


def get_emails_by_query(service, query: str, max_results: int = 100) -> List[Dict]:
    results = (
        service.users()
        .messages()
        .list(userId="me", q=query, maxResults=max_results)
        .execute()
    )
    messages = results.get("messages", [])

    emails: List[Dict] = []
    for message in messages:
        msg = (
            service.users()
            .messages()
            .get(userId="me", id=message["id"], format="full")
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
                "content": _extract_plain_text(payload),
            }
        )

    return emails


def get_emails_from_domains(service, domains, max_results: int = 100):
    valid_domains = [domain.strip() for domain in domains if domain and domain.strip()]
    if not valid_domains:
        return []

    query = " OR ".join([f"from:{domain}" for domain in valid_domains])
    return get_emails_by_query(service, query=query, max_results=max_results)
