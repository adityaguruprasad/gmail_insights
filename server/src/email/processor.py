from anthropic import Anthropic, HUMAN_PROMPT, AI_PROMPT
from src.config.settings import ANTHROPIC_API_KEY
from src.email.safety import redact_sensitive_content

anthropic = Anthropic(api_key=ANTHROPIC_API_KEY)


def _build_prompt(email, redact_sensitive: bool = True) -> str:
    content = email.get("content", "")
    if redact_sensitive:
        content = redact_sensitive_content(content)

    archive_context = "archived" if email.get("is_archived") else "in inbox"

    return (
        f"{HUMAN_PROMPT} "
        "Analyze this Gmail message for read-only insights. "
        "Do NOT suggest sending, replying, deleting, forwarding, or modifying labels. "
        "You may propose a safe draft outline and archive recommendation only.\n\n"
        f"Subject: {email.get('subject', '(No Subject)')}\n"
        f"From: {email.get('sender', 'Unknown Sender')}\n"
        f"Date: {email.get('date', '')}\n"
        f"Mailbox state: {archive_context}\n"
        f"Snippet: {email.get('snippet', '')}\n"
        f"Content:\n{content}\n\n"
        "Return with this structure:\n"
        "1) Summary\n"
        "2) Action items\n"
        "3) Draft assistance (if needed)\n"
        "4) Archive suggestion (yes/no + reason)\n"
        f"{AI_PROMPT}"
    )


def extract_insights(email, redact_sensitive: bool = True):
    prompt = _build_prompt(email, redact_sensitive=redact_sensitive)

    response = anthropic.completions.create(
        model="claude-3-opus-20240229",
        max_tokens_to_sample=300,
        prompt=prompt,
    )

    return {
        "id": email.get("id"),
        "subject": email.get("subject"),
        "sender": email.get("sender"),
        "is_archived": email.get("is_archived", False),
        "summary": response.completion.strip(),
    }
