from anthropic import Anthropic, HUMAN_PROMPT, AI_PROMPT
from src.config.settings import ANTHROPIC_API_KEY

anthropic = Anthropic(api_key=ANTHROPIC_API_KEY)

def extract_insights(email):
    prompt = f"{HUMAN_PROMPT} Please analyze the following email and provide a concise summary of the key insights, main points, and any action items. Here's the email:\n\nSubject: {email['subject']}\nFrom: {email['sender']}\nContent: {email['content']}\n\n{AI_PROMPT} Here's a concise summary of the key insights, main points, and action items from the email:"

    response = anthropic.completions.create(
        model="claude-3-opus-20240229",
        max_tokens_to_sample=300,
        prompt=prompt
    )

    return {
        'subject': email['subject'],
        'sender': email['sender'],
        'summary': response.completion.strip()
    }