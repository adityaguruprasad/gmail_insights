from src.auth.gmail_auth import get_gmail_service
from src.email.fetcher import get_emails_from_domains
from src.email.processor import extract_insights
from src.output.document_writer import write_insights_to_document
from src.config.settings import TARGET_DOMAINS
import anthropic

def main():
    # Set up Gmail API service
    service = get_gmail_service()

    # Fetch emails
    print("Fetching emails...")
    emails = get_emails_from_domains(service, TARGET_DOMAINS)

    # Process emails and extract insights
    print("Extracting insights...")
    insights = []
    for email in emails:
        try:
            insight = extract_insights(email)
            insights.append(insight)
        except anthropic.APIError as e:
            print(f"Error processing email: {e}")
            continue

    # Write insights to document
    print("Writing insights to document...")
    output_file = write_insights_to_document(insights)

    print(f"Done! Insights have been written to {output_file}")

if __name__ == "__main__":
    main()