from google.oauth2.credentials import Credentials
from googleapiclient.discovery import build

def get_gmail_service(token):
    creds = Credentials(token)
    return build('gmail', 'v1', credentials=creds)