import os
from dotenv import load_dotenv

load_dotenv()

# Gmail API settings
SCOPES = ['https://www.googleapis.com/auth/gmail.readonly']
CREDENTIALS_FILE = 'data/credentials.json'
TOKEN_FILE = 'data/token.json'

# Anthropic API settings
ANTHROPIC_API_KEY = os.getenv('ANTHROPIC_API_KEY')

# Email domains to fetch from
TARGET_DOMAINS = ['aditya.guruprasad@gmail.com']

# Output settings
OUTPUT_DIR = 'output'

# Ensure output directory exists
os.makedirs(OUTPUT_DIR, exist_ok=True)