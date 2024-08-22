import os
from dotenv import load_dotenv

load_dotenv()

# Anthropic API settings
ANTHROPIC_API_KEY = os.getenv('ANTHROPIC_API_KEY')

# Gmail API settings
GMAIL_CLIENT_ID = os.getenv('GMAIL_CLIENT_ID')

# Email domains to fetch from
TARGET_DOMAINS = os.getenv('TARGET_DOMAINS', '').split(',')

# Flask settings
FLASK_SECRET_KEY = os.getenv('FLASK_SECRET_KEY')
FLASK_ENV = os.getenv('FLASK_ENV', 'development')
FLASK_DEBUG = int(os.getenv('FLASK_DEBUG', '1'))

# Chrome extension ID (for CORS configuration)
CHROME_EXTENSION_ID = os.getenv('CHROME_EXTENSION_ID')