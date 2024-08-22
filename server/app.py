from flask import Flask, request, jsonify
from flask_cors import CORS
from google.oauth2.credentials import Credentials
from googleapiclient.discovery import build
from src.email.fetcher import get_emails_from_domains
from src.email.processor import extract_insights
from src.config.settings import TARGET_DOMAINS, CHROME_EXTENSION_ID

app = Flask(__name__)
CORS(app, resources={r"/get_insights": {"origins": f"chrome-extension://{CHROME_EXTENSION_ID}"}})

@app.route('/get_insights', methods=['POST'])
def get_insights():
    token = request.json.get('token')
    if not token:
        return jsonify({"error": "No token provided"}), 400

    try:
        creds = Credentials(token)
        service = build('gmail', 'v1', credentials=creds)
        
        emails = get_emails_from_domains(service, TARGET_DOMAINS)
        insights = []
        for email in emails:
            insight = extract_insights(email)
            insights.append(insight)
        return jsonify({"insights": insights})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

if __name__ == '__main__':
    app.run(debug=True)