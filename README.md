
Creating a Gmail insights chrome extension that will scrape through a user's Gmail to provide high-level insights on their emails to help automate knowledge and workflow. 

The emails will be ingested using the Gmail OAuth API, insights processed through the Anthropic API, then sent to the user through a chrome extension UI.

gmail-insights-extension/
├── manifest.json
├── background.js
├── popup.html
├── popup.js
├── styles.css
├── icons/
│   ├── icon16.png
│   ├── icon48.png
│   └── icon128.png
└── server/
    ├── app.py
    ├── requirements.txt
    └── src/
        ├── auth/
        │   └── gmail_auth.py
        ├── email/
        │   ├── fetcher.py
        │   └── processor.py
        ├── config/
        │   └── settings.py
        └── output/
            └── document_writer.py

