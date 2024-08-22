import base64

def get_emails_from_domains(service, domains, max_results=100):
    query = ' OR '.join([f'from:{domain}' for domain in domains])
    results = service.users().messages().list(userId='me', q=query, maxResults=max_results).execute()
    messages = results.get('messages', [])
    
    emails = []
    for message in messages:
        msg = service.users().messages().get(userId='me', id=message['id']).execute()
        email_data = msg['payload']['headers']
        subject = next(item for item in email_data if item["name"] == "Subject")['value']
        sender = next(item for item in email_data if item["name"] == "From")['value']
        
        content = ""
        if 'parts' in msg['payload']:
            for part in msg['payload']['parts']:
                if part['mimeType'] == 'text/plain':
                    data = part['body']['data']
                    content = base64.urlsafe_b64decode(data).decode()
        elif 'body' in msg['payload']:
            data = msg['payload']['body']['data']
            content = base64.urlsafe_b64decode(data).decode()
        
        emails.append({
            'subject': subject,
            'sender': sender,
            'content': content
        })
    
    return emails