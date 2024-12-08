from flask import Flask, redirect, url_for, session, request, Response, json, jsonify
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import Flow
from googleapiclient.discovery import build
from email.header import decode_header
import os

app = Flask(__name__)
app.secret_key = 'a8e864939aac48c7d441781a9568668b'

CREDENTIALS_FILE = 'web_google.json'

SCOPES = ['https://www.googleapis.com/auth/gmail.readonly']

flow = Flow.from_client_secrets_file(
    CREDENTIALS_FILE,
    scopes=SCOPES,
    redirect_uri='http://localhost:5000/callback'
)


@app.route('/')
def home():
    if 'credentials' not in session:
        return redirect(url_for('authorize'))
    return redirect(url_for('read_emails'))


@app.route('/authorize')
def authorize():
    authorization_url, state = flow.authorization_url(access_type='offline', include_granted_scopes='true')
    session['state'] = state
    return redirect(authorization_url)


@app.route('/callback')
def callback():
    flow.fetch_token(authorization_response=request.url)
    credentials = flow.credentials
    session['credentials'] = {
        'token': credentials.token,
        'refresh_token': credentials.refresh_token,
        'token_uri': credentials.token_uri,
        'client_id': credentials.client_id,
        'client_secret': credentials.client_secret,
        'scopes': credentials.scopes
    }
    return redirect(url_for('read_emails'))


@app.route('/read-emails')
def read_emails():
    if 'credentials' not in session:
        return redirect(url_for('authorize'))

    credentials = Credentials(**session['credentials'])
    service = build('gmail', 'v1', credentials=credentials)

    try:
        results = service.users().messages().list(userId='me', maxResults=50).execute()
        messages = results.get('messages', [])
        if not messages:
            return jsonify({"message": "No messages found"})

        subjects = []
        for message in messages:
            msg = service.users().messages().get(userId="me", id=message['id']).execute()
            payload = msg.get('payload', {})
            headers = payload.get('headers', [])

            subject = next((header['value'] for header in headers if header['name'] == 'Subject'), 'No Subject')

            subjects.append(subject)

        session['credentials'] = credentials_to_dict(credentials)
        return jsonify(subjects)
    except Exception as e:
        return jsonify({"error": str(e)}), 500


def credentials_to_dict(credentials):
    return {
        'token': credentials.token,
        'refresh_token': credentials.refresh_token,
        'token_uri': credentials.token_uri,
        'client_id': credentials.client_id,
        'client_secret': credentials.client_secret,
        'scopes': credentials.scopes
    }


if __name__ == '__main__':
    os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'
    app.run('localhost', 5000, debug=True)
