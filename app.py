from flask import Flask, render_template, request, redirect, url_for, session
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import Flow
from googleapiclient.discovery import build
from apscheduler.schedulers.background import BackgroundScheduler
from email.message import EmailMessage
import pandas as pd
import smtplib
import os
import time
import json
from datetime import datetime
from authlib.integrations.flask_client import OAuth

app = Flask(__name__)
app.secret_key = os.environ.get('FLASK_SECRET_KEY', 'default_secret_key')
log_file = "log.txt"
scheduler = BackgroundScheduler()
scheduler.start()
keywords_map = {}
oauth = OAuth(app)

# Cấu hình OAuth cho Google
google = oauth.register(
    'google',
    client_id='YOUR_CLIENT_ID',
    client_secret='YOUR_CLIENT_SECRET',
    access_token_url='https://accounts.google.com/o/oauth2/token',
    access_token_params=None,
    authorize_url='https://accounts.google.com/o/oauth2/auth',
    api_base_url='https://www.googleapis.com/oauth2/v1/',
    client_kwargs={'scope': 'email'},
)
# Thay đổi cách lấy token cho OAuth 2.0
# @google.tokengetter
def get_google_oauth2_token():
    return session.get('google_token')
# Hàm ghi log
def write_log(message):
    with open(log_file, "a") as file:
        file.write(f"{datetime.now()}: {message}\n")

# Khởi tạo OAuth 2.0
def gmail_login():
    flow = Flow.from_client_secrets_file(
        'credentials.json',
        scopes=['https://www.googleapis.com/auth/gmail.send', 'https://www.googleapis.com/auth/gmail.readonly'],
        redirect_uri=url_for('oauth2callback', _external=True)
    )
    auth_url, _ = flow.authorization_url(prompt='consent')
    return auth_url

# Xử lý callback OAuth
@app.route('/oauth2callback')
def oauth2callback():
    flow = Flow.from_client_secrets_file(
        'credentials.json',
        scopes=['https://www.googleapis.com/auth/gmail.send', 'https://www.googleapis.com/auth/gmail.readonly'],
        redirect_uri=url_for('oauth2callback', _external=True)
    )
    flow.fetch_token(authorization_response=request.url)

    # Kiểm tra xem có lỗi không
    if 'error' in request.args:
        return f"Error: {request.args['error']}"

    credentials = flow.credentials
    session['credentials'] = credentials_to_dict(credentials)
    write_log("Đăng nhập thành công qua OAuth.")
    return redirect(url_for('index'))

# Chuyển credentials thành dict
def credentials_to_dict(credentials):
    return {
        'token': credentials.token,
        'refresh_token': credentials.refresh_token,
        'token_uri': credentials.token_uri,
        'client_id': credentials.client_id,
        'client_secret': credentials.client_secret,
        'scopes': credentials.scopes
    }

# Hàm quét và chuyển tiếp email
def scan_emails():
    if 'credentials' not in session:
        write_log("Cần đăng nhập lại.")
        return
    creds = Credentials(**session['credentials'])
    service = build('gmail', 'v1', credentials=creds)

    query = f"is:unread after:{int(time.mktime(datetime.now().date().timetuple()))}"
    results = service.users().messages().list(userId='me', q=query).execute()
    messages = results.get('messages', [])

    if not messages:
        write_log("Không có email chưa đọc.")
    else:
        write_log(f"Tìm thấy {len(messages)} email chưa đọc.")
        for msg in messages:
            msg_detail = service.users().messages().get(userId='me', id=msg['id']).execute()
            subject = ""
            sender = ""

            for header in msg_detail['payload']['headers']:
                if header['name'] == 'Subject':
                    subject = header['value']
                if header['name'] == 'From':
                    sender = header['value']
            
            write_log(f"Kiểm tra email từ: {sender} với tiêu đề: {subject}")

            for keyword, receiver_email in keywords_map.items():
                if keyword.lower() in subject.lower():
                    write_log(f"Phát hiện từ khóa '{keyword}' trong email từ '{sender}'")
                    send_email(service, receiver_email, f"Chuyển tiếp: {subject}", subject)
                    break

# Hàm gửi email
def send_email(service, receiver_email, subject, body):
    message = EmailMessage()
    message['to'] = receiver_email
    message['subject'] = subject
    message.set_content(body)

    encoded_message = {'raw': base64.urlsafe_b64encode(message.as_bytes()).decode()}
    service.users().messages().send(userId='me', body=encoded_message).execute()
    write_log(f"Đã gửi email đến {receiver_email} với tiêu đề '{subject}'")

# Đọc từ khóa từ Excel
def load_keywords(file_path):
    if not os.path.isfile(file_path):
        return {}
    df = pd.read_excel(file_path)
    return {row["Từ khóa"]: row["Email"] for _, row in df.iterrows()}

# Giao diện chính
@app.route('/', methods=['GET', 'POST'])
def index():
    global keywords_map

    if request.method == 'POST':
        if 'add_keyword' in request.form:
            new_keyword = request.form['new_keyword']
            new_email = request.form['new_email']
            if new_keyword and new_email:
                keywords_map[new_keyword] = new_email
                write_log(f"Đã thêm từ khóa: '{new_keyword}' với email: '{new_email}'")

    return render_template('index.html', log=open(log_file).readlines(), keywords_map=keywords_map)

@app.route('/login')
def login():
    flow = Flow.from_client_secrets_file(
        'credentials.json',
        scopes=['https://www.googleapis.com/auth/gmail.send', 'https://www.googleapis.com/auth/gmail.readonly'],
        redirect_uri=url_for('oauth2callback', _external=True)
    )
    print("Redirect URI:", url_for('oauth2callback', _external=True))  # In ra URL callback
    auth_url, _ = flow.authorization_url(prompt='consent')
    return redirect(auth_url)

@app.route('/logout')
def logout():
    session.pop('google_token')
    return redirect(url_for('index'))

@app.route('/login/authorized')
def authorized():
    response = google.authorized_response()
    if response is None or 'access_token' not in response:
        return 'Access denied: reason={} error={}'.format(
            request.args['error_reason'],
            request.args['error_description']
        )
    session['google_token'] = (response['access_token'], '')
    user_info = google.get('userinfo')
    return 'Logged in as: ' + user_info.data['email']

# Thay đổi cách lấy token cho OAuth 2.0
def get_google_oauth2_token():
    return session.get('google_token')

if __name__ == '__main__':
    keywords_map = load_keywords('keywords.xlsx')
    app.run(debug=True, port=5001)
