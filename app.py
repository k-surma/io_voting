import os
import smtplib
import ssl
from email.utils import formataddr
from flask import Flask, render_template, request, flash
from dotenv import load_dotenv

load_dotenv()

app = Flask(__name__, static_folder='static', template_folder='templates')
app.secret_key = os.getenv('FLASK_SECRET_KEY', 'change-this-in-production')

SMTP_HOST = os.getenv('SMTP_HOST', 'smtp.gmail.com')
SMTP_PORT = int(os.getenv('SMTP_PORT', '587'))
SMTP_USERNAME = os.getenv('SMTP_USERNAME', '')
SMTP_PASSWORD = os.getenv('SMTP_PASSWORD', '')
MAIL_FROM = os.getenv('MAIL_FROM', SMTP_USERNAME)
MAIL_TO_DEFAULT = os.getenv('MAIL_TO_DEFAULT', SMTP_USERNAME)


def send_email(subject: str, body: str, reply_to_email: str | None = None, reply_to_name: str | None = None) -> None:
	if not SMTP_USERNAME or not SMTP_PASSWORD:
		raise RuntimeError('SMTP_USERNAME or SMTP_PASSWORD not set')

	headers: list[str] = []
	headers.append(f"From: {formataddr(('Website', MAIL_FROM))}")
	headers.append(f"To: {MAIL_TO_DEFAULT}")
	headers.append(f"Subject: {subject}")
	headers.append('MIME-Version: 1.0')
	headers.append('Content-Type: text/plain; charset=utf-8')
	if reply_to_email:
		if reply_to_name:
			headers.append(f"Reply-To: {formataddr((reply_to_name, reply_to_email))}")
		else:
			headers.append(f"Reply-To: {reply_to_email}")

	message = '\r\n'.join(headers) + '\r\n\r\n' + body
	context = ssl.create_default_context()
	with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=15) as server:
		server.ehlo()
		server.starttls(context=context)
		server.ehlo()
		server.login(SMTP_USERNAME, SMTP_PASSWORD)
		server.sendmail(MAIL_FROM, [MAIL_TO_DEFAULT], message.encode('utf-8'))


@app.get('/')
def index_get():
	return render_template('index.html')


@app.post('/')
def index_post():
	name = request.form.get('name', '').strip()
	email = request.form.get('email', '').strip()
	message = request.form.get('message', '').strip()

	if not name or not email or not message:
		flash('Wypełnij wszystkie pola.', 'error')
		return render_template('index.html', name=name, email=email, message=message), 400

	if len(message) > 5000:
		flash('Wiadomość jest zbyt długa.', 'error')
		return render_template('index.html', name=name, email=email, message=message), 400

	try:
		subject = f'Nowa wiadomość ze strony od {name}'
		body = f'Imię: {name}\nEmail: {email}\n\n{message}'
		send_email(subject, body, reply_to_email=email, reply_to_name=name)
		flash('Wiadomość wysłana. Dziękujemy!', 'success')
		return render_template('index.html'), 200
	except Exception as exc:
		print(f'Error sending email: {exc}', flush=True)
		flash('Nie udało się wysłać wiadomości. Spróbuj ponownie później.', 'error')
		return render_template('index.html', name=name, email=email, message=message), 500


@app.get('/healthz')
def healthz():
	return 'ok', 200


if __name__ == '__main__':
	port = int(os.getenv('PORT', '3000'))
	app.run(host='0.0.0.0', port=port)
