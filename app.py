import os
import smtplib
import ssl
import sqlite3
import secrets
import time
from email.utils import formataddr
from flask import Flask, render_template, request, flash, redirect, url_for, session, g, abort
from werkzeug.utils import secure_filename
from dotenv import load_dotenv
from werkzeug.security import generate_password_hash, check_password_hash

load_dotenv()

app = Flask(__name__, static_folder='static', template_folder='templates')
app.secret_key = os.getenv('FLASK_SECRET_KEY', 'change-this-in-production')

# SMTP config
SMTP_HOST = os.getenv('SMTP_HOST', 'smtp.gmail.com')
SMTP_PORT = int(os.getenv('SMTP_PORT', '587'))
SMTP_USERNAME = os.getenv('SMTP_USERNAME', '')
SMTP_PASSWORD = os.getenv('SMTP_PASSWORD', '')
MAIL_FROM = os.getenv('MAIL_FROM', SMTP_USERNAME)
MAIL_TO_DEFAULT = os.getenv('MAIL_TO_DEFAULT', SMTP_USERNAME)

# DB and admin config
DATABASE_PATH = os.getenv('DATABASE_PATH', os.path.join(os.path.dirname(__file__), 'app.db'))
ADMIN_USERNAME = os.getenv('ADMIN_USERNAME')
ADMIN_PASSWORD = os.getenv('ADMIN_PASSWORD')

# Uploads config
STATIC_DIR = os.path.join(os.path.dirname(__file__), 'static')
UPLOAD_BASE = os.path.join(STATIC_DIR, 'uploads')
AVATARS_DIR = os.path.join(UPLOAD_BASE, 'avatars')
FILES_DIR = os.path.join(UPLOAD_BASE, 'files')
os.makedirs(AVATARS_DIR, exist_ok=True)
os.makedirs(FILES_DIR, exist_ok=True)
app.config['MAX_CONTENT_LENGTH'] = int(os.getenv('MAX_CONTENT_LENGTH', '10485760'))  # 10 MB


def get_db() -> sqlite3.Connection:
	if not hasattr(g, 'db_conn'):
		conn = sqlite3.connect(DATABASE_PATH)
		conn.row_factory = sqlite3.Row
		conn.execute('PRAGMA foreign_keys = ON')
		g.db_conn = conn
	return g.db_conn


@app.teardown_appcontext
def close_db(exception=None):
	conn = getattr(g, 'db_conn', None)
	if conn is not None:
		conn.close()


def init_db() -> None:
	conn = get_db()
	conn.executescript(
		'''
		CREATE TABLE IF NOT EXISTS admins (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			username TEXT UNIQUE NOT NULL,
			password_hash TEXT NOT NULL,
			created_at TEXT DEFAULT CURRENT_TIMESTAMP
		);

		CREATE TABLE IF NOT EXISTS contests (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			name TEXT NOT NULL,
			description TEXT,
			is_active INTEGER NOT NULL DEFAULT 1,
			created_at TEXT DEFAULT CURRENT_TIMESTAMP
		);

		CREATE TABLE IF NOT EXISTS projects (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			contest_id INTEGER NOT NULL,
			title TEXT NOT NULL,
			description TEXT,
			link TEXT,
			author TEXT,
			avatar_path TEXT,
			attachment_path TEXT,
			votes_count INTEGER NOT NULL DEFAULT 0,
			created_at TEXT DEFAULT CURRENT_TIMESTAMP,
			FOREIGN KEY(contest_id) REFERENCES contests(id) ON DELETE CASCADE
		);

		CREATE TABLE IF NOT EXISTS votes (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			contest_id INTEGER NOT NULL,
			project_id INTEGER NOT NULL,
			email TEXT NOT NULL,
			created_at INTEGER NOT NULL,
			UNIQUE(contest_id, email),
			FOREIGN KEY(contest_id) REFERENCES contests(id) ON DELETE CASCADE,
			FOREIGN KEY(project_id) REFERENCES projects(id) ON DELETE CASCADE
		);

		CREATE TABLE IF NOT EXISTS votes_pending (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			contest_id INTEGER NOT NULL,
			project_id INTEGER NOT NULL,
			email TEXT NOT NULL,
			code TEXT NOT NULL,
			expires_at INTEGER NOT NULL,
			created_at INTEGER NOT NULL,
			FOREIGN KEY(contest_id) REFERENCES contests(id) ON DELETE CASCADE,
			FOREIGN KEY(project_id) REFERENCES projects(id) ON DELETE CASCADE
		);
		'''
	)
	conn.commit()


def ensure_admin() -> None:
	conn = get_db()
	if ADMIN_USERNAME and ADMIN_PASSWORD:
		row = conn.execute('SELECT id FROM admins WHERE username = ?', (ADMIN_USERNAME,)).fetchone()
		if row is None:
			conn.execute(
				'INSERT INTO admins(username, password_hash) VALUES (?, ?)',
				(ADMIN_USERNAME, generate_password_hash(ADMIN_PASSWORD))
			)
			conn.commit()


@app.before_request
def load_current_admin():
	g.admin_id = session.get('admin_id')


@app.context_processor
def inject_globals():
	return {
		'is_admin': bool(session.get('admin_id'))
	}


def send_email(subject: str, body: str, reply_to_email: str | None = None, reply_to_name: str | None = None, to_email: str | None = None) -> None:
	if not SMTP_USERNAME or not SMTP_PASSWORD:
		raise RuntimeError('SMTP_USERNAME or SMTP_PASSWORD not set')

	recipient = to_email or MAIL_TO_DEFAULT
	headers: list[str] = []
	headers.append(f"From: {formataddr(('Website', MAIL_FROM))}")
	headers.append(f"To: {recipient}")
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
		server.sendmail(MAIL_FROM, [recipient], message.encode('utf-8'))


# Public: Home - list contests and projects
@app.get('/')
def home():
	conn = get_db()
	contests = conn.execute('SELECT id, name, description FROM contests WHERE is_active = 1 ORDER BY created_at DESC').fetchall()
	projects_by_contest: dict[int, list[sqlite3.Row]] = {}
	for c in contests:
		projects_by_contest[c['id']] = conn.execute(
			'SELECT id, title, description, link, author, avatar_path, attachment_path, votes_count FROM projects WHERE contest_id = ? ORDER BY votes_count DESC, id DESC',
			(c['id'],)
		).fetchall()
	return render_template('index.html', contests=contests, projects_by_contest=projects_by_contest)


# Public: Contest page with voting form
@app.get('/contest/<int:contest_id>')
def contest_page(contest_id: int):
	conn = get_db()
	contest = conn.execute('SELECT id, name, description FROM contests WHERE id = ? AND is_active = 1', (contest_id,)).fetchone()
	if contest is None:
		abort(404)
	projects = conn.execute(
		'SELECT id, title, description, link, author, avatar_path, attachment_path, votes_count FROM projects WHERE contest_id = ? ORDER BY votes_count DESC, id DESC',
		(contest_id,)
	).fetchall()
	return render_template('contest.html', contest=contest, projects=projects)


def _valid_email(email: str) -> bool:
	return '@' in email and '.' in email and len(email) <= 254


@app.post('/contest/<int:contest_id>/vote')
def contest_vote(contest_id: int):
	email = request.form.get('email', '').strip()
	project_id_raw = request.form.get('project_id', '').strip()
	if not _valid_email(email) or not project_id_raw.isdigit():
		flash('Nieprawidłowe dane formularza.', 'error')
		return redirect(url_for('contest_page', contest_id=contest_id))

	project_id = int(project_id_raw)
	conn = get_db()

	# Already voted?
	existing_vote = conn.execute('SELECT id FROM votes WHERE contest_id = ? AND email = ?', (contest_id, email)).fetchone()
	if existing_vote:
		flash('Ten adres e-mail już oddał głos w tym konkursie.', 'error')
		return redirect(url_for('contest_page', contest_id=contest_id))

	# Create code and pending entry
	code = f"{secrets.randbelow(1000000):06d}"
	now = int(time.time())
	expires = now + 15 * 60
	conn.execute(
		'INSERT INTO votes_pending(contest_id, project_id, email, code, created_at, expires_at) VALUES (?, ?, ?, ?, ?, ?)',
		(contest_id, project_id, email, code, now, expires)
	)
	conn.commit()

	# Send verification email to voter
	subject = f'Kod weryfikacyjny do głosowania w konkursie #{contest_id}'
	body = f'Twój kod weryfikacyjny: {code}\n\nKod jest ważny 15 minut.'
	try:
		send_email(subject, body, to_email=email)
		flash('Wysłaliśmy kod weryfikacyjny na podany e-mail.', 'success')
		return redirect(url_for('contest_verify_get', contest_id=contest_id, email=email))
	except Exception as exc:
		print(f'Error sending verification email: {exc}', flush=True)
		flash('Nie udało się wysłać kodu. Spróbuj ponownie.', 'error')
		return redirect(url_for('contest_page', contest_id=contest_id))


@app.get('/contest/<int:contest_id>/verify')
def contest_verify_get(contest_id: int):
	email = request.args.get('email', '').strip()
	if not _valid_email(email):
		email = ''
	return render_template('verify.html', contest_id=contest_id, email=email)


@app.post('/contest/<int:contest_id>/verify')
def contest_verify_post(contest_id: int):
	email = request.form.get('email', '').strip()
	code = request.form.get('code', '').strip()
	if not _valid_email(email) or not (len(code) == 6 and code.isdigit()):
		flash('Nieprawidłowe dane.', 'error')
		return redirect(url_for('contest_verify_get', contest_id=contest_id, email=email))

	conn = get_db()
	now = int(time.time())
	pending = conn.execute(
		'SELECT id, project_id FROM votes_pending WHERE contest_id = ? AND email = ? AND code = ? AND expires_at >= ? ORDER BY id DESC',
		(contest_id, email, code, now)
	).fetchone()
	if not pending:
		flash('Nieprawidłowy lub przeterminowany kod.', 'error')
		return redirect(url_for('contest_verify_get', contest_id=contest_id, email=email))

	project_id = pending['project_id']
	try:
		conn.execute(
			'INSERT INTO votes(contest_id, project_id, email, created_at) VALUES (?, ?, ?, ?)',
			(contest_id, project_id, email, now)
		)
		conn.execute(
			'UPDATE projects SET votes_count = votes_count + 1 WHERE id = ?',
			(project_id,)
		)
		# cleanup all pendings for this email & contest
		conn.execute('DELETE FROM votes_pending WHERE contest_id = ? AND email = ?', (contest_id, email))
		conn.commit()
		flash('Głos został potwierdzony. Dziękujemy!', 'success')
		return redirect(url_for('contest_page', contest_id=contest_id))
	except sqlite3.IntegrityError:
		# Unique constraint: already voted
		flash('Ten adres e-mail już oddał głos w tym konkursie.', 'error')
		return redirect(url_for('contest_page', contest_id=contest_id))


# Admin auth
@app.get('/admin/login')
def admin_login_get():
	if session.get('admin_id'):
		return redirect(url_for('admin_dashboard'))
	return render_template('admin_login.html')


@app.post('/admin/login')
def admin_login_post():
	username = request.form.get('username', '').strip()
	password = request.form.get('password', '').strip()
	if not username or not password:
		flash('Podaj login i hasło.', 'error')
		return redirect(url_for('admin_login_get'))
	conn = get_db()
	admin = conn.execute('SELECT id, password_hash FROM admins WHERE username = ?', (username,)).fetchone()
	if not admin or not check_password_hash(admin['password_hash'], password):
		flash('Nieprawidłowe dane logowania.', 'error')
		return redirect(url_for('admin_login_get'))
	session['admin_id'] = admin['id']
	flash('Zalogowano.', 'success')
	return redirect(url_for('admin_dashboard'))


@app.get('/admin/logout')
def admin_logout():
	session.pop('admin_id', None)
	flash('Wylogowano.', 'success')
	return redirect(url_for('home'))


# Admin: dashboard
@app.get('/admin')
def admin_dashboard():
	if not session.get('admin_id'):
		return redirect(url_for('admin_login_get'))
	conn = get_db()
	contests = conn.execute('SELECT id, name, description, is_active, created_at FROM contests ORDER BY id DESC').fetchall()
	return render_template('admin_dashboard.html', contests=contests)


# Admin: create contest
@app.get('/admin/contests/new')
def admin_contest_new_get():
	if not session.get('admin_id'):
		return redirect(url_for('admin_login_get'))
	return render_template('admin_contest_new.html')


@app.post('/admin/contests/new')
def admin_contest_new_post():
	if not session.get('admin_id'):
		return redirect(url_for('admin_login_get'))
	name = request.form.get('name', '').strip()
	description = request.form.get('description', '').strip()
	is_active = 1 if request.form.get('is_active') == 'on' else 0
	if not name:
		flash('Nazwa jest wymagana.', 'error')
		return redirect(url_for('admin_contest_new_get'))
	conn = get_db()
	cur = conn.execute('INSERT INTO contests(name, description, is_active) VALUES (?, ?, ?)', (name, description, is_active))
	contest_id = cur.lastrowid
	conn.commit()
	flash('Konkurs utworzony.', 'success')
	return redirect(url_for('admin_contest_detail', contest_id=contest_id))


# Admin: contest detail + add project
@app.get('/admin/contests/<int:contest_id>')
def admin_contest_detail(contest_id: int):
	if not session.get('admin_id'):
		return redirect(url_for('admin_login_get'))
	conn = get_db()
	contest = conn.execute('SELECT id, name, description, is_active FROM contests WHERE id = ?', (contest_id,)).fetchone()
	if not contest:
		abort(404)
	projects = conn.execute('SELECT id, title, description, link, author, avatar_path, attachment_path, votes_count FROM projects WHERE contest_id = ? ORDER BY id DESC', (contest_id,)).fetchall()
	return render_template('admin_contest.html', contest=contest, projects=projects)


@app.post('/admin/contests/<int:contest_id>/projects/new')
def admin_project_new(contest_id: int):
	if not session.get('admin_id'):
		return redirect(url_for('admin_login_get'))
	title = request.form.get('title', '').strip()
	description = request.form.get('description', '').strip()
	link = request.form.get('link', '').strip()
	author = request.form.get('author', '').strip()
	avatar = request.files.get('avatar')
	attachment = request.files.get('attachment')

	if not title or not author:
		flash('Tytuł i autor są wymagane.', 'error')
		return redirect(url_for('admin_contest_detail', contest_id=contest_id))

	def _ext(filename: str) -> str | None:
		if '.' not in filename:
			return None
		return filename.rsplit('.', 1)[1].lower()

	def _save_upload(file, dst_dir: str, allowed_exts: set[str]) -> str | None:
		if not file or not getattr(file, 'filename', ''):
			return None
		ext = _ext(file.filename)
		if ext not in allowed_exts:
			return None
		name = f"{secrets.token_hex(16)}.{ext}"
		full_path = os.path.join(dst_dir, name)
		file.save(full_path)
		if dst_dir == AVATARS_DIR:
			return f"uploads/avatars/{name}"
		elif dst_dir == FILES_DIR:
			return f"uploads/files/{name}"
		return None

	avatar_rel = _save_upload(avatar, AVATARS_DIR, {'jpg', 'jpeg', 'png', 'gif', 'webp'})
	file_rel = _save_upload(attachment, FILES_DIR, {'pdf'})

	conn = get_db()
	conn.execute(
		'INSERT INTO projects(contest_id, title, description, link, author, avatar_path, attachment_path) VALUES (?, ?, ?, ?, ?, ?, ?)',
		(contest_id, title, description, link, author, avatar_rel, file_rel)
	)
	conn.commit()
	flash('Projekt dodany.', 'success')
	return redirect(url_for('admin_contest_detail', contest_id=contest_id))


# Contact page (moved from homepage)
@app.get('/contact')
def contact_get():
	return render_template('contact.html')


@app.post('/contact')
def contact_post():
	name = request.form.get('name', '').strip()
	email = request.form.get('email', '').strip()
	message = request.form.get('message', '').strip()

	if not name or not email or not message:
		flash('Wypełnij wszystkie pola.', 'error')
		return render_template('contact.html', name=name, email=email, message=message), 400

	if len(message) > 5000:
		flash('Wiadomość jest zbyt długa.', 'error')
		return render_template('contact.html', name=name, email=email, message=message), 400

	try:
		subject = f'Nowa wiadomość ze strony od {name}'
		body = f'Imię: {name}\nEmail: {email}\n\n{message}'
		send_email(subject, body, reply_to_email=email, reply_to_name=name)
		flash('Wiadomość wysłana. Dziękujemy!', 'success')
		return render_template('contact.html'), 200
	except Exception as exc:
		print(f'Error sending email: {exc}', flush=True)
		flash('Nie udało się wysłać wiadomości. Spróbuj ponownie później.', 'error')
		return render_template('contact.html', name=name, email=email, message=message), 500


@app.get('/healthz')
def healthz():
	return 'ok', 200


# Initialize DB and ensure admin
with app.app_context():
	init_db()
	ensure_admin()


if __name__ == '__main__':
	port = int(os.getenv('PORT', '3000'))
	app.run(host='0.0.0.0', port=port)
