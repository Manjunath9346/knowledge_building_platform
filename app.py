import os
os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'

import mysql.connector
import re
from flask import Flask, render_template, request, redirect, url_for, flash, session, send_from_directory, g, abort, jsonify
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from datetime import datetime
import config
import click
from flask.cli import with_appcontext
from functools import wraps
from math import ceil

# --- NEW IMPORTS for Email and Social Login (Google) ---
from flask_mail import Mail, Message
from flask_dance.contrib.google import make_google_blueprint, google



# --- AUTO THUMBNAIL GENERATOR ---
from PIL import Image, ImageDraw, ImageFont
import random

import subprocess

def get_video_duration_seconds(filepath):
    """Return duration in seconds for a video using ffprobe."""
    try:
        cmd = ['ffprobe', '-v', 'error',
               '-show_entries', 'format=duration',
               '-of', 'default=noprint_wrappers=1:nokey=1',
               filepath]
        out = subprocess.check_output(cmd, stderr=subprocess.STDOUT).decode().strip()
        return int(float(out)) if out else None
    except Exception as e:
        print(f"ffprobe error: {e}")
        return None

app = Flask(__name__)


def generate_auto_thumbnail(title, course_id):
    width, height = 600, 350
    img = Image.new("RGB", (width, height), (10, 10, 20))
    draw = ImageDraw.Draw(img)

    gradients = [
        (102, 126, 234),
        (118, 75, 162),
        (240, 147, 251),
        (245, 87, 108)
    ]

    r, g, b = random.choice(gradients)
    for y in range(height):
        blend = int(255 * (y / height))
        draw.line([(0, y), (width, y)], fill=(r, g, min(255, b + blend)))

    text = title[:22]
    try:
        font = ImageFont.truetype("arial.ttf", 40)
    except:
        font = ImageFont.load_default()

    bbox = draw.textbbox((0, 0), text, font=font)
    text_w = bbox[2] - bbox[0]
    text_h = bbox[3] - bbox[1]
    draw.text(((width - text_w) // 2, (height - text_h) // 2), text, font=font, fill="white")

    filename = f"auto_thumb_{course_id}.jpg"
    filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    img.save(filepath)

    return filename

app.secret_key = config.SECRET_KEY
app.config['UPLOAD_FOLDER'] = config.UPLOAD_FOLDER


os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# New constant for quiz pagination
QUESTIONS_PER_PAGE = 5 

# --- NEW MAIL CONFIGURATION ---
app.config['MAIL_SERVER'] = config.MAIL_SERVER
app.config['MAIL_PORT'] = config.MAIL_PORT
app.config['MAIL_USE_TLS'] = config.MAIL_USE_TLS
app.config['MAIL_USERNAME'] = config.MAIL_USERNAME
app.config['MAIL_PASSWORD'] = config.MAIL_PASSWORD
app.config['MAIL_DEFAULT_SENDER'] = config.MAIL_SENDER
mail = Mail(app)

# --- NEW EMAIL HELPER FUNCTION ---
def send_email(subject, recipients, html_body):
    """Sends an email using the configured Flask-Mail instance.""" 
    try:
        msg = Message(subject, recipients=recipients, html=html_body)
        mail.send(msg)
        print(f"Email sent successfully to: {', '.join(recipients)}")
        return True
    except Exception as e:
        # In a real app, you might log this error more formally
        print(f"ERROR: Failed to send email: {e}")
        return False
# ---------------------------------

# ---------------------------
# GOOGLE OAUTH FIXED CONFIG
# ---------------------------
# IMPORTANT: redirect_url must match the redirect URI you registered in
# Google Cloud Console (e.g. http://127.0.0.1:5000/login/google/authorized)

google_oauth = make_google_blueprint(
    client_id=config.GOOGLE_OAUTH_CLIENT_ID,
    client_secret=config.GOOGLE_OAUTH_CLIENT_SECRET,
    scope=[
        "openid",
        "https://www.googleapis.com/auth/userinfo.email",
        "https://www.googleapis.com/auth/userinfo.profile"
    ],
    redirect_to="after_google_login"
)

app.register_blueprint(google_oauth, url_prefix="/login")


@app.route("/after_google_login")
def after_google_login():
    if not google.authorized:
        flash("Google login failed.", "danger")
        return redirect(url_for("login"))

    resp = google.get("/oauth2/v2/userinfo")
    info = resp.json()

    email = info["email"]
    fullname = info.get("name", "")
    username = email.split("@")[0]

    user = execute_query(
        "SELECT * FROM users WHERE email=%s",
        (email,),
        one=True
    )

    is_new_user = False

    # If user doesn't exist — create new
    if not user:
        is_new_user = True
        execute_query(
            "INSERT INTO users (username, email, password, role, fullname, created_at) VALUES (%s,%s,%s,%s,%s,%s)",
            (username, email, "", "student", fullname, datetime.utcnow()),
            commit=True
        )
        user = execute_query(
            "SELECT * FROM users WHERE email=%s",
            (email,),
            one=True
        )

    # Login user
    session["user_id"] = user["id"]
    session["username"] = user["username"]
    session["role"] = user["role"]
    session["fullname"] = user["fullname"]

    # ------------------------------
    # ✅ SEND EMAIL FOR GOOGLE LOGIN
    # ------------------------------
    if is_new_user:
        # New Google account registration
        send_email(
            "Welcome to Knowledge Sea!",
            [email],
            f"""
            <h2>Hello, {fullname or username}!</h2>
            <p>Your Google account was successfully registered.</p>
            <p>You can now access all features inside Knowledge Sea.</p>
            """
        )
    else:
        # Existing user Google login
        send_email(
            "Google Login Successful",
            [email],
            f"""
            <h2>Hello, {fullname or username}!</h2>
            <p>You have successfully logged in using Google.</p>
            <p>If this was not you, please reset your password immediately.</p>
            """
        )
    # ------------------------------

    return redirect(url_for("index"))



# --- Database Functions ---
def get_db():
    if not hasattr(g, 'db'):
        g.db = mysql.connector.connect(**config.DB_CONFIG)
    return g.db

@app.teardown_appcontext
def close_db(exc):
    if hasattr(g, 'db'):
        g.db.close()

def execute_query(query, args=(), one=False, commit=False):
    db = get_db()
    cursor = db.cursor(dictionary=True)
    cursor.execute(query, args)
    if commit:
        db.commit()
        cursor.close()
        return None
    results = cursor.fetchall()
    cursor.close()
    if one:
        return results[0] if results else None
    return results

# --- Decorators and Helper Functions ---

def normalize_answer(answer):
    """Normalize answer string for robust, case-insensitive comparison.
    It removes leading/trailing whitespace, collapses internal whitespace, and converts to lowercase.
    """
    if not answer:
        return ""
    # Remove leading/trailing whitespace, collapse multiple internal spaces/newlines, and convert to lower case
    normalized = re.sub(r'\s+', ' ', answer.strip()).lower()
    return normalized

def login_required(f):
    @wraps(f)
    def wrapped(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please login first', 'warning')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return wrapped

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'role' not in session or session['role'] != 'admin':
            flash('You do not have permission to access this page.', 'danger')
            return redirect(url_for('index'))
        return f(*args, **kwargs)
    return decorated_function

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.',1)[1].lower() in config.ALLOWED_EXTENSIONS

# --- CLI Commands (Omitted for brevity) ---
@click.command('create-admin')
@with_appcontext
@click.argument('username')
@click.argument('password')
def create_admin_command(username, password):
    """Creates a new admin user."""
    hashed_password = generate_password_hash(password)
    try:
        db = mysql.connector.connect(**config.DB_CONFIG)
        cursor = db.cursor()
        cursor.execute(
            'INSERT INTO users (username, password, role, fullname, created_at) VALUES (%s, %s, %s, %s, %s)',
            (username, hashed_password, 'admin', 'Admin', datetime.utcnow())
        )
        db.commit()
        click.echo(f'Admin user {username} created successfully.')
    except mysql.connector.IntegrityError:
        click.echo(f'Error: Admin user {username} already exists.')
    except Exception as e:
        click.echo(f'An error occurred: {e}')
    finally:
        if db.is_connected():
            cursor.close()
            db.close()

app.cli.add_command(create_admin_command)




def init_db_command_logic():
    """Initializes the database and creates tables."""
    try:
        db = mysql.connector.connect(host=config.DB_CONFIG['host'], user=config.DB_CONFIG['user'], password=config.DB_CONFIG['password'])
        cursor = db.cursor()
        cursor.execute(f"CREATE DATABASE IF NOT EXISTS {config.DB_CONFIG['database']}")
        cursor.close()
        db.close()
        db = mysql.connector.connect(**config.DB_CONFIG)
        cursor = db.cursor()
        # --- Original Tables (Updated with email column) ---
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS users(
            id INT AUTO_INCREMENT PRIMARY KEY, username VARCHAR(255) UNIQUE, email VARCHAR(255) UNIQUE, password VARCHAR(255),
            role VARCHAR(50) DEFAULT 'student', fullname VARCHAR(255), created_at DATETIME
        )''')
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS courses(
            id INT AUTO_INCREMENT PRIMARY KEY, title TEXT, description TEXT, filename VARCHAR(255), filetype VARCHAR(50),
            thumbnail_filename VARCHAR(255), price DECIMAL(10, 2) DEFAULT 0.00, is_paid BOOLEAN DEFAULT 0,
            content_text LONGTEXT,
            uploaded_by INT, created_at DATETIME, FOREIGN KEY(uploaded_by) REFERENCES users(id) ON DELETE CASCADE
        )''')
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS subscriptions(
            id INT AUTO_INCREMENT PRIMARY KEY, subscriber_id INT, creator_id INT, created_at DATETIME,
            UNIQUE(subscriber_id, creator_id), FOREIGN KEY(subscriber_id) REFERENCES users(id) ON DELETE CASCADE,
            FOREIGN KEY(creator_id) REFERENCES users(id) ON DELETE CASCADE
        )''')
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS likes(
            user_id INT NOT NULL, course_id INT NOT NULL, created_at DATETIME NOT NULL, PRIMARY KEY (user_id, course_id),
            FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE, FOREIGN KEY(course_id) REFERENCES courses(id) ON DELETE CASCADE
        )''')
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS comments(
            id INT AUTO_INCREMENT PRIMARY KEY, content TEXT NOT NULL, user_id INT NOT NULL, course_id INT NOT NULL,
            created_at DATETIME NOT NULL, FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE,
            FOREIGN KEY(course_id) REFERENCES courses(id) ON DELETE CASCADE
        )''')
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS notifications(
            id INT AUTO_INCREMENT PRIMARY KEY, recipient_id INT NOT NULL, actor_id INT NOT NULL, action VARCHAR(255) NOT NULL,
            course_id INT, is_read BOOLEAN DEFAULT 0, created_at DATETIME NOT NULL,
            FOREIGN KEY(recipient_id) REFERENCES users(id) ON DELETE CASCADE, FOREIGN KEY(actor_id) REFERENCES users(id) ON DELETE CASCADE,
            FOREIGN KEY(course_id) REFERENCES courses(id) ON DELETE CASCADE
        )''')
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS reports(
            id INT AUTO_INCREMENT PRIMARY KEY, reporter_id INT NOT NULL, reported_course_id INT, reason TEXT NOT NULL,
            status VARCHAR(50) DEFAULT 'open', created_at DATETIME NOT NULL,
            FOREIGN KEY(reporter_id) REFERENCES users(id) ON DELETE CASCADE,
            FOREIGN KEY(reported_course_id) REFERENCES courses(id) ON DELETE CASCADE
        )''')
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS help_tickets(
            id INT AUTO_INCREMENT PRIMARY KEY, user_id INT NOT NULL, subject VARCHAR(255) NOT NULL, message TEXT NOT NULL,
            status VARCHAR(50) DEFAULT 'open', created_at DATETIME NOT NULL, FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
        )''')
        
        # --- New Tables for Watch Later & Playlists ---
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS watch_later (
            user_id INT NOT NULL,
            course_id INT NOT NULL,
            created_at DATETIME NOT NULL,
            PRIMARY KEY (user_id, course_id),
            FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE,
            FOREIGN KEY(course_id) REFERENCES courses(id) ON DELETE CASCADE
        )''')
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS playlists (
            id INT AUTO_INCREMENT PRIMARY KEY,
            user_id INT NOT NULL,
            name VARCHAR(255) NOT NULL,
            description TEXT,
            is_public BOOLEAN DEFAULT 0,
            created_at DATETIME NOT NULL,
            FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
        )''')
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS playlist_items (
            id INT AUTO_INCREMENT PRIMARY KEY,
            playlist_id INT NOT NULL,
            course_id INT NOT NULL,
            added_at DATETIME NOT NULL,
            UNIQUE(playlist_id, course_id),
            FOREIGN KEY(playlist_id) REFERENCES playlists(id) ON DELETE CASCADE,
            FOREIGN KEY(course_id) REFERENCES courses(id) ON DELETE CASCADE
        )''')

        # --- NEW TABLES FOR COURSE STRUCTURE ---
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS course_sections (
            id INT AUTO_INCREMENT PRIMARY KEY,
            course_id INT NOT NULL,
            title VARCHAR(255) NOT NULL,
            sequence_order INT NOT NULL,
            FOREIGN KEY(course_id) REFERENCES courses(id) ON DELETE CASCADE
        )
        ''')
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS section_lessons (
            id INT AUTO_INCREMENT PRIMARY KEY,
            section_id INT NULL,
            title VARCHAR(255) NOT NULL,
            content_type VARCHAR(50), 
            filename VARCHAR(255), 
            content_text TEXT, 
            sequence_order INT NOT NULL,
            is_standalone BOOLEAN NOT NULL DEFAULT 0,
            FOREIGN KEY(section_id) REFERENCES course_sections(id) ON DELETE CASCADE
        )
        ''')
        # --- END NEW TABLES FOR COURSE STRUCTURE ---
        
        # --- NEW TABLES FOR QUIZ/PRACTICE FEATURE ---
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS practice_topics(
            id INT AUTO_INCREMENT PRIMARY KEY, name VARCHAR(255) UNIQUE, description TEXT,
            category VARCHAR(50), 
            is_active BOOLEAN DEFAULT 1
        )
        ''')
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS quiz_questions (
            id INT AUTO_INCREMENT PRIMARY KEY,
            topic_id INT NOT NULL, 
            question_text TEXT NOT NULL,
            question_type VARCHAR(50) NOT NULL,
            code_snippet TEXT,
            correct_answer TEXT,
            explanation TEXT,
            difficulty INT DEFAULT 1,
            FOREIGN KEY(topic_id) REFERENCES practice_topics(id) ON DELETE CASCADE
        )
        ''')
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS quiz_options (
            id INT AUTO_INCREMENT PRIMARY KEY,
            question_id INT NOT NULL,
            option_text TEXT NOT NULL,
            is_correct BOOLEAN DEFAULT 0,
            FOREIGN KEY(question_id) REFERENCES quiz_questions(id) ON DELETE CASCADE
        )
        ''')
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS quiz_attempts (
            id INT AUTO_INCREMENT PRIMARY KEY,
            user_id INT NOT NULL,
            topic_id INT NOT NULL,
            score INT NOT NULL,
            total_questions INT NOT NULL,
            completed_at DATETIME NOT NULL,
            FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE,
            FOREIGN KEY(topic_id) REFERENCES practice_topics(id) ON DELETE CASCADE
        )
        ''')
        # ---------------------------------------------


        db.commit()
        cursor.close()
        db.close()
        print("Database initialized and all tables created successfully.")
    except mysql.connector.Error as err:
        print(f"Error during DB initialization: {err}")

@click.command('init-db')
@with_appcontext
def init_db_command():
    init_db_command_logic()

app.cli.add_command(init_db_command)

@app.context_processor
def inject_notifications():
    if 'user_id' in session:
        count_result = execute_query('SELECT COUNT(*) as count FROM notifications WHERE recipient_id = %s AND is_read = 0', (session['user_id'],), one=True)
        return dict(notification_count=count_result['count'])
    return dict(notification_count=0)

# ----------------- Routes -----------------
@app.route('/')
def index():
    courses = execute_query('SELECT c.*, u.username as uploader, u.id as uploader_id FROM courses c LEFT JOIN users u ON c.uploaded_by = u.id ORDER BY c.created_at DESC')
    subscribed_ids = []
    if 'user_id' in session:
        subs = execute_query('SELECT creator_id FROM subscriptions WHERE subscriber_id=%s', (session['user_id'],))
        subscribed_ids = [s['creator_id'] for s in subs]
    return render_template('index.html', courses=courses, subscribed_ids=subscribed_ids)

@app.route('/register', methods=['GET','POST'])
def register():
    if request.method == 'POST':
        username = request.form['username'].strip()
        email = request.form['email'].strip() 
        password = request.form['password']
        fullname = request.form.get('fullname','').strip()
        role = request.form.get('role','student')
        
        if not username or not email or not password:
            flash('Please provide username, email, and password', 'danger')
            return redirect(url_for('register'))
            
        # --- SECURE ADMIN CREATION LOGIC ---
        admin_count = execute_query("SELECT COUNT(*) as count FROM users WHERE role='admin'", one=True)
        
        if admin_count['count'] == 0:
            # If no admin exists, force the current user's role to 'admin'.
            role = 'admin'
        # -----------------------------------
            
        hashed = generate_password_hash(password)
        try:
            execute_query('INSERT INTO users (username, email, password, role, fullname, created_at) VALUES (%s,%s,%s,%s,%s,%s)', (username, email, hashed, role, fullname, datetime.utcnow()), commit=True)
            
            # --- NEW EMAIL SENDING LOGIC (Standard Registration) ---
            subject = "Welcome to Knowledge Sea!"
            body = f"""
                <h2>Hello, {fullname or username}!</h2>
                <p>Thank yourself for registering your new {'Admin' if role == 'admin' else 'Student'} account on Mini-Coursera. Your verified email is <strong>{email}</strong>.</p>
                <p>You can now explore and upload courses.</p>
                <p>Happy learning/teaching!</p>
            """
            send_email(subject, [email], body)
            # --------------------------------------------------------
            
            if role == 'admin':
                flash('Initial Admin account registered successfully. Please login.', 'success')
            else:
                flash('Registration successful. Please login.', 'success')
                
            return redirect(url_for('login'))
        except mysql.connector.IntegrityError:
            flash('Username or Email already exists', 'danger')
            return redirect(url_for('register'))
    return render_template('register.html')


@app.route('/login', methods=['GET','POST'])
def login():
    if request.method == 'POST':
        # Accepts either username or email
        login_id = request.form['login_id']
        password = request.form['password']
        
        # Check against both username and email columns
        user = execute_query('SELECT * FROM users WHERE username=%s OR email=%s', (login_id, login_id), one=True)
        
        if user and check_password_hash(user['password'], password):
            session['user_id'] = user['id']
            session['username'] = user['username']
            session['role'] = user['role']
            session['fullname'] = user['fullname']
            flash('Logged in successfully', 'success')

            # ------------------------------
            # ✅ SEND LOGIN SUCCESS EMAIL
            # ------------------------------
            send_email(
                "Login Successful - Knowledge Sea",
                [user['email']],
                f"""
                <h2>Hello, {user['fullname'] or user['username']}!</h2>
                <p>You have successfully logged into your Knowledge Sea account.</p>
                <p>If this wasn't you, please reset your password immediately.</p>
                """
            )
            # ------------------------------

            return redirect(url_for('index'))
        
        flash('Invalid credentials', 'danger')
    return render_template('login.html')

    

@app.route('/logout')
def logout():
    session.clear()
    flash('Logged out')
    return redirect(url_for('index'))

@app.route('/explore')
def explore():
    q = request.args.get('q', '').strip()
    filetype = request.args.get('filetype', 'all').strip()
    is_paid_filter = request.args.get('is_paid_filter', 'all').strip()

    sql = '''
        SELECT 
            c.*, 
            u.username AS uploader,
            u.id AS uploader_id,
            (SELECT COUNT(*) FROM course_sections WHERE course_id = c.id) AS section_count
        FROM courses c
        LEFT JOIN users u ON c.uploaded_by = u.id
    '''
    
    params = []
    filters = []

    if q:
        filters.append('(c.title LIKE %s OR c.description LIKE %s OR u.username LIKE %s)')
        params.extend([f"%{q}%", f"%{q}%", f"%{q}%"])

    if filetype != 'all':
        filters.append('c.filetype = %s')
        params.append(filetype)

    if is_paid_filter == 'free':
        filters.append('c.is_paid = 0')
    elif is_paid_filter == 'paid':
        filters.append('c.is_paid = 1')

    if filters:
        sql += ' WHERE ' + ' AND '.join(filters)

    sql += ' ORDER BY c.created_at DESC'

    courses = execute_query(sql, tuple(params))

    subscribed_ids = []
    if 'user_id' in session:
        subs = execute_query('SELECT creator_id FROM subscriptions WHERE subscriber_id=%s', (session['user_id'],))
        subscribed_ids = [s['creator_id'] for s in subs]

    file_types = execute_query('SELECT DISTINCT filetype FROM courses WHERE filetype IS NOT NULL AND filetype != ""')
    unique_file_types = [ft['filetype'] for ft in file_types]

    return render_template(
        'explore.html',
        courses=courses,
        subscribed_ids=subscribed_ids,
        q=q,
        filetype_filter=filetype,
        is_paid_filter=is_paid_filter,
        unique_file_types=unique_file_types
    )



# -------------------------
# Progress Tracking API
# -------------------------
@login_required
@app.route('/progress/update', methods=['POST'])
def progress_update():
    """
    Expects JSON:
    {
      "lesson_id": 123,
      "watched_seconds": 42,
      "duration_seconds": 120  // optional
    }
    """
    data = request.get_json(force=True, silent=True)
    if not data:
        return jsonify({"ok": False, "error": "Missing JSON payload"}), 400

    try:
        lesson_id = int(data.get('lesson_id') or 0)
        watched_seconds = int(data.get('watched_seconds') or 0)
    except Exception:
        return jsonify({"ok": False, "error": "Invalid numeric values"}), 400

    duration_seconds = data.get('duration_seconds')
    try:
        duration_seconds = int(duration_seconds) if duration_seconds is not None else None
    except:
        duration_seconds = None

    if lesson_id <= 0:
        return jsonify({"ok": False, "error": "Invalid lesson_id"}), 400

    user_id = session.get('user_id')
    if not user_id:
        return jsonify({"ok": False, "error": "Authentication required"}), 401

    # Prefer lesson's stored duration if available
    lesson_row = execute_query('SELECT duration_seconds FROM section_lessons WHERE id=%s', (lesson_id,), one=True)
    lesson_duration = lesson_row['duration_seconds'] if lesson_row and lesson_row.get('duration_seconds') else duration_seconds

    percent_complete = 0.0
    is_completed = False
    if lesson_duration and lesson_duration > 0:
        percent_complete = min(100.0, round((watched_seconds / lesson_duration) * 100.0, 2))
        is_completed = percent_complete >= 90.0
    else:
        # fallback: treat >=5min watched as complete
        if watched_seconds >= 300:
            percent_complete = 100.0
            is_completed = True
        else:
            percent_complete = min(100.0, round(watched_seconds / max(1, watched_seconds) * 100.0, 2))

    now = datetime.utcnow()

    try:
        execute_query('''
            INSERT INTO user_progress (user_id, lesson_id, watched_seconds, percent_complete, is_completed, last_watched_at)
            VALUES (%s, %s, %s, %s, %s, %s)
            ON DUPLICATE KEY UPDATE 
                watched_seconds = GREATEST(watched_seconds, VALUES(watched_seconds)),
                percent_complete = GREATEST(percent_complete, VALUES(percent_complete)),
                is_completed = is_completed OR VALUES(is_completed),
                last_watched_at = VALUES(last_watched_at)
        ''', (user_id, lesson_id, watched_seconds, percent_complete, is_completed, now), commit=True)

        # Notify creator when lesson is completed (optional)
        if is_completed:
            creator = execute_query('''
                SELECT c.uploaded_by as creator_id, c.id AS course_id 
                FROM section_lessons sl
                LEFT JOIN course_sections cs ON sl.section_id = cs.id
                LEFT JOIN courses c ON cs.course_id = c.id
                WHERE sl.id = %s
            ''', (lesson_id,), one=True)
            if creator and creator.get('creator_id') and creator['creator_id'] != user_id:
                execute_query('''
                    INSERT INTO notifications (recipient_id, actor_id, action, course_id, created_at)
                    VALUES (%s, %s, %s, %s, %s)
                ''', (creator['creator_id'], user_id, 'lesson_completed', creator.get('course_id'), datetime.utcnow()), commit=True)

        return jsonify({
            "ok": True,
            "lesson_id": lesson_id,
            "watched_seconds": watched_seconds,
            "percent_complete": float(percent_complete),
            "is_completed": bool(is_completed)
        })
    except Exception as e:
        app.logger.error(f"Progress update error: {e}")
        return jsonify({"ok": False, "error": "Database error"}), 500


# Optional: mark lesson complete manually (form POST)
@login_required
@app.route('/progress/complete', methods=['POST'])
def progress_mark_complete():
    lesson_id = int(request.form.get('lesson_id') or 0)
    user_id = session.get('user_id')
    if lesson_id <= 0:
        flash('Invalid lesson id', 'danger')
        return redirect(request.referrer or url_for('index'))

    now = datetime.utcnow()
    try:
        execute_query('''
            INSERT INTO user_progress (user_id, lesson_id, watched_seconds, percent_complete, is_completed, last_watched_at)
            VALUES (%s, %s, %s, %s, %s, %s)
            ON DUPLICATE KEY UPDATE
                watched_seconds = GREATEST(watched_seconds, VALUES(watched_seconds)),
                percent_complete = GREATEST(percent_complete, VALUES(percent_complete)),
                is_completed = 1,
                last_watched_at = VALUES(last_watched_at)
        ''', (user_id, lesson_id, 0, 100.0, 1, now), commit=True)
        flash('Lesson marked as complete', 'success')
    except Exception as e:
        app.logger.error(f"Mark complete error: {e}")
        flash('Failed to mark lesson complete', 'danger')

    return redirect(request.referrer or url_for('index'))


@app.route('/upload', methods=['GET','POST'])
@login_required
def upload():
    if request.method == 'POST':
        upload_mode = request.form.get('upload_mode', 'course')

        # Helper to save uploaded file
        def save_uploaded(file_obj, is_thumbnail=False):
            if not file_obj or not file_obj.filename:
                return None
            if not allowed_file(file_obj.filename):
                return None

            prefix = "thumb_" if is_thumbnail else ""
            filename = secure_filename(
                f"{prefix}{datetime.utcnow().strftime('%Y%m%d%H%M%S')}_{file_obj.filename}"
            )
            file_obj.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
            return filename

        # ==============================================================
        # 🚀 MODE 1: FULL COURSE UPLOAD
        # ==============================================================
        if upload_mode == 'course':
            title = request.form.get('title','').strip()
            description = request.form.get('description','').strip()
            is_paid = 1 if request.form.get('is_paid') == 'on' else 0
            price = float(request.form.get('price') or 0)
            category = request.form.get("category", "General")


   

            # Thumbnail (optional)
            thumbnail_file = request.files.get('thumbnail')
            thumbnail_filename = save_uploaded(thumbnail_file, is_thumbnail=True)

            # File (optional)
            course_file = request.files.get('file')
            filename = save_uploaded(course_file)
            filetype = filename.rsplit('.',1)[1].lower() if filename else None

            # Insert into DB with category
            cursor = get_db().cursor()
            cursor.execute('''
                INSERT INTO courses 
                (title, description, filename, filetype, thumbnail_filename,
                 price, is_paid, category, uploaded_by, created_at)
                VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
            ''', (
                title, description, filename, filetype, thumbnail_filename,
                price, is_paid, category, session['user_id'], datetime.utcnow()
            ))
            course_id = cursor.lastrowid
            get_db().commit()

            # Auto thumbnail
            if not thumbnail_filename:
                auto_thumb = generate_auto_thumbnail(title, course_id)
                cursor.execute("UPDATE courses SET thumbnail_filename=%s WHERE id=%s",
                               (auto_thumb, course_id))
                get_db().commit()

            cursor.close()
            flash('Course uploaded successfully. Now add sections & lessons!', 'success')
            return redirect(url_for('manage_course_content', course_id=course_id))

        # ==============================================================
        # 🚀 MODE 2: SINGLE CONTENT UPLOAD
        # ==============================================================
        elif upload_mode == 'single':
            stitle = request.form.get('single_title','').strip()
            stype = request.form.get('single_content_type','').strip()

            if not stitle or not stype:
                flash("Title & content type required.", "danger")
                return redirect(url_for("upload"))

            # Optional thumbnail
            s_thumbnail = save_uploaded(request.files.get('single_thumbnail'), is_thumbnail=True)

            sfilename, sfiletype, scontent_text = None, None, None

            if stype in ["video", "pdf"]:
                uploaded_file = request.files.get("single_file")
                sfilename = save_uploaded(uploaded_file)
                sfiletype = sfilename.rsplit('.', 1)[1].lower()

            elif stype == "text":
                scontent_text = request.form.get("single_text","").strip()
                sfiletype = "text"

            cursor = get_db().cursor()
            cursor.execute('''
                INSERT INTO courses 
                (title, description, filename, filetype, thumbnail_filename,
                 price, is_paid, content_text, category, uploaded_by, created_at)
                VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
            ''', (
                stitle, "",
                sfilename, sfiletype,
                s_thumbnail,
                0.00, 0,
                scontent_text,
                "General",  # default category
                session['user_id'],
                datetime.utcnow()
            ))
            course_id = cursor.lastrowid
            get_db().commit()

            # Auto Thumbnail
            if not s_thumbnail:
                auto_thumb = generate_auto_thumbnail(stitle, course_id)
                cursor.execute("UPDATE courses SET thumbnail_filename=%s WHERE id=%s",
                               (auto_thumb, course_id))
                get_db().commit()

            cursor.close()
            flash('Single content uploaded!', 'success')
            return redirect(url_for('course_detail', course_id=course_id))

        else:
            flash("Invalid upload mode.", "danger")
            return redirect(url_for("upload"))

    return render_template("upload.html")

@app.route('/course/<int:course_id>')
def course_detail(course_id):
    # Fetch course
    course = execute_query('''
        SELECT c.*, u.username as uploader, u.id as uploader_id 
        FROM courses c 
        LEFT JOIN users u ON c.uploaded_by = u.id 
        WHERE c.id=%s
    ''', (course_id,), one=True)

    if not course:
        flash('Course not found', 'danger')
        return redirect(url_for('explore'))

    # Fetch sections & lessons
    sections_query = '''
        SELECT cs.id, cs.title, cs.sequence_order
        FROM course_sections cs
        WHERE cs.course_id = %s
        ORDER BY cs.sequence_order ASC
    '''
    sections = execute_query(sections_query, (course_id,))

    for section in sections:
        lessons_query = '''
            SELECT sl.id, sl.title, sl.content_type, sl.filename, sl.content_text, sl.sequence_order
            FROM section_lessons sl
            WHERE sl.section_id = %s
            ORDER BY sl.sequence_order ASC
        '''
        section['lessons'] = execute_query(lessons_query, (section['id'],))

    course['sections'] = sections

    # ---- Likes / Subscriptions / Watch Later ----
    subscribed = liked = watch_later = False

    if 'user_id' in session:

        # Subscription status
        sub = execute_query(
            'SELECT 1 FROM subscriptions WHERE subscriber_id=%s AND creator_id=%s',
            (session['user_id'], course['uploader_id']),
            one=True
        )
        subscribed = sub is not None

        # Like status
        like_check = execute_query(
            'SELECT 1 FROM likes WHERE user_id=%s AND course_id=%s',
            (session['user_id'], course_id),
            one=True
        )
        liked = like_check is not None

        # Watch Later
        watch_later_check = execute_query(
            'SELECT 1 FROM watch_later WHERE user_id=%s AND course_id=%s',
            (session['user_id'], course_id),
            one=True
        )
        watch_later = watch_later_check is not None

    # Like count
    like_count = execute_query(
        'SELECT COUNT(*) as count FROM likes WHERE course_id=%s',
        (course_id,), one=True
    )['count']

    # Comments
    comments = execute_query('''
        SELECT c.*, u.username 
        FROM comments c 
        JOIN users u ON c.user_id = u.id 
        WHERE c.course_id = %s 
        ORDER BY c.created_at DESC
    ''', (course_id,))

    # ---- QUIZ availability (optional) ----
    quiz_exists_res = execute_query(
        'SELECT COUNT(*) as count FROM quiz_questions WHERE topic_id IN (SELECT id FROM practice_topics WHERE name LIKE %s)',
        (f"%{course['title']}%",),
        one=True
    )
    quiz_exists = quiz_exists_res['count'] > 0 if quiz_exists_res else False

    # ---- NEW: Load user's playlists for playlist popup ----
    playlists = []
    if 'user_id' in session:
        playlists = execute_query(
            "SELECT id, name FROM playlists WHERE user_id=%s ORDER BY created_at DESC",
            (session['user_id'],)
        )

    # Render page
    return render_template(
        'course_detail.html',
        course=course,
        subscribed=subscribed,
        liked=liked,
        watch_later=watch_later,
        like_count=like_count,
        comments=comments,
        quiz_exists=quiz_exists,
        playlists=playlists   # ⭐ IMPORTANT
    )



@app.route('/report/course/<int:course_id>', methods=['GET', 'POST'])
@login_required
def report_course(course_id):
    # Ensure course exists and fetch its title for the report page
    course = execute_query('SELECT id, title FROM courses WHERE id=%s', (course_id,), one=True)
    if not course:
        flash('Course not found.', 'danger')
        return redirect(url_for('explore'))

    if request.method == 'POST':
        reason = request.form.get('reason', '').strip()
        if not reason:
            flash('Reason is required.', 'danger')
            return redirect(url_for('report_course', course_id=course_id))

        try:
            # Insert report with status
            execute_query(
                '''INSERT INTO reports (reporter_id, reported_course_id, reason, status, created_at)
                   VALUES (%s, %s, %s, %s, %s)''',
                (session['user_id'], course_id, reason, 'open', datetime.utcnow()),
                commit=True
            )

            # Notify admins
            admins = execute_query("SELECT id FROM users WHERE role = 'admin'")
            for admin in admins:
                execute_query(
                    '''INSERT INTO notifications (recipient_id, actor_id, action, course_id, created_at)
                       VALUES (%s, %s, %s, %s, %s)''',
                    (admin['id'], session['user_id'], 'report', course_id, datetime.utcnow()),
                    commit=True
                )

            flash('Report submitted successfully. Admin will review it.', 'success')

            # --- NEW: Fetch user email and send confirmation ---
            reporter_details = execute_query('SELECT email, fullname FROM users WHERE id=%s', (session['user_id'],), one=True)
            if reporter_details:
                reporter_email = reporter_details['email']
                reporter_name = reporter_details['fullname'] or session['username']
                
                email_subject = f"Confirmation: Your Report for Course '{course['title']}'"
                email_body = f"""
                    <h2>Dear {reporter_name},</h2>
                    <p>We confirm receipt of your report regarding the course: <strong>{course['title']}</strong>.</p>
                    <p>Reason provided: "{reason[:150]}..."</p>
                    <p>The report status is currently <strong>open</strong>. Our administration team will review it.</p>
                    <p>Thank yourself for helping us maintain a safe community.</p>
                """
                send_email(email_subject, [reporter_email], email_body)
            # ----------------------------------------------------


        except mysql.connector.Error as e:
            # Debugging code: prints full error to console and shows error number to user
            print(f"MySQL Error during report submission: {e}") 
            flash(f'Failed to submit report. Database Error: {e.errno}. Please check server logs.', 'danger')

        return redirect(url_for('course_detail', course_id=course_id))

    # Handle GET request: Show the report form page
    return render_template('report.html', course=course)
@app.route('/view/lesson/<int:lesson_id>')
def view_lesson(lesson_id):
    lesson = execute_query('''
        SELECT sl.*, cs.course_id AS course_id
        FROM section_lessons sl
        LEFT JOIN course_sections cs ON sl.section_id = cs.id
        WHERE sl.id = %s
    ''', (lesson_id,), one=True)
    if not lesson:
        flash('Lesson content not found.', 'danger')
        return redirect(url_for('explore'))

    course_title = None
    if lesson.get('course_id'):
        course = execute_query('SELECT id, title FROM courses WHERE id=%s', (lesson['course_id'],), one=True)
        if course:
            course_title = course['title']

    user_progress = None
    if 'user_id' in session:
        user_progress = execute_query('SELECT percent_complete, watched_seconds, is_completed FROM user_progress WHERE user_id=%s AND lesson_id=%s', (session['user_id'], lesson_id), one=True)

    return render_template('view_lesson.html', lesson=lesson, course_title=course_title, user_progress=user_progress)

# MODIFIED: view_course is removed as content is structured. download_course kept for legacy/single-file upload.

@app.route('/course/<int:course_id>/download')
@login_required
def download_course(course_id):
    course = execute_query('SELECT * FROM courses WHERE id=%s', (course_id,), one=True)
    if not course or not course['filename']:
        flash('File not available to download')
        return redirect(url_for('course_detail', course_id=course_id))
    return send_from_directory(app.config['UPLOAD_FOLDER'], course['filename'], as_attachment=True)

@app.route('/course/<int:course_id>/edit', methods=['GET','POST'])
@login_required
def edit_course(course_id):
    course = execute_query('SELECT * FROM courses WHERE id=%s', (course_id,), one=True)
    if not course:
        flash('Course not found')
        return redirect(url_for('explore'))
    if course['uploaded_by'] != session['user_id']:
        flash('Unauthorized')
        return redirect(url_for('course_detail', course_id=course_id))
    if request.method == 'POST':
        title = request.form['title'].strip()
        description = request.form.get('description','').strip()
        is_paid = 1 if request.form.get('is_paid')=='on' else 0
        price = float(request.form.get('price') or 0)
        file = request.files.get('file')
        thumbnail = request.files.get('thumbnail')
        filename, filetype, thumbnail_filename = course['filename'], course['filetype'], course['thumbnail_filename']
        if thumbnail and thumbnail.filename:
            if allowed_file(thumbnail.filename):
                if thumbnail_filename:
                    try: os.remove(os.path.join(app.config['UPLOAD_FOLDER'], thumbnail_filename))
                    except OSError: pass
                thumbnail_filename = secure_filename(f"thumb_{datetime.utcnow().strftime('%Y%m%d%H%M%S')}_{thumbnail.filename}")
                thumbnail.save(os.path.join(app.config['UPLOAD_FOLDER'], thumbnail_filename))
            else:
                flash('New thumbnail file type not allowed')
                return redirect(url_for('edit_course', course_id=course_id))
        if file and file.filename:
            if allowed_file(file.filename):
                if filename:
                    try: os.remove(os.path.join(app.config['UPLOAD_FOLDER'], filename))
                    except OSError: pass
                filename = secure_filename(f"{datetime.utcnow().strftime('%Y%m%d%H%M%S')}_{file.filename}")
                file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
                filetype = filename.rsplit('.',1)[1].lower()
            else:
                flash('New course file type not allowed')
                return redirect(url_for('edit_course', course_id=course_id))
        # If content_text is provided in edit form, update it
        content_text = request.form.get('content_text')
        if content_text is not None:
            execute_query('UPDATE courses SET title=%s, description=%s, filename=%s, filetype=%s, thumbnail_filename=%s, price=%s, is_paid=%s, content_text=%s WHERE id=%s', (title, description, filename, filetype, thumbnail_filename, price, is_paid, content_text, course_id), commit=True)
        else:
            execute_query('UPDATE courses SET title=%s, description=%s, filename=%s, filetype=%s, thumbnail_filename=%s, price=%s, is_paid=%s WHERE id=%s', (title, description, filename, filetype, thumbnail_filename, price, is_paid, course_id), commit=True)
        flash('Course updated successfully')
        return redirect(url_for('course_detail', course_id=course_id))
    return render_template('edit_course.html', course=course)

@app.route('/course/<int:course_id>/delete', methods=['POST'])
@login_required
def delete_course(course_id):
    course = execute_query('SELECT * FROM courses WHERE id=%s', (course_id,), one=True)
    if not course:
        flash('Course not found')
        return redirect(url_for('explore'))
    if course['uploaded_by'] != session['user_id']:
        flash('Unauthorized')
        return redirect(url_for('course_detail', course_id=course_id))
    try:
        if course['filename']: os.remove(os.path.join(app.config['UPLOAD_FOLDER'], course['filename']))
        if course['thumbnail_filename']: os.remove(os.path.join(app.config['UPLOAD_FOLDER'], course['thumbnail_filename']))
    except OSError: pass
    execute_query('DELETE FROM courses WHERE id=%s', (course_id,), commit=True)
    flash('Course deleted')
    return redirect(url_for('explore'))

@app.route('/subscribe/<int:creator_id>', methods=['POST'])
@login_required
def subscribe(creator_id):
    if creator_id == session['user_id']:
        flash('Cannot subscribe to yourself')
        return redirect(request.referrer or url_for('explore'))
    try:
        execute_query('INSERT INTO subscriptions (subscriber_id, creator_id, created_at) VALUES (%s, %s, %s)', (session['user_id'], creator_id, datetime.utcnow()), commit=True)
        execute_query('INSERT INTO notifications (recipient_id, actor_id, action, created_at) VALUES (%s, %s, %s, %s)', (creator_id, session['user_id'], 'subscribe', datetime.utcnow()), commit=True)
        flash('Subscribed to creator')
        
        # --- NEW: Send subscription confirmation email to subscriber ---
        subscriber_details = execute_query('SELECT email, fullname FROM users WHERE id=%s', (session['user_id'],), one=True)
        creator_details = execute_query('SELECT username FROM users WHERE id=%s', (creator_id,), one=True)
        
        if subscriber_details and creator_details:
            subscriber_email = subscriber_details['email']
            subscriber_name = subscriber_details['fullname'] or session['username']
            
            email_subject = f"Subscription Confirmed: Following {creator_details['username']}"
            email_body = f"""
                <h2>Dear {subscriber_name},</h2>
                <p>You have successfully subscribed to the content creator <strong>{creator_details['username']}</strong>.</p>
                <p>You will now receive notifications when they upload new content.</p>
                <p>Thank you for supporting our creators!</p>
            """
            send_email(email_subject, [subscriber_email], email_body)
        # --------------------------------------------------------------

    except mysql.connector.IntegrityError:
        flash('Already subscribed')
    return redirect(request.referrer or url_for('explore'))

@app.route('/unsubscribe/<int:creator_id>', methods=['POST'])
@login_required
def unsubscribe(creator_id):
    execute_query('DELETE FROM subscriptions WHERE subscriber_id=%s AND creator_id=%s', (session['user_id'], creator_id), commit=True)
    flash('Unsubscribed')
    return redirect(request.referrer or url_for('explore'))

@app.route('/creator/<username>')
def creator_page(username):
    creator = execute_query('SELECT * FROM users WHERE username=%s', (username,), one=True)
    if not creator:
        flash('Creator not found')
        return redirect(url_for('explore'))
    courses = execute_query('SELECT * FROM courses WHERE uploaded_by=%s ORDER BY created_at DESC', (creator['id'],))
    subscribed_ids = []
    if 'user_id' in session:
        subs = execute_query('SELECT creator_id FROM subscriptions WHERE subscriber_id=%s', (session['user_id'],))
        subscribed_ids = [s['creator_id'] for s in subs]
    return render_template('creator.html', creator=creator, courses=courses, subscribed_ids=subscribed_ids)

@app.route('/media/<path:filename>')
def media(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename, as_attachment=False)

@app.route('/account', methods=['GET','POST'])
@login_required
def account():
    user = execute_query('SELECT * FROM users WHERE id=%s', (session['user_id'],), one=True)
    if request.method == 'POST':
        new_fullname = request.form.get('fullname','').strip()
        current_password = request.form.get('current_password','')
        new_password = request.form.get('new_password','')
        if new_fullname and new_fullname != user['fullname']:
            execute_query('UPDATE users SET fullname=%s WHERE id=%s', (new_fullname, session['user_id']), commit=True)
            session['fullname'] = new_fullname
            flash('Full name updated')
        if new_password:
            if not current_password or not check_password_hash(user['password'], current_password):
                flash('Current password is incorrect. Password not changed.')
            else:
                hashed = generate_password_hash(new_password)
                execute_query('UPDATE users SET password=%s WHERE id=%s', (hashed, session['user_id']), commit=True)
                flash('Password updated successfully')
        return redirect(url_for('account'))
    uploads = execute_query('SELECT * FROM courses WHERE uploaded_by=%s ORDER BY created_at DESC', (session['user_id'],))
    subs = execute_query('SELECT u.* FROM subscriptions s JOIN users u ON s.creator_id = u.id WHERE s.subscriber_id=%s', (session['user_id'],))
    return render_template('account.html', user=user, uploads=uploads, subs=subs)

@app.route('/like/<int:course_id>', methods=['POST'])
@login_required
def like_course(course_id):
    course = execute_query('SELECT * FROM courses WHERE id=%s', (course_id,), one=True)
    if not course:
        flash('Course not found')
        return redirect(request.referrer or url_for('explore'))
    try:
        execute_query('INSERT INTO likes (user_id, course_id, created_at) VALUES (%s, %s, %s)', (session['user_id'], course_id, datetime.utcnow()), commit=True)
        if course['uploaded_by'] != session['user_id']:
            execute_query('INSERT INTO notifications (recipient_id, actor_id, action, course_id, created_at) VALUES (%s, %s, %s, %s, %s)', (course['uploaded_by'], session['user_id'], 'like', course_id, datetime.utcnow()), commit=True)
    except mysql.connector.IntegrityError:
        flash('You have already liked this course.')
    return redirect(request.referrer or url_for('course_detail', course_id=course_id))

@app.route('/unlike/<int:course_id>', methods=['POST'])
@login_required
def unlike_course(course_id):
    execute_query('DELETE FROM likes WHERE user_id=%s AND course_id=%s', (session['user_id'], course_id), commit=True)
    return redirect(request.referrer or url_for('course_detail', course_id=course_id))

@app.route('/course/<int:course_id>/comment', methods=['POST'])
@login_required
def post_comment(course_id):
    content = request.form.get('content', '').strip()
    if not content:
        flash('Comment cannot be empty.')
        return redirect(url_for('course_detail', course_id=course_id))
    course = execute_query('SELECT * FROM courses WHERE id=%s', (course_id,), one=True)
    if course:
        execute_query('INSERT INTO comments (content, user_id, course_id, created_at) VALUES (%s, %s, %s, %s)', (content, session['user_id'], course_id, datetime.utcnow()), commit=True)
        if course['uploaded_by'] != session['user_id']:
            execute_query('INSERT INTO notifications (recipient_id, actor_id, action, course_id, created_at) VALUES (%s, %s, %s, %s, %s)', (course['uploaded_by'], session['user_id'], 'comment', course_id, datetime.utcnow()), commit=True)
        flash('Comment posted.')
    else:
        flash('Course not found.')
    return redirect(url_for('course_detail', course_id=course_id))

@app.route('/notifications')
@login_required
def notifications():
    user_notifications = execute_query('''
        SELECT n.*, a.username as actor_username, c.title as course_title
        FROM notifications n JOIN users a ON n.actor_id = a.id LEFT JOIN courses c ON n.course_id = c.id
        WHERE n.recipient_id = %s ORDER BY n.created_at DESC
    ''', (session['user_id'],))
    execute_query('UPDATE notifications SET is_read = 1 WHERE recipient_id = %s', (session['user_id'],), commit=True)
    processed_notifications = []
    for n in user_notifications:
        notification = dict(n)
        if session.get('role') == 'admin':
            if notification['action'] == 'report':
                notification['url'] = url_for('admin_dashboard') + '#reports-panel'
            elif notification['action'] == 'help_ticket':
                notification['url'] = url_for('admin_dashboard') + '#tickets-panel'
            else:
                 notification['url'] = url_for('course_detail', course_id=notification['course_id']) if notification['course_id'] else '#'
        else:
            notification['url'] = url_for('course_detail', course_id=notification['course_id']) if notification['course_id'] else '#'
        processed_notifications.append(notification)
    return render_template('notifications.html', notifications=processed_notifications)

@app.route('/dashboard')
@login_required
def dashboard():
    user_id = session['user_id']
    course_count_res = execute_query('SELECT COUNT(*) as count FROM courses WHERE uploaded_by = %s', (user_id,), one=True)
    subscriber_count_res = execute_query('SELECT COUNT(*) as count FROM subscriptions WHERE creator_id = %s', (user_id,), one=True)
    total_likes_res = execute_query('SELECT COUNT(*) as count FROM likes l JOIN courses c ON l.course_id = c.id WHERE c.uploaded_by = %s', (user_id,), one=True)
    total_comments_res = execute_query('SELECT COUNT(*) as count FROM comments cm JOIN courses c ON cm.course_id = c.id WHERE c.uploaded_by = %s', (user_id,), one=True)
    course_count = course_count_res['count'] if course_count_res else 0
    subscriber_count = subscriber_count_res['count'] if subscriber_count_res else 0
    total_likes = total_likes_res['count'] if total_likes_res else 0
    total_comments = total_comments_res['count'] if total_comments_res else 0
    
    # COMBINED RECENT ACTIVITY QUERY (Notifications + Quiz Attempts)
    recent_activity_query = '''
        (
            -- Notifications: Actions on the user's content (recipient is the user)
            SELECT n.created_at, n.action, a.username as actor_username, c.title as content_title, n.course_id as content_id, NULL as score_info
            FROM notifications n 
            JOIN users a ON n.actor_id = a.id 
            LEFT JOIN courses c ON n.course_id = c.id
            WHERE n.recipient_id = %s AND n.action IN ('like', 'comment', 'subscribe')
        )
        UNION ALL
        (
            -- Quiz Attempts: User's own quiz history (actor is the user)
            SELECT qa.completed_at as created_at, 'quiz_attempt' as action, u.username as actor_username, pt.name as content_title, pt.id as content_id, CONCAT(qa.score, '/', qa.total_questions) as score_info
            FROM quiz_attempts qa
            JOIN users u ON qa.user_id = u.id 
            JOIN practice_topics pt ON qa.topic_id = pt.id
            WHERE qa.user_id = %s
        )
        ORDER BY created_at DESC
        LIMIT 10
    '''
    
    # Pass user_id twice for the two separate SELECT statements in the UNION
    recent_activity = execute_query(recent_activity_query, (user_id, user_id))

    return render_template('dashboard.html', course_count=course_count, subscriber_count=subscriber_count, total_likes=total_likes, total_comments=total_comments, recent_activity=recent_activity)

# --- Admin Routes ---


@app.route('/admin')
@login_required
@admin_required
def admin_dashboard():
    all_users = execute_query('SELECT id, username, fullname, role, created_at FROM users ORDER BY created_at DESC')
    all_courses = execute_query('''
        SELECT c.id, c.title, u.username as uploader
        FROM courses c
        JOIN users u ON c.uploaded_by = u.id
        ORDER BY c.created_at DESC
    ''')
    reports = execute_query('''
        SELECT r.*, reporter.username as reporter_username, course.title as course_title
        FROM reports r
        JOIN users reporter ON r.reporter_id = reporter.id
        LEFT JOIN courses course ON r.reported_course_id = course.id
        ORDER BY r.created_at DESC
    ''')
    help_tickets = execute_query('''
        SELECT h.*, u.username as username
        FROM help_tickets h
        JOIN users u ON h.user_id = u.id
        ORDER BY h.created_at DESC
    ''')

    # Practice Topics
    topics = execute_query('''
        SELECT pt.*, COUNT(qq.id) as question_count
        FROM practice_topics pt
        LEFT JOIN quiz_questions qq ON pt.id = qq.topic_id
        GROUP BY pt.id
        ORDER BY pt.category ASC, pt.name ASC
    ''')

    # -----------------------
    # NEW ANALYTICS DATA
    # -----------------------
    total_users = execute_query("SELECT COUNT(*) as c FROM users", one=True)['c']
    total_courses = execute_query("SELECT COUNT(*) as c FROM courses", one=True)['c']
    total_lessons = execute_query("SELECT COUNT(*) as c FROM section_lessons", one=True)['c']

    daily_signups = execute_query("""
        SELECT DATE(created_at) AS day, COUNT(*) AS count
        FROM users
        WHERE created_at >= DATE_SUB(CURDATE(), INTERVAL 7 DAY)
        GROUP BY DATE(created_at)
        ORDER BY day ASC
    """)

    daily_uploads = execute_query("""
        SELECT DATE(created_at) AS day, COUNT(*) AS count
        FROM courses
        WHERE created_at >= DATE_SUB(CURDATE(), INTERVAL 7 DAY)
        GROUP BY DATE(created_at)
        ORDER BY day ASC
    """)

    top_creators = execute_query("""
        SELECT u.username, COUNT(s.subscriber_id) AS subs
        FROM subscriptions s
        JOIN users u ON s.creator_id = u.id
        GROUP BY s.creator_id
        ORDER BY subs DESC
        LIMIT 5
    """)

    top_courses = execute_query("""
        SELECT c.title, COUNT(l.user_id) AS likes
        FROM likes l
        JOIN courses c ON l.course_id = c.id
        GROUP BY l.course_id
        ORDER BY likes DESC
        LIMIT 5
    """)

    return render_template(
        'admin_dashboard.html',
        users=all_users,
        courses=all_courses,
        reports=reports,
        help_tickets=help_tickets,
        topics=topics,
        total_users=total_users,
        total_courses=total_courses,
        total_lessons=total_lessons,
        daily_signups=daily_signups,
        daily_uploads=daily_uploads,
        top_creators=top_creators,
        top_courses=top_courses
    )



@app.route('/admin/delete_user/<int:user_id>', methods=['POST'])
@login_required
@admin_required
def admin_delete_user(user_id):
    user_to_delete = execute_query('SELECT * FROM users WHERE id = %s', (user_id,), one=True)
    if not user_to_delete:
        flash('User not found.', 'danger')
        return redirect(url_for('admin_dashboard'))
    if user_to_delete['role'] == 'admin':
        flash('Cannot delete an admin account.', 'danger')
        return redirect(url_for('admin_dashboard'))
    execute_query('DELETE FROM users WHERE id = %s', (user_id,), commit=True)
    flash(f"User '{user_to_delete['username']}' and all their content have been deleted.", 'success')
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/delete_course/<int:course_id>', methods=['POST'])
@login_required
@admin_required
def admin_delete_course(course_id):
    course_to_delete = execute_query('SELECT * FROM courses WHERE id = %s', (course_id,), one=True)
    if not course_to_delete:
        flash('Course not found.', 'danger')
        return redirect(url_for('admin_dashboard'))
    try:
        if course_to_delete['filename']: os.remove(os.path.join(app.config['UPLOAD_FOLDER'], course_to_delete['filename']))
        if course_to_delete['thumbnail_filename']: os.remove(os.path.join(app.config['UPLOAD_FOLDER'], course_to_delete['thumbnail_filename']))
    except OSError: pass
    execute_query('DELETE FROM courses WHERE id = %s', (course_id,), commit=True)
    flash(f"Course '{course_to_delete['title']}' has been deleted.", 'success')
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/update_status/<item_type>/<int:item_id>', methods=['POST'])
@login_required
@admin_required
def update_status(item_type, item_id):
    new_status = request.form.get('status')
    if item_type == 'report':
        execute_query('UPDATE reports SET status = %s WHERE id = %s', (new_status, item_id), commit=True)
        flash('Report status updated.', 'success')
    elif item_type == 'ticket':
        execute_query('UPDATE help_tickets SET status = %s WHERE id = %s', (new_status, item_id), commit=True)
        flash('Help ticket status updated.', 'success')
    return redirect(url_for('admin_dashboard'))

# --- NEW COURSE CONTENT MANAGEMENT ROUTES ---

def check_course_owner(course_id):
    course = execute_query('SELECT uploaded_by FROM courses WHERE id=%s', (course_id,), one=True)
    if not course or course['uploaded_by'] != session.get('user_id'):
        return False
    return course

@app.route('/course/<int:course_id>/manage', methods=['GET'])
@login_required
def manage_course_content(course_id):
    course_data = check_course_owner(course_id)
    if not course_data:
        flash('Unauthorized access or course not found.', 'danger')
        return redirect(url_for('explore'))

    course = execute_query('SELECT * FROM courses WHERE id=%s', (course_id,), one=True)
    
    sections_query = '''
        SELECT cs.id, cs.title, cs.sequence_order, COUNT(sl.id) as lesson_count
        FROM course_sections cs
        LEFT JOIN section_lessons sl ON cs.id = sl.section_id
        WHERE cs.course_id = %s
        GROUP BY cs.id
        ORDER BY cs.sequence_order ASC
    '''
    sections = execute_query(sections_query, (course_id,))
    
    for section in sections:
        lessons_query = '''
            SELECT sl.id, sl.title, sl.content_type, sl.sequence_order
            FROM section_lessons sl
            WHERE sl.section_id = %s
            ORDER BY sl.sequence_order ASC
        '''
        section['lessons'] = execute_query(lessons_query, (section['id'],))

    return render_template('manage_course_content.html', course=course, sections=sections)

# Section Management
@app.route('/course/<int:course_id>/section/add', methods=['POST'])
@login_required
def add_section(course_id):
    if not check_course_owner(course_id):
        flash('Unauthorized access.', 'danger')
        return redirect(url_for('explore'))

    title = request.form['title'].strip()
    if not title:
        flash('Section title is required.', 'danger')
        return redirect(url_for('manage_course_content', course_id=course_id))

    # Determine next sequence order
    order_res = execute_query('SELECT MAX(sequence_order) as max_order FROM course_sections WHERE course_id=%s', (course_id,), one=True)
    next_order = (order_res['max_order'] or 0) + 1

    execute_query(
        'INSERT INTO course_sections (course_id, title, sequence_order) VALUES (%s, %s, %s)',
        (course_id, title, next_order), commit=True
    )
    flash(f'Section "{title}" added successfully.', 'success')
    return redirect(url_for('manage_course_content', course_id=course_id))



# Lesson Management (Add/Edit)
@app.route('/section/<int:section_id>/lesson/add', methods=['GET', 'POST'])
@login_required
def add_lesson(section_id):
    # FIX APPLIED: Ensure 'id' is selected for Jinja to access section.id
    section = execute_query('SELECT id, course_id, title FROM course_sections WHERE id=%s', (section_id,), one=True)
    if not section or not check_course_owner(section['course_id']):
        flash('Unauthorized access or section not found.', 'danger')
        return redirect(url_for('explore'))
        
    course_id = section['course_id']

    if request.method == 'POST':
        title = request.form['title'].strip()
        content_type = request.form['content_type']
        content_text = request.form.get('content_text', '').strip()
        file = request.files.get('file')
        
        filename = None

        # Handle file uploads (video, pdf, doc)
        if content_type in ['video', 'pdf', 'document']:
            if file and file.filename:
                if not allowed_file(file.filename):
                    flash(f'File type for {content_type} not allowed.', 'danger')
                    return redirect(request.referrer)

                filename = secure_filename(f"{datetime.utcnow().strftime('%Y%m%d%H%M%S')}_{file.filename}")
                file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
            else:
                flash('File required for this content type.', 'danger')
                return redirect(request.referrer)

        # Determine next sequence order
        order_res = execute_query(
            'SELECT MAX(sequence_order) AS max_order FROM section_lessons WHERE section_id=%s',
            (section_id,), one=True
        )
        next_order = (order_res['max_order'] or 0) + 1

        # ----------------------------
        #  NEW: Video Duration Finder
        # ----------------------------
        duration_seconds = None
        if content_type == 'video' and filename:
            saved_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            duration_seconds = get_video_duration_seconds(saved_path)

        # Insert lesson with video duration
        execute_query(
            '''
            INSERT INTO section_lessons 
            (section_id, title, content_type, filename, content_text, sequence_order, duration_seconds)
            VALUES (%s, %s, %s, %s, %s, %s, %s)
            ''',
            (section_id, title, content_type, filename, content_text, next_order, duration_seconds),
            commit=True
        )

        flash(f'Lesson "{title}" added successfully.', 'success')
        return redirect(url_for('manage_course_content', course_id=course_id))

    return render_template('add_lesson.html', section=section)


# Delete Lesson/Section (Simplified POST requests)
@app.route('/section/<int:section_id>/delete', methods=['POST'])
@login_required
def delete_section(section_id):
    section = execute_query('SELECT course_id, title FROM course_sections WHERE id=%s', (section_id,), one=True)
    if not section or not check_course_owner(section['course_id']):
        flash('Unauthorized access.', 'danger')
        return redirect(url_for('explore'))
        
    course_id = section['course_id']
    # MySQL ON DELETE CASCADE handles deletion of associated lessons
    execute_query('DELETE FROM course_sections WHERE id=%s', (section_id,), commit=True)
    flash(f'Section "{section["title"]}" and all its lessons deleted.', 'success')
    return redirect(url_for('manage_course_content', course_id=course_id))

@app.route('/lesson/<int:lesson_id>/delete', methods=['POST'])
@login_required
def delete_lesson(lesson_id):
    lesson = execute_query('SELECT sl.title, cs.course_id FROM section_lessons sl JOIN course_sections cs ON sl.section_id = cs.id WHERE sl.id=%s', (lesson_id,), one=True)
    if not lesson or not check_course_owner(lesson['course_id']):
        flash('Unauthorized access.', 'danger')
        return redirect(url_for('explore'))
        
    course_id = lesson['course_id']
    execute_query('DELETE FROM section_lessons WHERE id=%s', (lesson_id,), commit=True)
    flash(f'Lesson "{lesson["title"]}" deleted.', 'success')
    return redirect(url_for('manage_course_content', course_id=course_id))

# --- NEW PRACTICE ADMIN UPLOAD ROUTES ---

@app.route('/admin/add_topic', methods=['GET', 'POST'])
@login_required
@admin_required
def admin_add_topic():
    if request.method == 'POST':
        name = request.form['name'].strip()
        description = request.form.get('description', '').strip()
        category = request.form.get('category', 'Aptitude').strip()
        
        if not name:
            flash('Topic name is required.', 'danger')
            return redirect(url_for('admin_add_topic'))
            
        try:
            execute_query('INSERT INTO practice_topics (name, description, category) VALUES (%s, %s, %s)', 
                          (name, description, category), commit=True)
            flash(f'Practice Topic "{name}" added successfully.', 'success')
            return redirect(url_for('admin_dashboard') + '#practice-panel')
        except mysql.connector.IntegrityError:
            flash('A topic with this name already exists.', 'danger')
        
    return render_template('admin_add_topic.html')

@app.route('/admin/add_question/<int:topic_id>', methods=['GET', 'POST'])
@login_required
@admin_required
def admin_add_question(topic_id):
    topic = execute_query('SELECT * FROM practice_topics WHERE id=%s', (topic_id,), one=True)
    if not topic:
        flash('Topic not found.', 'danger')
        return redirect(url_for('admin_dashboard') + '#practice-panel')
        
    if request.method == 'POST':
        question_text = request.form['question_text'].strip()
        question_type = request.form['question_type']
        explanation = request.form.get('explanation', '').strip()
        code_snippet = request.form.get('code_snippet', '').strip()
        correct_answer = None
        
        if not question_text:
            flash('Question text is required.', 'danger')
            return redirect(url_for('admin_add_question', topic_id=topic_id))

        try:
            # 1. Insert the main question
            if question_type == 'mcq' or (question_type in ['aptitude', 'coding'] and request.form.get('option_1')):
                
                # Check if the correct option radio button was selected (required for any MCQ flow)
                correct_option_index = int(request.form.get('correct_option', 0))
                if correct_option_index == 0:
                    flash('You must select the correct option using the radio button.', 'danger')
                    return redirect(url_for('admin_add_question', topic_id=topic_id))
                    
                # Insert question first, get its ID
                cursor = get_db().cursor()
                cursor.execute(
                    'INSERT INTO quiz_questions (topic_id, question_text, question_type, code_snippet, explanation) VALUES (%s, %s, %s, %s, %s)',
                    (topic_id, question_text, question_type, code_snippet, explanation)
                )
                question_id = cursor.lastrowid
                
                # 2. Insert all options (Handles dynamic options from the form keys)
                options = {}
                for key in request.form:
                    if key.startswith('option_'):
                        try:
                            # Use key as a unique identifier for the option form field
                            options[key] = request.form.get(key, '').strip()
                        except ValueError:
                            continue

                correct_option_id = None
                
                for key, opt_text in options.items():
                    # Determine if this is the correct option based on its index
                    option_number = int(key.split('_')[1])
                    is_correct = (option_number == correct_option_index)

                    if opt_text:
                        cursor.execute(
                            'INSERT INTO quiz_options (question_id, option_text, is_correct) VALUES (%s, %s, %s)',
                            (question_id, opt_text, is_correct)
                        )
                        if is_correct:
                            correct_option_id = cursor.lastrowid

                # 3. Update the question with the correct option ID
                if correct_option_id:
                    cursor.execute('UPDATE quiz_questions SET correct_answer = %s WHERE id = %s', (correct_option_id, question_id))
                
                get_db().commit()
                cursor.close()
                flash('MCQ question and options added successfully.', 'success')

            elif question_type in ['coding', 'aptitude']:
                correct_answer = request.form.get('correct_answer', '').strip()
                if not correct_answer:
                     flash('Correct Answer/Output is required for this question type.', 'danger')
                     return redirect(url_for('admin_add_question', topic_id=topic_id))
                     
                execute_query(
                    'INSERT INTO quiz_questions (topic_id, question_text, question_type, code_snippet, correct_answer, explanation) VALUES (%s, %s, %s, %s, %s, %s)',
                    (topic_id, question_text, question_type, code_snippet, correct_answer, explanation), commit=True
                )
                flash(f'{question_type.capitalize()} problem added successfully (Text Answer).', 'success')
            
            # NOTE: Redirecting to the new single-question view entry point
            return redirect(url_for('practice_topic_detail', topic_id=topic_id))

        except Exception as e:
            flash(f'An unexpected error occurred: {e}', 'danger')
            return redirect(url_for('admin_add_question', topic_id=topic_id))

    # Fetch existing questions and options for display/management
    questions = execute_query('SELECT * FROM quiz_questions WHERE topic_id=%s ORDER BY id DESC', (topic_id,),)
    for q in questions:
        q['options'] = execute_query('SELECT * FROM quiz_options WHERE question_id=%s ORDER BY id ASC', (q['id'],))
        
    return render_template('admin_add_question.html', topic=topic, questions=questions)

# --- NEW QUESTION DELETION ROUTE ---

@app.route('/admin/delete_question/<int:question_id>', methods=['POST'])
@login_required
@admin_required
def admin_delete_question(question_id):
    """Deletes a quiz question and cascades to options and attempts."""
    question = execute_query('SELECT topic_id, question_text FROM quiz_questions WHERE id=%s', (question_id,), one=True)
    if not question:
        flash('Question not found.', 'danger')
        return redirect(request.referrer or url_for('admin_dashboard') + '#practice-panel')
        
    topic_id = question['topic_id']
    
    # Deleting the question triggers cascade deletion of options and attempts
    execute_query('DELETE FROM quiz_questions WHERE id=%s', (question_id,), commit=True)
    
    flash(f'Question "{question["question_text"][:30]}..." successfully deleted.', 'success')
    # Redirect back to the question addition page for the same topic
    return redirect(url_for('admin_add_question', topic_id=topic_id))

# --- NEW PRACTICE OPTION DELETION ROUTE (FIXED) ---

@app.route('/admin/delete_option/<int:option_id>', methods=['POST'])
@login_required
@admin_required
def admin_delete_option(option_id):
    option = execute_query('SELECT * FROM quiz_options WHERE id=%s', (option_id,), one=True)
    if not option:
        flash('Option not found.', 'danger')
        return redirect(request.referrer or url_for('admin_dashboard') + '#practice-panel')
        
    question_id = option['question_id']
    question = execute_query('SELECT * FROM quiz_questions WHERE id=%s', (question_id,), one=True)
    topic_id = question['topic_id'] if question else None

    # 1. Check if the deleted option was the correct answer
    if question and str(question['correct_answer']) == str(option_id):
        # If it was the correct answer, reset the correct_answer for the question to NULL
        execute_query('UPDATE quiz_questions SET correct_answer = NULL WHERE id = %s', (question_id,), commit=True)
        flash('Warning: The correct option was deleted. Please re-edit the question and select a new correct option.', 'warning')
    
    # 2. Delete the option
    execute_query('DELETE FROM quiz_options WHERE id=%s', (option_id,), commit=True)
    
    flash('Option deleted successfully.', 'success')
    return redirect(url_for('admin_add_question', topic_id=topic_id) if topic_id else url_for('admin_dashboard') + '#practice-panel')

# --- END NEW PRACTICE ADMIN UPLOAD ROUTES ---

@app.route('/help', methods=['GET', 'POST'])
def help_center():
    if request.method == 'POST':
        if 'user_id' not in session:
            flash('You must be logged in to submit a help request.', 'warning')
            return redirect(url_for('login'))
        subject = request.form.get('subject')
        message = request.form.get('message')
        if not subject or not message:
            flash('Subject and message are required.', 'danger')
            return render_template('help_center.html')
            
        execute_query('INSERT INTO help_tickets (user_id, subject, message, created_at) VALUES (%s, %s, %s, %s)', (session['user_id'], subject, message, datetime.utcnow()), commit=True)
        
        admins = execute_query("SELECT id FROM users WHERE role = 'admin'")
        for admin in admins:
            execute_query('INSERT INTO notifications (recipient_id, actor_id, action, created_at) VALUES (%s, %s, %s, %s)', (admin['id'], session['user_id'], 'help_ticket', datetime.utcnow()), commit=True)
        
        flash('Your help request has been sent. An admin will get back to you soon.', 'success')

        # --- NEW: Send help request confirmation email to user ---
        user_details = execute_query('SELECT email, fullname FROM users WHERE id=%s', (session['user_id'],), one=True)
        if user_details:
            user_email = user_details['email']
            user_name = user_details['fullname'] or session['username']
            
            email_subject = f"Confirmation: Help Request Received ({subject[:50]}...)"
            email_body = f"""
                <h2>Dear {user_name},</h2>
                <p>We have received your help request with the subject: <strong>{subject}</strong>.</p>
                <p>Our team is currently reviewing your message and will respond as soon as possible.</p>
                <p>You will receive a notification and a direct email response once your ticket is handled.</p>
            """
            send_email(email_subject, [user_email], email_body)
        # --------------------------------------------------------
        
        return redirect(url_for('index'))
    return render_template('help_center.html')

# --- NEW ROUTES FOR WATCH LATER & PLAYLISTS (Omitted for brevity) ---
@app.route('/watch_later/<int:course_id>', methods=['POST'])
@login_required
def add_to_watch_later(course_id):
    course = execute_query('SELECT id FROM courses WHERE id=%s', (course_id,), one=True)
    if not course:
        flash('Course not found', 'danger')
        return redirect(request.referrer or url_for('explore'))
    try:
        execute_query('INSERT INTO watch_later (user_id, course_id, created_at) VALUES (%s, %s, %s)',
                      (session['user_id'], course_id, datetime.utcnow()), commit=True)
        flash('Course added to Watch Later.', 'success')
    except mysql.connector.IntegrityError:
        flash('Course is already in your Watch Later list.', 'info')
    return redirect(request.referrer or url_for('course_detail', course_id=course_id))

@app.route('/watch_later/remove/<int:course_id>', methods=['POST'])
@login_required
def remove_from_watch_later(course_id):
    execute_query('DELETE FROM watch_later WHERE user_id=%s AND course_id=%s',
                  (session['user_id'], course_id), commit=True)
    flash('Course removed from Watch Later.', 'success')
    return redirect(request.referrer or url_for('course_detail', course_id=course_id))


@app.route('/playlists')
@login_required
def view_playlists():
    user_id = session['user_id']

    user_playlists = execute_query('''
        SELECT p.*, 
               (SELECT COUNT(*) FROM playlist_items WHERE playlist_id = p.id) AS course_count
        FROM playlists p
        WHERE p.user_id = %s
        ORDER BY p.created_at DESC
    ''', (user_id,))

    liked_courses = execute_query('''
        SELECT c.*, u.username as uploader, u.id as uploader_id 
        FROM likes l
        JOIN courses c ON l.course_id = c.id
        JOIN users u ON c.uploaded_by = u.id
        WHERE l.user_id = %s
    ''', (user_id,))

    watch_later_courses = execute_query('''
        SELECT c.*, u.username as uploader, u.id as uploader_id 
        FROM watch_later wl
        JOIN courses c ON wl.course_id = c.id
        JOIN users u ON c.uploaded_by = u.id
        WHERE wl.user_id = %s
    ''', (user_id,))

    subscribed_courses = execute_query('''
        SELECT c.*, u.username as uploader, u.id as uploader_id
        FROM subscriptions s
        JOIN courses c ON s.creator_id = c.uploaded_by
        JOIN users u ON c.uploaded_by = u.id
        WHERE s.subscriber_id = %s
    ''', (user_id,))

    return render_template(
        'playlists.html',
        user_playlists=user_playlists,
        liked_courses=liked_courses,
        watch_later_courses=watch_later_courses,
        subscribed_courses=subscribed_courses
    )





@app.route('/playlist/<int:playlist_id>')
@login_required
def view_single_playlist(playlist_id):

    # Fetch playlist info
    playlist = execute_query('''
        SELECT *
        FROM playlists
        WHERE id = %s AND user_id = %s
    ''', (playlist_id, session['user_id']), one=True)

    if not playlist:
        flash("Playlist not found.", "danger")
        return redirect(url_for('view_playlists'))

    # Fetch all courses inside playlist
    courses = execute_query('''
        SELECT c.*, u.username as uploader
        FROM playlist_items pi
        JOIN courses c ON pi.course_id = c.id
        JOIN users u ON c.uploaded_by = u.id
        WHERE pi.playlist_id = %s
        ORDER BY pi.added_at DESC
    ''', (playlist_id,))

    return render_template(
        'view_playlist.html',
        playlist=playlist,
        courses=courses
    )

# -------------------------
# PLAYLIST: CREATE NEW PLAYLIST + ADD COURSE
# -------------------------

@app.route('/playlist/create/<int:course_id>', methods=['POST'])
@login_required
def create_playlist(course_id):

    playlist_name = request.form.get('name')

    if not playlist_name:
        flash("Playlist name cannot be empty", "warning")
        return redirect(url_for('course_detail', course_id=course_id))

    conn = mysql.connector.connect(**config.DB_CONFIG)
    cursor = conn.cursor(dictionary=True)

    # INSERT playlist WITH created_at
    cursor.execute("""
        INSERT INTO playlists (user_id, name, created_at)
        VALUES (%s, %s, %s)
    """, (session['user_id'], playlist_name, datetime.utcnow()))

    playlist_id = cursor.lastrowid

    # INSERT into playlist_items WITH added_at
    cursor.execute("""
        INSERT INTO playlist_items (playlist_id, course_id, added_at)
        VALUES (%s, %s, %s)
    """, (playlist_id, course_id, datetime.utcnow()))

    conn.commit()
    cursor.close()
    conn.close()

    flash("Playlist created and course added!", "success")
    return redirect(url_for('course_detail', course_id=course_id))




# -------------------------
# PLAYLIST: ADD COURSE TO EXISTING PLAYLIST
# -------------------------


@app.route('/playlist/add/<int:course_id>', methods=['POST'])
@login_required
def add_to_playlist(course_id):

    playlist_id = request.form.get('playlist_id')

    conn = mysql.connector.connect(**config.DB_CONFIG)
    cursor = conn.cursor()

    cursor.execute("""
        SELECT id FROM playlist_items 
        WHERE playlist_id = %s AND course_id = %s
    """, (playlist_id, course_id))
    exists = cursor.fetchone()

    if exists:
        flash("Already in this playlist", "info")
    else:
        cursor.execute("""
            INSERT INTO playlist_items (playlist_id, course_id, added_at)
            VALUES (%s, %s, %s)
        """, (playlist_id, course_id, datetime.utcnow()))
        conn.commit()
        flash("Added to playlist!", "success")

    cursor.close()
    conn.close()

    return redirect(url_for('course_detail', course_id=course_id))




# ----------------- NEW PRACTICE ROUTES (Quiz/Test Mode) -----------------
@app.route('/practice')
def practice_center():
    """Displays a list of all Aptitude, Logical, and Coding topics."""
    # Logic to count questions per topic (for display on the practice center)
    topics = execute_query('''
        SELECT pt.*, COUNT(qq.id) as question_count
        FROM practice_topics pt
        LEFT JOIN quiz_questions qq ON pt.id = qq.topic_id
        WHERE pt.is_active = 1
        GROUP BY pt.id
        ORDER BY pt.name ASC
    ''')
    
    return render_template('quiz_practice.html', topics=topics)

@app.route('/practice/topic/<int:topic_id>')
@login_required
def practice_topic_detail(topic_id):
    """Entry point to the quiz mode, sets up the session and redirects to the first page."""
    topic = execute_query('SELECT * FROM practice_topics WHERE id=%s', (topic_id,), one=True)
    if not topic:
        flash('Practice topic not found', 'danger')
        return redirect(url_for('practice_center'))
    
    # Start the timer and clear/init answers for a new quiz session for this topic
    session['quiz_start_time'] = datetime.utcnow().timestamp()
    session['quiz_topic_id'] = topic_id
    session['quiz_answers'] = {} # Store answers across pages
    
    # Redirect to the first page of the Quiz
    return redirect(url_for('quiz_view', topic_id=topic_id, page=1))


@app.route('/practice/topic/<int:topic_id>/page/<int:page>', methods=['GET', 'POST'])
@login_required
def quiz_view(topic_id, page):
    """Shows 5 questions per page for the quiz mode, with pagination."""
    topic = execute_query('SELECT * FROM practice_topics WHERE id=%s', (topic_id,), one=True)
    
    # Security check for valid session/topic
    if not topic or session.get('quiz_topic_id') != topic_id:
        flash('Quiz session expired or invalid topic. Restarting quiz.', 'danger')
        return redirect(url_for('practice_topic_detail', topic_id=topic_id))

    # 1. Handle previous page submission (POST request for navigation)
    if request.method == 'POST':
        # Save answers from the current page before navigating
        for key, value in request.form.items():
            if key.startswith('answer_'):
                q_id = int(key.split('_')[1])
                session['quiz_answers'][q_id] = value.strip()
                
        # Handle button actions
        if 'next_page' in request.form:
            next_page = page + 1
            return redirect(url_for('quiz_view', topic_id=topic_id, page=next_page))
        elif 'prev_page' in request.form:
            prev_page = page - 1
            # Navigation logic will ensure prev_page is never < 1
            return redirect(url_for('quiz_view', topic_id=topic_id, page=prev_page))
        
        # If the button pressed was 'finish_quiz', proceed to scoring
        elif 'finish_quiz' in request.form:
            # Reroute to submission which will now lead to results page
            return redirect(url_for('submit_quiz', topic_id=topic_id))

    # 2. Fetch questions for the current page (GET request)
    
    # Get total count for pagination math
    total_count_res = execute_query('SELECT COUNT(*) as count FROM quiz_questions WHERE topic_id=%s', (topic_id,), one=True)
    total_questions = total_count_res['count'] if total_count_res else 0
    total_pages = ceil(total_questions / QUESTIONS_PER_PAGE) if total_questions > 0 else 0

    if total_questions == 0:
        flash(f'No questions found for topic: {topic["name"]}.', 'warning')
        # Clear quiz session if there are no questions
        session.pop('quiz_start_time', None)
        session.pop('quiz_topic_id', None)
        session.pop('quiz_answers', None)
        return redirect(url_for('practice_center'))

    # Check if page is out of bounds
    if page < 1: page = 1
    if page > total_pages: page = total_pages
        
    # Calculate offset and limits
    offset = (page - 1) * QUESTIONS_PER_PAGE
    limit = QUESTIONS_PER_PAGE
        
    # Fetch questions for the current page
    # FIX: Building the query string for LIMIT/OFFSET directly to prevent the driver from quoting the integers.
    query_fragment = f"LIMIT {limit} OFFSET {offset}"
    
    questions = execute_query(f'''
        SELECT * FROM quiz_questions WHERE topic_id=%s ORDER BY id ASC {query_fragment}
    ''', (topic_id,)) # Pass only the topic_id as a parameter
    
    # Fetch options and inject user's previous answer
    for q in questions:
        q['options'] = execute_query('SELECT * FROM quiz_options WHERE question_id=%s ORDER BY id ASC', (q['id'],))
        # Inject the user's stored answer for this question ID
        q['user_answer'] = session['quiz_answers'].get(q['id'])
    
    # Fetch user's history (attempts) for sidebar display
    attempts = execute_query('SELECT score, total_questions, completed_at FROM quiz_attempts WHERE user_id = %s AND topic_id = %s ORDER BY completed_at DESC', (session['user_id'], topic_id))
    
    # Calculate elapsed time for the timer display
    elapsed_time = int(datetime.utcnow().timestamp() - session['quiz_start_time']) if 'quiz_start_time' in session else 0

    return render_template('topic_questions.html', 
                           topic=topic, 
                           questions=questions,
                           current_page=page,
                           total_pages=total_pages,
                           total_questions=total_questions,
                           questions_per_page=QUESTIONS_PER_PAGE,
                           attempts=attempts,
                           elapsed_time=elapsed_time)


@app.route('/practice/topic/<int:topic_id>/submit', methods=['GET', 'POST'])
@login_required
def submit_quiz(topic_id):
    # 1. Process last page's form submission if it was a POST request
    if request.method == 'POST':
        for key, value in request.form.items():
            if key.startswith('answer_'):
                q_id = int(key.split('_')[1])
                session['quiz_answers'][q_id] = value.strip()

    quiz_topic_id = session.get('quiz_topic_id')
    quiz_start_time = session.get('quiz_start_time')
    
    if quiz_topic_id != topic_id:
        flash('Invalid quiz submission.', 'danger')
        return redirect(url_for('practice_center'))

    topic_name_res = execute_query('SELECT name FROM practice_topics WHERE id=%s', (topic_id,), one=True)
    topic_name = topic_name_res['name'] if topic_name_res else 'Quiz Topic'
    
    # 2. Get all questions and options for scoring and displaying results
    questions_data = execute_query('SELECT * FROM quiz_questions WHERE topic_id = %s ORDER BY id ASC', (topic_id,))
    
    final_results = []
    score = 0
    total_questions = len(questions_data)

    for q in questions_data:
        user_answer_id_or_text = session['quiz_answers'].get(q['id'], '').strip()
        is_correct = False
        
        result_item = {
            'question_text': q['question_text'],
            'question_type': q['question_type'],
            'code_snippet': q['code_snippet'],
            'explanation': q['explanation'],
            'user_answer': user_answer_id_or_text,
            'is_correct': False,
            'correct_answer_display': q['correct_answer'] # Default for coding/aptitude (plain text)
        }
        
        if q['question_type'] == 'mcq':
            options = execute_query('SELECT id, option_text, is_correct FROM quiz_options WHERE question_id=%s ORDER BY id ASC', (q['id'],))
            result_item['options'] = options
            # Find the correct option text and check score
            correct_option = next((opt for opt in options if opt['is_correct'] == 1), None)
            if correct_option:
                result_item['correct_answer_display'] = correct_option['option_text']
                # Check if user's submitted option ID matches the correct option ID
                if user_answer_id_or_text and str(user_answer_id_or_text) == str(correct_option['id']):
                    is_correct = True
            
        elif q['question_type'] in ['coding', 'aptitude']:
            # Check score for text answers
            if normalize_answer(user_answer_id_or_text) == normalize_answer(q['correct_answer']):
                is_correct = True

        if is_correct:
            score += 1
        result_item['is_correct'] = is_correct
        final_results.append(result_item)

    # 3. Record the attempt in the database
    execute_query(
        'INSERT INTO quiz_attempts (user_id, topic_id, score, total_questions, completed_at) VALUES (%s, %s, %s, %s, %s)',
        (session['user_id'], topic_id, score, total_questions, datetime.utcnow()), commit=True
    )
    
    # Calculate total time taken
    time_taken_seconds = 0
    if quiz_start_time:
        time_taken_seconds = int(datetime.utcnow().timestamp() - quiz_start_time)

    # Store final results, score, and time in session for the results page
    session['quiz_final_score'] = score
    session['quiz_total_questions'] = total_questions
    session['quiz_time_taken'] = time_taken_seconds
    session['quiz_detailed_results'] = final_results
    session['quiz_results_topic_name'] = topic_name
    
    # 4. Clear the quiz session data (except for the final results)
    session.pop('quiz_start_time', None)
    session.pop('quiz_topic_id', None)
    session.pop('quiz_answers', None)
        
    # 5. Redirect to the new results page
    return redirect(url_for('quiz_results', topic_id=topic_id))

@app.route('/practice/topic/<int:topic_id>/results')
@login_required
def quiz_results(topic_id):
    """Displays the final score and detailed results."""
    # Retrieve data from session
    score = session.get('quiz_final_score')
    total_questions = session.get('quiz_total_questions')
    time_taken = session.get('quiz_time_taken')
    detailed_results = session.get('quiz_detailed_results')
    topic_name = session.get('quiz_results_topic_name')
    
    # Clear final results from session after retrieval
    session.pop('quiz_final_score', None)
    session.pop('quiz_total_questions', None)
    session.pop('quiz_time_taken', None)
    session.pop('quiz_detailed_results', None)
    session.pop('quiz_results_topic_name', None)

    if score is None or detailed_results is None:
        flash("Quiz results not found. Please try the quiz again.", 'danger')
        return redirect(url_for('practice_topic_detail', topic_id=topic_id))
        
    return render_template('quiz_results.html',
                           topic_id=topic_id,
                           topic_name=topic_name,
                           score=score,
                           total_questions=total_questions,
                           time_taken=time_taken,
                           results=detailed_results)

if __name__ == '__main__':
    app.run(debug=True, port=5000)
