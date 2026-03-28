import os

BASE_DIR = os.path.abspath(os.path.dirname(__file__))

# -------------------------
# DATABASE CONFIG (SAFE)
# -------------------------
DB_CONFIG = {
    'host': os.environ.get("DB_HOST"),
    'user': os.environ.get("DB_USER"),
    'password': os.environ.get("DB_PASSWORD"),
    'database': os.environ.get("DB_NAME")
}

# -------------------------
# FILE UPLOAD CONFIG
# -------------------------
UPLOAD_FOLDER = os.path.join(BASE_DIR, 'static', 'uploads')

ALLOWED_EXTENSIONS = {
    'pdf', 'docx', 'doc', 'txt',
    'pptx', 'ppt', 'mp4', 'mp3',
    'wav', 'jpg', 'png', 'zip'
}

SECRET_KEY = os.environ.get("SECRET_KEY", "dev-secret-key")

# -------------------------
# EMAIL CONFIG (SAFE)
# -------------------------
MAIL_SERVER = "smtp.gmail.com"
MAIL_PORT = 587
MAIL_USE_TLS = True

MAIL_USERNAME = os.environ.get("MAIL_USERNAME")
MAIL_PASSWORD = os.environ.get("MAIL_PASSWORD")
MAIL_SENDER = os.environ.get("MAIL_SENDER")

# -------------------------
# GOOGLE OAUTH CONFIG (SAFE)
# -------------------------
GOOGLE_OAUTH_CLIENT_ID = os.environ.get("GOOGLE_CLIENT_ID")
GOOGLE_OAUTH_CLIENT_SECRET = os.environ.get("GOOGLE_CLIENT_SECRET")