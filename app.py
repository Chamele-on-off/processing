# app.py
import os
import logging
import secrets
from logging.handlers import RotatingFileHandler
from datetime import datetime, timedelta
from functools import wraps
import uuid
import random

from flask import Flask, render_template, jsonify, request, session, send_from_directory, redirect, url_for
from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.utils import secure_filename

from database import YAMLDatabase

# Инициализация логгера
def setup_logger():
    logger = logging.getLogger(__name__)
    logger.setLevel(logging.DEBUG)
    
    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    
    console_handler = logging.StreamHandler()
    console_handler.setFormatter(formatter)
    logger.addHandler(console_handler)
    
    file_handler = RotatingFileHandler(
        'processing_platform.log',
        maxBytes=1024 * 1024,
        backupCount=3
    )
    file_handler.setFormatter(formatter)
    logger.addHandler(file_handler)
    
    return logger

logger = setup_logger()

# Инициализация базы данных
def initialize_database():
    try:
        db = YAMLDatabase()
        logger.info("Database initialized successfully")
        return db
    except Exception as e:
        logger.error(f"Database initialization failed: {str(e)}")
        raise

# Вспомогательные функции
def authenticate(email, password, db):
    user = db.find_one('users', {'email': email})
    if user and check_password_hash(user['password_hash'], password):
        return user
    return None

def get_current_user(db):
    if 'user_id' in session:
        return db.find_one('users', {'id': int(session['user_id'])})
    return None

def allowed_file(filename, allowed_extensions):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in allowed_extensions

def calculate_avg_processing_time(db):
    transactions = db.find('transactions') or []
    completed = [t for t in transactions 
                if isinstance(t, dict) and 
                t.get('status') == 'completed' and 
                isinstance(t.get('created_at'), str) and 
                isinstance(t.get('completed_at'), str)]
    
    if not completed:
        return 0
    
    total_seconds = 0
    for t in completed:
        try:
            created = datetime.fromisoformat(t['created_at'])
            completed_dt = datetime.fromisoformat(t['completed_at'])
            total_seconds += (completed_dt - created).total_seconds()
        except (ValueError, TypeError) as e:
            logger.error(f"Error calculating processing time: {str(e)}")
            continue
    
    return round((total_seconds / len(completed)) / 60, 2)

def assign_random_trader(db, logger):
    try:
        traders = [
            u for u in (db.find('users') or [])
            if isinstance(u, dict) and 
               u.get('role') == 'trader' and 
               u.get('status', 'inactive') == 'active'
        ]

        if not traders:
            logger.warning("No active traders available")
            return None

        selected_trader = random.choice(traders)
        trader_id = int(selected_trader['id'])
        logger.info(f"Assigned trader {trader_id} to transaction")
        return trader_id

    except Exception as e:
        logger.error(f"Error in assign_random_trader: {str(e)}")
        return None

# Декораторы
def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'user_id' not in session:
            if request.is_json:
                return jsonify({'error': 'Authentication required'}), 401
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated

def role_required(role):
    def decorator(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            user = get_current_user(db)
            if not user or user.get('role') != role:
                if request.is_json:
                    return jsonify({'error': 'Forbidden'}), 403
                return redirect(url_for('home'))
            return f(*args, **kwargs)
        return decorated
    return decorator

def csrf_protect(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if request.method in ('POST', 'PUT', 'PATCH', 'DELETE'):
            token = request.headers.get('X-CSRF-Token') or request.form.get('csrf_token')
            if not token or token != session.get('csrf_token'):
                if request.is_json:
                    return jsonify({'error': 'Invalid CSRF token'}), 403
                return render_template('403.html'), 403
        return f(*args, **kwargs)
    return decorated

# Форматирование даты для Jinja2
def format_datetime(value, format='%d.%m.%Y %H:%M'):
    if value is None:
        return ""
    if isinstance(value, str):
        try:
            value = datetime.fromisoformat(value)
        except ValueError:
            return value
    return value.strftime(format)

# Создание Flask приложения
db = initialize_database()
app = Flask(__name__, template_folder='templates', static_folder='static')

# Конфигурация приложения
app.secret_key = os.environ.get('SECRET_KEY', 'super-secret-key-123')
app.config.update(
    SESSION_COOKIE_NAME='processing_session',
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SECURE=False,
    SESSION_COOKIE_SAMESITE='Lax',
    PERMANENT_SESSION_LIFETIME=timedelta(hours=1),
    UPLOAD_FOLDER='uploads',
    ALLOWED_EXTENSIONS={'pdf'}
)

# Создание папки для загрузок
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# Настройка Jinja2
app.jinja_env.filters['datetimeformat'] = format_datetime
app.jinja_env.globals.update(zip=zip)

# Генерация CSRF токена
@app.before_request
def generate_csrf_token():
    if 'csrf_token' not in session:
        session['csrf_token'] = secrets.token_hex(16)

# Основные маршруты
@app.route('/')
def home():
    user = get_current_user(db)
    if user:
        return redirect(url_for(f"{user['role']}_dashboard"))
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'GET':
        user = get_current_user(db)
        if user:
            return redirect(url_for(f"{user['role']}_dashboard"))
        return render_template('login.html')

    try:
        data = request.get_json() if request.is_json else request.form
        email = data.get('email', '').strip().lower()
        password = data.get('password', '')

        if not email or not password:
            logger.warning("Empty email or password")
            error = {'error': 'Email and password are required'}
            return jsonify(error), 400 if request.is_json else render_template('login.html', error=error['error']), 400

        user = authenticate(email, password, db)
        if not user:
            logger.warning(f"Failed login attempt for {email}")
            error = {'error': 'Invalid credentials'}
            return jsonify(error), 401 if request.is_json else render_template('login.html', error=error['error']), 401

        session.clear()
        session['user_id'] = int(user['id'])
        session['role'] = user['role']
        session.permanent = True
        logger.info(f"User {email} logged in successfully")

        response = {
            'success': True,
            'redirect': url_for(f"{user['role']}_dashboard")
        }
        return jsonify(response) if request.is_json else redirect(response['redirect'])

    except Exception as e:
        logger.error(f"Login error: {str(e)}")
        error = {'error': 'Internal server error'}
        return jsonify(error), 500 if request.is_json else render_template('login.html', error=error['error']), 500

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('home'))

# Статические файлы
@app.route('/static/<path:path>')
def serve_static(path):
    return send_from_directory('static', path)

@app.route('/assets/<path:path>')
def serve_assets(path):
    return send_from_directory('static/assets', path)

@app.route('/uploads/<filename>')
@login_required
def serve_upload(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

# Обработка ошибок
@app.errorhandler(404)
def not_found(error):
    return render_template('404.html'), 404

@app.errorhandler(403)
def forbidden(error):
    return render_template('403.html'), 403

@app.errorhandler(500)
def internal_error(error):
    return render_template('500.html'), 500

# Регистрация маршрутов из других модулей
def register_routes():
    try:
        from admin import admin_routes
        admin_routes(app, db, logger)
    except ImportError as e:
        logger.error(f"Failed to import admin routes: {str(e)}")

    try:
        from trader import trader_routes
        trader_routes(app, db, logger)
    except ImportError as e:
        logger.error(f"Failed to import trader routes: {str(e)}")

    try:
        from merchant import merchant_routes
        merchant_routes(app, db, logger)
    except ImportError as e:
        logger.error(f"Failed to import merchant routes: {str(e)}")

# Запуск приложения
if __name__ == '__main__':
    with app.app_context():
        register_routes()
    app.run(host='0.0.0.0', port=5001, debug=True)
