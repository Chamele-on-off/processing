import os
import logging
from datetime import datetime, timedelta
from functools import wraps
from flask import Flask, render_template, request, session, redirect, jsonify, send_from_directory, url_for, make_response, Response
from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.utils import secure_filename
from database.database import YAMLDatabase, TransactionRequisitesManager
from database.init_db import init_db
import json
import random
from flask import make_response
import uuid
import secrets
from services.matching_service import MatchingService
import time
import threading

# Настройка логгирования
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('processing_platform.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# Инициализация базы данных
def initialize_database():
    try:
        if not os.path.exists('data'):
            os.makedirs('data')
        db = YAMLDatabase('data/db.yaml')
        if not os.path.exists('data/db.yaml'):
            init_db(db)
            logger.info("Database initialized successfully")
        return db
    except Exception as e:
        logger.error(f"Database initialization failed: {str(e)}")
        raise

# Функция для форматирования даты
def format_datetime(value, format='%d.%m.%Y %H:%M'):
    if value is None:
        return ""
    if isinstance(value, str):
        try:
            value = datetime.fromisoformat(value)
        except ValueError:
            return value
    return value.strftime(format)

# Создаем экземпляр приложения
db = initialize_database()
app = Flask(__name__, template_folder='templates', static_folder='static')
app.jinja_env.filters['datetimeformat'] = format_datetime
app.jinja_env.globals.update(zip=zip)

# Конфигурация
app.secret_key = os.environ.get('SECRET_KEY', 'super-secret-key-123')
app.config['SESSION_COOKIE_NAME'] = 'processing_session'
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SECURE'] = False
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(hours=1)
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['ALLOWED_EXTENSIONS'] = {'pdf'}

# Создаем папку для загрузок
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# Декоратор для логирования всех запросов
def log_request(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        logger.info(f"Request: {request.method} {request.path} from {request.remote_addr}")
        logger.debug(f"Request headers: {dict(request.headers)}")
        if request.method in ['POST', 'PUT']:
            if request.is_json:
                logger.debug(f"Request JSON data: {request.get_json()}")
            else:
                logger.debug(f"Request form data: {request.form.to_dict()}")
        try:
            return f(*args, **kwargs)
        except Exception as e:
            logger.error(f"Error processing request: {str(e)}", exc_info=True)
            raise
    return decorated

# Декоратор для логирования всех ответов
def log_response(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        response = f(*args, **kwargs)
        
        if isinstance(response, tuple):
            response = make_response(response)
            
        if not isinstance(response, Response):
            response = make_response(response)
            
        logger.info(f"Response: {response.status_code} for {request.path}")
        if response.is_json:
            logger.debug(f"Response JSON data: {response.get_json()}")
        return response
    return decorated

# Генерация CSRF токена
def generate_csrf_token():
    if 'csrf_token' not in session:
        session['csrf_token'] = secrets.token_hex(16)
    return session['csrf_token']

# Проверка CSRF токена
def check_csrf_token():
    if request.method in ('POST', 'PUT', 'PATCH', 'DELETE'):
        token = request.headers.get('X-CSRF-Token') or request.form.get('csrf_token')
        if not token or token != session.get('csrf_token'):
            return jsonify({'error': 'Invalid CSRF token'}), 403
    return None

# Вспомогательные функции
def authenticate(email, password):
    user = db.find_one('users', {'email': email})
    if user and check_password_hash(user['password_hash'], password):
        return user
    return None

def get_current_user():
    if 'user_id' in session:
        return db.find_one('users', {'id': int(session['user_id'])})
    return None

def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']

# ============
# Вспомогательные методы для панелей
# ============

def calculate_avg_processing_time():
    """Рассчитывает среднее время обработки транзакций"""
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
            logger.error(f"Error calculating processing time for transaction {t.get('id')}: {str(e)}")
            continue
    
    return round((total_seconds / len(completed)) / 60, 2)  # в минутах

def generate_activity_data(days=7):
    """Генерирует данные активности за последние дни"""
    now = datetime.now()
    labels = []
    values = []
    
    for i in range(days, -1, -1):
        date = (now - timedelta(days=i)).date()
        labels.append(date.strftime('%d.%m'))
        
        transactions = db.find('transactions') or []
        count = len([t for t in transactions 
                    if isinstance(t, dict) and
                    isinstance(t.get('created_at'), str) and
                    datetime.fromisoformat(t['created_at']).date() == date])
        values.append(count)
    
    return {'labels': labels, 'values': values}

def calculate_conversion_rate(transactions):
    """Рассчитывает коэффициент конверсии для мерчанта"""
    if not transactions or not isinstance(transactions, list):
        return 0
    
    completed = len([t for t in transactions 
                    if isinstance(t, dict) and 
                    t.get('status') == 'completed'])
    return round((completed / len(transactions)) * 100, 2) if transactions else 0

def calculate_weekly_stats(transactions):
    """Рассчитывает недельную статистику для мерчанта"""
    stats = {
        'deposits': 0,
        'withdrawals': 0,
        'total_amount': 0
    }
    
    week_ago = datetime.now() - timedelta(days=7)
    
    for t in transactions:
        if not isinstance(t, dict) or not isinstance(t.get('created_at'), str):
            continue
            
        try:
            created = datetime.fromisoformat(t['created_at'])
            if created < week_ago:
                continue
                
            amount = float(t.get('amount', 0))
            stats['total_amount'] += amount
            
            if t.get('type') == 'deposit':
                stats['deposits'] += 1
            elif t.get('type') == 'withdrawal':
                stats['withdrawals'] += 1
        except (ValueError, TypeError):
            continue
    
    return stats

# ============
# Декораторы
# ============

def csrf_protect(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        response = check_csrf_token()
        if response:
            return response
        return f(*args, **kwargs)
    return decorated_function

def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'user_id' not in session:
            return jsonify({'error': 'Authentication required'}), 401
        return f(*args, **kwargs)
    return decorated

def role_required(role):
    def decorator(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            user = get_current_user()
            if not user or user.get('role') != role:
                return jsonify({'error': 'Forbidden'}), 403
            return f(*args, **kwargs)
        return decorated
    return decorator

# Добавляем декораторы и вспомогательные методы к объекту app
app.role_required = role_required
app.login_required = login_required
app.csrf_protect = csrf_protect
app.log_request = log_request
app.log_response = log_response
app.get_current_user = get_current_user
app.allowed_file = allowed_file
app.calculate_avg_processing_time = calculate_avg_processing_time
app.generate_activity_data = generate_activity_data
app.calculate_conversion_rate = calculate_conversion_rate
app.calculate_weekly_stats = calculate_weekly_stats

# Инъекция CSRF токена во все шаблоны
@app.context_processor
def inject_csrf_token():
    def get_csrf_token():
        return session.get('csrf_token', '')
    return dict(csrf_token=get_csrf_token)

# ============
# Общие маршруты
# ============

@app.route('/login.html', methods=['GET', 'POST'])
def login():
    if request.method == 'GET':
        user = get_current_user()
        if user:
            return redirect(url_for(f"{user['role']}_dashboard"))
        return render_template('login.html')
    
    if request.is_json:
        data = request.get_json()
    else:
        data = request.form
    
    email = data.get('email')
    password = data.get('password')
    
    if not email or not password:
        return jsonify({'error': 'Email and password are required'}), 400
    
    user = authenticate(email, password)
    if user:
        session['user_id'] = int(user['id'])
        session['role'] = user['role']
        session.permanent = True
        generate_csrf_token()
        logger.info(f"User {email} logged in")
        
        if request.is_json:
            return jsonify({
                'success': True,
                'redirect': url_for(f"{user['role']}_dashboard")
            })
        else:
            return redirect(url_for(f"{user['role']}_dashboard"))
    
    return jsonify({'error': 'Invalid credentials'}), 401

@app.route('/logout', methods=['GET', 'POST'])
def logout():
    session.clear()
    return redirect(url_for('home'))

@app.route('/')
def home():
    user = get_current_user()
    if user:
        return redirect(url_for(f"{user['role']}_dashboard"))
    return render_template('index.html')

# Импортируем маршруты из других файлов
from admin import admin_routes
from trader import trader_routes
from merchant import merchant_routes

# Регистрируем маршруты
admin_routes(app, db, logger)
trader_routes(app, db, logger)
merchant_routes(app, db, logger)

# ===========================================
# Обработка файлов, ошибок, статические файлы
# ===========================================

@app.route('/static/<path:path>')
def serve_static(path):
    return send_from_directory('static', path)

@app.route('/uploads/<filename>')
@login_required
def serve_upload(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

@app.errorhandler(404)
def not_found(error):
    return render_template('404.html'), 404

@app.errorhandler(500)
def server_error(error):
    return render_template('500.html'), 500

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5001, debug=True)
else:
    gunicorn_app = app
    gunicorn_logger = logging.getLogger('gunicorn.error')
    app.logger.handlers = gunicorn_logger.handlers
    app.logger.setLevel(gunicorn_logger.level)
