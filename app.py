# app.py
import os
import logging
from logging.handlers import RotatingFileHandler
from datetime import datetime, timedelta
from functools import wraps
import uuid
import random # <-- Добавлен импорт

from flask import Flask, render_template, jsonify, request, session, send_from_directory, redirect, url_for
from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.utils import secure_filename

# Предполагается, что database.py находится в той же папке
from database import YAMLDatabase

# Инициализация логгера
logging.basicConfig(level=logging.DEBUG) # Установите на INFO или WARNING в продакшене
logger = logging.getLogger(__name__)
handler = RotatingFileHandler('processing_platform.log', maxBytes=1000000, backupCount=3)
handler.setLevel(logging.DEBUG) # Установите уровень логирования
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
handler.setFormatter(formatter)
logger.addHandler(handler)
logger.setLevel(logging.DEBUG) # Установите уровень логирования

# --- Определение вспомогательных функций ---
def initialize_database():
    """Инициализирует и возвращает экземпляр базы данных."""
    return YAMLDatabase()

def authenticate(email, password, db):
    """Проверяет учетные данные пользователя."""
    logger.debug(f"Attempting to authenticate user: {email}")
    user = db.find_one('users', {'email': email})
    if user:
        logger.debug(f"User found: {user.get('id')}, Role: {user.get('role')}")
        if 'password_hash' in user and check_password_hash(user['password_hash'], password):
            logger.debug("Password check successful")
            return user
        else:
            logger.debug("Password check failed")
    else:
        logger.debug("User not found in database")
    return None

def get_current_user(db):
    """Получает текущего пользователя из сессии."""
    if 'user_id' in session:
        try:
            return db.find_one('users', {'id': int(session['user_id'])})
        except (ValueError, TypeError) as e:
            logger.error(f"Error retrieving user from session: {e}")
    return None

def allowed_file(filename, app):
    """Проверяет, разрешено ли расширение файла."""
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']

def calculate_avg_processing_time(db):
    """Рассчитывает среднее время обработки транзакций."""
    transactions = db.find('transactions') or []
    completed = [t for t in transactions
                 if isinstance(t, dict) and
                 t.get('status') == 'completed' and
                 isinstance(t.get('created_at'), str) and
                 isinstance(t.get('completed_at'), str)]
    if not completed:
        return 0
    try:
        total_seconds = sum(
            (datetime.fromisoformat(t['completed_at']) - datetime.fromisoformat(t['created_at'])).total_seconds()
            for t in completed
        )
        return total_seconds / len(completed)
    except Exception as e:
        logger.error(f"Error calculating avg processing time: {e}")
        return 0

# --- Функция назначения трейдера ---
def assign_random_trader(db, logger):
    """
    Назначает случайного активного трейдера.
    Возвращает ID трейдера (int) или None, если активных трейдеров нет.
    Предполагается, что у пользователей есть поля 'role' и 'status'.
    """
    try:
        # Получаем всех пользователей
        all_users = db.find('users') or []
        # Фильтруем активных трейдеров
        traders = [
            u for u in all_users 
            if isinstance(u, dict) and 
               u.get('role') == 'trader' and 
               u.get('status', 'inactive') == 'active' # Предполагаем, что 'status' может быть 'active'/'inactive'
        ]

        if not traders:
            logger.warning("No active traders found for assignment.")
            return None 

        # Выбираем случайного трейдера
        selected_trader = random.choice(traders)
        trader_id = selected_trader.get('id')
        logger.info(f"Assigned trader {trader_id} ({selected_trader.get('email')}) to transaction.")
        return trader_id

    except Exception as e:
        logger.error(f"Error in assign_random_trader: {e}", exc_info=True)
        return None

# --- Декораторы ---
def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'user_id' not in session:
            # Проверяем, является ли запрос AJAX/json
            if request.is_json or request.headers.get('Accept', '').find('application/json') != -1:
                return jsonify({'error': 'Authentication required'}), 401
            else:
                # Для обычных запросов перенаправляем на логин
                return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated

def role_required(role):
    def decorator(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            # Передаем db в get_current_user
            user = get_current_user(db) 
            if not user or user.get('role') != role:
                # Проверяем, является ли запрос AJAX/json
                if request.is_json or request.headers.get('Accept', '').find('application/json') != -1:
                    return jsonify({'error': 'Forbidden'}), 403
                else:
                    # Для обычных запросов перенаправляем на главную или показываем ошибку
                    return redirect(url_for('home')) # Или render_template('error/403.html')
            return f(*args, **kwargs)
        return decorated
    return decorator

def csrf_protect(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if request.method in ('POST', 'PUT', 'PATCH', 'DELETE'):
            token = request.headers.get('X-CSRF-Token') or request.form.get('csrf_token')
            if not token or token != session.get('csrf_token'):
                # Проверяем, является ли запрос AJAX/json
                if request.is_json or request.headers.get('Accept', '').find('application/json') != -1:
                    return jsonify({'error': 'Invalid CSRF token'}), 403
                else:
                    # Для обычных запросов показываем ошибку
                     return render_template('error/403.html', message="Invalid CSRF token"), 403
        return f(*args, **kwargs)
    return decorated

# --- Функция для форматирования даты (для Jinja2) ---
def format_datetime(value, format='%d.%m.%Y %H:%M'):
    if value is None:
        return ""
    if isinstance(value, str):
        try:
            value = datetime.fromisoformat(value)
        except ValueError:
            return value
    return value.strftime(format)

# --- Создание экземпляра приложения ---
db = initialize_database()
app = Flask(__name__, template_folder='templates', static_folder='static')

# --- Конфигурация приложения ---
app.secret_key = os.environ.get('SECRET_KEY', 'super-secret-key-123-change-in-production')
app.config['SESSION_COOKIE_NAME'] = 'processing_session'
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SECURE'] = False # Установите True, если используете HTTPS
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(hours=1)
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['ALLOWED_EXTENSIONS'] = {'pdf'}

# Создаем папку для загрузок
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# --- Настройка Jinja2 ---
app.jinja_env.filters['datetimeformat'] = format_datetime
app.jinja_env.globals.update(zip=zip)

# --- Добавление вспомогательных функций и декораторов в app ---
app.login_required = login_required
app.role_required = role_required
app.csrf_protect = csrf_protect
app.get_current_user = lambda: get_current_user(db) # Лямбда для захвата db
app.allowed_file = lambda filename: allowed_file(filename, app) # Лямбда для захвата app
app.calculate_avg_processing_time = lambda: calculate_avg_processing_time(db) # Лямбда для захвата db
app.assign_random_trader = lambda db_inner, logger_inner: assign_random_trader(db_inner, logger_inner) # Лямбда для захвата функции

# --- Генерация CSRF токена ---
@app.before_request
def generate_csrf_token():
    if 'csrf_token' not in session:
        session['csrf_token'] = uuid.uuid4().hex

# --- Маршруты ---
@app.route('/')
def home():
    user = get_current_user(db)
    if user:
        return redirect(url_for(f"{user['role']}_dashboard"))
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        # Определяем, откуда пришли данные (JSON или form)
        if request.is_json:
            data = request.get_json()
        else:
            # Для обычных форм
            data = request.form
        
        email = data.get('email')
        password = data.get('password')
        
        logger.info(f"User {email} attempted to log in.")

        if email and password:
            user = authenticate(email, password, db) # Передаем db
            if user:
                session['user_id'] = user['id']
                session['user_role'] = user['role']
                logger.info(f"User {email} logged in")
                
                # Определяем URL для перенаправления
                redirect_url = url_for(f"{user['role']}_dashboard")
                
                # Отвечаем по-разному для AJAX и обычных запросов
                if request.is_json:
                    return jsonify({'success': True, 'redirect': redirect_url})
                else:
                    return redirect(redirect_url)
            else:
                logger.info(f"Failed login attempt for {email}")
                error_msg = 'Неверный email или пароль'
                if request.is_json:
                    return jsonify({'success': False, 'error': error_msg}), 401
                else:
                    # Передаем ошибку в шаблон
                    return render_template('login.html', error=error_msg), 401
        else:
            error_msg = 'Email и пароль обязательны'
            if request.is_json:
                return jsonify({'success': False, 'error': error_msg}), 400
            else:
                return render_template('login.html', error=error_msg), 400
    else:
        # Отображение страницы логина
        return render_template('login.html')

@app.route('/logout', methods=['GET', 'POST'])
def logout():
    session.clear()
    return redirect(url_for('home'))

# --- Статические файлы и загрузки ---
@app.route('/static/<path:path>')
def serve_static(path):
    return send_from_directory('static', path)

@app.route('/uploads/<filename>')
@login_required
def serve_upload(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)


# --- Импорт и регистрация маршрутов из других модулей ---
# ВАЖНО: Делаем это после создания app, db, logger
def register_routes():
    try:
        from admin import admin_routes
        admin_routes(app, db, logger)
        logger.info("Admin routes registered successfully.")
    except ImportError as e:
        logger.warning(f"Could not import admin routes: {e}")
    except Exception as e:
        logger.error(f"Error registering admin routes: {e}", exc_info=True)

    try:
        from trader import trader_routes
        trader_routes(app, db, logger)
        logger.info("Trader routes registered successfully.")
    except ImportError as e:
        logger.warning(f"Could not import trader routes: {e}")
    except Exception as e:
        logger.error(f"Error registering trader routes: {e}", exc_info=True)

    try:
        from merchant import merchant_routes
        # Передаем app.assign_random_trader как callable
        merchant_routes(app, db, logger) 
        logger.info("Merchant routes registered successfully.")
    except ImportError as e:
        logger.warning(f"Could not import merchant routes: {e}")
    except Exception as e:
        logger.error(f"Error registering merchant routes: {e}", exc_info=True)

# --- Обработка ошибок ---
@app.errorhandler(404)
def not_found(error):
    return render_template('error/404.html'), 404

@app.errorhandler(403)
def forbidden(error):
    return render_template('error/403.html'), 403

@app.errorhandler(500)
def internal_error(error):
    # db.session.rollback() # Не нужно для YAMLDatabase
    return render_template('error/500.html'), 500

# --- Запуск приложения ---
if __name__ == '__main__':
    # Регистрируем маршруты из других файлов после создания app
    with app.app_context():
        register_routes()
    app.run(debug=True) # Установите debug=False в продакшене
