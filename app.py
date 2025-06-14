import os
import logging
from datetime import datetime, timedelta
from functools import wraps
from flask import Flask, render_template, request, session, redirect, jsonify, send_from_directory, url_for, make_response, Response
from werkzeug.security import check_password_hash, generate_password_hash
from database.database import JSONDatabase
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
# Настройка расширенного логгирования
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('processing_platform.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

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
        
        # Если response - это кортеж (например, (response, status)), преобразуем его в Response
        if isinstance(response, tuple):
            response = make_response(response)
            
        # Если response - это строка или другой не-ответ, преобразуем его в ответ
        if not isinstance(response, Response):
            response = make_response(response)
            
        logger.info(f"Response: {response.status_code} for {request.path}")
        if response.is_json:
            logger.debug(f"Response JSON data: {response.get_json()}")
        return response
    return decorated


# Инициализация базы данных
def initialize_database():
    try:
        if not os.path.exists('data'):
            os.makedirs('data')
        db = JSONDatabase('data/db.json')
        if not os.path.exists('data/db.json'):
            init_db(db)
            logger.info("Database initialized successfully")
        return db
    except Exception as e:
        logger.error(f"Database initialization failed: {str(e)}")
        raise

# Функция для форматирования даты
def format_datetime(value, format='%d.%m.%Y %H:%M'):
    """Форматирование даты для Jinja2"""
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

# Генерация CSRF токена
def generate_csrf_token():
    if 'csrf_token' not in session:
        session['csrf_token'] = secrets.token_hex(16)
    return session['csrf_token']

# Инъекция CSRF токена во все шаблоны
@app.context_processor
def inject_csrf_token():
    def get_csrf_token():
        return session.get('csrf_token', '')
    return dict(csrf_token=get_csrf_token)

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

def generate_activity_data(days=7):
    """Генерирует данные активности за последние N дней"""
    labels = []
    values = []
    today = datetime.now().date()
    
    for i in range(days, 0, -1):
        date = today - timedelta(days=i)
        labels.append(date.strftime('%a'))
        values.append((i * 10) % 30 + 5)  # Демо-данные
    
    return {'labels': labels, 'values': values}

def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']

def calculate_conversion_rate(transactions):
    """Безопасный расчет коэффициента конверсии"""
    try:
        if not transactions:
            return 0
        completed = len([t for t in transactions if isinstance(t, dict) and t.get('status') == 'completed'])
        return round((completed / len(transactions)) * 100, 2) if transactions else 0
    except Exception as e:
        logger.error(f"Error calculating conversion rate: {str(e)}")
        return 0

def calculate_avg_processing_time():
    """Рассчитывает среднее время обработки только для завершенных транзакций"""
    transactions = db.find('transactions', {'status': 'completed'})
    if not transactions:
        return 0
    
    total_seconds = 0
    valid_transactions = 0
    
    for tx in transactions:
        if not isinstance(tx, dict):
            continue
        try:
            if 'created_at' in tx and 'completed_at' in tx:
                created = datetime.fromisoformat(tx['created_at'])
                completed = datetime.fromisoformat(tx['completed_at'])
                total_seconds += (completed - created).total_seconds()
                valid_transactions += 1
        except (KeyError, ValueError) as e:
            logger.warning(f"Skipping transaction {tx.get('id')} due to error: {str(e)}")
            continue
    
    if valid_transactions == 0:
        return 0
    
    avg_seconds = total_seconds / valid_transactions
    return round(avg_seconds / 60, 1)  # Возвращаем в минутах

def calculate_weekly_stats(transactions):
    """Безопасный расчет недельной статистики"""
    try:
        today = datetime.now().date()
        week_ago = today - timedelta(days=7)
        
        completed = len([t for t in transactions 
                        if isinstance(t, dict) and
                        t.get('status') == 'completed' and 
                        'completed_at' in t and
                        datetime.fromisoformat(t['completed_at']).date() >= week_ago])
        
        rejected = len([t for t in transactions 
                       if isinstance(t, dict) and
                       t.get('status') == 'rejected' and 
                       'created_at' in t and
                       datetime.fromisoformat(t['created_at']).date() >= week_ago])
        
        pending = len([t for t in transactions 
                      if isinstance(t, dict) and
                      t.get('status') == 'pending' and 
                      'created_at' in t and
                      datetime.fromisoformat(t['created_at']).date() >= week_ago])
        
        return {
            'labels': ['Успешно', 'Отклонено', 'В процессе'],
            'values': [completed, rejected, pending]
        }
    except Exception as e:
        logger.error(f"Error calculating weekly stats: {str(e)}")
        return {
            'labels': ['Успешно', 'Отклонено', 'В процессе'],
            'values': [0, 0, 0]
        }

# ===================
# НЕПРЕРЫВНЫЙ МАТЧИНГ
# ===================

AUTO_MATCHING_ENABLED = True
MATCHING_INTERVAL = 60  # Интервал проверки в секундах
DEFAULT_COMMISSION = 0.02  # 2% комиссия по умолчанию
SUPPORTED_CURRENCIES = ['RUB', 'USD', 'EUR', 'USDT']

def start_auto_matching():
    """Фоновая задача для автоматического матчинга"""
    def matching_loop():
        while True:
            if AUTO_MATCHING_ENABLED:
                try:
                    logger.info("Запуск автоматического поиска совпадений...")
                    perform_matching()
                except Exception as e:
                    logger.error(f"Ошибка в автоматическом матчинге: {str(e)}")
            time.sleep(MATCHING_INTERVAL)
    
    thread = threading.Thread(target=matching_loop, daemon=True)
    thread.start()

def perform_matching():
    try:
        # Получаем настройки
        currency_rates = db.find_one('system_settings', {'type': 'currency_rates'}) or {
            'USD': 75.0, 'EUR': 85.0, 'USDT': 1.0
        }
        commission_settings = db.find_one('system_settings', {'type': 'commissions'}) or {
            'default': 0.02
        }

        # Получаем транзакции
        pending_deposits = [
            tx for tx in db.find('transactions', {'status': 'pending', 'type': 'deposit'})
            if tx and tx.get('requisites_approved')
        ]
        pending_withdrawals = [
            tx for tx in db.find('transactions', {'status': 'pending', 'type': 'withdrawal'})
            if tx and tx.get('requisites_approved')
        ]

        # Конвертация в RUB
        for tx in pending_deposits + pending_withdrawals:
            tx['converted_amount'] = float(tx['amount']) * currency_rates.get(tx.get('currency', 'RUB'), 1)

        # Сортировка
        pending_deposits.sort(key=lambda x: -x['converted_amount'])
        pending_withdrawals.sort(key=lambda x: x['converted_amount'])

        matched_pairs = []
        used_deposit_ids = set()

        for withdrawal in pending_withdrawals:
            merchant_id = withdrawal.get('merchant_id')
            commission = commission_settings.get('per_merchant', {}).get(merchant_id, 
                          commission_settings.get('default', 0.02))
            
            required_amount = withdrawal['converted_amount'] * (1 + commission)
            matched_deposits = []
            remaining_amount = required_amount

            for deposit in pending_deposits:
                if deposit['id'] in used_deposit_ids:
                    continue
                
                if deposit['converted_amount'] <= remaining_amount:
                    matched_deposits.append(deposit)
                    remaining_amount -= deposit['converted_amount']
                    used_deposit_ids.add(deposit['id'])
                    
                    if remaining_amount <= 0:
                        break

            if remaining_amount <= 0 and matched_deposits:
                match = {
                    'id': str(uuid.uuid4()),
                    'deposit_ids': [d['id'] for d in matched_deposits],
                    'withdrawal_id': withdrawal['id'],
                    'amount': withdrawal['amount'],
                    'commission': commission,
                    'status': 'pending',
                    'created_at': datetime.now().isoformat()
                }
                db.insert_one('matches', match)
                matched_pairs.append(match)

                # Обновляем статусы транзакций
                for d in matched_deposits:
                    db.update_one('transactions', {'id': d['id']}, {
                        'status': 'matched',
                        'match_id': match['id']
                    })
                db.update_one('transactions', {'id': withdrawal['id']}, {
                    'status': 'matched',
                    'match_id': match['id']
                })

        return matched_pairs
    except Exception as e:
        logger.error(f"Matching error: {str(e)}")
        return []

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

# ============
# Маршруты аутентификации
# ============

@app.route('/login.html', methods=['GET', 'POST'])
def login():
    if request.method == 'GET':
        user = get_current_user()
        if user:
            return redirect(url_for(f"{user['role']}_dashboard"))
        return render_template('login.html')
    
    # Обработка POST запроса
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
        generate_csrf_token()  # Генерируем новый токен при входе
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

# ============
# Админ панель 
# ============

@app.route('/admin.html')
@role_required('admin')
@log_request
@log_response
def admin_dashboard():
    try:
        logger.info("Admin dashboard accessed - starting data loading")
        user = get_current_user()
        logger.debug(f"Current admin user: {user['email']}")

        # Логируем загрузку пользователей
        users = [u for u in (db.find('users') or []) if isinstance(u, dict)]
        logger.debug(f"Loaded {len(users)} users from database")
        
        # Логируем загрузку транзакций
        transactions = [t for t in (db.find('transactions') or []) if isinstance(t, dict)]
        logger.debug(f"Loaded {len(transactions)} transactions from database")
        
        # Детальное логирование для депозитов
        pending_deposits = [t for t in transactions if t.get('type') == 'deposit' and t.get('status') == 'pending']
        logger.debug(f"Pending deposits: {[(d['id'], d['amount'], d.get('user_email')) for d in pending_deposits]}")

        users = [u for u in (db.find('users') or []) if isinstance(u, dict)]
        for u in users:
            if not isinstance(u, dict):
                continue
            logger.info(f"User in DB: {u.get('id')}, {u.get('email')}, {u.get('role')}")
        
        transactions = [t for t in (db.find('transactions') or []) if isinstance(t, dict)]
        alerts = [a for a in (db.find('fraud_alerts', {'resolved': False}) or []) if isinstance(a, dict)]
        
        alerts.sort(key=lambda x: x.get('timestamp', ''), reverse=True)
        
        activity_data = generate_activity_data()
        
        stats = {
            'total_users': len(users),
            'today_transactions': len([t for t in transactions 
                                    if isinstance(t.get('created_at'), str) and
                                    datetime.fromisoformat(t['created_at']).date() == datetime.now().date()]),
            'active_traders': len([u for u in users 
                                 if u.get('role') == 'trader' and u.get('active', True)]),
            'avg_processing_time': calculate_avg_processing_time(),
            'activity': activity_data,
            'volume_chart': {
                'labels': activity_data['labels'],
                'values': [v * 1000 for v in activity_data['values']] 
                }
        }
        
        recent_transactions = []
        for t in sorted(transactions, key=lambda x: x.get('created_at', ''), reverse=True)[:5]:
            recent_transactions.append({
                'id': t.get('id', 'N/A'),
                'type': t.get('type', 'unknown'),
                'amount': float(t.get('amount', 0)),
                'status': t.get('status', 'pending'),
                'created_at': t.get('created_at', datetime.now().isoformat()),
                'user_email': t.get('user_email', 'Unknown')
            })
        
        all_transactions = []
        for t in sorted(transactions, key=lambda x: x.get('created_at', ''), reverse=True):
            all_transactions.append({
                'id': t.get('id', 'N/A'),
                'user_email': t.get('user_email', 'Unknown'),
                'amount': float(t.get('amount', 0)),
                'status': t.get('status', 'pending'),
                'created_at': t.get('created_at', datetime.now().isoformat()),
                'completed_at': t.get('completed_at', '')
            })
        
        pending_transactions = [t for t in all_transactions if t['status'] == 'pending']
        completed_transactions = [t for t in all_transactions if t['status'] == 'completed']

        all_orders = [o for o in (db.find('orders') or []) if isinstance(o, dict)]
        pending_orders = [o for o in all_orders if o.get('status') == 'pending']
        
        active_users = [{
            'id': u.get('id', ''),
            'email': u.get('email', ''),
            'role': u.get('role', '')
        } for u in users if u.get('active', True)]

        activity_data = list(zip(stats['activity']['labels'], stats['activity']['values']))
        
        return render_template(
            'admin.html',
            current_user=user,
            stats=stats,
            activity_data=activity_data,
            recent_transactions=recent_transactions,
            users=users,
            fraud_alerts=alerts[:5],
            all_transactions=all_transactions,
            pending_transactions=pending_transactions,
            completed_transactions=completed_transactions,
            active_users=active_users,
            pending_orders=pending_orders,
            all_orders=all_orders
        )
        
    except Exception as e:
        logger.error(f"Error in admin dashboard: {str(e)}")
        return render_template(
            'admin.html',
            current_user=user,
            stats={
                'total_users': 0,
                'today_transactions': 0,
                'active_traders': 0,
                'avg_processing_time': 0,
                'activity': {'labels': [], 'values': []},
                'volume_chart': {'labels': [], 'values': []}
            },
            recent_transactions=[],
            all_users=[],
            fraud_alerts=[],
            all_transactions=[],
            pending_transactions=[],
            completed_transactions=[],
            active_users=[]
        )

@app.route('/admin/users/create', methods=['GET', 'POST'])
@role_required('admin')
@log_request
@log_response
def admin_create_user():
    current_user = get_current_user()
    if request.method == 'GET':
        return render_template('admin_create_user.html', 
                           current_user=current_user,
                           stats=None)
    
    # Обработка POST запроса
    try:
        data = request.form
        new_user = {
            'id': int(uuid.uuid4().int & (1<<31)-1),  # Генерируем уникальный ID как int
            'email': data['email'],
            'password_hash': generate_password_hash(data['password']),
            'role': data['role'],
            'active': True,
            'created_at': datetime.now().isoformat(),
            'updated_at': datetime.now().isoformat()
        }
        
        # Проверяем, существует ли уже пользователь с таким email
        existing_user = db.find_one('users', {'email': data['email']})
        if existing_user:
            return render_template('admin_create_user.html',
                               current_user=current_user,
                               error="Пользователь с таким email уже существует")
        
        # Сохраняем пользователя
        db.insert_one('users', new_user)
        logger.info(f"Создан новый пользователь: {new_user['email']}")
        return redirect(url_for('admin_dashboard'))
    
    except Exception as e:
        logger.error(f"Ошибка при создании пользователя: {str(e)}")
        return render_template('admin_create_user.html',
                           current_user=current_user,
                           error=str(e))

@app.route('/admin/users/<user_id>', methods=['GET', 'POST'])
@role_required('admin')
@log_request
@log_response
def admin_edit_user(user_id):
    try:
        user_id_int = int(user_id)  # Преобразуем в int
        user = db.find_one('users', {'id': user_id_int})
        
        if not user:
            return render_template('404.html'), 404
        
        if request.method == 'POST':
            data = request.form
            updates = {
                'email': data.get('email'),
                'role': data.get('role'),
                'active': 'active' in request.form,
                'updated_at': datetime.now().isoformat()
            }
            
            if data.get('password'):
                updates['password_hash'] = generate_password_hash(data['password'])
            
            db.update_one('users', {'id': user_id_int}, updates)
            db.save()  # Явное сохранение
            
            return redirect(url_for('admin_dashboard'))
        
        return render_template('admin_edit_user.html', 
                           current_user=get_current_user(),
                           user=user)
    
    except Exception as e:
        logger.error(f"Error in admin_edit_user: {str(e)}")
        return render_template('admin_edit_user.html',
                           current_user=get_current_user(),
                           user=user,
                           error=str(e))

@app.route('/admin/deposits')
@role_required('admin')
@log_request
@log_response
def admin_deposits():
    user = get_current_user()
    
    # Получаем только депозитные транзакции
    deposits = [t for t in (db.find('transactions', {'type': 'deposit'}) or []) if isinstance(t, dict)]
    
    # Разделяем по статусам
    pending_deposits = [d for d in deposits if d.get('status') == 'pending']
    completed_deposits = [d for d in deposits if d.get('status') == 'completed']
    rejected_deposits = [d for d in deposits if d.get('status') == 'rejected']
    
    return render_template(
        'admin_deposits.html',
        current_user=user,
        pending_deposits=sorted(pending_deposits, key=lambda x: x.get('created_at', '')), 
        completed_deposits=sorted(completed_deposits, key=lambda x: x.get('completed_at', '')), 
        rejected_deposits=sorted(rejected_deposits, key=lambda x: x.get('rejected_at', '')))

@app.route('/api/admin/deposits/<int:deposit_id>/complete', methods=['POST'])
@role_required('admin')
@csrf_protect
def api_complete_deposit(deposit_id):
    try:
        deposit = db.find_one('transactions', {
            'id': deposit_id,
            'type': 'deposit',
            'status': 'pending'
        })
        
        if not deposit:
            return jsonify({'error': 'Deposit not found'}), 404
            
        # Обновляем статус депозита
        updates = {
            'status': 'completed',
            'completed_at': datetime.now().isoformat(),
            'completed_by': session['user_id']
        }
        db.update_one('transactions', {'id': deposit_id}, updates)
        
        # Обновляем баланс пользователя
        if 'user_id' in deposit:
            try:
                user = db.find_one('users', {'id': int(deposit['user_id'])})
                if user:
                    current_balance = float(user.get('balance', 0))
                    deposit_amount = float(deposit['amount'])
                    db.update_one('users', {'id': user['id']}, {
                        'balance': current_balance + deposit_amount
                    })
            except Exception as e:
                logger.error(f"Ошибка обновления баланса: {str(e)}")
                return jsonify({'error': 'User balance update failed'}), 500
        
        return jsonify({'success': True})
    
    except Exception as e:
        logger.error(f"Ошибка подтверждения депозита: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/admin/deposits/<int:deposit_id>/reject', methods=['POST'])
@role_required('admin')
@csrf_protect
def api_reject_deposit(deposit_id):
    try:
        deposit = db.find_one('transactions', {
            'id': deposit_id,
            'type': 'deposit',
            'status': 'pending'
        })
        
        if not deposit:
            return jsonify({'error': 'Deposit not found'}), 404
            
        updates = {
            'status': 'rejected',
            'rejected_at': datetime.now().isoformat(),
            'rejected_by': session['user_id']
        }
        db.update_one('transactions', {'id': deposit_id}, updates)
        
        return jsonify({'success': True})
    
    except Exception as e:
        logger.error(f"Ошибка отклонения депозита: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/admin/users/<user_id>/transactions')
@role_required('admin')
@log_request
@log_response
def admin_view_user_transactions(user_id):
    try:
        user = db.find_one('users', {'id': int(user_id)})
        if not user:
            return render_template('404.html'), 404
        
        transactions = db.find('transactions', {'user_id': int(user_id)})
        transactions = sorted(transactions, key=lambda x: x.get('created_at', ''), reverse=True)
        
        return render_template(
            'admin_user_transactions.html',
            current_user=get_current_user(),
            user=user,
            transactions=transactions
        )
    except Exception as e:
        logger.error(f"Error viewing user transactions: {str(e)}")
        return render_template('500.html'), 500

@app.route('/admin/users/<user_id>/requisites')
@role_required('admin')
@log_request
@log_response
def admin_view_user_requisites(user_id):
    try:
        user = db.find_one('users', {'id': int(user_id)})
        if not user:
            return render_template('404.html'), 404
        
        requisites = []
        if user.get('role') == 'trader':
            requisites = db.find('details', {'trader_id': int(user_id)})
            requisites = sorted(requisites, key=lambda x: x.get('created_at', ''), reverse=True)
        
        return render_template(
            'admin_user_requisites.html',
            current_user=get_current_user(),
            user=user,
            requisites=requisites
        )
    except Exception as e:
        logger.error(f"Error viewing user requisites: {str(e)}")
        return render_template('500.html'), 500

@app.route('/admin/requisites/<requisite_id>/approve', methods=['POST'])
@role_required('admin')
@csrf_protect
@log_request
@log_response
def admin_approve_requisite(requisite_id):
    try:
        requisite = db.find_one('details', {'id': int(requisite_id)})
        if not requisite:
            return redirect(url_for('admin_dashboard'))
        
        db.update_one('details', {'id': int(requisite_id)}, {
            'status': 'active',
            'approved_at': datetime.now().isoformat(),
            'approved_by': int(get_current_user()['id'])
        })
        
        return redirect(url_for('admin_view_user_requisites', user_id=requisite['trader_id']))
    except Exception as e:
        logger.error(f"Error approving requisite: {str(e)}")
        return render_template('500.html'), 500

@app.route('/admin/transactions/create', methods=['GET', 'POST'])
@role_required('admin')
@log_request
@log_response
def admin_create_transaction():
    current_user = get_current_user()
    
    if request.method == 'GET':
        active_users = [u for u in (db.find('users') or []) 
                       if isinstance(u, dict) and u.get('active', True)]
        return render_template('admin_create_transaction.html',
                           current_user=current_user,
                           active_users=active_users)

    # Обработка POST
    try:
        data = request.form
        logger.info(f"Получены данные формы: {data}")
        
        user = db.find_one('users', {'id': int(data['user_id'])})
        if not user:
            raise ValueError(f"User {data['user_id']} not found")

        new_tx = {
            'id': int(uuid.uuid4().int & (1<<31)-1),  # Генерируем ID как int
            'user_id': int(user['id']),
            'user_email': user['email'],
            'type': data['type'],
            'amount': float(data['amount']),
            'status': 'pending',
            'created_at': datetime.now().isoformat(),
            'admin_id': int(current_user['id'])
        }
        
        logger.info(f"Создаётся транзакция: {new_tx}")
        db.insert_one('transactions', new_tx)
        
        if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
            return jsonify({'success': True, 'transaction': new_tx})
        return redirect(url_for('admin_dashboard'))

    except Exception as e:
        logger.error(f"Transaction creation error: {str(e)}")
        if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
            return jsonify({'error': str(e)}), 400
        active_users = [u for u in (db.find('users') or []) 
                       if isinstance(u, dict) and u.get('active', True)]
        return render_template('admin_create_transaction.html',
                           current_user=current_user,
                           active_users=active_users,
                           error=str(e))

@app.route('/api/transactions/<tx_id>/complete', methods=['POST'])
@role_required('admin')
@csrf_protect
@log_request
@log_response
def complete_transaction_api(tx_id):
    try:
        logger.info(f"Attempting to complete transaction {tx_id}")
        
        tx = db.find_one('transactions', {'id': int(tx_id)})
        if not tx:
            logger.error(f"Transaction {tx_id} not found.")
            return jsonify({'error': 'Transaction not found'}), 404
        
        logger.info(f"Found transaction to complete: {tx}")
        
        updates = {
            'status': 'completed',
            'completed_at': datetime.now().isoformat(),
            'completed_by': int(get_current_user()['id'])
        }
        
        # Обновляем транзакцию
        result = db.update_one('transactions', {'id': int(tx['id'])}, updates)
        db.save()  # Явное сохранение
        
        if not result:
            logger.error("Update operation failed")
            return jsonify({'error': 'Update failed'}), 500
        
        # Получаем обновлённую транзакцию для проверки
        updated_tx = db.find_one('transactions', {'id': int(tx['id'])})
        logger.info(f"Transaction after update: {updated_tx}")
        
        return jsonify({
            'success': True,
            'transaction': updated_tx
        })
    
    except Exception as e:
        logger.error(f"Error completing transaction {tx_id}: {str(e)}", exc_info=True)
        return jsonify({'error': str(e)}), 500

@app.route('/api/admin/currency_rates', methods=['POST'])
@role_required('admin')
@csrf_protect
@log_request
@log_response
def update_currency_rates():
    try:
        data = request.get_json()
        current_rates = db.find_one('system_settings', {'type': 'currency_rates'}) or {}
        
        updates = {
            'USD': float(data.get('USD', current_rates.get('USD', 75.0))),
            'EUR': float(data.get('EUR', current_rates.get('EUR', 85.0))),
            'USDT': float(data.get('USDT', current_rates.get('USDT', 1.0))),
            'updated_at': datetime.now().isoformat()
        }
        
        db.update_one('system_settings', {'type': 'currency_rates'}, updates)
        return jsonify({'success': True, 'rates': updates})
    except Exception as e:
        return jsonify({'error': str(e)}), 400

@app.route('/api/admin/commissions', methods=['POST'])
@role_required('admin')
@csrf_protect
@log_request
@log_response
def update_commissions():
    try:
        data = request.get_json()
        current = db.find_one('system_settings', {'type': 'commissions'}) or {
            'default': DEFAULT_COMMISSION,
            'per_merchant': {}
        }
        
        updates = {
            'default': float(data.get('default', current.get('default'))),
            'per_merchant': data.get('per_merchant', current.get('per_merchant', {})),
            'updated_at': datetime.now().isoformat()
        }
        
        db.update_one('system_settings', {'type': 'commissions'}, updates)
        return jsonify({'success': True, 'commissions': updates})
    except Exception as e:
        return jsonify({'error': str(e)}), 400

@app.route('/api/transactions/<tx_id>/requisites', methods=['POST'])
@login_required
@csrf_protect
@log_request
@log_response
def add_transaction_requisites(tx_id):
    try:
        data = request.get_json()
        tx = db.find_one('transactions', {'id': int(tx_id)})
        
        if not tx:
            return jsonify({'error': 'Transaction not found'}), 404
        
        requisites = {
            'type_id': data['type_id'],
            'details': data['details'],
            'status': 'pending',
            'added_at': datetime.now().isoformat()
        }
        
        db.update_one('transactions', {'id': int(tx_id)}, {
            'requisites': requisites,
            'requisites_approved': False
        })
        
        return jsonify({'success': True})
    except Exception as e:
        return jsonify({'error': str(e)}), 400

@app.route('/api/admin/requisites/<tx_id>/approve', methods=['POST'])
@role_required('admin')
@csrf_protect
@log_request
@log_response
def approve_requisites(tx_id):
    try:
        db.update_one('transactions', {'id': int(tx_id)}, {
            'requisites_approved': True,
            'requisites.status': 'approved'
        })
        return jsonify({'success': True})
    except Exception as e:
        return jsonify({'error': str(e)}), 400

@app.route('/api/deposit_requests', methods=['POST'])
@login_required
@csrf_protect
@log_request
@log_response
def create_deposit_request():
    try:
        data = request.get_json()
        user = get_current_user()
        
        request_data = {
            'id': int(uuid.uuid4().int & (1<<31)-1),  # Генерируем ID как int
            'user_id': int(user['id']),
            'amount': float(data['amount']),
            'currency': data.get('currency', 'RUB'),
            'payment_method': data['payment_method'],
            'requisites': data.get('requisites'),
            'status': 'pending',
            'created_at': datetime.now().isoformat()
        }
        
        db.insert_one('deposit_requests', request_data)
        return jsonify({'success': True, 'request': request_data})
    except Exception as e:
        return jsonify({'error': str(e)}), 400

@app.route('/api/admin/deposit_requests/<req_id>/approve', methods=['POST'])
@role_required('admin')
@csrf_protect
@log_request
@log_response
def approve_deposit_request(req_id):
    try:
        req = db.find_one('deposit_requests', {'id': int(req_id)})
        if not req:
            return jsonify({'error': 'Request not found'}), 404
        
        # Создаем транзакцию
        tx = {
            'id': int(uuid.uuid4().int & (1<<31)-1),  # Генерируем ID как int
            'user_id': int(req['user_id']),
            'amount': req['amount'],
            'currency': req['currency'],
            'type': 'deposit',
            'status': 'completed',
            'requisites': req['requisites'],
            'requisites_approved': True,
            'created_at': datetime.now().isoformat()
        }
        
        db.insert_one('transactions', tx)
        db.update_one('deposit_requests', {'id': int(req_id)}, {'status': 'approved'})
        
        return jsonify({'success': True})
    except Exception as e:
        return jsonify({'error': str(e)}), 400



# В раздел маршрутов администратора
@app.route('/api/admin/pending-deposits')
@role_required('admin')
@log_request
@log_response
def get_pending_deposits():
    deposits = db.find('transactions', {'status': 'pending', 'type': 'deposit'}) or []
    return jsonify([d for d in deposits if isinstance(d, dict)])

@app.route('/api/admin/users/<user_id>/transactions')
@role_required('admin')
@log_request
@log_response
def get_user_transactions(user_id):
    status = request.args.get('status')
    query = {'user_id': int(user_id)}
    if status:
        query['status'] = status
    
    transactions = db.find('transactions', query) or []
    return jsonify([t for t in transactions if isinstance(t, dict)])

@app.route('/admin/platform-balance', methods=['GET'])
@role_required('admin')
def platform_balance():
    # Рассчитываем общий баланс
    users = db.find('users') or []
    transactions = db.find('transactions', {'status': 'completed'}) or []
    
    total_balance = sum(float(u.get('balance', 0)) for u in users if isinstance(u, dict))
    available_balance = total_balance * 0.8  # 80% доступно для выплат
    
    distribution = [
        {'type': 'Средства пользователей', 'amount': total_balance * 0.7, 'percentage': 70},
        {'type': 'Резерв платформы', 'amount': total_balance * 0.2, 'percentage': 20},
        {'type': 'Доход платформы', 'amount': total_balance * 0.1, 'percentage': 10}
    ]
    
    # Формируем список пользователей с балансами
    users_balances = []
    for user in users:
        if isinstance(user, dict):
            users_balances.append({
                'email': user.get('email', ''),
                'role': user.get('role', ''),
                'balance': float(user.get('balance', 0))
            })
    
    return render_template('admin_balance.html',
                         total_balance=total_balance,
                         available_balance=available_balance,
                         distribution=distribution,
                         users_balances=users_balances)

@app.route('/api/admin/matches')
@role_required('admin')
@log_request
@log_response
def get_matches():
    matches = db.find('matches') or []
    return jsonify([m for m in matches if isinstance(m, dict)])

@app.route('/api/admin/matching/run', methods=['POST'])
@role_required('admin')
@log_request
@log_response
def run_matching():
    matched_pairs = perform_matching()
    return jsonify({
        'success': True,
        'matches_count': len(matched_pairs),
        'matches': matched_pairs
    })

@app.route('/api/admin/matches/<match_id>/confirm', methods=['POST'])
@role_required('admin')
@log_request
@log_response
def confirm_match(match_id):
    match = db.find_one('matches', {'id': int(match_id)})
    if not match:
        return jsonify({'error': 'Match not found'}), 404
    
    db.update_one('matches', {'id': int(match_id)}, {'status': 'completed'})
    return jsonify({'success': True})

@app.route('/api/admin/settings')
@role_required('admin')
@log_request
@log_response
def get_settings():
    settings = db.find_one('system_settings', {'type': 'platform_settings'}) or {
        'usd_rate': 75.0,
        'eur_rate': 85.0,
        'usdt_rate': 1.0,
        'default_fee': 2.0,
        'trader_fee': 1.5
    }
    return jsonify(settings)

@app.route('/api/admin/settings', methods=['POST'])
@role_required('admin')
@log_request
@log_response
def update_settings():
    data = request.form
    updates = {
        'usd_rate': float(data.get('usd_rate', 75.0)),
        'eur_rate': float(data.get('eur_rate', 85.0)),
        'usdt_rate': float(data.get('usdt_rate', 1.0)),
        'default_fee': float(data.get('default_fee', 2.0)),
        'trader_fee': float(data.get('trader_fee', 1.5)),
        'updated_at': datetime.now().isoformat()
    }
    
    db.update_one('system_settings', {'type': 'platform_settings'}, updates)
    return jsonify({'success': True})




# ===============
# Панель трейдера
# ===============

@app.route('/trader.html')
@role_required('trader')
def trader_dashboard():
    user = get_current_user()
    active_orders = [o for o in (db.find('orders', {'trader_id': int(user['id']), 'status': 'pending'})) or [] if isinstance(o, dict)]
    all_orders = [o for o in (db.find('orders', {'trader_id': int(user['id'])})) or [] if isinstance(o, dict)]
    details = [d for d in (db.find('details', {'trader_id': int(user['id'])})) or [] if isinstance(d, dict)]
    
    merchant_transactions = [t for t in (db.find('transactions', {'status': 'pending'}) or []) 
                           if isinstance(t, dict)]
    
    return render_template(
        'trader.html',
        user=user,
        active_orders=active_orders,
        all_orders=all_orders,
        details=details,
        merchant_transactions=merchant_transactions
    )

@app.route('/api/trader/orders', methods=['POST'])
@role_required('trader')
@csrf_protect
def create_trader_order():
    user = get_current_user()
    try:
        data = request.get_json()
        if not data:
            return jsonify({'error': 'No data provided'}), 400

        detail = db.find_one('details', {'id': int(data['details_id']), 'trader_id': int(user['id'])})
        if not detail:
            return jsonify({'error': 'Invalid details or not found'}), 400

        new_order = {
            'id': int(uuid.uuid4().int & (1<<31)-1),  # Генерируем ID как int
            'trader_id': int(user['id']),
            'type': data['type'],
            'amount': float(data['amount']),
            'method': data['method'],
            'details_id': int(data['details_id']),
            'status': 'pending',
            'created_at': datetime.now().isoformat(),
            'updated_at': datetime.now().isoformat()
        }
        
        db.insert_one('orders', new_order)
        return jsonify({'success': True, 'order': new_order})
    
    except Exception as e:
        logger.error(f"Error creating order: {str(e)}")
        return jsonify({'error': str(e)}), 400

@app.route('/api/trader/orders/<order_id>/complete', methods=['POST'])
@role_required('trader')
@csrf_protect
def complete_trader_order(order_id):
    user = get_current_user()
    order = db.find_one('orders', {'id': int(order_id), 'trader_id': int(user['id'])})
    if not order:
        return jsonify({'error': 'Order not found'}), 404
    
    try:
        updates = {
            'status': 'completed',
            'completed_at': datetime.now().isoformat(),
            'updated_at': datetime.now().isoformat()
        }
        db.update_one('orders', {'id': int(order_id)}, updates)
        return jsonify({'success': True})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/trader/orders/<order_id>/cancel', methods=['POST'])
@role_required('trader')
@csrf_protect
def cancel_trader_order(order_id):
    user = get_current_user()
    order = db.find_one('orders', {'id': int(order_id), 'trader_id': int(user['id'])})
    if not order:
        return jsonify({'error': 'Order not found'}), 404
    
    try:
        updates = {
            'status': 'cancelled',
            'updated_at': datetime.now().isoformat()
        }
        db.update_one('orders', {'id': int(order_id)}, updates)
        return jsonify({'success': True})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/trader/details', methods=['POST'])
@role_required('trader')
@csrf_protect
def add_trader_details():
    user = get_current_user()
    try:
        data = request.get_json()
        if not data:
            return jsonify({'error': 'No data provided'}), 400

        if data['type'] == 'bank_account':
            if not all(k in data for k in ['account_number', 'bik', 'owner_name']):
                return jsonify({'error': 'Missing required fields for bank account'}), 400
            details = f"Счет: {data['account_number']}, БИК: {data['bik']}, Владелец: {data['owner_name']}"
        elif data['type'] == 'card':
            if not all(k in data for k in ['card_number', 'card_owner', 'card_expiry']):
                return jsonify({'error': 'Missing required fields for card'}), 400
            details = f"Карта: {data['card_number']}, Владелец: {data['card_owner']}, Срок: {data['card_expiry']}"
        elif data['type'] == 'crypto':
            if not all(k in data for k in ['wallet_address', 'crypto_type']):
                return jsonify({'error': 'Missing required fields for crypto wallet'}), 400
            details = f"Адрес: {data['wallet_address']}, Тип: {data['crypto_type']}"
        else:
            return jsonify({'error': 'Invalid details type'}), 400

        new_detail = {
            'id': int(uuid.uuid4().int & (1<<31)-1),  # Генерируем ID как int
            'trader_id': int(user['id']),
            'type': data['type'],
            'details': details,
            'status': 'pending',
            'created_at': datetime.now().isoformat()
        }
        
        db.insert_one('details', new_detail)
        return jsonify({'success': True, 'detail': new_detail})
    except Exception as e:
        logger.error(f"Error adding details: {str(e)}")
        return jsonify({'error': str(e)}), 400

@app.route('/api/trader/details/<detail_id>', methods=['GET'])
@role_required('trader')
def get_trader_detail(detail_id):
    user = get_current_user()
    try:
        detail = db.find_one('details', {'id': int(detail_id), 'trader_id': int(user['id'])})
        if not detail:
            return jsonify({'error': 'Details not found or access denied'}), 404
        
        return jsonify(detail)
    
    except Exception as e:
        logger.error(f"Error getting detail: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/trader/details/<detail_id>', methods=['DELETE'])
@role_required('trader')
@csrf_protect
def delete_trader_details(detail_id):
    user = get_current_user()
    try:
        detail = db.find_one('details', {'id': int(detail_id), 'trader_id': int(user['id'])})
        if not detail:
            return jsonify({'error': 'Details not found or access denied'}), 404
        
        orders_with_detail = db.find('orders', {'details_id': int(detail_id), 'status': 'pending'})
        if orders_with_detail:
            return jsonify({'error': 'Cannot delete details used in active orders'}), 400
        
        db.delete_one('details', {'id': int(detail_id)})
        return jsonify({'success': True})
    
    except Exception as e:
        logger.error(f"Error deleting details: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/trader/deposits/toggle', methods=['POST'])
@role_required('trader')
@csrf_protect
def toggle_deposits():
    user = get_current_user()
    try:
        data = request.get_json()
        enable = data.get('enable', False)
        
        db.update_one('users', {'id': int(user['id'])}, {'deposits_enabled': enable})
        return jsonify({'success': True, 'enabled': enable})
    except Exception as e:
        return jsonify({'error': str(e)}), 400

@app.route('/api/trader/merchant-transactions/<transaction_id>', methods=['GET'])
@role_required('trader')
def get_merchant_transaction(transaction_id):
    user = get_current_user()
    try:
        transaction = db.find_one('transactions', {'id': int(transaction_id)})
        if not transaction:
            return jsonify({'error': 'Transaction not found'}), 404
        
        # Проверяем, что транзакция либо принадлежит трейдеру, либо еще не взята
        if transaction.get('trader_id') and int(transaction['trader_id']) != int(user['id']):
            return jsonify({'error': 'Access denied'}), 403
        
        if 'fee' not in transaction:
            transaction['fee'] = 0.0
        
        return jsonify(transaction)
    
    except Exception as e:
        logger.error(f"Error getting transaction: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/trader/deposits/<deposit_id>/upload-receipt', methods=['POST'])
@role_required('trader')
@csrf_protect
def upload_deposit_receipt(deposit_id):
    try:
        if 'receipt' not in request.files:
            return jsonify({'error': 'No file uploaded'}), 400
        
        file = request.files['receipt']
        if file.filename == '':
            return jsonify({'error': 'No selected file'}), 400
        
        if file and allowed_file(file.filename):
            filename = f"deposit_{deposit_id}_{datetime.now().timestamp()}.pdf"
            file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
            
            db.update_one('transactions', {'id': int(deposit_id)}, {
                'receipt_file': filename,
                'receipt_uploaded_at': datetime.now().isoformat(),
                'status': 'pending_verification'
            })
            
            return jsonify({'success': True})
        
        return jsonify({'error': 'Invalid file type'}), 400
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/trader/transactions/<transaction_id>/take', methods=['POST'])
@role_required('trader')
@csrf_protect
def take_transaction(transaction_id):
    user = get_current_user()
    try:
        transaction = db.find_one('transactions', {'id': int(transaction_id)})
        if not transaction:
            return jsonify({'error': 'Transaction not found'}), 404
        
        if transaction.get('status') != 'pending':
            return jsonify({'error': 'Only pending transactions can be taken'}), 400
        
        updates = {
            'status': 'in_progress',
            'trader_id': int(user['id']),
            'taken_at': datetime.now().isoformat()
        }
        
        db.update_one('transactions', {'id': int(transaction_id)}, {
            'status': 'in_progress',
            'trader_id': int(user['id']),  # Важно: сохраняем ID трейдера
            'taken_at': datetime.now().isoformat()})
        
        return jsonify({'success': True})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/trader/transactions/<transaction_id>/assign-details', methods=['POST'])
@role_required('trader')
@csrf_protect
def assign_transaction_details(transaction_id):
    user = get_current_user()
    try:
        data = request.get_json()
        transaction = db.find_one('transactions', {'id': int(transaction_id), 'trader_id': int(user['id'])})
        
        if not transaction:
            return jsonify({'error': 'Transaction not found or access denied'}), 404
        
        detail = db.find_one('details', {'id': int(data['detail_id']), 'trader_id': int(user['id'])})
        if not detail:
            return jsonify({'error': 'Details not found or access denied'}), 404
        
        db.update_one('transactions', {'id': int(transaction_id)}, {
            'trader_details_id': int(data['detail_id']),
            'updated_at': datetime.now().isoformat()
        })
        
        return jsonify({'success': True})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/trader/transactions/<transaction_id>/complete', methods=['POST'])
@role_required('trader')
@csrf_protect
def trader_complete_transaction(transaction_id):
    user = get_current_user()
    try:
        transaction = db.find_one('transactions', {'id': int(transaction_id), 'trader_id': int(user['id'])})
        
        if not transaction:
            return jsonify({'error': 'Transaction not found or access denied'}), 404
        
        if not transaction.get('receipt_file'):
            return jsonify({'error': 'Receipt is required to complete transaction'}), 400
        
        db.update_one('transactions', {'id': int(transaction_id)}, {
            'status': 'pending_admin_approval',
            'completed_at': datetime.now().isoformat(),
            'updated_at': datetime.now().isoformat()
        })
        
        return jsonify({'success': True})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/trader/transactions/<transaction_id>/requisites', methods=['POST'])
@role_required('trader')
@csrf_protect
def assign_requisites_to_transaction(transaction_id):
    user = get_current_user()
    data = request.get_json()
    
    detail = db.find_one('details', {
        'id': int(data['detail_id']),
        'trader_id': int(user['id'])
    })
    if not detail:
        return jsonify({'error': 'Реквизиты не найдены или не принадлежат вам'}), 400
    
    db.update_one('transactions', {'id': int(transaction_id)}, {
        'requisites_id': int(data['detail_id']),
        'updated_at': datetime.now().isoformat()
    })
    
    return jsonify({'success': True})

@app.route('/api/trader/transactions/<transaction_id>/receipt', methods=['POST'])
@role_required('trader')
@csrf_protect
def upload_transaction_receipt(transaction_id):
    if 'receipt' not in request.files:
        return jsonify({'error': 'No file uploaded'}), 400
    
    file = request.files['receipt']
    if file.filename == '':
        return jsonify({'error': 'No selected file'}), 400
    
    if file and allowed_file(file.filename):
        filename = f"receipt_{transaction_id}_{datetime.now().timestamp()}.{file.filename.rsplit('.', 1)[1].lower()}"
        file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
        
        db.update_one('transactions', {'id': int(transaction_id)}, {
            'receipt_file': filename,
            'receipt_uploaded_at': datetime.now().isoformat()
        })
        
        return jsonify({'success': True, 'filename': filename})
    
    return jsonify({'error': 'Invalid file type'}), 400

@app.route('/api/trader/orders/<order_id>', methods=['PUT', 'DELETE'])
@role_required('trader')
@csrf_protect
def manage_order(order_id):
    user = get_current_user()
    
    if request.method == 'PUT':
        data = request.get_json()
        
        order = db.find_one('orders', {'id': int(order_id), 'trader_id': int(user['id'])})
        if not order:
            return jsonify({'error': 'Order not found or access denied'}), 404
        
        updates = {
            'type': data['type'],
            'amount': float(data['amount']),
            'method': data['method'],
            'details_id': int(data['details_id']),
            'status': data['status'],
            'updated_at': datetime.now().isoformat()
        }
        
        db.update_one('orders', {'id': int(order_id)}, updates)
        return jsonify({'success': True})
    
    elif request.method == 'DELETE':
        order = db.find_one('orders', {'id': int(order_id), 'trader_id': int(user['id'])})
        if not order:
            return jsonify({'error': 'Order not found or access denied'}), 404
        
        if order['status'] == 'completed':
            return jsonify({'error': 'Cannot delete completed order'}), 400
        
        db.delete_one('orders', {'id': int(order_id)})
        return jsonify({'success': True})

@app.route('/api/trader/active-transactions')
@role_required('trader')
def get_active_transactions_tra():
    user = get_current_user()
    try:
        transactions = db.find('transactions', {
            'trader_id': int(user['id']),
            'status': {'$nin': ['completed', 'failed', 'cancelled']}
        }) or []
        
        for tx in transactions:
            tx['id'] = str(tx.get('id', ''))
        
        return jsonify(transactions)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/trader/orders/<order_id>', methods=['GET'])
@role_required('trader')
def get_trader_order_tr(order_id):
    user = get_current_user()
    try:
        order = db.find_one('orders', {'id': int(order_id), 'trader_id': int(user['id'])})
        if not order:
            return jsonify({'error': 'Order not found or access denied'}), 404
        
        order['id'] = str(order.get('id', ''))
        order['details_id'] = str(order.get('details_id', ''))
        
        return jsonify(order)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/trader/orders/<order_id>', methods=['PUT'])
@role_required('trader')
@csrf_protect
def update_trader_order(order_id):
    user = get_current_user()
    try:
        data = request.get_json()
        
        order = db.find_one('orders', {'id': int(order_id), 'trader_id': int(user['id'])})
        if not order:
            return jsonify({'error': 'Order not found or access denied'}), 404
        
        updates = {
            'type': data['type'],
            'amount': float(data['amount']),
            'method': data['method'],
            'details_id': int(data['details_id']),
            'status': data['status'],
            'updated_at': datetime.now().isoformat()
        }
        
        db.update_one('orders', {'id': int(order['id'])}, updates)
        return jsonify({'success': True, 'order': updates})
    except Exception as e:
        return jsonify({'error': str(e)}), 400

@app.route('/api/trader/orders/<order_id>', methods=['DELETE'])
@role_required('trader')
@csrf_protect
def delete_trader_order(order_id):
    user = get_current_user()
    try:
        order = db.find_one('orders', {'id': int(order_id), 'trader_id': int(user['id'])})
        if not order:
            return jsonify({'error': 'Order not found or access denied'}), 404
        
        if order.get('status') == 'completed':
            return jsonify({'error': 'Cannot delete completed order'}), 400
        
        db.delete_one('orders', {'id': int(order['id'])})
        return jsonify({'success': True})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/trader/transactions/<transaction_id>/complete', methods=['POST'])
@role_required('trader')
@csrf_protect
def complete_merchant_transaction(transaction_id):
    user = get_current_user()
    try:
        transaction = db.find_one('transactions', {
            'id': int(transaction_id),
            'trader_id': int(user['id']),
            'status': 'in_progress'
        })
        
        if not transaction:
            return jsonify({'error': 'Transaction not found, not assigned to you, or not in progress'}), 404
        
        if transaction['type'] == 'withdrawal' and not transaction.get('receipt_file'):
            return jsonify({'error': 'Receipt is required for withdrawal transactions'}), 400
        
        db.update_one('transactions', {'id': int(transaction_id)}, {
            'status': 'pending_admin_approval',
            'completed_at': datetime.now().isoformat()
        })
        
        return jsonify({'success': True})
    except Exception as e:
        return jsonify({'error': str(e)}), 500






# ===============
# Панель мерчанта
# ===============

@app.route('/merchant.html')
@role_required('merchant')
def merchant_dashboard():
    user = get_current_user()
    merchant_id = int(user['id'])

    requisites_types = db.find_one('requisites_types', {}) or {}
    if requisites_types and 'types' in requisites_types:
        requisites_types = requisites_types['types']
    else:
        requisites_types = []
    
    transactions = [t for t in (db.find('transactions', {'merchant_id': merchant_id})) or [] if isinstance(t, dict)]
    api_keys = [k for k in (db.find('api_keys', {'merchant_id': merchant_id})) or [] if isinstance(k, dict)]
    matches = [m for m in (db.find('matches', {'merchant_id': merchant_id})) or [] if isinstance(m, dict)]
    
    recent_transactions = sorted(
        [t for t in transactions if isinstance(t, dict)],
        key=lambda x: x.get('created_at', ''),
        reverse=True
    )[:5]
    
    stats = {
        'today_transactions': len([t for t in transactions 
                                 if isinstance(t.get('created_at'), str) and
                                 datetime.fromisoformat(t['created_at']).date() == datetime.now().date()]),
        'avg_amount': round(sum(float(t.get('amount', 0)) for t in transactions) / len(transactions), 2) if transactions else 0,
        'conversion_rate': calculate_conversion_rate(transactions),
        'weekly_stats': calculate_weekly_stats(transactions)
    }
    
    pending_transactions = [t for t in transactions if t.get('status') == 'pending']
    completed_transactions = [t for t in transactions if t.get('status') == 'completed']
    
    pending_matches = [m for m in matches if m.get('status') == 'pending']
    completed_matches = [m for m in matches if m.get('status') == 'completed']
    rejected_matches = [m for m in matches if m.get('status') == 'rejected']

    deposit_requests = db.find('deposit_requests', {'user_id': merchant_id}) or []
    withdrawal_requests = db.find('withdrawal_requests', {'user_id': merchant_id}) or []

    requisites_types = [
        {'id': '1', 'name': 'Банковский счет'},
        {'id': '2', 'name': 'Банковская карта'},
        {'id': '3', 'name': 'Криптокошелек'}
    ]
    
    return render_template(
        'merchant.html',
        user=user,
        requisites_types=requisites_types,
        stats=stats,
        recent_transactions=recent_transactions,
        all_transactions=transactions,
        pending_transactions=pending_transactions,
        completed_transactions=completed_transactions,
        api_keys=api_keys,
        pending_matches=pending_matches,
        completed_matches=completed_matches,
        rejected_matches=rejected_matches,
        current_date=datetime.now().strftime('%Y-%m-%d'),
        deposit_requests=deposit_requests,
        withdrawal_requests=withdrawal_requests
    )

@app.route('/api/merchant/transactions', methods=['POST'])
@role_required('merchant')
@csrf_protect
def create_merchant_transaction():
    user = get_current_user()
    try:
        data = request.get_json()
        if not data:
            return jsonify({'error': 'No data provided'}), 400

        new_tx = {
            'id': int(uuid.uuid4().int & (1<<31)-1),  # Генерируем ID как int
            'merchant_id': int(user['id']),
            'type': data.get('type'),
            'amount': float(data.get('amount', 0)),
            'method': data.get('method'),
            'status': 'pending',
            'created_at': datetime.now().isoformat(),
            'updated_at': datetime.now().isoformat()
        }
        
        db.insert_one('transactions', new_tx)
        return jsonify({'success': True, 'transaction': new_tx})
    
    except Exception as e:
        logger.error(f"Error creating merchant transaction: {str(e)}")
        return jsonify({'error': str(e)}), 400

@app.route('/api/merchant/transactions/<tx_id>/cancel', methods=['POST'])
@role_required('merchant')
@csrf_protect
def cancel_merchant_transaction(tx_id):
    user = get_current_user()
    try:
        tx = db.find_one('transactions', {'id': int(tx_id), 'merchant_id': int(user['id'])})
        if not tx:
            return jsonify({'error': 'Transaction not found'}), 404
        
        if tx.get('status') != 'pending':
            return jsonify({'error': 'Only pending transactions can be canceled'}), 400
        
        db.update_one('transactions', {'id': int(tx['id'])}, {
            'status': 'cancelled',
            'cancelled_at': datetime.now().isoformat(),
            'cancelled_by': int(user['id'])
        })
        
        return jsonify({'success': True})
    
    except Exception as e:
        logger.error(f"Error canceling transaction: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/transactions/<tx_id>/requisites', methods=['POST'])
@role_required('merchant')
@csrf_protect
def add_transaction_requisites_merchant(tx_id):
    try:
        data = request.get_json()
        user = get_current_user()
        
        tx = db.find_one('transactions', {'id': int(tx_id), 'merchant_id': int(user['id'])})
        if not tx:
            return jsonify({'error': 'Transaction not found or access denied'}), 404
        
        requisites = {
            'type_id': data['type_id'],
            'details': data['details'],
            'status': 'pending',
            'added_at': datetime.now().isoformat()
        }
        
        db.update_one('transactions', {'id': int(tx_id)}, {
            'requisites': requisites,
            'requisites_approved': False
        })
        
        return jsonify({'success': True})
    except Exception as e:
        return jsonify({'error': str(e)}), 400

@app.route('/api/merchant/api_keys', methods=['POST'])
@role_required('merchant')
@csrf_protect
def generate_merchant_api_key():
    user = get_current_user()
    try:
        new_key = {
            'id': int(uuid.uuid4().int & (1<<31)-1),  # Генерируем ID как int
            'merchant_id': int(user['id']),
            'key': secrets.token_hex(16),
            'secret': secrets.token_hex(32),
            'created_at': datetime.now().isoformat(),
            'active': True
        }
        
        db.insert_one('api_keys', new_key)
        return jsonify({
            'success': True,
            'api_key': new_key['key'],
            'secret_key': new_key['secret']
        })
    
    except Exception as e:
        logger.error(f"Error generating API key: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/merchant/api_keys/<key_id>', methods=['DELETE'])
@role_required('merchant')
@csrf_protect
def revoke_merchant_api_key(key_id):
    user = get_current_user()
    try:
        key = db.find_one('api_keys', {'id': int(key_id), 'merchant_id': int(user['id'])})
        if not key:
            return jsonify({'error': 'API key not found'}), 404
        
        db.delete_one('api_keys', {'id': int(key_id)})
        return jsonify({'success': True})
    
    except Exception as e:
        logger.error(f"Error revoking API key: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/merchant/matches/perform', methods=['POST'])
@role_required('merchant')
@csrf_protect
def perform_merchant_matching():
    try:
        user = get_current_user()
        merchant_id = int(user['id'])
        
        currency_rates = db.find_one('system_settings', {'type': 'currency_rates'}) or {
            'USD': 75.0, 'EUR': 85.0, 'USDT': 1.0
        }
        commission_settings = db.find_one('system_settings', {'type': 'commissions'}) or {
            'default': 0.02
        }

        pending_deposits = [
            tx for tx in db.find('transactions', {
                'status': 'pending', 
                'type': 'deposit',
                'merchant_id': merchant_id
            }) if tx and tx.get('requisites_approved')
        ]
        
        pending_withdrawals = [
            tx for tx in db.find('transactions', {
                'status': 'pending', 
                'type': 'withdrawal',
                'merchant_id': merchant_id
            }) if tx and tx.get('requisites_approved')
        ]

        for tx in pending_deposits + pending_withdrawals:
            tx['converted_amount'] = float(tx['amount']) * currency_rates.get(tx.get('currency', 'RUB'), 1)

        pending_deposits.sort(key=lambda x: -x['converted_amount'])
        pending_withdrawals.sort(key=lambda x: x['converted_amount'])

        matched_pairs = []
        used_deposit_ids = set()

        for withdrawal in pending_withdrawals:
            commission = commission_settings.get('per_merchant', {}).get(str(merchant_id), 
                          commission_settings.get('default', 0.02))
            
            required_amount = withdrawal['converted_amount'] * (1 + commission)
            matched_deposits = []
            remaining_amount = required_amount

            for deposit in pending_deposits:
                if deposit['id'] in used_deposit_ids:
                    continue
                
                if deposit['converted_amount'] <= remaining_amount:
                    matched_deposits.append(deposit)
                    remaining_amount -= deposit['converted_amount']
                    used_deposit_ids.add(deposit['id'])
                    
                    if remaining_amount <= 0:
                        break

            if remaining_amount <= 0 and matched_deposits:
                match = {
                    'id': int(uuid.uuid4().int & (1<<31)-1),  # Генерируем ID как int
                    'deposit_ids': [d['id'] for d in matched_deposits],
                    'withdrawal_id': withdrawal['id'],
                    'amount': withdrawal['amount'],
                    'commission': commission,
                    'status': 'pending',
                    'created_at': datetime.now().isoformat(),
                    'merchant_id': merchant_id
                }
                db.insert_one('matches', match)
                matched_pairs.append(match)

                for d in matched_deposits:
                    db.update_one('transactions', {'id': d['id']}, {
                        'status': 'matched',
                        'match_id': match['id']
                    })
                db.update_one('transactions', {'id': withdrawal['id']}, {
                    'status': 'matched',
                    'match_id': match['id']
                })

        return jsonify({
            'success': True,
            'matches_created': len(matched_pairs)
        })
    except Exception as e:
        logger.error(f"Merchant matching error: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/merchant/matches', methods=['GET'])
@role_required('merchant')
def get_merchant_matches():
    try:
        user = get_current_user()
        status = request.args.get('status', 'pending')
        
        matches = db.find('matches', {
            'merchant_id': int(user['id']),
            'status': status
        }) or []
        
        return jsonify(matches)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/merchant/matches/<match_id>/confirm', methods=['POST'])
@role_required('merchant')
@csrf_protect
def merchant_confirm_match(match_id):
    try:
        user = get_current_user()
        match = db.find_one('matches', {
            'id': int(match_id),
            'merchant_id': int(user['id'])
        })
        
        if not match:
            return jsonify({'error': 'Match not found or access denied'}), 404
        
        db.update_one('matches', {'id': int(match_id)}, {
            'status': 'completed',
            'completed_at': datetime.now().isoformat()
        })
        
        for dep_id in match.get('deposit_ids', []):
            db.update_one('transactions', {'id': dep_id}, {
                'status': 'completed',
                'completed_at': datetime.now().isoformat()
            })
        
        if match.get('withdrawal_id'):
            db.update_one('transactions', {'id': match['withdrawal_id']}, {
                'status': 'completed',
                'completed_at': datetime.now().isoformat()
            })
        
        return jsonify({'success': True})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/merchant/matches/<match_id>/reject', methods=['POST'])
@role_required('merchant')
@csrf_protect
def reject_merchant_match(match_id):
    user = get_current_user()
    try:
        data = request.get_json()
        match = db.find_one('matches', {'id': int(match_id), 'merchant_id': int(user['id'])})
        if not match:
            return jsonify({'error': 'Match not found'}), 404
        
        updates = {
            'status': 'rejected',
            'rejected_at': datetime.now().isoformat(),
            'rejected_by': int(user['id']),
            'reason': data.get('reason', 'No reason provided')
        }
        
        db.update_one('matches', {'id': int(match_id)}, updates)
        
        if match.get('deposit_id'):
            db.update_one('transactions', {'id': match['deposit_id']}, {'status': 'rejected'})
        if match.get('withdrawal_id'):
            db.update_one('transactions', {'id': match['withdrawal_id']}, {'status': 'rejected'})
        
        return jsonify({'success': True})
    
    except Exception as e:
        logger.error(f"Error rejecting match: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/merchant/transactions/<tx_id>/verify', methods=['POST'])
@role_required('merchant')
@csrf_protect
def verify_merchant_transaction_sole(tx_id):
    user = get_current_user()
    try:
        if 'file' not in request.files:
            return jsonify({'error': 'No file uploaded'}), 400
        
        file = request.files['file']
        if file.filename == '':
            return jsonify({'error': 'No selected file'}), 400
        
        if file and allowed_file(file.filename):
            filename = f"{tx_id}_{datetime.now().timestamp()}.pdf"
            file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
            
            db.update_one('transactions', {'id': int(tx_id), 'merchant_id': int(user['id'])}, {
                'verified': True,
                'verification_file': filename,
                'verified_at': datetime.now().isoformat()
            })
            
            return jsonify({'success': True})
        
        return jsonify({'error': 'Invalid file type'}), 400
    
    except Exception as e:
        logger.error(f"Error verifying transaction: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/merchant/matches/refresh', methods=['POST'])
@role_required('merchant')
@csrf_protect
def refresh_matches():
    try:
        matched_pairs = perform_matching()
        return jsonify({
            'success': True,
            'count': len(matched_pairs),
            'matches': matched_pairs
        })
    except Exception as e:
        logger.error(f"Ошибка при обновлении матчинга: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/merchant/matches/pending', methods=['GET'])
@role_required('merchant')
def get_pending_matches():
    try:
        page = int(request.args.get('page', 1))
        per_page = int(request.args.get('per_page', 10))
        
        matches = MatchingService.get_pending_matches(
            limit=per_page,
            offset=(page-1)*per_page
        )
        
        return jsonify({
            'success': True,
            'data': matches['data'],
            'total': matches['total'],
            'page': page,
            'per_page': per_page
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 400

@app.route('/api/merchant/matching/auto', methods=['POST'])
@role_required('merchant')
@csrf_protect
def toggle_auto_matching():
    global AUTO_MATCHING_ENABLED
    try:
        data = request.get_json()
        AUTO_MATCHING_ENABLED = bool(data.get('enabled', False))
        
        return jsonify({
            'success': True,
            'auto_matching': AUTO_MATCHING_ENABLED
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 400

@app.route('/api/requisites/types/<method>')
@role_required('merchant')
def get_requisites_types(method):
    try:
        types = db.find_one('requisites_types', {}) or {}
        if types and 'types' in types:
            req_type = next((t for t in types['types'] if t['name'].lower() == method.lower()), None)
            if req_type:
                return jsonify(req_type)
        return jsonify({'error': 'Type not found'}), 404
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/deposit_requests', methods=['POST'])
@role_required('merchant')
@csrf_protect
def create_deposit_request_merch():
    try:
        data = request.get_json()
        user = get_current_user()
        
        if not data or 'amount' not in data or 'payment_method' not in data:
            return jsonify({'error': 'Missing required fields'}), 400

        request_data = {
            'id': int(uuid.uuid4().int & (1<<31)-1),  # Генерируем ID как int
            'user_id': int(user['id']),
            'amount': float(data['amount']),
            'currency': data.get('currency', 'RUB'),
            'payment_method': data['payment_method'],
            'requisites': data.get('requisites', {}),
            'status': 'pending',
            'created_at': datetime.now().isoformat()
        }
        
        db.insert_one('deposit_requests', request_data)
        return jsonify({'success': True, 'request': request_data})
    except Exception as e:
        return jsonify({'error': str(e)}), 400

@app.route('/api/withdrawal_requests', methods=['POST'])
@role_required('merchant')
@csrf_protect
def create_withdrawal_request_merch():
    try:
        data = request.get_json()
        user = get_current_user()
        
        if not data or 'amount' not in data or 'withdrawal_method' not in data:
            return jsonify({'error': 'Missing required fields'}), 400

        if float(data['amount']) > float(user.get('balance', 0)):
            return jsonify({'error': 'Недостаточно средств'}), 400

        request_data = {
            'id': int(uuid.uuid4().int & (1<<31)-1),  # Генерируем ID как int
            'user_id': int(user['id']),
            'amount': float(data['amount']),
            'currency': data.get('currency', 'RUB'),
            'withdrawal_method': data['withdrawal_method'],
            'requisites': data.get('requisites', {}),
            'status': 'pending',
            'created_at': datetime.now().isoformat()
        }
        
        db.insert_one('withdrawal_requests', request_data)
        return jsonify({'success': True, 'request': request_data})
    except Exception as e:
        return jsonify({'error': str(e)}), 400

@app.route('/api/requisites/types', methods=['GET'])
@role_required('merchant')
def get_requisites_types_by_method():
    method = request.args.get('method')
    if not method:
        return jsonify({'error': 'Method parameter is required'}), 400
    
    types_data = {
        'bank': {
            'fields': [
                {'name': 'account_number', 'label': 'Номер счета', 'type': 'text'},
                {'name': 'bik', 'label': 'БИК', 'type': 'text'},
                {'name': 'bank_name', 'label': 'Название банка', 'type': 'text'},
                {'name': 'owner_name', 'label': 'ФИО владельца', 'type': 'text'}
            ]
        },
        'card': {
            'fields': [
                {'name': 'card_number', 'label': 'Номер карты', 'type': 'text'},
                {'name': 'card_owner', 'label': 'ФИО владельца', 'type': 'text'},
                {'name': 'card_expiry', 'label': 'Срок действия', 'type': 'text'},
                {'name': 'card_cvv', 'label': 'CVV код', 'type': 'password'}
            ]
        },
        'crypto': {
            'fields': [
                {'name': 'wallet_address', 'label': 'Адрес кошелька', 'type': 'text'},
                {'name': 'crypto_type', 'label': 'Тип криптовалюты', 'type': 'select', 
                 'options': ['BTC', 'ETH', 'USDT', 'USDC', 'BNB']}
            ]
        }
    }
    
    if method not in types_data:
        return jsonify({'error': 'Method not found'}), 404
    
    return jsonify(types_data[method])

@app.route('/api/requisites/types/<type_id>', methods=['GET'])
@role_required('merchant')
def get_requisites_type_fields(type_id):
    try:
        types_data = {
            '1': {
                'fields': [
                    {'name': 'account_number', 'label': 'Номер счета', 'type': 'text'},
                    {'name': 'bik', 'label': 'БИК', 'type': 'text'},
                    {'name': 'bank_name', 'label': 'Название банка', 'type': 'text'},
                    {'name': 'owner_name', 'label': 'ФИО владельца', 'type': 'text'}
                ]
            },
            '2': {
                'fields': [
                    {'name': 'card_number', 'label': 'Номер карты', 'type': 'text'},
                    {'name': 'card_owner', 'label': 'ФИО владельца', 'type': 'text'},
                    {'name': 'card_expiry', 'label': 'Срок действия', 'type': 'text'},
                    {'name': 'card_cvv', 'label': 'CVV код', 'type': 'password'}
                ]
            },
            '3': {
                'fields': [
                    {'name': 'wallet_address', 'label': 'Адрес кошелька', 'type': 'text'},
                    {'name': 'crypto_type', 'label': 'Тип криптовалюты', 'type': 'select', 
                     'options': ['BTC', 'ETH', 'USDT', 'USDC', 'BNB']}
                ]
            }
        }
        
        if type_id not in types_data:
            return jsonify({'error': 'Type not found'}), 404
        
        return jsonify(types_data[type_id])
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# ===========================================
# Обработка файлов, ошибок, статические файлы
# ===========================================

@app.route('/api/transactions/<tx_id>/verify', methods=['POST'])
@login_required
def api_verify_transaction(tx_id):
    if 'file' not in request.files:
        return jsonify({'error': 'No file uploaded'}), 400
    
    file = request.files['file']
    if file.filename == '':
        return jsonify({'error': 'No selected file'}), 400
    
    if file and allowed_file(file.filename):
        filename = f"{tx_id}_{datetime.now().timestamp()}.pdf"
        file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
        
        db.update_one('transactions', {'id': int(tx_id)}, {
            'verified': True,
            'verification_file': filename,
            'verified_at': datetime.now().isoformat()
        })
        
        return jsonify({'success': True})
    
    return jsonify({'error': 'Invalid file type'}), 400

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
    start_auto_matching()
else:
    gunicorn_app = app
    gunicorn_logger = logging.getLogger('gunicorn.error')
    app.logger.handlers = gunicorn_logger.handlers
    app.logger.setLevel(gunicorn_logger.level)