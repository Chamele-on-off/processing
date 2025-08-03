import os
import logging
import json
from datetime import datetime, timedelta
from functools import wraps
from flask import Flask, render_template, request, session, redirect, jsonify, send_from_directory, url_for, make_response, Response
from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.utils import secure_filename
import random
import uuid
import secrets
import time
import threading
from copy import deepcopy
from collections import defaultdict

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

# ============
# JSON Database
# ============

class JSONDatabase:
    def __init__(self):
        self.data_dir = 'data'
        self.lock = threading.RLock()
        self.init_db()
        
    def init_db(self):
        """Инициализация базы данных с созданием необходимых файлов"""
        os.makedirs(self.data_dir, exist_ok=True)
        
        # Основные файлы базы данных
        self.db_files = {
            'settings': os.path.join(self.data_dir, 'settings.json'),
            'transactions': os.path.join(self.data_dir, 'transactions.json'),
            'users': os.path.join(self.data_dir, 'users.json'),
            'matches': os.path.join(self.data_dir, 'matches.json'),
            'requisites': os.path.join(self.data_dir, 'requisites.json')
        }
        
        # Инициализация файлов, если они не существуют
        for file_type, file_path in self.db_files.items():
            if not os.path.exists(file_path):
                with self.lock:
                    with open(file_path, 'w') as f:
                        if file_type == 'settings':
                            json.dump({
                                'exchange_rates': {
                                    'USD': 1.0,
                                    'EUR': 0.85,
                                    'RUB': 75.0
                                },
                                'fees': {
                                    'deposit': 0.01,
                                    'withdrawal': 0.02
                                },
                                'last_ids': {
                                    'transactions': 0,
                                    'users': 0,
                                    'matches': 0,
                                    'requisites': 0
                                }
                            }, f)
                        else:
                            json.dump([], f)
        
        # Создание тестовых пользователей, если их нет
        self.create_test_users()
    
    def create_test_users(self):
        """Создание тестовых пользователей при инициализации"""
        test_users = [
            {
                'email': 'admin@example.com',
                'password_hash': generate_password_hash('admin123'),
                'role': 'admin',
                'name': 'Admin User',
                'created_at': datetime.now().isoformat(),
                'updated_at': datetime.now().isoformat()
            },
            {
                'email': 'trader@example.com',
                'password_hash': generate_password_hash('trader123'),
                'role': 'trader',
                'name': 'Trader User',
                'created_at': datetime.now().isoformat(),
                'updated_at': datetime.now().isoformat()
            },
            {
                'email': 'merchant@example.com',
                'password_hash': generate_password_hash('merchant123'),
                'role': 'merchant',
                'name': 'Merchant User',
                'created_at': datetime.now().isoformat(),
                'updated_at': datetime.now().isoformat()
            }
        ]
        
        for user in test_users:
            try:
                existing = self.find_one('users', {'email': user['email']})
                if not existing:
                    user['id'] = self.get_next_id('users')
                    self.insert_one('users', user)
            except Exception as e:
                logger.error(f"Error creating test user {user['email']}: {str(e)}")
                continue
    
    def _read_file(self, file_type):
        """Чтение данных из файла с обработкой ошибок"""
        file_path = self.db_files[file_type]
        with self.lock:
            try:
                with open(file_path, 'r') as f:
                    try:
                        return json.load(f)
                    except json.JSONDecodeError:
                        logger.warning(f"Invalid JSON in {file_path}, initializing with empty data")
                        # Если файл поврежден, переинициализируем его
                        default_data = [] if file_type != 'settings' else {
                            'exchange_rates': {'USD': 1.0, 'EUR': 0.85, 'RUB': 75.0},
                            'fees': {'deposit': 0.01, 'withdrawal': 0.02},
                            'last_ids': {'transactions': 0, 'users': 0, 'matches': 0, 'requisites': 0}
                        }
                        with open(file_path, 'w') as f_write:
                            json.dump(default_data, f_write)
                        return default_data
            except FileNotFoundError:
                logger.warning(f"File {file_path} not found, initializing")
                self.init_db()
                return [] if file_type != 'settings' else {
                    'exchange_rates': {'USD': 1.0, 'EUR': 0.85, 'RUB': 75.0},
                    'fees': {'deposit': 0.01, 'withdrawal': 0.02},
                    'last_ids': {'transactions': 0, 'users': 0, 'matches': 0, 'requisites': 0}
                }
    
    def _write_file(self, file_type, data):
        """Запись данных в файл"""
        with self.lock:
            with open(self.db_files[file_type], 'w') as f:
                json.dump(data, f, indent=2)
    
    def get_next_id(self, entity_type):
        """Получение следующего ID для указанного типа сущности"""
        settings = self._read_file('settings')
        settings['last_ids'][entity_type] += 1
        self._write_file('settings', settings)
        return settings['last_ids'][entity_type]
    
    def find_one(self, collection, query):
        """Поиск одного документа в коллекции"""
        data = self._read_file(collection)
        if not isinstance(data, list):
            return None
        for item in data:
            if all(item.get(k) == v for k, v in query.items()):
                return deepcopy(item)
        return None
    
    def find(self, collection, query=None):
        """Поиск всех документов в коллекции"""
        data = self._read_file(collection)
        if not isinstance(data, list):
            return []
        if query is None:
            return deepcopy(data)
        return [deepcopy(item) for item in data if all(item.get(k) == v for k, v in query.items())]
    
    def insert_one(self, collection, document):
        """Вставка одного документа в коллекцию"""
        data = self._read_file(collection)
        if not isinstance(data, list):
            data = []
        
        if 'id' not in document:
            document['id'] = self.get_next_id(collection)
        
        document['created_at'] = datetime.now().isoformat()
        document['updated_at'] = document['created_at']
        
        data.append(document)
        self._write_file(collection, data)
        return document
    
    def update_one(self, collection, query, updates):
        """Обновление одного документа в коллекции"""
        data = self._read_file(collection)
        if not isinstance(data, list):
            return False
        
        updated = False
        for item in data:
            if all(item.get(k) == v for k, v in query.items()):
                item.update(updates)
                item['updated_at'] = datetime.now().isoformat()
                updated = True
                break
        
        if updated:
            self._write_file(collection, data)
        return updated
    
    def delete_one(self, collection, query):
        """Удаление одного документа из коллекции"""
        data = self._read_file(collection)
        if not isinstance(data, list):
            return False
        
        new_data = [item for item in data if not all(item.get(k) == v for k, v in query.items())]
        
        if len(new_data) < len(data):
            self._write_file(collection, new_data)
            return True
        return False
    
    def get_settings(self):
        """Получение настроек"""
        return self._read_file('settings')
    
    def update_settings(self, updates):
        """Обновление настроек"""
        settings = self._read_file('settings')
        settings.update(updates)
        self._write_file('settings', settings)
        return settings

# ============
# Matching Service
# ============

class MatchingService:
    def __init__(self, db):
        self.db = db
        self.lock = threading.RLock()
    
    def find_match(self, transaction):
        """Поиск совпадения для транзакции"""
        with self.lock:
            # Получаем все противоположные транзакции
            opposite_type = 'withdrawal' if transaction['type'] == 'deposit' else 'deposit'
            candidates = self.db.find('transactions', {
                'type': opposite_type,
                'currency': transaction['currency'],
                'status': 'pending',
                'amount': transaction['amount']
            })
            
            # Ищем лучшую кандидатуру
            for candidate in candidates:
                # Проверяем, что транзакции еще не связаны
                existing_match = self.db.find_one('matches', {
                    'transaction_id': transaction['id'],
                    'matched_transaction_id': candidate['id']
                })
                
                if not existing_match:
                    # Создаем запись о совпадении
                    match_id = self.db.get_next_id('matches')
                    match_record = {
                        'id': match_id,
                        'transaction_id': transaction['id'],
                        'matched_transaction_id': candidate['id'],
                        'status': 'matched',
                        'created_at': datetime.now().isoformat(),
                        'updated_at': datetime.now().isoformat()
                    }
                    
                    self.db.insert_one('matches', match_record)
                    
                    # Обновляем статусы транзакций
                    self.db.update_one('transactions', {'id': transaction['id']}, {'status': 'matched'})
                    self.db.update_one('transactions', {'id': candidate['id']}, {'status': 'matched'})
                    
                    return match_record
            
            return None
    
    def process_matches(self):
        """Обработка всех ожидающих совпадений"""
        with self.lock:
            pending_transactions = self.db.find('transactions', {'status': 'pending'})
            
            for transaction in pending_transactions:
                self.find_match(transaction)

# ============
# Flask App
# ============

app = Flask(__name__, template_folder='templates', static_folder='static')
app.jinja_env.filters['datetimeformat'] = lambda value, format='%d.%m.%Y %H:%M': value.strftime(format) if isinstance(value, datetime) else value
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

# Инициализация базы данных и сервисов
db = JSONDatabase()
matching_service = MatchingService(db)

# Создаем папку для загрузок
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# ============
# Helpers
# ============

def generate_csrf_token():
    if 'csrf_token' not in session:
        session['csrf_token'] = secrets.token_hex(16)
    return session['csrf_token']

def check_csrf_token():
    if request.method in ('POST', 'PUT', 'PATCH', 'DELETE'):
        token = request.headers.get('X-CSRF-Token') or request.form.get('csrf_token')
        if not token or token != session.get('csrf_token'):
            return jsonify({'error': 'Invalid CSRF token'}), 403
    return None

def authenticate(email, password):
    user = db.find_one('users', {'email': email})
    if user and check_password_hash(user['password_hash'], password):
        return user
    return None

def get_current_user():
    if 'user_id' in session:
        return db.find_one('users', {'id': session['user_id']})
    return None

def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']

def calculate_avg_processing_time():
    transactions = db.find('transactions', {'status': 'completed'})
    if not transactions:
        return 0
    
    total_seconds = 0
    for t in transactions:
        try:
            created = datetime.fromisoformat(t['created_at'])
            completed = datetime.fromisoformat(t['completed_at'])
            total_seconds += (completed - created).total_seconds()
        except:
            continue
    
    return round((total_seconds / len(transactions)) / 60, 2)

def generate_activity_data(days=7):
    now = datetime.now()
    labels = []
    values = []
    
    for i in range(days, -1, -1):
        date = (now - timedelta(days=i)).date()
        labels.append(date.strftime('%d.%m'))
        
        transactions = db.find('transactions')
        count = len([t for t in transactions 
                    if datetime.fromisoformat(t['created_at']).date() == date])
        values.append(count)
    
    return {'labels': labels, 'values': values}

def calculate_conversion_rate(transactions):
    if not transactions:
        return 0
    completed = len([t for t in transactions if t['status'] == 'completed'])
    return round((completed / len(transactions)) * 100, 2)

def calculate_weekly_stats(transactions):
    stats = {'deposits': 0, 'withdrawals': 0, 'total_amount': 0}
    week_ago = datetime.now() - timedelta(days=7)
    
    for t in transactions:
        created = datetime.fromisoformat(t['created_at'])
        if created < week_ago:
            continue
            
        amount = float(t.get('amount', 0))
        stats['total_amount'] += amount
        
        if t['type'] == 'deposit':
            stats['deposits'] += 1
        elif t['type'] == 'withdrawal':
            stats['withdrawals'] += 1
    
    return stats

# ============
# Decorators
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
app.get_current_user = get_current_user
app.allowed_file = allowed_file
app.calculate_avg_processing_time = calculate_avg_processing_time
app.generate_activity_data = generate_activity_data
app.calculate_conversion_rate = calculate_conversion_rate
app.calculate_weekly_stats = calculate_weekly_stats

# Инъекция CSRF токена во все шаблоны
@app.context_processor
def inject_csrf_token():
    return dict(csrf_token=generate_csrf_token())

# ============
# Routes
# ============

@app.route('/login.html', methods=['GET', 'POST'])
def login():
    if request.method == 'GET':
        user = get_current_user()
        if user:
            return redirect(url_for(f"{user['role']}_dashboard"))
        return render_template('login.html')
    
    data = request.get_json() if request.is_json else request.form
    email = data.get('email')
    password = data.get('password')
    
    if not email or not password:
        return jsonify({'error': 'Email and password are required'}), 400
    
    user = authenticate(email, password)
    if user:
        session['user_id'] = user['id']
        session['role'] = user['role']
        session.permanent = True
        generate_csrf_token()
        
        if request.is_json:
            return jsonify({
                'success': True,
                'redirect': url_for(f"{user['role']}_dashboard")
            })
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
# Admin Routes
# ============

@app.route('/admin/dashboard')
@login_required
@role_required('admin')
def admin_dashboard():
    users = db.find('users')
    transactions = db.find('transactions')
    settings = db.get_settings()
    
    stats = {
        'total_users': len(users),
        'total_transactions': len(transactions),
        'pending_transactions': len([t for t in transactions if t['status'] == 'pending']),
        'avg_processing_time': calculate_avg_processing_time(),
        'activity_data': generate_activity_data()
    }
    
    return render_template('admin.html', 
                         users=users,
                         transactions=transactions,
                         settings=settings,
                         stats=stats)

@app.route('/admin/update_settings', methods=['POST'])
@login_required
@role_required('admin')
@csrf_protect
def update_settings():
    data = request.get_json()
    if not data:
        return jsonify({'error': 'No data provided'}), 400
    
    try:
        updated = db.update_settings(data)
        return jsonify({'success': True, 'settings': updated})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# ============
# Trader Routes
# ============

@app.route('/trader/dashboard')
@login_required
@role_required('trader')
def trader_dashboard():
    user = get_current_user()
    transactions = db.find('transactions', {'trader_id': user['id']})
    
    stats = {
        'pending': len([t for t in transactions if t['status'] == 'pending']),
        'matched': len([t for t in transactions if t['status'] == 'matched']),
        'completed': len([t for t in transactions if t['status'] == 'completed']),
        'weekly_stats': calculate_weekly_stats(transactions)
    }
    
    return render_template('trader.html', 
                         transactions=transactions,
                         stats=stats)

@app.route('/trader/process_transaction', methods=['POST'])
@login_required
@role_required('trader')
@csrf_protect
def process_transaction():
    data = request.get_json()
    if not data or 'transaction_id' not in data:
        return jsonify({'error': 'Transaction ID required'}), 400
    
    transaction = db.find_one('transactions', {'id': data['transaction_id']})
    if not transaction:
        return jsonify({'error': 'Transaction not found'}), 404
    
    try:
        db.update_one('transactions', {'id': transaction['id']}, {'status': 'completed', 'completed_at': datetime.now().isoformat()})
        return jsonify({'success': True})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# ============
# Merchant Routes
# ============

@app.route('/merchant/dashboard')
@login_required
@role_required('merchant')
def merchant_dashboard():
    user = get_current_user()
    transactions = db.find('transactions', {'merchant_id': user['id']})
    
    stats = {
        'total': len(transactions),
        'conversion_rate': calculate_conversion_rate(transactions),
        'weekly_stats': calculate_weekly_stats(transactions)
    }
    
    return render_template('merchant.html', 
                         transactions=transactions,
                         stats=stats)

@app.route('/merchant/create_transaction', methods=['POST'])
@login_required
@role_required('merchant')
@csrf_protect
def create_transaction():
    data = request.get_json()
    if not data or 'amount' not in data or 'currency' not in data or 'type' not in data:
        return jsonify({'error': 'Amount, currency and type required'}), 400
    
    user = get_current_user()
    transaction_data = {
        'merchant_id': user['id'],
        'amount': float(data['amount']),
        'currency': data['currency'],
        'type': data['type'],
        'status': 'pending',
        'created_at': datetime.now().isoformat(),
        'updated_at': datetime.now().isoformat()
    }
    
    try:
        transaction = db.insert_one('transactions', transaction_data)
        matching_service.find_match(transaction)
        return jsonify({'success': True, 'transaction': transaction})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# ============
# Static Files & Errors
# ============

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

# ============
# Background Tasks
# ============

def background_match_processing():
    """Фоновая задача для обработки совпадений"""
    while True:
        try:
            matching_service.process_matches()
            time.sleep(10)
        except Exception as e:
            logger.error(f"Error in background matching: {str(e)}")
            time.sleep(30)

# Запуск фоновой задачи
thread = threading.Thread(target=background_match_processing, daemon=True)
thread.start()

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5001, debug=True)
else:
    gunicorn_app = app
    gunicorn_logger = logging.getLogger('gunicorn.error')
    app.logger.handlers = gunicorn_logger.handlers
    app.logger.setLevel(gunicorn_logger.level)