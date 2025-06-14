from flask import Blueprint, request, jsonify
from werkzeug.security import check_password_hash
import logging

bp = Blueprint('auth', __name__)
logger = logging.getLogger(__name__)

# Пример базы данных (должно совпадать с app.py)
users_db = {
    "admin@example.com": {
        "id": 1,
        "email": "admin@example.com",
        "password_hash": "pbkdf2:sha256:260000$...",  # Замените на реальный хеш
        "role": "admin"
    },
    "trader@example.com": {
        "id": 2,
        "email": "trader@example.com",
        "password_hash": "pbkdf2:sha256:260000$...",  # Замените на реальный хеш
        "role": "trader"
    },
    "merchant@example.com": {
        "id": 3,
        "email": "merchant@example.com",
        "password_hash": "pbkdf2:sha256:260000$...",  # Замените на реальный хеш
        "role": "merchant"
    }
}

@bp.route('/api/auth/login', methods=['POST'])
def login():
    try:
        data = request.get_json()
        email = data.get('email')
        password = data.get('password')
        
        if not email or not password:
            return jsonify({'success': False, 'error': 'Email and password required'}), 400
        
        user = users_db.get(email)
        if not user or not check_password_hash(user['password_hash'], password):
            return jsonify({'success': False, 'error': 'Invalid credentials'}), 401
        
        return jsonify({
            'success': True,
            'user': {
                'id': user['id'],
                'email': user['email'],
                'role': user['role']
            }
        })
    
    except Exception as e:
        logger.error(f"Login error: {str(e)}")
        return jsonify({'success': False, 'error': 'Internal server error'}), 500

@bp.route('/api/auth/check', methods=['GET'])
def check_auth():
    # В реальном приложении здесь должна быть проверка сессии или JWT
    return jsonify({'success': True})