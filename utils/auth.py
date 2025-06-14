import logging
from functools import wraps
from flask import request, jsonify
from flask_jwt_extended import verify_jwt_in_request, get_jwt
from models.user import User
from extensions import db

logger = logging.getLogger(__name__)

def get_current_user():
    """Получение текущего пользователя из JWT"""
    verify_jwt_in_request()
    jwt_data = get_jwt()
    return User.find_by_id(jwt_data['sub']['id'])

def sync_user_activity(f):
    """Декоратор для синхронизации активности пользователя"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        user = get_current_user()
        if user:
            User.update_last_login(user['id'], request.remote_addr)
            logger.info(f"User activity: {user['id']} from {request.remote_addr}")
        return f(*args, **kwargs)
    return decorated_function

def password_complexity(password):
    """Проверка сложности пароля"""
    if len(password) < 8:
        return False, "Password must be at least 8 characters"
    if not any(c.isupper() for c in password):
        return False, "Password must contain uppercase letters"
    if not any(c.isdigit() for c in password):
        return False, "Password must contain digits"
    if not any(c in '!@#$%^&*' for c in password):
        return False, "Password must contain special characters"
    return True, ""

def refresh_token_required(f):
    """Декоратор для проверки refresh token"""
    @wraps(f)
    def decorated(*args, **kwargs):
        verify_jwt_in_request(refresh=True)
        return f(*args, **kwargs)
    return decorated

def get_user_permissions(user_id):
    """Получение прав пользователя"""
    user = User.find_by_id(user_id)
    if not user:
        return []
    
    role_permissions = {
        'admin': ['full_access', 'view_dashboard', 'manage_users', 'view_reports'],
        'trader': ['create_transactions', 'view_dashboard', 'upload_documents'],
        'merchant': ['view_transactions', 'request_payouts']
    }
    
    return role_permissions.get(user['role'], [])

def check_permission(permission):
    """Декоратор для проверки прав"""
    def decorator(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            user = get_current_user()
            if not user:
                return jsonify({'error': 'Authentication required'}), 401
            
            permissions = get_user_permissions(user['id'])
            if permission not in permissions:
                logger.warning(f"Permission denied for {user['id']} ({permission})")
                return jsonify({'error': 'Insufficient permissions'}), 403
            return f(*args, **kwargs)
        return decorated
    return decorator