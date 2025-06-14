import logging
from functools import wraps
from flask import jsonify, request
from flask_jwt_extended import verify_jwt_in_request, get_jwt
from models.transaction import Transaction
from datetime import datetime, timedelta

logger = logging.getLogger(__name__)

def role_required(roles):
    """Декоратор для проверки роли"""
    if isinstance(roles, str):
        roles = [roles]
    
    def decorator(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            verify_jwt_in_request()
            claims = get_jwt()
            if claims['sub']['role'] not in roles:
                logger.warning(f"Role check failed for {claims['sub']['role']}")
                return jsonify({'error': 'Insufficient permissions'}), 403
            return f(*args, **kwargs)
        return decorated
    return decorator

def admin_required(f):
    """Декоратор для проверки админских прав"""
    return role_required('admin')(f)

def trader_required(f):
    """Декоратор для проверки прав трейдера"""
    return role_required('trader')(f)

def merchant_required(f):
    """Декоратор для проверки прав мерчанта"""
    return role_required('merchant')(f)

def transaction_limit(max_per_hour=100):
    """Ограничение количества транзакций"""
    def decorator(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            verify_jwt_in_request()
            user_id = get_jwt()['sub']['id']
            hour_ago = (datetime.now() - timedelta(hours=1)).isoformat()
            
            count = Transaction.count({
                'user_id': user_id,
                'created_at': {'$gte': hour_ago}
            })
            
            if count >= max_per_hour:
                logger.warning(f"Transaction limit exceeded for user {user_id}")
                return jsonify({
                    'error': 'Transaction limit exceeded',
                    'limit': max_per_hour,
                    'remaining': 0
                }), 429
            
            return f(*args, **kwargs)
        return decorated
    return decorator

def validate_input(schema):
    """Валидация входных данных по схеме"""
    from jsonschema import validate, ValidationError
    
    def decorator(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            try:
                data = request.get_json()
                validate(instance=data, schema=schema)
                return f(*args, **kwargs)
            except ValidationError as e:
                logger.warning(f"Validation error: {str(e)}")
                return jsonify({'error': str(e)}), 400
        return decorated
    return decorator