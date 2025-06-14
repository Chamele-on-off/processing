from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash
from flask_jwt_extended import create_access_token
from extensions import db

class User:
    @staticmethod
    def create(email, password, role, **kwargs):
        user = {
            'email': email,
            'password_hash': generate_password_hash(password),
            'role': role,
            'is_active': True,
            'created_at': datetime.now().isoformat(),
            'last_login': None,
            'ip_address': None,
            'geo_location': None,
            'balance': 0.0,
            'insurance_deposit': 0.0,
            'priority': 0,
            **kwargs
        }
        return db.insert_one('users', user)

    @staticmethod
    def find_by_email(email):
        return db.find_one('users', {'email': email})

    @staticmethod
    def find_by_id(user_id):
        return db.find_one('users', {'id': user_id})

    @staticmethod
    def authenticate(email, password):
        user = User.find_by_email(email)
        if user and check_password_hash(user.get('password_hash', ''), password):
            return user
        return None

    @staticmethod
    def update_last_login(user_id, ip_address=None, geo_location=None):
        update_data = {
            'last_login': datetime.now().isoformat(),
            'ip_address': ip_address,
            'geo_location': geo_location
        }
        db.update_one('users', {'id': user_id}, update_data)

    @staticmethod
    def get_available_traders():
        traders = db.find('users', {
            'role': 'trader',
            'is_active': True
        })
        return sorted(traders, key=lambda x: (-x.get('priority', 0), -x.get('insurance_deposit', 0)))

    @staticmethod
    def get_count():
        return len(db.find('users', {}))

    @staticmethod
    def get_active_traders_count():
        return len(db.find('users', {
            'role': 'trader',
            'is_active': True
        }))

    @staticmethod
    def generate_token(user):
        return create_access_token(identity={
            'id': user['id'],
            'email': user['email'],
            'role': user['role']
        })

    @staticmethod
    def verify_jwt(token_payload):
        return db.find_one('users', {'id': token_payload['id']})

    @staticmethod
    def to_dict(user):
        if not user:
            return None
            
        return {
            'id': user['id'],
            'email': user['email'],
            'role': user['role'],
            'balance': user.get('balance', 0),
            'insurance_deposit': user.get('insurance_deposit', 0),
            'is_active': user.get('is_active', True),
            'priority': user.get('priority', 0),
            'last_login': user.get('last_login')
        }