from routes.auth import bp as auth_bp
from routes.admin import bp as admin_bp
from routes.trader import bp as trader_bp
from routes.merchant import bp as merchant_bp
from routes.transactions import bp as transactions_bp
from routes.requisites import bp as requisites_bp
from routes.notifications import bp as notifications_bp

__all__ = [
    'auth_bp', 
    'admin_bp', 
    'trader_bp', 
    'merchant_bp', 
    'transactions_bp', 
    'requisites_bp',
    'notifications_bp'
]