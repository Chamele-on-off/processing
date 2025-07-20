# init_db.py
from werkzeug.security import generate_password_hash
from datetime import datetime

def init_db(db):
    """Инициализация базы данных с тестовыми данными"""
    try:
        # Проверяем, была ли уже инициализация
        if db.find_one('users', {'email': 'admin@example.com'}):
            return True
        
        # Создаем обязательные коллекции
        required_collections = [
            'users', 
            'transactions', 
            'requisites', 
            'disputes', 
            'audit_logs', 
            'settings',
            'triangle_transactions', 
            'system_settings',
            'deposit_requests',  
            'withdrawal_requests',
            'transaction_requisites',
            'requisites_types'  
        ]
        
        for collection in required_collections:
            if not db.collection_exists(collection):
                db.create_collection(collection)
        
        # Создаем администратора
        admin_user = {
            'email': 'admin@example.com',
            'password_hash': generate_password_hash('admin123'),
            'role': 'admin',
            'is_active': True,
            'verified': True,
            'created_at': datetime.now().isoformat(),
            'balance': 10000.0,
            'insurance_deposit': 0.0,
            'working_balance_usdt': 0.0,
            'working_balance_rub': 0.0,
            'insurance_balance': 0.0,
            'deposit_rate': 0.02,
            'withdrawal_rate': 0.02
        }
        db.insert_one('users', admin_user)
        
        # Создаем тестового мерчанта
        merchant_user = {
            'email': 'merchant@example.com',
            'password_hash': generate_password_hash('merchant123'),
            'role': 'merchant',
            'is_active': True,
            'verified': True,
            'created_at': datetime.now().isoformat(),
            'balance': 5000.0,
            'insurance_deposit': 1000.0,
            'merchant_id': 'merch_12345',
            'api_key': 'test_api_key_123',
            'working_balance_usdt': 0.0,
            'working_balance_rub': 0.0,
            'insurance_balance': 0.0,
            'deposit_rate': 0.02,
            'withdrawal_rate': 0.02
        }
        db.insert_one('users', merchant_user)
        
        # Создаем тестового трейдера с полными данными балансов
        trader_user = {
            'email': 'trader@example.com',
            'password_hash': generate_password_hash('trader123'),
            'role': 'trader',
            'is_active': True,
            'verified': True,
            'created_at': datetime.now().isoformat(),
            'balance': 2000.0,
            'insurance_deposit': 500.0,
            'payment_methods': ['bank_transfer', 'crypto'],
            'working_balance_usdt': 1000.0,
            'working_balance_rub': 50000.0,
            'insurance_balance': 200.0,
            'deposit_rate': 0.015,
            'withdrawal_rate': 0.025,
            'deposits_enabled': True,
            'withdrawals_enabled': True
        }
        db.insert_one('users', trader_user)
        
        # Настройки системы
        system_settings = {
            'system_name': 'Crypto-Fiat Processing',
            'default_currency': 'USD',
            'transaction_fee': 0.02,
            'min_amount': 10,
            'max_amount': 1000000,
            'crypto_currencies': ['BTC', 'ETH', 'USDT'],
            'fiat_currencies': ['USD', 'EUR', 'GBP', 'RUB'],
            'created_at': datetime.now().isoformat(),
            'updated_at': datetime.now().isoformat()
        }
        db.data['settings'] = system_settings
        
        # Курсы валют
        currency_rates = {
            'type': 'currency_rates',
            'USD': 75.0,       # 1 USD = 75 RUB
            'EUR': 85.0,       # 1 EUR = 85 RUB
            'GBP': 95.0,       # 1 GBP = 95 RUB
            'USDT': 75.0,      # 1 USDT = 75 RUB
            'BTC': 30000.0,    # 1 BTC = 30000 USD
            'ETH': 2000.0,     # 1 ETH = 2000 USD
            'updated_at': datetime.now().isoformat(),
            'auto_update': True,
            'source': 'internal'
        }
        db.insert_one('system_settings', currency_rates)
        
        # Настройки комиссий
        commission_settings = {
            'type': 'commissions',
            'default': 0.02,  # 2% по умолчанию
            'per_merchant': {
                'merch_12345': 0.015  # 1.5% для тестового мерчанта
            },
            'min_commission': 0.01,    # Минимальная комиссия 1%
            'max_commission': 0.05,    # Максимальная комиссия 5%
            'updated_at': datetime.now().isoformat()
        }
        db.insert_one('system_settings', commission_settings)
        
        # Настройки матчинга
        matching_settings = {
            'type': 'matching',
            'auto_matching': True,
            'min_amount': 10.0,
            'max_amount': 100000.0,
            'currency_tolerance': 0.05,  # 5% отклонение по курсу
            'time_window': 3600,         # 1 час для поиска совпадений
            'updated_at': datetime.now().isoformat()
        }
        db.insert_one('system_settings', matching_settings)

        # Типы реквизитов
        requisites_types = [
            {
                'id': 1,
                'name': 'Банковский счет',
                'fields': [
                    {'name': 'account_number', 'label': 'Номер счета', 'type': 'text'},
                    {'name': 'bank_name', 'label': 'Банк', 'type': 'text'},
                    {'name': 'bik', 'label': 'БИК', 'type': 'text'},
                    {'name': 'owner_name', 'label': 'Владелец', 'type': 'text'}
                ]
            },
            {
                'id': 2,
                'name': 'Банковская карта',
                'fields': [
                    {'name': 'card_number', 'label': 'Номер карты', 'type': 'text'},
                    {'name': 'card_holder', 'label': 'Держатель', 'type': 'text'},
                    {'name': 'expiry_date', 'label': 'Срок действия', 'type': 'text'},
                    {'name': 'cvv', 'label': 'CVV', 'type': 'password'}
                ]
            },
            {
                'id': 3,
                'name': 'Криптокошелек',
                'fields': [
                    {'name': 'wallet_address', 'label': 'Адрес', 'type': 'text'},
                    {'name': 'currency', 'label': 'Валюта', 'type': 'select', 
                     'options': ['BTC', 'ETH', 'USDT', 'OTHER']}
                ]
            }
        ]
        db.insert_one('requisites_types', {'types': requisites_types})

        # Тестовые заявки на пополнение
        sample_deposit_requests = [
            {
                'id': 'dep_req_1',
                'user_id': 2,  # merchant
                'amount': 1000.0,
                'currency': 'USD',
                'payment_method': 'bank',
                'requisites': {
                    'account_number': '1234567890',
                    'bank_name': 'Test Bank',
                    'bik': '123456789',
                    'owner_name': 'Test Merchant'
                },
                'status': 'pending',
                'created_at': datetime.now().isoformat()
            }
        ]
        for dr in sample_deposit_requests:
            db.insert_one('deposit_requests', dr)

        # Тестовые заявки на вывод
        sample_withdrawal_requests = [
            {
                'id': 'with_req_1',
                'user_id': 2,  # merchant
                'amount': 500.0,
                'currency': 'USD',
                'withdrawal_method': 'bank',
                'requisites': {
                    'account_number': '9876543210',
                    'bank_name': 'Test Bank',
                    'bik': '987654321',
                    'owner_name': 'Test Merchant'
                },
                'status': 'pending',
                'created_at': datetime.now().isoformat()
            }
        ]
        for wr in sample_withdrawal_requests:
            db.insert_one('withdrawal_requests', wr)

        # Тестовые обычные транзакции
        sample_transactions = [
            {
                'user_id': 2,  # merchant
                'amount': 1000,
                'currency': 'USD',
                'type': 'deposit',
                'status': 'completed',
                'created_at': datetime.now().isoformat()
            },
            {
                'user_id': 3,  # trader
                'amount': 0.05,
                'currency': 'BTC',
                'type': 'withdrawal',
                'status': 'pending',
                'created_at': datetime.now().isoformat()
            }
        ]
        for tx in sample_transactions:
            db.insert_one('transactions', tx)

        # Тестовые треугольные транзакции
        sample_triangles = [
            {
                'deposit_ids': [1, 2],
                'payout_id': 3,
                'amount': 1500,
                'status': 'completed',
                'created_at': datetime.now().isoformat()
            }
        ]
        for triangle in sample_triangles:
            db.insert_one('triangle_transactions', triangle)
        
        db.save()
        print("✅ Database initialized successfully")
        return True
    except Exception as e:
        print(f"❌ Database initialization failed: {str(e)}", exc_info=True)
        return False

if __name__ == '__main__':
    from database import JSONDatabase
    db = JSONDatabase()
    init_db(db)