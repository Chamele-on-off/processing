from werkzeug.security import generate_password_hash
from datetime import datetime

def init_db(db):
    """Инициализация базы данных с тестовыми данными"""
    try:
        # Проверяем, была ли уже инициализация
        if db.find_one('users', {'email': 'admin@example.com'}):
            print("ℹ️ Database already initialized")
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
            'requisites_types',
            'platform_settings',  # Новая коллекция для реквизитов платформы
            'matches'            # Коллекция для хранения совпадений матчинга
        ]
        
        for collection in required_collections:
            if not db.collection_exists(collection):
                db.create_collection(collection)
                print(f"✅ Created collection: {collection}")
        
        # Создаем администратора
        admin_user = {
            'id': 1,
            'email': 'admin@example.com',
            'password_hash': generate_password_hash('admin123'),
            'role': 'admin',
            'is_active': True,
            'verified': True,
            'created_at': datetime.now().isoformat(),
            'updated_at': datetime.now().isoformat(),
            'balance': 10000.0,
            'insurance_deposit': 0.0,
            'permissions': ['full_access']
        }
        db.insert_one('users', admin_user)
        print("✅ Created admin user")
        
        # Создаем тестового мерчанта
        merchant_user = {
            'id': 2,
            'email': 'merchant@example.com',
            'password_hash': generate_password_hash('merchant123'),
            'role': 'merchant',
            'is_active': True,
            'verified': True,
            'created_at': datetime.now().isoformat(),
            'updated_at': datetime.now().isoformat(),
            'balance': 5000.0,
            'insurance_deposit': 1000.0,
            'merchant_id': 'merch_12345',
            'api_key': 'test_api_key_123',
            'payment_methods': ['bank_transfer', 'card']
        }
        db.insert_one('users', merchant_user)
        print("✅ Created merchant user")
        
        # Создаем тестового трейдера
        trader_user = {
            'id': 3,
            'email': 'trader@example.com',
            'password_hash': generate_password_hash('trader123'),
            'role': 'trader',
            'is_active': True,
            'verified': True,
            'created_at': datetime.now().isoformat(),
            'updated_at': datetime.now().isoformat(),
            'balance': 2000.0,
            'insurance_deposit': 500.0,
            'payment_methods': ['bank_transfer', 'crypto'],
            'limits': {
                'max_deposit': 10000,
                'max_withdrawal': 5000,
                'daily_limit': 20000
            }
        }
        db.insert_one('users', trader_user)
        print("✅ Created trader user")
        
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
            'updated_at': datetime.now().isoformat(),
            'security': {
                '2fa_enabled': True,
                'ip_whitelist': [],
                'session_timeout': 3600
            }
        }
        db.insert_one('settings', system_settings)
        print("✅ Created system settings")
        
        # Курсы валют
        currency_rates = {
            'type': 'currency_rates',
            'rates': {
                'USD_RUB': 75.0,       # 1 USD = 75 RUB
                'EUR_RUB': 85.0,       # 1 EUR = 85 RUB
                'GBP_RUB': 95.0,       # 1 GBP = 95 RUB
                'USDT_USD': 1.0,       # 1 USDT = 1 USD
                'BTC_USD': 30000.0,    # 1 BTC = 30000 USD
                'ETH_USD': 2000.0      # 1 ETH = 2000 USD
            },
            'updated_at': datetime.now().isoformat(),
            'auto_update': True,
            'source': 'internal'
        }
        db.insert_one('system_settings', currency_rates)
        print("✅ Created currency rates")
        
        # Настройки комиссий
        commission_settings = {
            'type': 'commissions',
            'default': 0.02,  # 2% по умолчанию
            'per_merchant': {
                'merch_12345': 0.015  # 1.5% для тестового мерчанта
            },
            'min_commission': 0.01,    # Минимальная комиссия 1%
            'max_commission': 0.05,    # Максимальная комиссия 5%
            'updated_at': datetime.now().isoformat(),
            'fee_distribution': {
                'platform': 0.7,
                'trader': 0.3
            }
        }
        db.insert_one('system_settings', commission_settings)
        print("✅ Created commission settings")
        
        # Настройки матчинга
        matching_settings = {
            'type': 'matching',
            'auto_matching': True,
            'min_amount': 10.0,
            'max_amount': 100000.0,
            'currency_tolerance': 0.05,  # 5% отклонение по курсу
            'time_window': 3600,         # 1 час для поиска совпадений
            'updated_at': datetime.now().isoformat(),
            'algorithms': {
                'default': 'fifo',
                'available': ['fifo', 'amount_based', 'time_based']
            }
        }
        db.insert_one('system_settings', matching_settings)
        print("✅ Created matching settings")

        # Реквизиты платформы
        platform_requisites = {
            'key': 'platform_requisites',
            'bank_details': {
                'name': 'Processing Platform LLC',
                'account': '40702810500000012345',
                'bank': 'Tinkoff Bank',
                'bik': '044525974',
                'corr_account': '30101810100000000974',
                'currency': 'RUB'
            },
            'crypto_wallets': {
                'BTC': '3FZbgi29cpjq2GjdwV8eyHuJJnkLtktZc5',
                'ETH': '0x71C7656EC7ab88b098defB751B7401B5f6d8976F',
                'USDT': '0x71C7656EC7ab88b098defB751B7401B5f6d8976F'
            },
            'payment_methods': [
                {
                    'method': 'bank_transfer',
                    'currencies': ['RUB', 'USD', 'EUR'],
                    'details': 'Bank transfers are processed within 1-3 business days'
                },
                {
                    'method': 'crypto',
                    'currencies': ['BTC', 'ETH', 'USDT'],
                    'details': 'Cryptocurrency transfers are processed within 15 minutes'
                }
            ],
            'created_at': datetime.now().isoformat(),
            'updated_at': datetime.now().isoformat()
        }
        db.insert_one('platform_settings', platform_requisites)
        print("✅ Created platform requisites")

        # Типы реквизитов
        requisites_types = [
            {
                'id': 1,
                'name': 'Банковский счет',
                'type': 'bank_account',
                'fields': [
                    {'name': 'account_number', 'label': 'Номер счета', 'type': 'text', 'required': True},
                    {'name': 'bank_name', 'label': 'Банк', 'type': 'text', 'required': True},
                    {'name': 'bik', 'label': 'БИК', 'type': 'text', 'required': True},
                    {'name': 'owner_name', 'label': 'Владелец', 'type': 'text', 'required': True},
                    {'name': 'currency', 'label': 'Валюта', 'type': 'select', 'options': ['RUB', 'USD', 'EUR'], 'required': True}
                ]
            },
            {
                'id': 2,
                'name': 'Банковская карта',
                'type': 'bank_card',
                'fields': [
                    {'name': 'card_number', 'label': 'Номер карты', 'type': 'text', 'required': True},
                    {'name': 'card_holder', 'label': 'Держатель', 'type': 'text', 'required': True},
                    {'name': 'expiry_date', 'label': 'Срок действия', 'type': 'text', 'required': True},
                    {'name': 'cvv', 'label': 'CVV', 'type': 'password', 'required': False}
                ]
            },
            {
                'id': 3,
                'name': 'Криптокошелек',
                'type': 'crypto_wallet',
                'fields': [
                    {'name': 'wallet_address', 'label': 'Адрес', 'type': 'text', 'required': True},
                    {'name': 'currency', 'label': 'Валюта', 'type': 'select', 
                     'options': ['BTC', 'ETH', 'USDT', 'OTHER'], 'required': True},
                    {'name': 'network', 'label': 'Сеть', 'type': 'select',
                     'options': ['ERC20', 'TRC20', 'BEP20', 'Mainnet'], 'required': True}
                ]
            }
        ]
        db.insert_one('requisites_types', {'types': requisites_types})
        print("✅ Created requisites types")

        # Тестовые заявки на пополнение
        sample_deposit_requests = [
            {
                'id': 1,
                'user_id': 2,  # merchant
                'amount': 1000.0,
                'currency': 'USD',
                'payment_method': 'bank',
                'requisites': {
                    'account_number': '1234567890',
                    'bank_name': 'Test Bank',
                    'bik': '123456789',
                    'owner_name': 'Test Merchant',
                    'currency': 'USD'
                },
                'status': 'completed',
                'created_at': datetime.now().isoformat(),
                'completed_at': datetime.now().isoformat()
            },
            {
                'id': 2,
                'user_id': 3,  # trader
                'amount': 0.05,
                'currency': 'BTC',
                'payment_method': 'crypto',
                'requisites': {
                    'wallet_address': '3FZbgi29cpjq2GjdwV8eyHuJJnkLtktZc5',
                    'currency': 'BTC',
                    'network': 'Mainnet'
                },
                'status': 'pending',
                'created_at': datetime.now().isoformat()
            }
        ]
        for dr in sample_deposit_requests:
            db.insert_one('deposit_requests', dr)
        print("✅ Created sample deposit requests")

        # Тестовые заявки на вывод
        sample_withdrawal_requests = [
            {
                'id': 1,
                'user_id': 2,  # merchant
                'amount': 500.0,
                'currency': 'USD',
                'withdrawal_method': 'bank',
                'requisites': {
                    'account_number': '9876543210',
                    'bank_name': 'Test Bank',
                    'bik': '987654321',
                    'owner_name': 'Test Merchant',
                    'currency': 'USD'
                },
                'status': 'completed',
                'created_at': datetime.now().isoformat(),
                'completed_at': datetime.now().isoformat()
            },
            {
                'id': 2,
                'user_id': 3,  # trader
                'amount': 0.1,
                'currency': 'BTC',
                'withdrawal_method': 'crypto',
                'requisites': {
                    'wallet_address': 'bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq',
                    'currency': 'BTC',
                    'network': 'Mainnet'
                },
                'status': 'pending',
                'created_at': datetime.now().isoformat()
            }
        ]
        for wr in sample_withdrawal_requests:
            db.insert_one('withdrawal_requests', wr)
        print("✅ Created sample withdrawal requests")

        # Тестовые транзакции
        sample_transactions = [
            {
                'id': 1,
                'user_id': 2,  # merchant
                'amount': 1000,
                'currency': 'USD',
                'type': 'deposit',
                'status': 'completed',
                'method': 'bank',
                'requisites': {
                    'account_number': '1234567890',
                    'bank_name': 'Test Bank'
                },
                'created_at': datetime.now().isoformat(),
                'completed_at': datetime.now().isoformat()
            },
            {
                'id': 2,
                'user_id': 3,  # trader
                'amount': 0.05,
                'currency': 'BTC',
                'type': 'withdrawal',
                'status': 'pending',
                'method': 'crypto',
                'requisites': {
                    'wallet_address': 'bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq'
                },
                'created_at': datetime.now().isoformat()
            },
            {
                'id': 3,
                'user_id': 2,  # merchant
                'amount': 500,
                'currency': 'USD',
                'type': 'withdrawal',
                'status': 'pending_admin_approval',
                'method': 'bank',
                'requisites': {
                    'account_number': '9876543210',
                    'bank_name': 'Test Bank'
                },
                'receipt_file': 'receipt_merchant_1.pdf',
                'created_at': datetime.now().isoformat()
            }
        ]
        for tx in sample_transactions:
            db.insert_one('transactions', tx)
        print("✅ Created sample transactions")

        # Тестовые треугольные транзакции
        sample_triangles = [
            {
                'id': 1,
                'deposit_ids': [1, 2],
                'payout_id': 3,
                'amount': 1500,
                'currency': 'USD',
                'status': 'completed',
                'created_at': datetime.now().isoformat(),
                'completed_at': datetime.now().isoformat()
            }
        ]
        for triangle in sample_triangles:
            db.insert_one('triangle_transactions', triangle)
        print("✅ Created sample triangle transactions")

        # Тестовые совпадения матчинга
        sample_matches = [
            {
                'id': 1,
                'deposit_ids': [1],
                'withdrawal_id': 2,
                'amount': 1000,
                'currency': 'USD',
                'commission': 0.02,
                'status': 'pending',
                'created_at': datetime.now().isoformat()
            }
        ]
        for match in sample_matches:
            db.insert_one('matches', match)
        print("✅ Created sample matches")

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