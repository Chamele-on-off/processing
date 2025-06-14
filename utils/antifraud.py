import logging
from datetime import datetime, timedelta
from models.transaction import Transaction
from models.user import User
from extensions import db

logger = logging.getLogger(__name__)

class FraudDetection:
    @staticmethod
    def get_fraud_rules():
        """Получение активных правил антифрода"""
        return {
            'max_amount': 1000000,
            'max_transactions_per_hour': 50,
            'allowed_countries': ['RU', 'KZ', 'BY'],
            'min_amount_diff': 100
        }

    @staticmethod
    def check_transaction(transaction):
        """Комплексная проверка транзакции"""
        rules = FraudDetection.get_fraud_rules()
        checks = [
            (FraudDetection.check_amount(transaction['amount'], rules['max_amount']), 
             "Amount exceeds limit"),
            (FraudDetection.check_frequency(transaction['trader_id'], rules['max_transactions_per_hour']), 
             "Too many transactions"),
            (FraudDetection.check_ip(transaction['trader_id'], rules['allowed_countries']), 
             "Suspicious IP location"),
            (FraudDetection.check_sender_blacklist(transaction.get('sender')), 
             "Sender in blacklist")
        ]
        
        for is_fraud, reason in checks:
            if is_fraud:
                FraudDetection.log_fraud_attempt(transaction, reason)
                return True
        return False

    @staticmethod
    def check_amount(amount, max_amount):
        """Проверка суммы транзакции"""
        return amount > max_amount
    
    @staticmethod
    def check_frequency(trader_id, max_per_hour):
        """Проверка частоты транзакций"""
        hour_ago = (datetime.now() - timedelta(hours=1)).isoformat()
        count = db.count('transactions', {
            'trader_id': trader_id,
            'created_at': {'$gte': hour_ago}
        })
        return count > max_per_hour
    
    @staticmethod
    def check_ip(trader_id, allowed_countries):
        """Проверка геолокации по IP"""
        user = User.find_by_id(trader_id)
        if not user:
            return False
        return user.get('geo_location', {}).get('country') not in allowed_countries

    @staticmethod
    def check_sender_blacklist(sender_info):
        """Проверка отправителя в черном списке"""
        if not sender_info:
            return False
        return db.exists('blacklist', {'sender': sender_info})

    @staticmethod
    def log_fraud_attempt(transaction, reason):
        """Логирование попытки мошенничества"""
        log_entry = {
            'transaction_id': transaction['id'],
            'reason': reason,
            'timestamp': datetime.now().isoformat(),
            'trader_id': transaction.get('trader_id'),
            'amount': transaction.get('amount'),
            'status': 'detected'
        }
        db.insert_one('fraud_logs', log_entry)
        logger.warning(f"Fraud detected: {reason} in transaction {transaction['id']}")

    @staticmethod
    def get_fraud_stats(days=7):
        """Статистика мошеннических попыток"""
        date_from = (datetime.now() - timedelta(days=days)).isoformat()
        pipeline = [
            {'$match': {'timestamp': {'$gte': date_from}}},
            {'$group': {
                '_id': '$reason',
                'count': {'$sum': 1},
                'total_amount': {'$sum': '$amount'}
            }}
        ]
        return list(db.aggregate('fraud_logs', pipeline))