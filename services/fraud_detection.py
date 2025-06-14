import logging
from datetime import datetime, timedelta
from database.database import JSONDatabase

logger = logging.getLogger(__name__)

class FraudDetectionService:
    @staticmethod
    def check_transaction_limit(user_id):
        """Проверка лимита транзакций"""
        hour_ago = (datetime.now() - timedelta(hours=1)).isoformat()
        transactions = db.find('transactions', {
            'trader_id': user_id,
            'created_at': {'$gte': hour_ago}
        })
        return len(transactions) >= 50

    @staticmethod
    def check_pdf_fraud(pdf_data, transaction):
        """Проверка PDF чека на мошенничество"""
        if abs(float(pdf_data['amount']) - transaction['amount']) > 100:
            return True
        
        check_time = datetime.fromisoformat(pdf_data['date'])
        if (datetime.now() - check_time) > timedelta(hours=24):
            return True
        
        same_sender = len(db.find('transactions', {
            'details.sender': pdf_data['sender'],
            'trader_id': transaction['trader_id']
        }))
        
        return same_sender > 3

    @staticmethod
    def get_active_alerts(limit=20, offset=0):
        """Получение активных алертов"""
        return {
            'data': db.find('fraud_alerts', 
                          {'resolved': False}, 
                          limit=limit, 
                          skip=offset,
                          sort={'timestamp': -1}),
            'total': db.count('fraud_alerts', {'resolved': False})
        }

    @staticmethod
    def resolve_alert(alert_id, resolved_by):
        """Разрешение алерта"""
        db.update_one('fraud_alerts', {'id': alert_id}, {
            'resolved': True,
            'resolved_at': datetime.now().isoformat(),
            'resolved_by': resolved_by
        })
        logger.info(f"Alert {alert_id} resolved by {resolved_by}")

    @staticmethod
    def create_alert(transaction_id, reason, severity='medium'):
        """Создание нового алерта"""
        alert = {
            'id': f"alert_{datetime.now().timestamp()}",
            'transaction_id': transaction_id,
            'reason': reason,
            'severity': severity,
            'resolved': False,
            'timestamp': datetime.now().isoformat()
        }
        db.insert_one('fraud_alerts', alert)
        return alert

    @staticmethod
    def monitor_transaction(transaction):
        """Мониторинг транзакции на подозрительность"""
        checks = [
            (transaction['amount'] > 100000, 'Большая сумма'),
            (FraudDetectionService.check_transaction_limit(transaction['trader_id']), 'Превышен лимит транзакций')
        ]
        
        for condition, reason in checks:
            if condition:
                return FraudDetectionService.create_alert(
                    transaction['id'], 
                    reason
                )
        return None