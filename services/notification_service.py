import logging
from datetime import datetime
from database.database import JSONDatabase

logger = logging.getLogger(__name__)

class NotificationService:
    @staticmethod
    def create_notification(user_id, message, notification_type='info', metadata=None):
        """Создание уведомления"""
        notification = {
            'id': f"notif_{datetime.now().timestamp()}",
            'user_id': user_id,
            'message': message,
            'type': notification_type,
            'metadata': metadata or {},
            'read': False,
            'timestamp': datetime.now().isoformat()
        }
        db.insert_one('notifications', notification)
        logger.debug(f"Notification created for user {user_id}")
        return notification

    @staticmethod
    def get_user_notifications(user_id, limit=10, offset=0, unread_only=False):
        """Получение уведомлений пользователя"""
        query = {'user_id': user_id}
        if unread_only:
            query['read'] = False

        return {
            'data': db.find('notifications', 
                          query, 
                          limit=limit, 
                          skip=offset,
                          sort={'timestamp': -1}),
            'total': db.count('notifications', query)
        }

    @staticmethod
    def mark_as_read(notification_ids):
        """Пометить уведомления как прочитанные"""
        if not notification_ids:
            return 0

        result = db.update_many('notifications', 
                              {'id': {'$in': notification_ids}},
                              {'$set': {'read': True}})
        return result.modified_count

    @staticmethod
    def notify_transaction_update(transaction_id):
        """Уведомление об изменении транзакции"""
        transaction = db.find_one('transactions', {'id': transaction_id})
        if not transaction:
            return

        user_ids = []
        if 'trader_id' in transaction:
            user_ids.append(transaction['trader_id'])
        if 'merchant_id' in transaction:
            user_ids.append(transaction['merchant_id'])

        message = f"Transaction {transaction_id} updated to {transaction['status']}"
        for user_id in user_ids:
            NotificationService.create_notification(
                user_id,
                message,
                'transaction_update',
                {'transaction_id': transaction_id}
            )

    @staticmethod
    def notify_match_created(match_id):
        """Уведомление о создании матча"""
        match = db.find_one('matches', {'id': match_id})
        if not match:
            return

        # Получаем всех пользователей, связанных с транзакциями в матче
        transactions = db.find('transactions', {
            'id': {'$in': [match['payout_id'] + match['deposit_ids']]}
        })
        user_ids = list(set(
            [t['trader_id'] for t in transactions if 'trader_id' in t] +
            [t['merchant_id'] for t in transactions if 'merchant_id' in t]
        ))

        message = f"New match created: {match_id}"
        for user_id in user_ids:
            NotificationService.create_notification(
                user_id,
                message,
                'match_created',
                {'match_id': match_id}
            )