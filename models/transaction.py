from datetime import datetime
from extensions import db

class Transaction:
    @staticmethod
    def get_by_id(tx_id):
        """Получить транзакцию по ID с деталями"""
        tx = db.find_one('transactions', {'id': tx_id})
        if not tx:
            return None
        
        # Добавляем детали пользователей
        merchant = db.find_one('users', {'id': tx['merchant_id']})
        trader = db.find_one('users', {'id': tx.get('trader_id')}) if tx.get('trader_id') else None
        
        tx_data = {
            'id': tx['id'],
            'amount': tx['amount'],
            'currency': tx.get('currency', 'RUB'),
            'type': tx['type'],
            'status': tx['status'],
            'method': tx.get('method'),
            'created_at': tx['created_at'],
            'updated_at': tx.get('updated_at'),
            'processing_time': tx.get('processing_time'),
            'merchant': {
                'id': merchant['id'],
                'email': merchant['email']
            }
        }
        
        if trader:
            tx_data['trader'] = {
                'id': trader['id'],
                'email': trader['email']
            }
        
        return tx_data

    @staticmethod
    def get_filtered(filters, page=1, per_page=20):
        """Получить отфильтрованный список транзакций"""
        query = {}
        
        if filters.get('type'):
            query['type'] = filters['type']
        if filters.get('status'):
            query['status'] = filters['status']
        if filters.get('method'):
            query['method'] = filters['method']
        if filters.get('date_from'):
            query['created_at'] = {'$gte': filters['date_from']}
        if filters.get('date_to'):
            if 'created_at' in query:
                query['created_at']['$lte'] = filters['date_to']
            else:
                query['created_at'] = {'$lte': filters['date_to']}
        
        transactions = db.find('transactions', query,
                             skip=(page-1)*per_page,
                             limit=per_page,
                             sort={'created_at': -1})
        
        total = db.count('transactions', query)
        
        return {
            'transactions': list(transactions),
            'total': total,
            'page': page,
            'per_page': per_page
        }
    @staticmethod
    def create(amount, transaction_type, merchant_id, trader_id=None, **kwargs):
        transaction = {
            'amount': amount,
            'currency': 'RUB',
            'type': transaction_type,
            'status': 'pending',
            'merchant_id': merchant_id,
            'trader_id': trader_id,
            'created_at': datetime.now().isoformat(),
            'updated_at': datetime.now().isoformat(),
            'processing_time': None,
            **kwargs
        }
        return db.insert_one('transactions', transaction)

    @staticmethod
    def get_pending_deposits():
        return db.find('transactions', {
            'type': 'deposit',
            'status': 'pending'
        })

    @staticmethod
    def get_pending_payouts():
        return db.find('transactions', {
            'type': 'withdrawal',
            'status': 'pending'
        })

    @staticmethod
    def get_user_transactions(user_id, role):
        query = {'merchant_id': user_id} if role == 'merchant' else {'trader_id': user_id}
        return db.find('transactions', query)

    @staticmethod
    def complete(transaction_id, processing_time=None):
        update_data = {
            'status': 'completed',
            'updated_at': datetime.now().isoformat()
        }
        if processing_time:
            update_data['processing_time'] = processing_time
        
        db.update_one('transactions', {'id': transaction_id}, update_data)

    @staticmethod
    def to_dict(transaction):
        return {
            'id': transaction['id'],
            'amount': transaction['amount'],
            'currency': transaction.get('currency', 'RUB'),
            'type': transaction['type'],
            'status': transaction['status'],
            'merchant_id': transaction['merchant_id'],
            'trader_id': transaction.get('trader_id'),
            'method': transaction.get('method'),
            'created_at': transaction['created_at'],
            'updated_at': transaction['updated_at'],
            'processing_time': transaction.get('processing_time')
        }