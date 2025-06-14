import logging
from datetime import datetime
from database.database import JSONDatabase

logger = logging.getLogger(__name__)

class TransactionService:
    @staticmethod
    def create_transaction(transaction_data):
        """Создание новой транзакции"""
        transaction = {
            'id': f"tx_{datetime.now().timestamp()}",
            'created_at': datetime.now().isoformat(),
            'status': 'pending',
            **transaction_data
        }
        db.insert_one('transactions', transaction)
        logger.info(f"Transaction created: {transaction['id']}")
        return transaction

    @staticmethod
    def get_transaction(transaction_id):
        """Получение транзакции по ID"""
        return db.find_one('transactions', {'id': transaction_id})

    @staticmethod
    def search_transactions(query_params, limit=20, offset=0):
        """Поиск транзакций с фильтрами"""
        filters = {}
        
        # Фильтр по типу
        if 'type' in query_params:
            filters['type'] = query_params['type']
        
        # Фильтр по статусу
        if 'status' in query_params:
            filters['status'] = query_params['status']
        
        # Фильтр по дате
        if 'date_from' in query_params:
            filters['created_at'] = {'$gte': query_params['date_from']}
        if 'date_to' in query_params:
            filters['created_at'] = {'$lte': query_params['date_to']}
        
        # Фильтр по пользователю
        if 'user_id' in query_params and 'user_role' in query_params:
            if query_params['user_role'] == 'trader':
                filters['trader_id'] = query_params['user_id']
            elif query_params['user_role'] == 'merchant':
                filters['merchant_id'] = query_params['user_id']
        
        return {
            'data': db.find('transactions', 
                          filters, 
                          limit=limit, 
                          skip=offset,
                          sort={'created_at': -1}),
            'total': db.count('transactions', filters)
        }

    @staticmethod
    def update_transaction_status(transaction_id, status, updated_by=None):
        """Обновление статуса транзакции"""
        updates = {
            'status': status,
            'updated_at': datetime.now().isoformat()
        }
        if updated_by:
            updates['updated_by'] = updated_by
        
        result = db.update_one('transactions', {'id': transaction_id}, updates)
        if result.modified_count > 0:
            logger.info(f"Transaction {transaction_id} status updated to {status}")
            return True
        return False

    @staticmethod
    def attach_document(transaction_id, document_type, file_path, uploaded_by):
        """Прикрепление документа к транзакции"""
        doc_key = f"{document_type}_document"
        updates = {
            doc_key: file_path,
            f"{doc_key}_uploaded_at": datetime.now().isoformat(),
            f"{doc_key}_uploaded_by": uploaded_by
        }
        db.update_one('transactions', {'id': transaction_id}, updates)
        logger.info(f"Document attached to transaction {transaction_id}")

    @staticmethod
    def get_transaction_stats(user_id=None, user_role=None):
        """Получение статистики по транзакциям"""
        filters = {}
        if user_id and user_role:
            if user_role == 'trader':
                filters['trader_id'] = user_id
            elif user_role == 'merchant':
                filters['merchant_id'] = user_id
        
        pipeline = [
            {'$match': filters},
            {'$group': {
                '_id': '$status',
                'count': {'$sum': 1},
                'total_amount': {'$sum': '$amount'}
            }}
        ]
        
        stats = {}
        for item in db.aggregate('transactions', pipeline):
            stats[item['_id']] = {
                'count': item['count'],
                'total_amount': item.get('total_amount', 0)
            }
        
        return stats