from datetime import datetime, timedelta
from flask import jsonify, request
from extensions import db

class TriangleTransaction:
    @staticmethod
    def get_all(page=1, per_page=20):
        """Получить список треугольных транзакций с пагинацией"""
        transactions = db.find('triangle_transactions', {}, 
                             skip=(page-1)*per_page, 
                             limit=per_page,
                             sort={'created_at': -1})
        
        # Преобразуем ObjectId в строки и добавляем детали депозитов/выплат
        result = []
        for tx in transactions:
            tx_data = TriangleTransaction.enrich_transaction_data(tx)
            result.append(tx_data)
        
        total = db.count('triangle_transactions', {})
        return {
            'transactions': result,
            'total': total,
            'page': page,
            'per_page': per_page
        }

    @staticmethod
    def search(query, page=1, per_page=20):
        """Поиск треугольных транзакций"""
        search_filter = {
            '$or': [
                {'deposit_ids': {'$regex': query, '$options': 'i'}},
                {'payout_id': {'$regex': query, '$options': 'i'}},
                {'status': {'$regex': query, '$options': 'i'}}
            ]
        }
        
        transactions = db.find('triangle_transactions', search_filter,
                             skip=(page-1)*per_page,
                             limit=per_page,
                             sort={'created_at': -1})
        
        result = [TriangleTransaction.enrich_transaction_data(tx) for tx in transactions]
        total = db.count('triangle_transactions', search_filter)
        
        return {
            'transactions': result,
            'total': total,
            'page': page,
            'per_page': per_page
        }

    @staticmethod
    def get_by_id(tx_id):
        """Получить детали конкретной треугольной транзакции"""
        tx = db.find_one('triangle_transactions', {'id': tx_id})
        if not tx:
            return None
        
        return TriangleTransaction.enrich_transaction_data(tx)

    @staticmethod
    def create_manual(deposit_methods, payout_method, amount):
        """Создать ручную треугольную транзакцию"""
        # Логика создания ручной транзакции
        # ...
        
        new_tx = {
            'deposit_ids': [],  # Здесь будут ID созданных депозитов
            'payout_id': '',    # ID созданной выплаты
            'payout_method': payout_method,
            'amount': amount,
            'status': 'pending',
            'is_manual': True,
            'created_at': datetime.now().isoformat()
        }
        
        tx_id = db.insert_one('triangle_transactions', new_tx)
        return tx_id

    @staticmethod
    def confirm(tx_id):
        """Подтвердить треугольную транзакцию"""
        tx = db.find_one('triangle_transactions', {'id': tx_id})
        if not tx:
            return False
        
        # Обновляем статус транзакции
        db.update_one('triangle_transactions', {'id': tx_id}, {
            'status': 'completed',
            'completed_at': datetime.now().isoformat()
        })
        
        # Обновляем статусы связанных транзакций
        for deposit_id in tx['deposit_ids']:
            db.update_one('transactions', {'id': deposit_id}, {'status': 'completed'})
        
        db.update_one('transactions', {'id': tx['payout_id']}, {'status': 'completed'})
        
        return True

    @staticmethod
    def get_stats():
        """Получить статистику по треугольным транзакциям"""
        now = datetime.now()
        yesterday = now - timedelta(days=1)
        
        # Объем за последние 24 часа
        daily_volume = db.aggregate('triangle_transactions', [
            {'$match': {
                'created_at': {'$gte': yesterday.isoformat()},
                'status': 'completed'
            }},
            {'$group': {
                '_id': None,
                'total': {'$sum': '$amount'}
            }}
        ])
        
        # Общая эффективность (процент успешных транзакций)
        total_count = db.count('triangle_transactions', {})
        completed_count = db.count('triangle_transactions', {'status': 'completed'})
        efficiency = (completed_count / total_count * 100) if total_count > 0 else 0
        
        return {
            'daily_volume': daily_volume[0]['total'] if daily_volume else 0,
            'efficiency': round(efficiency, 2)
        }

    @staticmethod
    def update_settings(settings):
        """Обновить настройки треугольных транзакций"""
        # Сохраняем настройки в базе или конфиге
        # ...
        return True

    @staticmethod
    def enrich_transaction_data(tx):
        """Добавить детали депозитов и выплаты к транзакции"""
        deposits = []
        for deposit_id in tx.get('deposit_ids', []):
            deposit = db.find_one('transactions', {'id': deposit_id})
            if deposit:
                deposits.append({
                    'id': deposit_id,
                    'amount': deposit['amount'],
                    'method': deposit.get('method', 'unknown')
                })
        
        payout = db.find_one('transactions', {'id': tx.get('payout_id')})
        payout_data = {
            'id': tx.get('payout_id'),
            'amount': tx['amount'],
            'method': tx.get('payout_method', 'unknown')
        } if not payout else {
            'id': payout['id'],
            'amount': payout['amount'],
            'method': payout.get('method', 'unknown')
        }
        
        return {
            'id': tx['id'],
            'deposits': deposits,
            'payout': payout_data,
            'amount': tx['amount'],
            'status': tx['status'],
            'created_at': tx['created_at'],
            'is_manual': tx.get('is_manual', False)
        }