from datetime import datetime
from extensions import db

class Dispute:
    @staticmethod
    def create_from_transaction(transaction_id, user_id, reason):
        dispute = {
            'transaction_id': transaction_id,
            'initiator_id': user_id,
            'reason': reason,
            'status': 'open',
            'created_at': datetime.now().isoformat()
        }
        
        # Обновляем статус транзакции
        db.update_one('transactions', {'id': transaction_id}, {'status': 'disputed'})
        
        return db.insert_one('disputes', dispute)

    @staticmethod
    def resolve(dispute_id, admin_id, resolution, status='resolved'):
        dispute = db.find_one('disputes', {'id': dispute_id})
        if not dispute:
            return None

        update_data = {
            'status': status,
            'resolution': resolution,
            'resolved_by': admin_id,
            'resolved_at': datetime.now().isoformat()
        }

        # Обновляем спор
        db.update_one('disputes', {'id': dispute_id}, update_data)

        # Обновляем статус транзакции
        new_status = 'completed' if status == 'resolved' else 'failed'
        db.update_one('transactions', 
                     {'id': dispute['transaction_id']}, 
                     {'status': new_status})

        return True

    @staticmethod
    def get_by_transaction(transaction_id):
        return db.find('disputes', {'transaction_id': transaction_id})

    @staticmethod
    def to_dict(dispute):
        return {
            'id': dispute['id'],
            'transaction_id': dispute['transaction_id'],
            'initiator_id': dispute['initiator_id'],
            'reason': dispute['reason'],
            'status': dispute['status'],
            'resolution': dispute.get('resolution'),
            'resolved_by': dispute.get('resolved_by'),
            'created_at': dispute['created_at'],
            'resolved_at': dispute.get('resolved_at')
        }