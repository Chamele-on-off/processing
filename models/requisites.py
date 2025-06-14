from datetime import datetime
from extensions import db

class Requisite:
    @staticmethod
    def create(user_id, type, details, max_amount=None, min_amount=0, currency='RUB'):
        requisite = {
            'user_id': user_id,
            'type': type,
            'details': details,
            'is_active': True,
            'max_amount': max_amount,
            'min_amount': min_amount,
            'currency': currency,
            'created_at': datetime.now().isoformat()
        }
        return db.insert_one('requisites', requisite)

    @staticmethod
    def get_active_for_trader(trader_id):
        return db.find('requisites', {
            'user_id': trader_id,
            'is_active': True
        })

    @staticmethod
    def to_dict(requisite):
        return {
            'id': requisite['id'],
            'type': requisite['type'],
            'details': requisite['details'],
            'max_amount': requisite.get('max_amount'),
            'min_amount': requisite.get('min_amount', 0),
            'currency': requisite.get('currency', 'RUB'),
            'is_active': requisite.get('is_active', True)
        }