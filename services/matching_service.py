import logging
from datetime import datetime
from database.database import JSONDatabase

logger = logging.getLogger(__name__)

class MatchingService:
    @staticmethod
    def find_matches(currency=None, min_amount=None):
        """Поиск возможных матчей"""
        query = {'status': 'pending'}
        if currency:
            query['currency'] = currency
        if min_amount:
            query['amount'] = {'$gte': min_amount}

        payouts = db.find('transactions', {**query, 'type': 'withdrawal'})
        deposits = db.find('transactions', {**query, 'type': 'deposit'})

        matches = []
        for payout in payouts:
            for deposit in deposits:
                if deposit['amount'] >= payout['amount'] * 0.9:
                    matches.append({
                        'payout': payout,
                        'deposit': deposit,
                        'score': deposit['amount'] / payout['amount']
                    })
        
        return sorted(matches, key=lambda x: -x['score'])

    @staticmethod
    def create_match(payout_id, deposit_ids, created_by=None):
        """Создание матча"""
        match = {
            'id': f"match_{datetime.now().timestamp()}",
            'payout_id': payout_id,
            'deposit_ids': deposit_ids,
            'status': 'pending',
            'created_at': datetime.now().isoformat(),
            'created_by': created_by
        }
        db.insert_one('matches', match)
        
        # Обновляем статусы транзакций
        db.update_one('transactions', {'id': payout_id}, {'status': 'matching'})
        for dep_id in deposit_ids:
            db.update_one('transactions', {'id': dep_id}, {'status': 'matching'})
        
        logger.info(f"Match created: {match['id']}")
        return match

    @staticmethod
    def confirm_match(match_id, confirmed_by):
        """Подтверждение матча"""
        match = db.find_one('matches', {'id': match_id})
        if not match:
            return None

        updates = {
            'status': 'completed',
            'confirmed_at': datetime.now().isoformat(),
            'confirmed_by': confirmed_by
        }
        db.update_one('matches', {'id': match_id}, updates)
        
        # Обновляем статусы транзакций
        db.update_one('transactions', {'id': match['payout_id']}, {'status': 'completed'})
        for dep_id in match['deposit_ids']:
            db.update_one('transactions', {'id': dep_id}, {'status': 'completed'})
        
        logger.info(f"Match confirmed: {match_id}")
        return match

    @staticmethod
    def get_pending_matches(limit=10, offset=0):
        """Получение ожидающих матчей"""
        return {
            'data': db.find('matches', 
                          {'status': 'pending'}, 
                          limit=limit, 
                          skip=offset,
                          sort={'created_at': -1}),
            'total': db.count('matches', {'status': 'pending'})
        }