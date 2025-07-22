import logging
from datetime import datetime
from database.database import YAMLDatabase

logger = logging.getLogger(__name__)

class MatchingService:
    def __init__(self, db):
        """
        Инициализация сервиса матчинга
        
        :param db: Экземпляр YAMLDatabase
        """
        self.db = db

    def find_matches(self, currency=None, min_amount=None):
        """Поиск возможных матчей"""
        query = {'status': 'pending'}
        if currency:
            query['currency'] = currency
        if min_amount:
            query['amount'] = {'$gte': min_amount}

        payouts = self.db.find('transactions', {**query, 'type': 'withdrawal'})
        deposits = self.db.find('transactions', {**query, 'type': 'deposit'})

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

    def create_match(self, payout_id, deposit_ids, created_by=None):
        """Создание матча"""
        match = {
            'id': f"match_{datetime.now().timestamp()}",
            'payout_id': payout_id,
            'deposit_ids': deposit_ids,
            'status': 'pending',
            'created_at': datetime.now().isoformat(),
            'created_by': created_by
        }
        self.db.insert_one('matches', match)
        
        # Обновляем статусы транзакций
        self.db.update_one('transactions', {'id': payout_id}, {'status': 'matching'})
        for dep_id in deposit_ids:
            self.db.update_one('transactions', {'id': dep_id}, {'status': 'matching'})
        
        logger.info(f"Match created: {match['id']}")
        return match

    def confirm_match(self, match_id, confirmed_by):
        """Подтверждение матча"""
        match = self.db.find_one('matches', {'id': match_id})
        if not match:
            return None

        updates = {
            'status': 'completed',
            'confirmed_at': datetime.now().isoformat(),
            'confirmed_by': confirmed_by
        }
        self.db.update_one('matches', {'id': match_id}, updates)
        
        # Обновляем статусы транзакций
        self.db.update_one('transactions', {'id': match['payout_id']}, {'status': 'completed'})
        for dep_id in match['deposit_ids']:
            self.db.update_one('transactions', {'id': dep_id}, {'status': 'completed'})
        
        logger.info(f"Match confirmed: {match_id}")
        return match

    def get_pending_matches(self, limit=10, offset=0):
        """Получение ожидающих матчей"""
        all_matches = self.db.find('matches', {'status': 'pending'})
        
        # Сортировка по дате создания (новые сначала)
        sorted_matches = sorted(
            all_matches, 
            key=lambda x: x.get('created_at', ''), 
            reverse=True
        )
        
        # Пагинация
        paginated_matches = sorted_matches[offset:offset+limit]
        
        return {
            'data': paginated_matches,
            'total': len(all_matches)
        }

    def auto_match_transactions(self):
        """Автоматический матчинг транзакций"""
        try:
            # Получаем все ожидающие депозиты и выплаты
            deposits = self.db.find('transactions', {
                'status': 'pending',
                'type': 'deposit'
            })
            
            payouts = self.db.find('transactions', {
                'status': 'pending',
                'type': 'withdrawal'
            })

            matched_count = 0
            
            # Проходим по всем выплатам и пытаемся найти подходящие депозиты
            for payout in payouts:
                suitable_deposits = []
                remaining_amount = float(payout['amount'])
                
                for deposit in deposits:
                    if deposit['status'] != 'pending':
                        continue
                    
                    deposit_amount = float(deposit['amount'])
                    if deposit_amount >= remaining_amount * 0.9:
                        suitable_deposits.append(deposit['id'])
                        remaining_amount -= deposit_amount
                        
                        if remaining_amount <= 0:
                            break
                
                if suitable_deposits and remaining_amount <= 0:
                    # Создаем матч
                    self.create_match(
                        payout_id=payout['id'],
                        deposit_ids=suitable_deposits,
                        created_by='system'
                    )
                    matched_count += 1
            
            logger.info(f"Auto-matched {matched_count} transactions")
            return matched_count
            
        except Exception as e:
            logger.error(f"Error in auto matching: {str(e)}", exc_info=True)
            return 0
