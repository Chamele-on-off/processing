from flask import render_template, jsonify, request, session, send_from_directory, redirect, url_for
from datetime import datetime, timedelta
from werkzeug.security import generate_password_hash, check_password_hash
import uuid
import os
import logging
import secrets
import random
from functools import wraps
import time
from threading import Lock

# Настройка логгирования
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)
handler = logging.StreamHandler()
handler.setFormatter(logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s'))
logger.addHandler(handler)

# Глобальная блокировка для операций матчинга
matching_lock = Lock()

def merchant_routes(app, db, logger):
    # ===============
    # Вспомогательные функции
    # ===============

    def assign_random_trader():
        """Назначает случайного трейдера для обработки транзакции"""
        try:
            # Получаем всех активных трейдеров
            traders = db.find('users', {'role': 'trader', 'is_active': True})
            
            if not traders:
                logger.error("No active traders available")
                return None
                
            # Выбираем случайного трейдера с учетом нагрузки
            trader_load = {}
            for trader in traders:
                active_txs = len(db.find('transactions', {
                    'trader_id': trader['id'],
                    'status': 'pending'
                }))
                trader_load[trader['id']] = active_txs
            
            # Выбираем трейдера с минимальной нагрузкой
            if trader_load:
                min_load = min(trader_load.values())
                candidates = [tid for tid, load in trader_load.items() if load == min_load]
                return random.choice(candidates)
            
            return None
            
        except Exception as e:
            logger.error(f"Error assigning random trader: {str(e)}", exc_info=True)
            return None

    def calculate_conversion_rate(transactions):
        """Рассчитывает процент успешных транзакций"""
        if not transactions:
            return 0.0
            
        completed = len([t for t in transactions if t.get('status') == 'completed'])
        total = len(transactions)
        return round((completed / total) * 100, 1) if total > 0 else 0.0

    def calculate_weekly_stats(transactions):
        """Возвращает статистику по дням недели"""
        days = ['Пн', 'Вт', 'Ср', 'Чт', 'Пт', 'Сб', 'Вс']
        counts = [0] * 7
        
        for tx in transactions:
            if isinstance(tx.get('created_at'), str):
                try:
                    date = datetime.fromisoformat(tx['created_at'])
                    weekday = date.weekday()  # 0-пн, 6-вс
                    counts[weekday] += 1
                except ValueError:
                    continue
        
        return {
            'days': days,
            'counts': counts
        }

    # ===============
    # Маршруты мерчанта
    # ===============

    @app.route('/merchant.html')
    @app.role_required('merchant')
    def merchant_dashboard():
        try:
            user = app.get_current_user()
            if not user:
                return redirect(url_for('login'))
            
            merchant_id = user['id']

            # Получаем типы реквизитов
            requisites_types = [
                {'id': '1', 'name': 'Банковский счет'},
                {'id': '2', 'name': 'Банковская карта'},
                {'id': '3', 'name': 'Криптокошелек'}
            ]
            
            # Получаем транзакции мерчанта
            transactions = db.find('transactions', {'merchant_id': merchant_id})
            
            # Получаем API ключи
            api_keys = db.find('api_keys', {'merchant_id': merchant_id})
            
            # Получаем матчи
            matches = db.find('matches', {'merchant_id': merchant_id})
            
            # Сортируем последние транзакции
            recent_transactions = sorted(
                transactions,
                key=lambda x: x.get('created_at', ''),
                reverse=True
            )[:5]
            
            # Рассчитываем статистику
            stats = {
                'today_transactions': len([t for t in transactions 
                                         if datetime.fromisoformat(t['created_at']).date() == datetime.now().date()]),
                'avg_amount': round(sum(float(t.get('amount', 0)) for t in transactions) / len(transactions), 2) if transactions else 0,
                'conversion_rate': calculate_conversion_rate(transactions),
                'weekly_stats': calculate_weekly_stats(transactions)
            }
            
            # Фильтруем транзакции по статусам
            pending_transactions = [t for t in transactions if t.get('status') == 'pending']
            completed_transactions = [t for t in transactions if t.get('status') == 'completed']
            
            # Фильтруем матчи по статусам
            pending_matches = [m for m in matches if m.get('status') == 'pending']
            completed_matches = [m for m in matches if m.get('status') == 'completed']
            rejected_matches = [m for m in matches if m.get('status') == 'rejected']

            # Получаем запросы на депозит и вывод
            deposit_requests = db.find('deposit_requests', {'user_id': merchant_id})
            withdrawal_requests = db.find('withdrawal_requests', {'user_id': merchant_id})

            return render_template(
                'merchant.html',
                user=user,
                requisites_types=requisites_types,
                stats=stats,
                recent_transactions=recent_transactions,
                all_transactions=transactions,
                pending_transactions=pending_transactions,
                completed_transactions=completed_transactions,
                api_keys=api_keys,
                pending_matches=pending_matches,
                completed_matches=completed_matches,
                rejected_matches=rejected_matches,
                current_date=datetime.now().strftime('%Y-%m-%d'),
                deposit_requests=deposit_requests,
                withdrawal_requests=withdrawal_requests
            )
            
        except Exception as e:
            logger.error(f"Error in merchant dashboard: {str(e)}", exc_info=True)
            return render_template('error.html', error="Ошибка загрузки данных"), 500

    @app.route('/api/merchant/transactions', methods=['POST'])
    @app.role_required('merchant')
    @app.csrf_protect
    def create_merchant_transaction():
        user = app.get_current_user()
        if not user:
            return jsonify({'error': 'Unauthorized'}), 401
            
        try:
            data = request.get_json()
            if not data:
                return jsonify({'error': 'No data provided'}), 400

            # Валидация данных
            required_fields = ['amount', 'type', 'method']
            if not all(field in data for field in required_fields):
                return jsonify({'error': 'Missing required fields'}), 400
                
            try:
                amount = float(data['amount'])
                if amount <= 0:
                    return jsonify({'error': 'Amount must be positive'}), 400
            except (ValueError, TypeError):
                return jsonify({'error': 'Invalid amount'}), 400

            if data['type'] not in ['deposit', 'withdrawal']:
                return jsonify({'error': 'Invalid transaction type'}), 400
                
            if data['method'] not in ['bank', 'card', 'crypto']:
                return jsonify({'error': 'Invalid payment method'}), 400

            # Назначаем случайного трейдера
            trader_id = assign_random_trader()
            if trader_id is None:
                return jsonify({'error': 'No traders available to process transaction'}), 503

            # Создаем новую транзакцию
            new_tx = {
                'merchant_id': user['id'],
                'trader_id': trader_id,
                'type': data['type'],
                'amount': amount,
                'currency': data.get('currency', 'RUB'), 
                'method': data['method'],
                'status': 'pending',
                'created_at': datetime.now().isoformat(),
                'updated_at': datetime.now().isoformat(),
                'requisites_approved': False,
                'expires_at': (datetime.now() + timedelta(minutes=30)).isoformat()
            }
            
            # Вставляем транзакцию
            inserted_tx = db.insert_one('transactions', new_tx)
            
            logger.info(f"Created new transaction {inserted_tx['id']} for merchant {user['id']} assigned to trader {trader_id}")
            return jsonify({'success': True, 'transaction': inserted_tx})
            
        except Exception as e:
            logger.error(f"Error creating merchant transaction: {str(e)}", exc_info=True)
            return jsonify({'error': str(e)}), 500

    @app.route('/api/merchant/transactions/<tx_id>/cancel', methods=['POST'])
    @app.role_required('merchant')
    @app.csrf_protect
    def cancel_merchant_transaction(tx_id):
        user = app.get_current_user()
        if not user:
            return jsonify({'error': 'Unauthorized'}), 401
            
        try:
            tx = db.find_one('transactions', {'id': int(tx_id), 'merchant_id': user['id']})
            if not tx:
                return jsonify({'error': 'Transaction not found'}), 404
            
            if tx.get('status') != 'pending':
                return jsonify({'error': 'Only pending transactions can be canceled'}), 400
            
            updates = {
                'status': 'cancelled',
                'cancelled_at': datetime.now().isoformat(),
                'cancelled_by': user['id'],
                'updated_at': datetime.now().isoformat()
            }
            
            if not db.update_one('transactions', {'id': int(tx_id)}, updates):
                return jsonify({'error': 'Failed to cancel transaction'}), 500
            
            logger.info(f"Cancelled transaction {tx_id} by merchant {user['id']}")
            return jsonify({'success': True})
            
        except Exception as e:
            logger.error(f"Error canceling transaction: {str(e)}", exc_info=True)
            return jsonify({'error': str(e)}), 500

    @app.route('/api/merchant/transactions/<int:tx_id>/requisites', methods=['POST'])
    @app.role_required('merchant')
    @app.csrf_protect
    def save_requisites(tx_id):
        user = app.get_current_user()
        if not user:
            return jsonify({'error': 'Unauthorized'}), 401
            
        try:
            data = request.get_json()
            if not data:
                return jsonify({'error': 'No data provided'}), 400
                
            # Проверяем существование транзакции
            tx = db.find_one('transactions', {'id': tx_id, 'merchant_id': user['id']})
            if not tx:
                return jsonify({'error': 'Transaction not found or access denied'}), 404
                
            if tx.get('status') != 'pending':
                return jsonify({'error': 'Can only add requisites to pending transactions'}), 400
                
            # Валидация реквизитов в зависимости от типа
            req_type = data.get('type')
            if not req_type:
                return jsonify({'error': 'Missing requisites type'}), 400
                
            errors = []
            if req_type == 'bank':
                required = ['bank_name', 'bik', 'account_number', 'account_holder']
                for field in required:
                    if not data.get(field):
                        errors.append(f"Missing required field: {field}")
            elif req_type == 'card':
                required = ['card_number', 'card_holder', 'expiry_date']
                for field in required:
                    if not data.get(field):
                        errors.append(f"Missing required field: {field}")
            elif req_type == 'crypto':
                if not data.get('wallet_address'):
                    errors.append("Missing wallet address")
            else:
                errors.append(f"Invalid requisites type: {req_type}")
                
            if errors:
                return jsonify({'error': 'Validation failed', 'details': errors}), 400
                
            requisites = {
                'transaction_id': tx_id,
                'type': req_type,
                'bank_name': data.get('bank_name'),
                'bik': data.get('bik'),
                'account_number': data.get('account_number'),
                'account_holder': data.get('account_holder'),
                'card_number': data.get('card_number'),
                'card_holder': data.get('card_holder'),
                'expiry_date': data.get('expiry_date'),
                'crypto_type': data.get('crypto_type'),
                'wallet_address': data.get('wallet_address'),
                'created_at': datetime.now().isoformat(),
                'added_by': user['id']
            }
            
            # Сохраняем реквизиты
            db.insert_one('requisites', requisites)
            
            # Обновляем статус транзакции
            db.update_one('transactions', {'id': tx_id}, {
                'requisites_approved': True,
                'updated_at': datetime.now().isoformat()
            })
            
            logger.info(f"Saved requisites for transaction {tx_id}")
            return jsonify({'success': True})
            
        except Exception as e:
            logger.error(f"Error saving requisites: {str(e)}", exc_info=True)
            return jsonify({'error': str(e)}), 500

    @app.route('/api/merchant/transactions/<int:tx_id>/requisites', methods=['GET'])
    @app.role_required('merchant')
    def get_requisites(tx_id):
        user = app.get_current_user()
        if not user:
            return jsonify({'error': 'Unauthorized'}), 401
            
        try:
            # Проверяем что транзакция принадлежит мерчанту
            tx = db.find_one('transactions', {'id': tx_id, 'merchant_id': user['id']})
            if not tx:
                return jsonify({'error': 'Transaction not found or access denied'}), 404
                
            requisites = db.find('requisites', {'transaction_id': tx_id})
            if not requisites:
                return jsonify({'error': 'Requisites not found'}), 404
                
            return jsonify(requisites)
            
        except Exception as e:
            logger.error(f"Error getting requisites: {str(e)}", exc_info=True)
            return jsonify({'error': str(e)}), 500

    @app.route('/api/merchant/api_keys', methods=['POST'])
    @app.role_required('merchant')
    @app.csrf_protect
    def generate_merchant_api_key():
        user = app.get_current_user()
        if not user:
            return jsonify({'error': 'Unauthorized'}), 401
            
        try:
            new_key = {
                'merchant_id': user['id'],
                'key': secrets.token_hex(16),
                'secret': secrets.token_hex(32),
                'created_at': datetime.now().isoformat(),
                'active': True,
                'last_used': None,
                'permissions': ['read', 'create_transactions']
            }
            
            db.insert_one('api_keys', new_key)
            
            logger.info(f"Generated new API key for merchant {user['id']}")
            return jsonify({
                'success': True,
                'api_key': new_key['key'],
                'secret_key': new_key['secret']
            })
            
        except Exception as e:
            logger.error(f"Error generating API key: {str(e)}", exc_info=True)
            return jsonify({'error': str(e)}), 500

    @app.route('/api/merchant/api_keys/<key_id>', methods=['DELETE'])
    @app.role_required('merchant')
    @app.csrf_protect
    def revoke_merchant_api_key(key_id):
        user = app.get_current_user()
        if not user:
            return jsonify({'error': 'Unauthorized'}), 401
            
        try:
            key = db.find_one('api_keys', {'id': int(key_id), 'merchant_id': user['id']})
            if not key:
                return jsonify({'error': 'API key not found'}), 404
            
            if not db.delete_one('api_keys', {'id': int(key_id)}):
                return jsonify({'error': 'Failed to revoke API key'}), 500
            
            logger.info(f"Revoked API key {key_id} for merchant {user['id']}")
            return jsonify({'success': True})
            
        except Exception as e:
            logger.error(f"Error revoking API key: {str(e)}", exc_info=True)
            return jsonify({'error': str(e)}), 500

    @app.route('/api/merchant/matches', methods=['GET'])
    @app.role_required('merchant')
    def get_merchant_matches():
        user = app.get_current_user()
        if not user:
            return jsonify({'error': 'Unauthorized'}), 401
            
        try:
            status = request.args.get('status', 'pending')
            
            matches = db.find('matches', {
                'merchant_id': user['id'],
                'status': status
            })
            
            return jsonify(matches)
            
        except Exception as e:
            logger.error(f"Error getting matches: {str(e)}", exc_info=True)
            return jsonify({'error': str(e)}), 500

    @app.route('/api/merchant/matches/<match_id>/confirm', methods=['POST'])
    @app.role_required('merchant')
    @app.csrf_protect
    def merchant_confirm_match(match_id):
        user = app.get_current_user()
        if not user:
            return jsonify({'error': 'Unauthorized'}), 401
            
        try:
            match = db.find_one('matches', {
                'id': int(match_id),
                'merchant_id': user['id']
            })
            
            if not match:
                return jsonify({'error': 'Match not found or access denied'}), 404
            
            if match.get('status') != 'pending':
                return jsonify({'error': 'Only pending matches can be confirmed'}), 400
            
            # Обновляем статус матча
            db.update_one('matches', {'id': int(match_id)}, {
                'status': 'completed',
                'completed_at': datetime.now().isoformat(),
                'updated_at': datetime.now().isoformat()
            })
            
            # Обновляем статусы связанных транзакций
            for dep_id in match.get('deposit_ids', []):
                db.update_one('transactions', {'id': dep_id}, {
                    'status': 'completed',
                    'completed_at': datetime.now().isoformat(),
                    'updated_at': datetime.now().isoformat()
                })
            
            if match.get('withdrawal_id'):
                db.update_one('transactions', {'id': match['withdrawal_id']}, {
                    'status': 'completed',
                    'completed_at': datetime.now().isoformat(),
                    'updated_at': datetime.now().isoformat()
                })
            
            logger.info(f"Merchant {user['id']} confirmed match {match_id}")
            return jsonify({'success': True})
            
        except Exception as e:
            logger.error(f"Error confirming match: {str(e)}", exc_info=True)
            return jsonify({'error': str(e)}), 500

    @app.route('/api/merchant/matches/<match_id>/reject', methods=['POST'])
    @app.role_required('merchant')
    @app.csrf_protect
    def reject_merchant_match(match_id):
        user = app.get_current_user()
        if not user:
            return jsonify({'error': 'Unauthorized'}), 401
            
        try:
            data = request.get_json()
            reason = data.get('reason', 'No reason provided')
            
            match = db.find_one('matches', {
                'id': int(match_id),
                'merchant_id': user['id']
            })
            
            if not match:
                return jsonify({'error': 'Match not found or access denied'}), 404
            
            if match.get('status') != 'pending':
                return jsonify({'error': 'Only pending matches can be rejected'}), 400
            
            updates = {
                'status': 'rejected',
                'rejected_at': datetime.now().isoformat(),
                'rejected_by': user['id'],
                'reason': reason,
                'updated_at': datetime.now().isoformat()
            }
            
            db.update_one('matches', {'id': int(match_id)}, updates)
            
            # Возвращаем транзакции в статус pending
            for dep_id in match.get('deposit_ids', []):
                db.update_one('transactions', {'id': dep_id}, {
                    'status': 'pending',
                    'updated_at': datetime.now().isoformat()
                })
            
            if match.get('withdrawal_id'):
                db.update_one('transactions', {'id': match['withdrawal_id']}, {
                    'status': 'pending',
                    'updated_at': datetime.now().isoformat()
                })
            
            logger.info(f"Merchant {user['id']} rejected match {match_id}")
            return jsonify({'success': True})
            
        except Exception as e:
            logger.error(f"Error rejecting match: {str(e)}", exc_info=True)
            return jsonify({'error': str(e)}), 500

    @app.route('/api/requisites/types', methods=['GET'])
    @app.role_required('merchant')
    def get_requisites_types_by_method():
        method = request.args.get('method')
        if not method:
            return jsonify({'error': 'Method parameter is required'}), 400
        
        types_data = {
            'bank': {
                'fields': [
                    {'name': 'account_number', 'label': 'Номер счета', 'type': 'text'},
                    {'name': 'bik', 'label': 'БИК', 'type': 'text'},
                    {'name': 'bank_name', 'label': 'Название банка', 'type': 'text'},
                    {'name': 'owner_name', 'label': 'ФИО владельца', 'type': 'text'}
                ]
            },
            'card': {
                'fields': [
                    {'name': 'card_number', 'label': 'Номер карты', 'type': 'text'},
                    {'name': 'card_owner', 'label': 'ФИО владельца', 'type': 'text'},
                    {'name': 'card_expiry', 'label': 'Срок действия', 'type': 'text'},
                    {'name': 'card_cvv', 'label': 'CVV код', 'type': 'password'}
                ]
            },
            'crypto': {
                'fields': [
                    {'name': 'wallet_address', 'label': 'Адрес кошелька', 'type': 'text'},
                    {'name': 'crypto_type', 'label': 'Тип криптовалюты', 'type': 'select', 
                     'options': ['BTC', 'ETH', 'USDT', 'USDC', 'BNB']}
                ]
            }
        }
        
        if method not in types_data:
            return jsonify({'error': 'Method not found'}), 404
        
        return jsonify(types_data[method])

    return app
