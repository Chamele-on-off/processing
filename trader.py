# trader.py
from flask import render_template, jsonify, request, session, send_from_directory, redirect, url_for
from datetime import datetime, timedelta
from werkzeug.utils import secure_filename
import uuid
import os
import logging
from functools import wraps
import json
import random
import time
from threading import Lock
from werkzeug.security import generate_password_hash

# Настройка логгирования
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)
handler = logging.StreamHandler()
handler.setFormatter(logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s'))
logger.addHandler(handler)

# Глобальная блокировка для операций с балансом
balance_lock = Lock()

def trader_routes(app, db, logger):
    # ===============
    # Панель трейдера
    # ===============

    @app.route('/trader.html')
    @app.role_required('trader')
    def trader_dashboard():
        try:
            user = app.get_current_user()
            if not user:
                return redirect(url_for('login'))
            
            # Убедимся, что у пользователя есть все необходимые поля
            required_fields = [
                'working_balance_usdt', 'working_balance_rub', 
                'insurance_balance', 'deposit_rate', 'withdrawal_rate'
            ]
            
            needs_update = False
            updates = {}
            for field in required_fields:
                if field not in user:
                    updates[field] = 0.0 if 'balance' in field else 0.01
                    needs_update = True
            
            if needs_update:
                with db.transaction():
                    db.update_one('users', {'id': user['id']}, updates)
                    user.update(updates)
            
            # Получаем текущие курсы валют из настроек системы
            rates = db.find_one('system_settings', {'type': 'currency_rates'}) or {
                'USD': 75.0,
                'EUR': 85.0,
                'USDT': 1.0,
                'RUB': 1.0,
                'usdt_rub': 90.0  # Добавляем значение по умолчанию
            }
            
            # Убедимся, что курс usdt_rub существует
            if 'usdt_rub' not in rates:
                rates['usdt_rub'] = 90.0
            
            # Получаем активные транзакции трейдера
            current_trader_id = int(user.get('id', 0))
            logger.debug(f"[Trader Dashboard] Current trader ID: {current_trader_id}")

            # Получаем транзакции с использованием индекса
            transactions = db.find('transactions', {'trader_id': current_trader_id}) or []
            logger.debug(f"[Trader Dashboard] Found {len(transactions)} transactions for trader")

            # Фильтруем активные транзакции
            active_transactions = []
            for t in transactions:
                if not isinstance(t, dict):
                    continue
                
                # Проверяем статус
                if t.get('status') != 'pending':
                    continue
                
                # Добавляем время истечения (30 минут с момента создания)
                if 'created_at' in t and not t.get('expires_at'):
                    try:
                        created_at = datetime.fromisoformat(t['created_at'])
                        expires_at = created_at + timedelta(minutes=30)
                        t['expires_at'] = expires_at.isoformat()
                        with db.transaction():
                            db.update_one('transactions', {'id': t['id']}, {'expires_at': t['expires_at']})
                    except (ValueError, TypeError) as e:
                        logger.error(f"Error processing transaction date: {str(e)}")
                        continue
                
                active_transactions.append(t)

            logger.debug(f"[Trader Dashboard] Found {len(active_transactions)} active transactions")
            
            # Статистика за сегодня
            today = datetime.now().date()
            today_transactions = []
            
            for t in transactions:
                if not isinstance(t, dict) or not isinstance(t.get('created_at'), str):
                    continue
                    
                try:
                    created_at = datetime.fromisoformat(t['created_at']).date()
                    if created_at == today:
                        today_transactions.append(t)
                except ValueError as e:
                    logger.error(f"Error processing today's transaction: {str(e)}")
                    continue
            
            today_stats = {
                'deposits_count': len([t for t in today_transactions if t.get('type') == 'deposit']),
                'deposits_amount': sum(float(t.get('amount', 0)) for t in today_transactions if t.get('type') == 'deposit'),
                'withdrawals_count': len([t for t in today_transactions if t.get('type') == 'withdrawal']),
                'withdrawals_amount': sum(float(t.get('amount', 0)) for t in today_transactions if t.get('type') == 'withdrawal'),
                'avg_processing_time': calculate_avg_processing_time(today_transactions),
                'conversion_rate': calculate_conversion_rate(today_transactions)
            }
            
            # Получаем все реквизиты трейдера
            requisites = db.find('requisites', {'trader_id': current_trader_id}) or []
            valid_requisites = [r for r in requisites if isinstance(r, dict)]
            
            # Получаем активные диспуты
            disputes = db.find('disputes', {'trader_id': current_trader_id}) or []
            valid_disputes = [d for d in disputes if isinstance(d, dict)]
            
            # Список банков (можно получать из базы или API)
            banks = ['Сбербанк', 'Тинькофф', 'Альфа-Банк', 'ВТБ', 'Газпромбанк']
            
            # Логирование для отладки
            logger.info(f"Rendering trader dashboard for user {user.get('id')}")
            logger.debug(f"User data: {user}")
            logger.debug(f"Active transactions: {active_transactions}")
            logger.debug(f"Today stats: {today_stats}")
            
            return render_template(
                'trader.html',
                user=user,
                active_transactions=active_transactions,
                transactions=transactions,
                active_deposits_count=len([t for t in active_transactions if t.get('type') == 'deposit']),
                active_withdrawals_count=len([t for t in active_transactions if t.get('type') == 'withdrawal']),
                requisites=valid_requisites,
                disputes=valid_disputes,
                today_stats=today_stats,
                rates=rates,
                banks=banks
            )
            
        except Exception as e:
            logger.error(f"Error in trader dashboard: {str(e)}", exc_info=True)
            return render_template('error.html', error="Ошибка загрузки данных"), 500

    def calculate_avg_processing_time(transactions):
        """Рассчитывает среднее время обработки транзакций"""
        if not transactions:
            return 0
            
        total_seconds = 0
        count = 0
        
        for t in transactions:
            if not isinstance(t, dict):
                continue
                
            if 'created_at' in t and 'completed_at' in t:
                try:
                    created = datetime.fromisoformat(t['created_at'])
                    completed = datetime.fromisoformat(t['completed_at'])
                    total_seconds += (completed - created).total_seconds()
                    count += 1
                except ValueError:
                    continue
        
        return round(total_seconds / count) if count > 0 else 0

    def calculate_conversion_rate(transactions):
        """Рассчитывает процент успешных транзакций"""
        if not transactions:
            return 0.0
            
        completed = len([t for t in transactions if isinstance(t, dict) and t.get('status') == 'completed'])
        total = len(transactions)
        return round((completed / total) * 100, 1) if total > 0 else 0.0

    @app.route('/api/trader/requisites', methods=['POST'])
    @app.role_required('trader')
    @app.csrf_protect
    def add_trader_requisites():
        user = app.get_current_user()
        if not user:
            return jsonify({'error': 'Unauthorized'}), 401
            
        try:
            data = request.get_json()
            if not data:
                return jsonify({'error': 'No data provided'}), 400

            # Проверяем обязательные поля
            required_fields = ['name', 'method', 'type', 'bank', 'min_amount', 'max_amount', 'max_requests', 'daily_limit']
            if not all(field in data for field in required_fields):
                return jsonify({'error': 'Missing required fields'}), 400

            # Валидация сумм
            try:
                min_amount = float(data['min_amount'])
                max_amount = float(data['max_amount'])
                max_requests = int(data['max_requests'])
                daily_limit = int(data['daily_limit'])
                
                if min_amount <= 0 or max_amount <= 0 or max_requests <= 0 or daily_limit <= 0:
                    return jsonify({'error': 'All numeric values must be positive'}), 400
                    
                if max_amount < min_amount:
                    return jsonify({'error': 'Max amount must be greater than min amount'}), 400
            except (ValueError, TypeError):
                return jsonify({'error': 'Invalid numeric values'}), 400

            # Формируем детали реквизитов в зависимости от типа
            details = ""
            if data['type'] == 'bank_account':
                required = ['account_number', 'bik', 'owner_name']
                if not all(field in data for field in required):
                    return jsonify({'error': 'Missing required fields for bank account'}), 400
                details = f"Счет: {data['account_number']}, БИК: {data['bik']}, Владелец: {data['owner_name']}"
            elif data['type'] == 'card':
                required = ['card_number', 'card_expiry', 'owner_name']
                if not all(field in data for field in required):
                    return jsonify({'error': 'Missing required fields for card'}), 400
                details = f"Карта: {data['card_number']}, Срок: {data['card_expiry']}, Владелец: {data['owner_name']}"
            elif data['type'] == 'phone':
                if 'phone_number' not in data:
                    return jsonify({'error': 'Missing phone number'}), 400
                details = f"Телефон: {data['phone_number']}"
            else:
                return jsonify({'error': 'Invalid requisites type'}), 400

            # Используем транзакцию для атомарности
            with db.transaction():
                new_requisite = {
                    'id': db._get_next_id('requisites'),
                    'trader_id': int(user['id']),
                    'name': data['name'],
                    'method': data['method'],
                    'type': data['type'],
                    'bank': data['bank'],
                    'details': details,
                    'min_amount': min_amount,
                    'max_amount': max_amount,
                    'max_requests': max_requests,
                    'daily_limit': daily_limit,
                    'description': data.get('description', ''),
                    'status': 'pending',
                    'created_at': datetime.now().isoformat(),
                    'updated_at': datetime.now().isoformat()
                }

                # Если это редактирование, обновляем существующие реквизиты
                if 'requisite_id' in data:
                    requisite = db.find_one('requisites', {'id': int(data['requisite_id']), 'trader_id': int(user['id'])})
                    if not requisite:
                        return jsonify({'error': 'Requisite not found or access denied'}), 404
                    
                    # Проверяем, нет ли активных транзакций с этими реквизитами
                    active_txs = db.find('transactions', {
                        'requisites_id': int(data['requisite_id']),
                        'status': 'pending'
                    }) or []
                    
                    if active_txs:
                        return jsonify({'error': 'Cannot edit requisite used in active transactions'}), 400
                    
                    if db.update_one('requisites', {'id': int(data['requisite_id'])}, new_requisite):
                        logger.info(f"Updated requisite {data['requisite_id']} for trader {user['id']}")
                        return jsonify({'success': True, 'requisite': new_requisite})
                    else:
                        return jsonify({'error': 'Failed to update requisite'}), 500
                
                # Иначе создаем новые реквизиты
                if db.insert_one('requisites', new_requisite):
                    # Логируем действие
                    db.insert_one('audit_logs', {
                        'id': db._get_next_id('audit_logs'),
                        'user_id': int(user['id']),
                        'action': 'add_requisites',
                        'details': f"Added new requisites {new_requisite['id']}",
                        'created_at': datetime.now().isoformat()
                    })
                    
                    logger.info(f"Added new requisites {new_requisite['id']} for trader {user['id']}")
                    return jsonify({'success': True, 'requisite': new_requisite})
                else:
                    return jsonify({'error': 'Failed to create requisite'}), 500
            
        except Exception as e:
            logger.error(f"Error adding requisites: {str(e)}", exc_info=True)
            return jsonify({'error': str(e)}), 500

    @app.route('/api/trader/requisites/<int:requisite_id>', methods=['GET'])
    @app.role_required('trader')
    def get_trader_requisite(requisite_id):
        user = app.get_current_user()
        if not user:
            return jsonify({'error': 'Unauthorized'}), 401
            
        try:
            requisite = db.find_one('requisites', {'id': requisite_id, 'trader_id': int(user['id'])})
            if not requisite:
                return jsonify({'error': 'Requisite not found or access denied'}), 404
            
            return jsonify(requisite)
            
        except Exception as e:
            logger.error(f"Error getting requisite: {str(e)}", exc_info=True)
            return jsonify({'error': str(e)}), 500

    @app.route('/api/trader/requisites/<int:requisite_id>', methods=['DELETE'])
    @app.role_required('trader')
    @app.csrf_protect
    def delete_trader_requisite(requisite_id):
        user = app.get_current_user()
        if not user:
            return jsonify({'error': 'Unauthorized'}), 401
            
        try:
            # Используем транзакцию для атомарности
            with db.transaction():
                requisite = db.find_one('requisites', {'id': requisite_id, 'trader_id': int(user['id'])})
                if not requisite:
                    return jsonify({'error': 'Requisite not found or access denied'}), 404
                
                # Проверяем, нет ли активных транзакций с этими реквизитами
                active_transactions = db.find('transactions', {
                    'requisites_id': requisite_id,
                    'status': 'pending'
                }) or []
                
                if active_transactions:
                    return jsonify({'error': 'Cannot delete requisite used in active transactions'}), 400
                
                if db.delete_one('requisites', {'id': requisite_id}):
                    # Логируем действие
                    db.insert_one('audit_logs', {
                        'id': db._get_next_id('audit_logs'),
                        'user_id': int(user['id']),
                        'action': 'delete_requisites',
                        'details': f"Deleted requisites {requisite_id}",
                        'created_at': datetime.now().isoformat()
                    })
                    
                    logger.info(f"Deleted requisite {requisite_id} for trader {user['id']}")
                    return jsonify({'success': True})
                else:
                    return jsonify({'error': 'Failed to delete requisite'}), 500
            
        except Exception as e:
            logger.error(f"Error deleting requisite: {str(e)}", exc_info=True)
            return jsonify({'error': str(e)}), 500

    @app.route('/api/trader/transactions/<int:transaction_id>', methods=['GET'])
    @app.role_required('trader')
    def get_trader_transaction(transaction_id):
        user = app.get_current_user()
        if not user:
            return jsonify({'error': 'Unauthorized'}), 401
            
        try:
            transaction = db.find_one('transactions', {'id': transaction_id})
            if not transaction:
                return jsonify({'error': 'Transaction not found'}), 404
            
            if transaction.get('trader_id') != int(user['id']):
                return jsonify({'error': 'Access denied'}), 403
            
            # Получаем реквизиты, если есть
            requisites = None
            if transaction.get('requisites_id'):
                requisites = db.find_one('requisites', {'id': int(transaction['requisites_id'])})
            
            # Получаем информацию о мерчанте
            merchant = None
            if transaction.get('merchant_id'):
                merchant = db.find_one('users', {'id': int(transaction['merchant_id'])})
            
            response = {
                'id': transaction.get('id'),
                'type': transaction.get('type'),
                'amount': float(transaction.get('amount', 0)),
                'currency': transaction.get('currency', 'RUB'),
                'method': transaction.get('method'),
                'status': transaction.get('status'),
                'created_at': transaction.get('created_at'),
                'expires_at': transaction.get('expires_at'),
                'merchant_id': transaction.get('merchant_id'),
                'merchant_email': merchant.get('email') if merchant else None,
                'trader_id': transaction.get('trader_id'),
                'requisites': requisites,
                'receipt_file': transaction.get('receipt_file'),
                'requisites_approved': transaction.get('requisites_approved', False)
            }
            
            return jsonify(response)
            
        except Exception as e:
            logger.error(f"Error getting transaction: {str(e)}", exc_info=True)
            return jsonify({'error': str(e)}), 500

    @app.route('/api/trader/transactions/<int:transaction_id>/complete', methods=['POST'])
    @app.role_required('trader')
    @app.csrf_protect
    def complete_trader_transaction(transaction_id):
        user = app.get_current_user()
        if not user:
            return jsonify({'error': 'Unauthorized'}), 401
            
        try:
            # Используем транзакцию для атомарности
            with db.transaction():
                transaction = db.find_one('transactions', {'id': transaction_id})
                if not transaction:
                    return jsonify({'error': 'Transaction not found'}), 404
                
                if transaction.get('trader_id') != int(user['id']):
                    return jsonify({'error': 'Access denied'}), 403
                
                if transaction.get('status') != 'pending':
                    return jsonify({'error': 'Only pending transactions can be completed'}), 400
                
                # Для выплат проверяем наличие загруженного чека
                if transaction.get('type') == 'withdrawal' and not transaction.get('receipt_file'):
                    return jsonify({'error': 'Receipt is required for withdrawal transactions'}), 400
                
                updates = {
                    'status': 'completed',
                    'completed_at': datetime.now().isoformat(),
                    'updated_at': datetime.now().isoformat()
                }
                
                if not db.update_one('transactions', {'id': transaction_id}, updates):
                    return jsonify({'error': 'Failed to update transaction'}), 500
                
                # Обновляем баланс трейдера с блокировкой
                with balance_lock:
                    trader = db.find_one('users', {'id': int(user['id'])})
                    if not trader:
                        return jsonify({'error': 'Trader not found'}), 404
                    
                    if transaction['type'] == 'deposit':
                        # Для депозитов уменьшаем рабочий баланс трейдера (RUB)
                        new_balance = float(trader.get('working_balance_rub', 0)) - float(transaction['amount'])
                        if new_balance < 0:
                            return jsonify({'error': 'Insufficient working balance'}), 400
                            
                        db.update_one('users', {'id': int(user['id'])}, {
                            'working_balance_rub': new_balance,
                            'updated_at': datetime.now().isoformat()
                        })
                    else:
                        # Для выплат увеличиваем рабочий баланс трейдера (USDT)
                        rate = float(transaction.get('rate', 90.0))  # По умолчанию 90 RUB за USDT
                        usdt_amount = float(transaction['amount']) / rate
                        new_balance = float(trader.get('working_balance_usdt', 0)) + usdt_amount
                        
                        db.update_one('users', {'id': int(user['id'])}, {
                            'working_balance_usdt': new_balance,
                            'updated_at': datetime.now().isoformat()
                        })
                
                # Логируем действие
                db.insert_one('audit_logs', {
                    'id': db._get_next_id('audit_logs'),
                    'user_id': int(user['id']),
                    'action': 'complete_transaction',
                    'details': f"Completed transaction {transaction_id}",
                    'created_at': datetime.now().isoformat()
                })
                
                logger.info(f"Completed transaction {transaction_id} by trader {user['id']}")
                return jsonify({'success': True})
            
        except Exception as e:
            logger.error(f"Error completing transaction: {str(e)}", exc_info=True)
            return jsonify({'error': str(e)}), 500

    @app.route('/api/trader/transactions/<int:transaction_id>/receipt', methods=['POST'])
    @app.role_required('trader')
    @app.csrf_protect
    def upload_transaction_receipt(transaction_id):
        user = app.get_current_user()
        if not user:
            return jsonify({'error': 'Unauthorized'}), 401
            
        try:
            if 'file' not in request.files:
                return jsonify({'error': 'No file uploaded'}), 400
            
            file = request.files['file']
            if file.filename == '':
                return jsonify({'error': 'No selected file'}), 400
            
            if file and app.allowed_file(file.filename):
                # Создаем папку для загрузок, если ее нет
                os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
                
                # Генерируем уникальное имя файла
                ext = file.filename.rsplit('.', 1)[1].lower()
                filename = f"receipt_{transaction_id}_{int(time.time())}.{ext}"
                filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                
                # Сохраняем файл
                file.save(filepath)
                
                # Используем транзакцию для атомарности
                with db.transaction():
                    # Проверяем что транзакция принадлежит трейдеру
                    tx = db.find_one('transactions', {
                        'id': transaction_id,
                        'trader_id': int(user['id'])
                    })
                    if not tx:
                        os.remove(filepath)
                        return jsonify({'error': 'Transaction not found or access denied'}), 404
                    
                    if tx.get('status') != 'pending':
                        os.remove(filepath)
                        return jsonify({'error': 'Can only upload receipt for pending transactions'}), 400
                    
                    db.update_one('transactions', {'id': transaction_id}, {
                        'receipt_file': filename,
                        'updated_at': datetime.now().isoformat()
                    })
                    
                    # Логируем действие
                    db.insert_one('audit_logs', {
                        'id': db._get_next_id('audit_logs'),
                        'user_id': int(user['id']),
                        'action': 'upload_receipt',
                        'details': f"Uploaded receipt for transaction {transaction_id}",
                        'created_at': datetime.now().isoformat()
                    })
                    
                    logger.info(f"Uploaded receipt for transaction {transaction_id}")
                    return jsonify({'success': True, 'filename': filename})
            
            return jsonify({'error': 'Invalid file type'}), 400
            
        except Exception as e:
            logger.error(f"Error uploading receipt: {str(e)}", exc_info=True)
            return jsonify({'error': str(e)}), 500

    @app.route('/api/trader/deposits/toggle', methods=['POST'])
    @app.role_required('trader')
    @app.csrf_protect
    def toggle_trader_deposits():
        user = app.get_current_user()
        if not user:
            return jsonify({'error': 'Unauthorized'}), 401
            
        try:
            data = request.get_json()
            enable = bool(data.get('enable', False))
            
            # Используем транзакцию для атомарности
            with db.transaction():
                if not db.update_one('users', {'id': int(user['id'])}, {'deposits_enabled': enable}):
                    return jsonify({'error': 'Failed to update settings'}), 500
                
                # Логируем действие
                db.insert_one('audit_logs', {
                    'id': db._get_next_id('audit_logs'),
                    'user_id': int(user['id']),
                    'action': 'toggle_deposits',
                    'details': f"Set deposits enabled to {enable}",
                    'created_at': datetime.now().isoformat()
                })
                
                logger.info(f"Set deposits enabled to {enable} for trader {user['id']}")
                return jsonify({'success': True, 'enabled': enable})
            
        except Exception as e:
            logger.error(f"Error toggling deposits: {str(e)}", exc_info=True)
            return jsonify({'error': str(e)}), 500

    @app.route('/api/trader/withdrawals/toggle', methods=['POST'])
    @app.role_required('trader')
    @app.csrf_protect
    def toggle_trader_withdrawals():
        user = app.get_current_user()
        if not user:
            return jsonify({'error': 'Unauthorized'}), 401
            
        try:
            data = request.get_json()
            enable = bool(data.get('enable', False))
            
            # Используем транзакцию для атомарности
            with db.transaction():
                if not db.update_one('users', {'id': int(user['id'])}, {'withdrawals_enabled': enable}):
                    return jsonify({'error': 'Failed to update settings'}), 500
                
                # Логируем действие
                db.insert_one('audit_logs', {
                    'id': db._get_next_id('audit_logs'),
                    'user_id': int(user['id']),
                    'action': 'toggle_withdrawals',
                    'details': f"Set withdrawals enabled to {enable}",
                    'created_at': datetime.now().isoformat()
                })
                
                logger.info(f"Set withdrawals enabled to {enable} for trader {user['id']}")
                return jsonify({'success': True, 'enabled': enable})
            
        except Exception as e:
            logger.error(f"Error toggling withdrawals: {str(e)}", exc_info=True)
            return jsonify({'error': str(e)}), 500

    @app.route('/api/trader/rates', methods=['POST'])
    @app.role_required('trader')
    @app.csrf_protect
    def update_trader_rates():
        user = app.get_current_user()
        if not user:
            return jsonify({'error': 'Unauthorized'}), 401
            
        try:
            data = request.get_json()
            if not data:
                return jsonify({'error': 'No data provided'}), 400
            
            try:
                deposit_rate = float(data.get('deposit_rate', 0)) / 100
                withdrawal_rate = float(data.get('withdrawal_rate', 0)) / 100
                
                if deposit_rate < 0 or deposit_rate > 0.2 or withdrawal_rate < 0 or withdrawal_rate > 0.2:
                    return jsonify({'error': 'Rates must be between 0% and 20%'}), 400
            except (ValueError, TypeError):
                return jsonify({'error': 'Invalid rate values'}), 400
            
            # Используем транзакцию для атомарности
            with db.transaction():
                updates = {
                    'deposit_rate': deposit_rate,
                    'withdrawal_rate': withdrawal_rate,
                    'updated_at': datetime.now().isoformat()
                }
                
                if not db.update_one('users', {'id': int(user['id'])}, updates):
                    return jsonify({'error': 'Failed to update rates'}), 500
                
                # Логируем действие
                db.insert_one('audit_logs', {
                    'id': db._get_next_id('audit_logs'),
                    'user_id': int(user['id']),
                    'action': 'update_rates',
                    'details': f"Updated rates: deposit={deposit_rate}, withdrawal={withdrawal_rate}",
                    'created_at': datetime.now().isoformat()
                })
                
                logger.info(f"Updated rates for trader {user['id']}")
                return jsonify({'success': True})
            
        except Exception as e:
            logger.error(f"Error updating rates: {str(e)}", exc_info=True)
            return jsonify({'error': str(e)}), 400

    @app.route('/api/trader/disputes/<int:dispute_id>', methods=['GET'])
    @app.role_required('trader')
    def get_trader_dispute(dispute_id):
        user = app.get_current_user()
        if not user:
            return jsonify({'error': 'Unauthorized'}), 401
            
        try:
            dispute = db.find_one('disputes', {'id': dispute_id, 'trader_id': int(user['id'])})
            if not dispute:
                return jsonify({'error': 'Dispute not found or access denied'}), 404
            
            # Получаем связанную транзакцию
            transaction = None
            if dispute.get('transaction_id'):
                transaction = db.find_one('transactions', {'id': int(dispute['transaction_id'])})
            
            # Получаем информацию о мерчанте
            merchant = None
            if transaction and transaction.get('merchant_id'):
                merchant = db.find_one('users', {'id': int(transaction['merchant_id'])})
            
            response = {
                'id': dispute.get('id'),
                'transaction_id': dispute.get('transaction_id'),
                'transaction_amount': transaction.get('amount') if transaction else None,
                'transaction_currency': transaction.get('currency') if transaction else None,
                'merchant_email': merchant.get('email') if merchant else None,
                'type': dispute.get('type'),
                'amount': float(dispute.get('amount', 0)),
                'currency': dispute.get('currency', 'RUB'),
                'status': dispute.get('status'),
                'reason': dispute.get('reason'),
                'comment': dispute.get('comment'),
                'created_at': dispute.get('created_at'),
                'updated_at': dispute.get('updated_at'),
                'evidence': dispute.get('evidence', [])
            }
            
            return jsonify(response)
            
        except Exception as e:
            logger.error(f"Error getting dispute: {str(e)}", exc_info=True)
            return jsonify({'error': str(e)}), 500

    @app.route('/api/trader/disputes/<int:dispute_id>/resolve', methods=['POST'])
    @app.role_required('trader')
    @app.csrf_protect
    def resolve_trader_dispute(dispute_id):
        user = app.get_current_user()
        if not user:
            return jsonify({'error': 'Unauthorized'}), 401
            
        try:
            data = request.get_json()
            resolve = bool(data.get('resolve', False))
            comment = data.get('comment', '')
            
            # Используем транзакцию для атомарности
            with db.transaction():
                dispute = db.find_one('disputes', {'id': dispute_id, 'trader_id': int(user['id'])})
                if not dispute:
                    return jsonify({'error': 'Dispute not found or access denied'}), 404
                
                if dispute.get('status') != 'open':
                    return jsonify({'error': 'Only open disputes can be resolved'}), 400
                
                updates = {
                    'status': 'resolved' if resolve else 'rejected',
                    'comment': comment,
                    'resolved_at': datetime.now().isoformat(),
                    'updated_at': datetime.now().isoformat()
                }
                
                if not db.update_one('disputes', {'id': dispute_id}, updates):
                    return jsonify({'error': 'Failed to update dispute'}), 500
                
                # Если диспут решен в пользу клиента, списываем средства со страхового депозита
                if resolve:
                    with balance_lock:
                        trader = db.find_one('users', {'id': int(user['id'])})
                        if not trader:
                            return jsonify({'error': 'Trader not found'}), 404
                        
                        insurance_amount = float(dispute.get('amount', 0))
                        new_insurance = float(trader.get('insurance_balance', 0)) - insurance_amount
                        
                        if new_insurance < 0:
                            return jsonify({'error': 'Insufficient insurance balance'}), 400
                            
                        db.update_one('users', {'id': int(user['id'])}, {
                            'insurance_balance': new_insurance,
                            'updated_at': datetime.now().isoformat()
                        })
                
                # Логируем действие
                db.insert_one('audit_logs', {
                    'id': db._get_next_id('audit_logs'),
                    'user_id': int(user['id']),
                    'action': 'resolve_dispute',
                    'details': f"Resolved dispute {dispute_id} as {'resolved' if resolve else 'rejected'}",
                    'created_at': datetime.now().isoformat()
                })
                
                logger.info(f"Resolved dispute {dispute_id} by trader {user['id']}")
                return jsonify({'success': True})
            
        except Exception as e:
            logger.error(f"Error resolving dispute: {str(e)}", exc_info=True)
            return jsonify({'error': str(e)}), 500

    @app.route('/api/trader/stats', methods=['GET'])
    @app.role_required('trader')
    def get_trader_stats():
        user = app.get_current_user()
        if not user:
            return jsonify({'error': 'Unauthorized'}), 401
            
        try:
            # Получаем параметры фильтрации
            date_from = request.args.get('date_from')
            date_to = request.args.get('date_to')
            
            # Получаем все транзакции трейдера
            transactions = db.find('transactions', {'trader_id': int(user['id'])}) or []
            
            # Фильтруем по дате, если указаны
            if date_from or date_to:
                filtered_transactions = []
                
                try:
                    date_from_dt = datetime.strptime(date_from, '%Y-%m-%d').date() if date_from else None
                    date_to_dt = datetime.strptime(date_to, '%Y-%m-%d').date() if date_to else None
                except ValueError:
                    return jsonify({'error': 'Invalid date format, use YYYY-MM-DD'}), 400
                
                for t in transactions:
                    if not isinstance(t, dict):
                        continue
                        
                    if not isinstance(t.get('created_at'), str):
                        continue
                        
                    try:
                        created_at = datetime.fromisoformat(t['created_at']).date()
                        
                        if date_from_dt and created_at < date_from_dt:
                            continue
                        
                        if date_to_dt and created_at > date_to_dt:
                            continue
                        
                        filtered_transactions.append(t)
                    except ValueError:
                        continue
                
                transactions = filtered_transactions
            
            # Рассчитываем статистику
            stats = {
                'total_transactions': len(transactions),
                'deposits_count': len([t for t in transactions if t.get('type') == 'deposit']),
                'deposits_amount': sum(float(t.get('amount', 0)) for t in transactions if t.get('type') == 'deposit'),
                'withdrawals_count': len([t for t in transactions if t.get('type') == 'withdrawal']),
                'withdrawals_amount': sum(float(t.get('amount', 0)) for t in transactions if t.get('type') == 'withdrawal'),
                'conversion_rate': calculate_conversion_rate(transactions),
                'avg_processing_time': calculate_avg_processing_time(transactions),
                'total_commission': sum(float(t.get('commission', 0)) for t in transactions if 'commission' in t),
                'start_date': date_from,
                'end_date': date_to
            }
            
            return jsonify(stats)
            
        except Exception as e:
            logger.error(f"Error getting stats: {str(e)}", exc_info=True)
            return jsonify({'error': str(e)}), 500

    return app