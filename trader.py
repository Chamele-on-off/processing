from flask import render_template, jsonify, request, session, send_from_directory, redirect, url_for
from datetime import datetime, timedelta
from werkzeug.utils import secure_filename
import uuid
import os
import logging
from functools import wraps
import json
import random


def trader_routes(app, db, logger):
    # ===============
    # Панель трейдера
    # ===============

    @app.route('/trader.html')
    @app.role_required('trader')
    def trader_dashboard():
        user = app.get_current_user()
        if not user:
            return redirect(url_for('login'))
        
        # Убедимся, что у пользователя есть все необходимые поля баланса
        user.setdefault('working_balance_usdt', 0.0)
        user.setdefault('working_balance_rub', 0.0)
        user.setdefault('insurance_balance', 0.0)
        user.setdefault('deposit_rate', 0.01)  # 1% по умолчанию
        user.setdefault('withdrawal_rate', 0.01)  # 1% по умолчанию
        
        # Получаем текущие курсы валют
        rates = {
            'usdt_rub': 90.0,  # Примерный курс
            'rub_usdt': 1 / 90.0
        }
        
        # Получаем активные транзакции трейдера
        active_transactions = []
        all_transactions = db.find('transactions', {'trader_id': int(user['id'])}) or []
        
        for t in all_transactions:
            if not isinstance(t, dict):
                continue
                
            if t.get('status') == 'pending':
                # Добавляем время истечения (30 минут с момента создания)
                if 'created_at' in t and not t.get('expires_at'):
                    created_at = datetime.fromisoformat(t['created_at'])
                    expires_at = created_at + timedelta(minutes=30)
                    t['expires_at'] = expires_at.isoformat()
                    db.update_one('transactions', {'id': t['id']}, {'expires_at': t['expires_at']})
                
                active_transactions.append(t)
        
        # Статистика за сегодня
        today = datetime.now().date()
        today_transactions = []
        
        for t in all_transactions:
            if not isinstance(t, dict) or not isinstance(t.get('created_at'), str):
                continue
                
            try:
                created_at = datetime.fromisoformat(t['created_at']).date()
                if created_at == today:
                    today_transactions.append(t)
            except ValueError:
                continue
        
        today_stats = {
            'deposits_count': len([t for t in today_transactions if t.get('type') == 'deposit']),
            'deposits_amount': sum(float(t.get('amount', 0)) for t in today_transactions if t.get('type') == 'deposit'),
            'withdrawals_count': len([t for t in today_transactions if t.get('type') == 'withdrawal']),
            'withdrawals_amount': sum(float(t.get('amount', 0)) for t in today_transactions if t.get('type') == 'withdrawal'),
            'avg_processing_time': app.calculate_avg_processing_time(),
            'conversion_rate': app.calculate_conversion_rate(today_transactions)
        }
        
        # Получаем все реквизиты трейдера
        requisites = db.find('requisites', {'trader_id': int(user['id'])}) or []
        
        # Получаем активные диспуты
        disputes = db.find('disputes', {'trader_id': int(user['id'])}) or []
        
        # Список банков (в реальности нужно получать из базы или API)
        banks = ['Сбербанк', 'Тинькофф', 'Альфа-Банк', 'ВТБ', 'Газпромбанк']
        
        # Логирование для отладки
        logger.info(f"Rendering trader dashboard for user {user['id']}")
        logger.debug(f"User data: {user}")
        logger.debug(f"Active transactions: {active_transactions}")
        logger.debug(f"Today stats: {today_stats}")
        
        return render_template(
            'trader.html',
            user=user,
            active_transactions=active_transactions,
            transactions=all_transactions,
            active_deposits_count=len([t for t in active_transactions if t.get('type') == 'deposit']),
            active_withdrawals_count=len([t for t in active_transactions if t.get('type') == 'withdrawal']),
            requisites=requisites,
            disputes=disputes,
            today_stats=today_stats,
            rates=rates,
            banks=banks
        )

    @app.route('/api/trader/requisites', methods=['POST'])
    @app.role_required('trader')
    @app.csrf_protect
    def add_trader_requisites():
        user = app.get_current_user()
        try:
            data = request.get_json()
            if not data:
                return jsonify({'error': 'No data provided'}), 400

            # Проверяем обязательные поля
            required_fields = ['name', 'method', 'type', 'bank', 'min_amount', 'max_amount', 'max_requests', 'daily_limit']
            if not all(field in data for field in required_fields):
                return jsonify({'error': 'Missing required fields'}), 400

            # Формируем детали реквизитов в зависимости от типа
            details = ""
            if data['type'] == 'bank_account':
                if not all(field in data for field in ['account_number', 'bik', 'owner_name']):
                    return jsonify({'error': 'Missing required fields for bank account'}), 400
                details = f"Счет: {data['account_number']}, БИК: {data['bik']}, Владелец: {data['owner_name']}"
            elif data['type'] == 'card':
                if not all(field in data for field in ['card_number', 'card_expiry', 'owner_name']):
                    return jsonify({'error': 'Missing required fields for card'}), 400
                details = f"Карта: {data['card_number']}, Срок: {data['card_expiry']}, Владелец: {data['owner_name']}"
            elif data['type'] == 'phone':
                if 'phone_number' not in data:
                    return jsonify({'error': 'Missing phone number'}), 400
                details = f"Телефон: {data['phone_number']}"

            new_requisite = {
                'id': int(uuid.uuid4().int & (1<<31)-1),
                'trader_id': int(user['id']),
                'name': data['name'],
                'method': data['method'],
                'type': data['type'],
                'bank': data['bank'],
                'details': details,
                'min_amount': float(data['min_amount']),
                'max_amount': float(data['max_amount']),
                'max_requests': int(data['max_requests']),
                'daily_limit': int(data['daily_limit']),
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
                
                if db.update_one('requisites', {'id': int(data['requisite_id'])}, new_requisite):
                    return jsonify({'success': True, 'requisite': new_requisite})
                else:
                    return jsonify({'error': 'Failed to update requisite'}), 500
            
            # Иначе создаем новые реквизиты
            if db.insert_one('requisites', new_requisite):
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
        try:
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
        try:
            transaction = db.find_one('transactions', {'id': transaction_id})
            if not transaction:
                return jsonify({'error': 'Transaction not found'}), 404
            
            if transaction.get('trader_id') and int(transaction['trader_id']) != int(user['id']):
                return jsonify({'error': 'Access denied'}), 403
            
            # Получаем реквизиты, если есть
            requisites = None
            if transaction.get('requisites_id'):
                requisites = db.find_one('requisites', {'id': int(transaction['requisites_id'])})
            
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
                'trader_id': transaction.get('trader_id'),
                'requisites': requisites,
                'receipt_file': transaction.get('receipt_file')
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
        try:
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
            
            # Обновляем баланс трейдера в зависимости от типа транзакции
            if transaction['type'] == 'deposit':
                # Для депозитов уменьшаем рабочий баланс трейдера
                new_balance = float(user.get('working_balance_rub', 0)) - float(transaction['amount'])
                if not db.update_one('users', {'id': int(user['id'])}, {'working_balance_rub': new_balance}):
                    return jsonify({'error': 'Failed to update balance'}), 500
            else:
                # Для выплат увеличиваем рабочий баланс трейдера (в USDT)
                rate = float(transaction.get('rate', 90.0))  # По умолчанию 90 RUB за USDT
                usdt_amount = float(transaction['amount']) / rate
                new_balance = float(user.get('working_balance_usdt', 0)) + usdt_amount
                if not db.update_one('users', {'id': int(user['id'])}, {'working_balance_usdt': new_balance}):
                    return jsonify({'error': 'Failed to update balance'}), 500
            
            return jsonify({'success': True})
        except Exception as e:
            logger.error(f"Error completing transaction: {str(e)}", exc_info=True)
            return jsonify({'error': str(e)}), 500

    @app.route('/api/trader/transactions/<int:transaction_id>/receipt', methods=['POST'])
    @app.role_required('trader')
    @app.csrf_protect
    def upload_transaction_receipt(transaction_id):
        if 'file' not in request.files:
            return jsonify({'error': 'No file uploaded'}), 400
        
        file = request.files['file']
        if file.filename == '':
            return jsonify({'error': 'No selected file'}), 400
        
        if file and app.allowed_file(file.filename):
            filename = secure_filename(f"receipt_{transaction_id}_{datetime.now().timestamp()}.{file.filename.rsplit('.', 1)[1].lower()}")
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            
            try:
                file.save(file_path)
                
                if not db.update_one('transactions', {'id': transaction_id}, {
                    'receipt_file': filename,
                    'updated_at': datetime.now().isoformat()
                }):
                    os.remove(file_path)
                    return jsonify({'error': 'Failed to update transaction'}), 500
                
                return jsonify({'success': True, 'filename': filename})
            except Exception as e:
                if os.path.exists(file_path):
                    os.remove(file_path)
                logger.error(f"Error saving receipt: {str(e)}", exc_info=True)
                return jsonify({'error': str(e)}), 500
        
        return jsonify({'error': 'Invalid file type'}), 400

    @app.route('/api/trader/deposits/toggle', methods=['POST'])
    @app.role_required('trader')
    @app.csrf_protect
    def toggle_trader_deposits():
        user = app.get_current_user()
        try:
            data = request.get_json()
            enable = bool(data.get('enable', False))
            
            if not db.update_one('users', {'id': int(user['id'])}, {'deposits_enabled': enable}):
                return jsonify({'error': 'Failed to update settings'}), 500
                
            return jsonify({'success': True, 'enabled': enable})
        except Exception as e:
            logger.error(f"Error toggling deposits: {str(e)}", exc_info=True)
            return jsonify({'error': str(e)}), 500

    @app.route('/api/trader/withdrawals/toggle', methods=['POST'])
    @app.role_required('trader')
    @app.csrf_protect
    def toggle_trader_withdrawals():
        user = app.get_current_user()
        try:
            data = request.get_json()
            enable = bool(data.get('enable', False))
            
            if not db.update_one('users', {'id': int(user['id'])}, {'withdrawals_enabled': enable}):
                return jsonify({'error': 'Failed to update settings'}), 500
                
            return jsonify({'success': True, 'enabled': enable})
        except Exception as e:
            logger.error(f"Error toggling withdrawals: {str(e)}", exc_info=True)
            return jsonify({'error': str(e)}), 500

    @app.route('/api/trader/rates', methods=['POST'])
    @app.role_required('trader')
    @app.csrf_protect
    def update_trader_rates():
        user = app.get_current_user()
        try:
            data = request.get_json()
            if not data:
                return jsonify({'error': 'No data provided'}), 400
            
            deposit_rate = float(data.get('deposit_rate', 0)) / 100
            withdrawal_rate = float(data.get('withdrawal_rate', 0)) / 100
            
            if deposit_rate < 0 or deposit_rate > 0.2 or withdrawal_rate < 0 or withdrawal_rate > 0.2:
                return jsonify({'error': 'Rates must be between 0% and 20%'}), 400
            
            updates = {
                'deposit_rate': deposit_rate,
                'withdrawal_rate': withdrawal_rate,
                'updated_at': datetime.now().isoformat()
            }
            
            if not db.update_one('users', {'id': int(user['id'])}, updates):
                return jsonify({'error': 'Failed to update rates'}), 500
                
            return jsonify({'success': True})
        except Exception as e:
            logger.error(f"Error updating rates: {str(e)}", exc_info=True)
            return jsonify({'error': str(e)}), 400

    @app.route('/api/trader/deposit', methods=['POST'])
    @app.role_required('trader')
    @app.csrf_protect
    def trader_deposit():
        user = app.get_current_user()
        try:
            data = request.get_json()
            amount = float(data.get('amount', 0))
            
            if amount <= 0:
                return jsonify({'error': 'Amount must be positive'}), 400
            
            # Генерируем адрес кошелька для пополнения
            wallet_address = f"T{user['id']}{int(datetime.now().timestamp())}"
            
            # Создаем запись о депозите
            deposit = {
                'id': int(uuid.uuid4().int & (1<<31)-1),
                'trader_id': int(user['id']),
                'type': 'deposit',
                'amount': amount,
                'currency': 'USDT',
                'status': 'pending',
                'wallet_address': wallet_address,
                'created_at': datetime.now().isoformat(),
                'updated_at': datetime.now().isoformat()
            }
            
            if not db.insert_one('deposits', deposit):
                return jsonify({'error': 'Failed to create deposit'}), 500
                
            return jsonify({
                'success': True,
                'wallet_address': wallet_address,
                'amount': amount
            })
        except Exception as e:
            logger.error(f"Error processing deposit: {str(e)}", exc_info=True)
            return jsonify({'error': str(e)}), 400

    @app.route('/api/trader/withdraw', methods=['POST'])
    @app.role_required('trader')
    @app.csrf_protect
    def trader_withdraw():
        user = app.get_current_user()
        try:
            data = request.get_json()
            amount = float(data.get('amount', 0))
            requisite_id = int(data.get('requisite_id', 0))
            
            if amount <= 0:
                return jsonify({'error': 'Amount must be positive'}), 400
            
            if amount > float(user.get('working_balance_usdt', 0)):
                return jsonify({'error': 'Insufficient funds'}), 400
            
            # Проверяем реквизиты
            requisite = db.find_one('requisites', {'id': requisite_id, 'trader_id': int(user['id'])})
            if not requisite:
                return jsonify({'error': 'Invalid requisites'}), 400
            
            # Создаем запись о выводе
            withdrawal = {
                'id': int(uuid.uuid4().int & (1<<31)-1),
                'trader_id': int(user['id']),
                'type': 'withdrawal',
                'amount': amount,
                'currency': 'USDT',
                'requisites_id': requisite_id,
                'status': 'pending',
                'created_at': datetime.now().isoformat(),
                'updated_at': datetime.now().isoformat()
            }
            
            if not db.insert_one('withdrawals', withdrawal):
                return jsonify({'error': 'Failed to create withdrawal'}), 500
            
            # Резервируем средства
            new_balance = float(user.get('working_balance_usdt', 0)) - amount
            if not db.update_one('users', {'id': int(user['id'])}, {'working_balance_usdt': new_balance}):
                return jsonify({'error': 'Failed to update balance'}), 500
            
            return jsonify({'success': True})
        except Exception as e:
            logger.error(f"Error processing withdrawal: {str(e)}", exc_info=True)
            return jsonify({'error': str(e)}), 400

    @app.route('/api/trader/disputes/<int:dispute_id>', methods=['GET'])
    @app.role_required('trader')
    def get_trader_dispute(dispute_id):
        user = app.get_current_user()
        try:
            dispute = db.find_one('disputes', {'id': dispute_id, 'trader_id': int(user['id'])})
            if not dispute:
                return jsonify({'error': 'Dispute not found or access denied'}), 404
            
            # Получаем связанную транзакцию
            transaction = db.find_one('transactions', {'id': int(dispute.get('transaction_id', 0))})
            
            response = {
                'id': dispute.get('id'),
                'transaction_id': dispute.get('transaction_id'),
                'type': dispute.get('type'),
                'amount': float(dispute.get('amount', 0)),
                'currency': dispute.get('currency', 'RUB'),
                'status': dispute.get('status'),
                'reason': dispute.get('reason'),
                'comment': dispute.get('comment'),
                'created_at': dispute.get('created_at'),
                'updated_at': dispute.get('updated_at'),
                'transaction': transaction,
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
        try:
            data = request.get_json()
            resolve = bool(data.get('resolve', False))
            comment = data.get('comment', '')
            
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
                transaction = db.find_one('transactions', {'id': int(dispute.get('transaction_id', 0))})
                if transaction:
                    insurance_amount = float(dispute.get('amount', 0))
                    new_insurance = float(user.get('insurance_balance', 0)) - insurance_amount
                    if not db.update_one('users', {'id': int(user['id'])}, {'insurance_balance': new_insurance}):
                        return jsonify({'error': 'Failed to update insurance balance'}), 500
            
            return jsonify({'success': True})
        except Exception as e:
            logger.error(f"Error resolving dispute: {str(e)}", exc_info=True)
            return jsonify({'error': str(e)}), 500

    @app.route('/api/trader/stats', methods=['GET'])
    @app.role_required('trader')
    def get_trader_stats():
        user = app.get_current_user()
        try:
            # Получаем все транзакции трейдера
            transactions = db.find('transactions', {'trader_id': int(user['id'])}) or []
            
            # Фильтруем по дате, если указаны
            date_from = request.args.get('date_from')
            date_to = request.args.get('date_to')
            
            if date_from or date_to:
                filtered_transactions = []
                for t in transactions:
                    if not isinstance(t, dict):
                        continue
                        
                    if not isinstance(t.get('created_at'), str):
                        continue
                        
                    try:
                        created_at = datetime.fromisoformat(t['created_at']).date()
                        
                        if date_from and created_at < datetime.strptime(date_from, '%Y-%m-%d').date():
                            continue
                        
                        if date_to and created_at > datetime.strptime(date_to, '%Y-%m-%d').date():
                            continue
                        
                        filtered_transactions.append(t)
                    except (ValueError, TypeError):
                        continue
                
                transactions = filtered_transactions
            
            # Рассчитываем статистику
            stats = {
                'total_transactions': len(transactions),
                'deposits_count': len([t for t in transactions if t.get('type') == 'deposit']),
                'deposits_amount': sum(float(t.get('amount', 0)) for t in transactions if t.get('type') == 'deposit'),
                'withdrawals_count': len([t for t in transactions if t.get('type') == 'withdrawal']),
                'withdrawals_amount': sum(float(t.get('amount', 0)) for t in transactions if t.get('type') == 'withdrawal'),
                'conversion_rate': app.calculate_conversion_rate(transactions),
                'avg_processing_time': app.calculate_avg_processing_time()
            }
            
            return jsonify(stats)
        except Exception as e:
            logger.error(f"Error getting stats: {str(e)}", exc_info=True)
            return jsonify({'error': str(e)}), 500

    return app
