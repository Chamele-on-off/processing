from flask import render_template, jsonify, request, session, send_from_directory, redirect, url_for
from datetime import datetime
from werkzeug.utils import secure_filename
import uuid
import os
import logging
from functools import wraps


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
        
        # Преобразуем словарь пользователя в объект с атрибутами
        class UserObject:
            def __init__(self, user_dict):
                self.__dict__ = user_dict
                # Устанавливаем значения по умолчанию для отсутствующих полей
                self.working_balance_usdt = user_dict.get('working_balance_usdt', 0.0)
                self.working_balance_rub = user_dict.get('working_balance_rub', 0.0)
                self.insurance_balance = user_dict.get('insurance_balance', 0.0)
                self.deposit_rate = user_dict.get('deposit_rate', 0.0)
                self.withdrawal_rate = user_dict.get('withdrawal_rate', 0.0)
                self.email = user_dict.get('email', '')
                self.id = user_dict.get('id', 0)
        
        user_obj = UserObject(user)
        
        active_orders = [o for o in (db.find('orders', {'trader_id': user['id'], 'status': 'pending'})) or [] 
                        if isinstance(o, dict)]
        
        all_orders = [o for o in (db.find('orders', {'trader_id': user['id']})) or [] 
                     if isinstance(o, dict)]
        
        details = [d for d in (db.find('details', {'trader_id': user['id']})) or [] 
                  if isinstance(d, dict)]
        
        merchant_transactions = [t for t in (db.find('transactions', {'status': 'pending'}) or []) 
                               if isinstance(t, dict)]
        
        return render_template(
            'trader.html',
            user=user_obj,
            active_orders=active_orders,
            all_orders=all_orders,
            details=details,
            merchant_transactions=merchant_transactions
        )

    @app.route('/api/trader/orders', methods=['POST'])
    @app.role_required('trader')
    @app.csrf_protect
    def create_trader_order():
        user = app.get_current_user()
        try:
            data = request.get_json()
            if not data:
                return jsonify({'error': 'No data provided'}), 400

            detail = db.find_one('details', {'id': int(data['details_id']), 'trader_id': int(user['id'])})
            if not detail:
                return jsonify({'error': 'Invalid details or not found'}), 400

            new_order = {
                'id': int(uuid.uuid4().int & (1<<31)-1),
                'trader_id': int(user['id']),
                'type': data['type'],
                'amount': float(data['amount']),
                'method': data['method'],
                'details_id': int(data['details_id']),
                'status': 'pending',
                'created_at': datetime.now().isoformat(),
                'updated_at': datetime.now().isoformat()
            }
            
            db.insert_one('orders', new_order)
            return jsonify({'success': True, 'order': new_order})
        
        except Exception as e:
            logger.error(f"Error creating order: {str(e)}")
            return jsonify({'error': str(e)}), 400

    @app.route('/api/trader/orders/<order_id>/complete', methods=['POST'])
    @app.role_required('trader')
    @app.csrf_protect
    def complete_trader_order(order_id):
        user = app.get_current_user()
        order = db.find_one('orders', {'id': int(order_id), 'trader_id': int(user['id'])})
        if not order:
            return jsonify({'error': 'Order not found'}), 404
        
        try:
            updates = {
                'status': 'completed',
                'completed_at': datetime.now().isoformat(),
                'updated_at': datetime.now().isoformat()
            }
            db.update_one('orders', {'id': int(order_id)}, updates)
            return jsonify({'success': True})
        except Exception as e:
            return jsonify({'error': str(e)}), 500

    @app.route('/api/trader/orders/<order_id>/cancel', methods=['POST'])
    @app.role_required('trader')
    @app.csrf_protect
    def cancel_trader_order(order_id):
        user = app.get_current_user()
        order = db.find_one('orders', {'id': int(order_id), 'trader_id': int(user['id'])})
        if not order:
            return jsonify({'error': 'Order not found'}), 404
        
        try:
            updates = {
                'status': 'cancelled',
                'updated_at': datetime.now().isoformat()
            }
            db.update_one('orders', {'id': int(order_id)}, updates)
            return jsonify({'success': True})
        except Exception as e:
            return jsonify({'error': str(e)}), 500

    @app.route('/api/trader/details', methods=['GET'])
    @app.role_required('trader')
    def get_trader_details():
        user = app.get_current_user()
        try:
            details = db.find('details', {'trader_id': int(user['id'])})
            return jsonify([d for d in details if isinstance(d, dict)])
        except Exception as e:
            return jsonify({'error': str(e)}), 500

    @app.route('/api/trader/details', methods=['POST'])
    @app.role_required('trader')
    @app.csrf_protect
    def add_trader_details():
        user = app.get_current_user()
        try:
            data = request.get_json()
            if not data:
                return jsonify({'error': 'No data provided'}), 400

            if data['type'] == 'bank_account':
                if not all(k in data for k in ['account_number', 'bik', 'owner_name']):
                    return jsonify({'error': 'Missing required fields for bank account'}), 400
                details = f"Счет: {data['account_number']}, БИК: {data['bik']}, Владелец: {data['owner_name']}"
            elif data['type'] == 'card':
                if not all(k in data for k in ['card_number', 'card_owner', 'card_expiry']):
                    return jsonify({'error': 'Missing required fields for card'}), 400
                details = f"Карта: {data['card_number']}, Владелец: {data['card_owner']}, Срок: {data['card_expiry']}"
            elif data['type'] == 'crypto':
                if not all(k in data for k in ['wallet_address', 'crypto_type']):
                    return jsonify({'error': 'Missing required fields for crypto wallet'}), 400
                details = f"Адрес: {data['wallet_address']}, Тип: {data['crypto_type']}"
            else:
                return jsonify({'error': 'Invalid details type'}), 400

            new_detail = {
                'id': int(uuid.uuid4().int & (1<<31)-1),
                'trader_id': int(user['id']),
                'type': data['type'],
                'details': details,
                'status': 'pending',
                'created_at': datetime.now().isoformat()
            }
            
            db.insert_one('details', new_detail)
            return jsonify({'success': True, 'detail': new_detail})
        except Exception as e:
            logger.error(f"Error adding details: {str(e)}")
            return jsonify({'error': str(e)}), 400

    @app.route('/api/trader/details/<detail_id>', methods=['GET'])
    @app.role_required('trader')
    def get_trader_detail(detail_id):
        user = app.get_current_user()
        try:
            detail = db.find_one('details', {'id': int(detail_id), 'trader_id': int(user['id'])})
            if not detail:
                return jsonify({'error': 'Details not found or access denied'}), 404
            
            return jsonify(detail)
        
        except Exception as e:
            logger.error(f"Error getting detail: {str(e)}")
            return jsonify({'error': str(e)}), 500

    @app.route('/api/trader/details/<detail_id>', methods=['DELETE'])
    @app.role_required('trader')
    @app.csrf_protect
    def delete_trader_details(detail_id):
        user = app.get_current_user()
        try:
            detail = db.find_one('details', {'id': int(detail_id), 'trader_id': int(user['id'])})
            if not detail:
                return jsonify({'error': 'Details not found or access denied'}), 404
            
            orders_with_detail = db.find('orders', {'details_id': int(detail_id), 'status': 'pending'})
            if orders_with_detail:
                return jsonify({'error': 'Cannot delete details used in active orders'}), 400
            
            db.delete_one('details', {'id': int(detail_id)})
            return jsonify({'success': True})
        
        except Exception as e:
            logger.error(f"Error deleting details: {str(e)}")
            return jsonify({'error': str(e)}), 500

    @app.route('/api/trader/deposits/toggle', methods=['POST'])
    @app.role_required('trader')
    @app.csrf_protect
    def toggle_deposits():
        user = app.get_current_user()
        try:
            data = request.get_json()
            enable = data.get('enable', False)
            
            db.update_one('users', {'id': int(user['id'])}, {'deposits_enabled': enable})
            return jsonify({'success': True, 'enabled': enable})
        except Exception as e:
            return jsonify({'error': str(e)}), 400

    @app.route('/api/trader/merchant-transactions/<transaction_id>', methods=['GET'])
    @app.role_required('trader')
    def get_merchant_transaction(transaction_id):
        user = app.get_current_user()
        try:
            transaction = db.find_one('transactions', {'id': int(transaction_id)})
            if not transaction:
                return jsonify({'error': 'Transaction not found'}), 404
            
            if transaction.get('trader_id') and int(transaction['trader_id']) != int(user['id']):
                return jsonify({'error': 'Access denied'}), 403
            
            merchant_requisites = None
            if transaction.get('requisites_id'):
                merchant_requisites = db.find_one('transaction_requisites', {'id': int(transaction['requisites_id'])})
            
            trader_requisites = None
            if transaction.get('trader_requisites_id'):
                trader_requisites = db.find_one('details', {'id': int(transaction['trader_requisites_id'])})
            
            response = {
                'id': transaction.get('id'),
                'type': transaction.get('type'),
                'amount': float(transaction.get('amount', 0)),
                'currency': transaction.get('currency', 'RUB'),
                'status': transaction.get('status'),
                'created_at': transaction.get('created_at'),
                'merchant_id': transaction.get('merchant_id'),
                'trader_id': transaction.get('trader_id'),
                'merchant_requisites': merchant_requisites,
                'trader_requisites': trader_requisites,
                'receipt_file': transaction.get('receipt_file')
            }
            
            return jsonify(response)
        
        except Exception as e:
            logger.error(f"Error getting transaction: {str(e)}")
            return jsonify({'error': str(e)}), 500

    @app.route('/api/trader/deposits/<deposit_id>/upload-receipt', methods=['POST'])
    @app.role_required('trader')
    @app.csrf_protect
    def upload_deposit_receipt(deposit_id):
        try:
            if 'receipt' not in request.files:
                return jsonify({'error': 'No file uploaded'}), 400
            
            file = request.files['receipt']
            if file.filename == '':
                return jsonify({'error': 'No selected file'}), 400
            
            if file and app.allowed_file(file.filename):
                filename = f"deposit_{deposit_id}_{datetime.now().timestamp()}.pdf"
                file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
                
                db.update_one('transactions', {'id': int(deposit_id)}, {
                    'receipt_file': filename,
                    'receipt_uploaded_at': datetime.now().isoformat(),
                    'status': 'pending_verification'
                })
                
                return jsonify({'success': True})
            
            return jsonify({'error': 'Invalid file type'}), 400
        except Exception as e:
            return jsonify({'error': str(e)}), 500

    @app.route('/api/trader/transactions/<transaction_id>/take', methods=['POST'])
    @app.role_required('trader')
    @app.csrf_protect
    def take_transaction(transaction_id):
        user = app.get_current_user()
        try:
            transaction = db.find_one('transactions', {'id': int(transaction_id)})
            if not transaction:
                return jsonify({'error': 'Transaction not found'}), 404
            
            if transaction.get('status') != 'pending':
                return jsonify({'error': 'Only pending transactions can be taken'}), 400
            
            updates = {
                'status': 'in_progress',
                'trader_id': int(user['id']),
                'taken_at': datetime.now().isoformat()
            }
            
            db.update_one('transactions', {'id': int(transaction_id)}, updates)
            return jsonify({'success': True})
        except Exception as e:
            return jsonify({'error': str(e)}), 500

    @app.route('/api/trader/transactions/<transaction_id>/requisites', methods=['POST'])
    @app.role_required('trader')
    @app.csrf_protect
    def assign_requisites_to_transaction(transaction_id):
        user = app.get_current_user()
        data = request.get_json()
        
        detail = db.find_one('details', {
            'id': int(data['detail_id']),
            'trader_id': int(user['id'])
        })
        if not detail:
            return jsonify({'error': 'Реквизиты не найдены или не принадлежат вам'}), 400
        
        db.update_one('transactions', {'id': int(transaction_id)}, {
            'requisites_id': int(data['detail_id']),
            'updated_at': datetime.now().isoformat()
        })
        
        return jsonify({'success': True})

    @app.route('/api/trader/transactions/<transaction_id>/receipt', methods=['POST'])
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
            file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
            
            db.update_one('transactions', {'id': int(transaction_id)}, {
                'receipt_file': filename,
                'updated_at': datetime.now().isoformat()
            })
            
            return jsonify({'success': True, 'filename': filename})
        
        return jsonify({'error': 'Invalid file type'}), 400

    @app.route('/api/trader/transactions/<transaction_id>/complete', methods=['POST'])
    @app.role_required('trader')
    @app.csrf_protect
    def trader_complete_transaction_tr(transaction_id):
        user = app.get_current_user()
        try:
            transaction = db.find_one('transactions', {
                'id': int(transaction_id),
                'trader_id': int(user['id'])
            })
            
            if not transaction:
                return jsonify({'error': 'Transaction not found or access denied'}), 404
            
            if transaction.get('type') == 'withdrawal' and not transaction.get('requisites_id'):
                return jsonify({'error': 'Requisites are required for withdrawals'}), 400
            
            updates = {
                'status': 'pending_admin_approval',
                'completed_at': datetime.now().isoformat(),
                'updated_at': datetime.now().isoformat()
            }
            
            db.update_one('transactions', {'id': int(transaction_id)}, updates)
            return jsonify({'success': True})
        except Exception as e:
            return jsonify({'error': str(e)}), 500

    @app.route('/api/trader/orders/<order_id>', methods=['GET'])
    @app.role_required('trader')
    def get_trader_order_tr(order_id):
        user = app.get_current_user()
        try:
            order = db.find_one('orders', {'id': int(order_id), 'trader_id': int(user['id'])})
            if not order:
                return jsonify({'error': 'Order not found or access denied'}), 404
            
            order['id'] = str(order.get('id', ''))
            order['details_id'] = str(order.get('details_id', ''))
            
            return jsonify(order)
        except Exception as e:
            return jsonify({'error': str(e)}), 500

    @app.route('/api/trader/orders/<order_id>', methods=['PUT'])
    @app.role_required('trader')
    @app.csrf_protect
    def update_trader_order(order_id):
        user = app.get_current_user()
        try:
            data = request.get_json()
            
            order = db.find_one('orders', {'id': int(order_id), 'trader_id': int(user['id'])})
            if not order:
                return jsonify({'error': 'Order not found or access denied'}), 404
            
            updates = {
                'type': data['type'],
                'amount': float(data['amount']),
                'method': data['method'],
                'details_id': int(data['details_id']),
                'status': data['status'],
                'updated_at': datetime.now().isoformat()
            }
            
            db.update_one('orders', {'id': int(order['id'])}, updates)
            return jsonify({'success': True, 'order': updates})
        except Exception as e:
            return jsonify({'error': str(e)}), 400

    @app.route('/api/trader/orders/<order_id>', methods=['DELETE'])
    @app.role_required('trader')
    @app.csrf_protect
    def delete_trader_order(order_id):
        user = app.get_current_user()
        try:
            order = db.find_one('orders', {'id': int(order_id), 'trader_id': int(user['id'])})
            if not order:
                return jsonify({'error': 'Order not found or access denied'}), 404
            
            if order.get('status') == 'completed':
                return jsonify({'error': 'Cannot delete completed order'}), 400
            
            db.delete_one('orders', {'id': int(order['id'])})
            return jsonify({'success': True})
        except Exception as e:
            return jsonify({'error': str(e)}), 500

    @app.route('/api/trader/transactions/<int:tx_id>/check-requisites', methods=['GET'])
    @app.role_required('trader')
    def check_transaction_requisites(tx_id):
        transaction = db.find_one('transactions', {'id': tx_id})
        if not transaction:
            return jsonify({'error': 'Transaction not found'}), 404
        
        if transaction.get('type') == 'withdrawal' and not transaction.get('requisites_id'):
            return jsonify({'error': 'Не назначены реквизиты'}), 400
        
        return jsonify({'success': True})

    return app