from datetime import datetime, timedelta
from flask import jsonify, render_template, request, redirect, url_for, session, make_response, send_from_directory
from werkzeug.security import generate_password_hash
import uuid
import os
import logging
from functools import wraps

def admin_routes(app, db, logger):
    # ============
    # Админ панель 
    # ============

    @app.route('/admin.html')
    @app.role_required('admin')
    @app.log_request
    @app.log_response
    def admin_dashboard():
        try:
            logger.info("Admin dashboard accessed - starting data loading")
            current_admin = app.get_current_user()
            if not current_admin:
                return redirect(url_for('login'))
                
            logger.debug(f"Current admin user: {current_admin['id']} - {current_admin['email']}")

            users = [u for u in (db.find('users') or []) if isinstance(u, dict)]
            logger.info(f"Loaded {len(users)} users from database")
            
            users_dict = {u['id']: u for u in users}

            logger.debug("Loading transactions from database...")
            transactions = [t for t in (db.find('transactions') or []) if isinstance(t, dict)]
            logger.info(f"Loaded {len(transactions)} transactions from database")

            logger.debug("Loading deposit orders from database...")
            orders_deposits = [o for o in (db.find('orders') or []) 
                             if isinstance(o, dict) and o.get('type') == 'deposit']
            logger.info(f"Loaded {len(orders_deposits)} deposit orders from database")

            all_transactions = []
            logger.debug("Processing transactions...")
            
            for t in sorted(transactions, key=lambda x: x.get('created_at', ''), reverse=True):
                tx_id = t.get('id', 'N/A')
                user_id = t.get('user_id') or t.get('merchant_id')
                user_email = 'Unknown'
                
                logger.debug(f"Processing transaction {tx_id}, user_id={user_id}")
                
                if user_id is not None:
                    try:
                        user_id_int = int(user_id)
                        tx_user = users_dict.get(user_id_int)
                        
                        if tx_user:
                            user_email = tx_user.get('email', 'Unknown')
                            logger.debug(f"Found user for tx {tx_id}: {user_email}")
                        else:
                            logger.warning(f"User not found for tx {tx_id}, user_id={user_id}")
                    except (ValueError, TypeError) as e:
                        logger.error(f"Invalid user_id in transaction {tx_id}: {user_id} - {str(e)}")
                
                if 'user_email' in t and t['user_email'] != 'Unknown':
                    user_email = t['user_email']

                transaction_type = t.get('type', 'unknown')
                type_display = {
                    'deposit': 'Пополнение',
                    'withdrawal': 'Вывод',
                    'unknown': 'Неизвестно'
                }.get(transaction_type, transaction_type.capitalize())

                all_transactions.append({
                    'id': int(t.get('id', 0)),
                    'user_id': user_id,
                    'user_email': user_email,
                    'type': transaction_type,
                    'type_display': type_display,
                    'amount': float(t.get('amount', 0)),
                    'currency': t.get('currency', 'USD'),
                    'status': t.get('status', 'pending'),
                    'created_at': t.get('created_at', datetime.now().isoformat()),
                    'completed_at': t.get('completed_at', '')
                })

            deposit_requests = []
            for order in orders_deposits:
                trader_id = order.get('trader_id')
                trader = users_dict.get(int(trader_id)) if trader_id else None
                
                details = {}
                if order.get('details_id'):
                    details = db.find_one('details', {'id': int(order['details_id'])}) or {}
                
                deposit_requests.append({
                    'id': order.get('id'),
                    'trader_id': trader_id,
                    'trader_email': trader.get('email') if trader else 'Unknown',
                    'amount': float(order.get('amount', 0)),
                    'method': order.get('method', 'unknown'),
                    'status': order.get('status', 'pending'),
                    'created_at': order.get('created_at', datetime.now().isoformat()),
                    'details': details.get('details', 'Не указаны')
                })

            traders = [u for u in users if u.get('role') == 'trader']
            merchants = [u for u in users if u.get('role') == 'merchant']
            active_users = [u for u in users if u.get('active', True)]

            stats = {
                'total_users': len(users),
                'today_transactions': len([t for t in all_transactions 
                                         if isinstance(t.get('created_at'), str) and
                                         datetime.fromisoformat(t['created_at']).date() == datetime.now().date()]),
                'active_traders': len([u for u in users 
                                     if u.get('role') == 'trader' and u.get('is_active', True)]),
                'avg_processing_time': app.calculate_avg_processing_time(),
                'activity': app.generate_activity_data(),
                'pending_deposits': len([d for d in deposit_requests if d['status'] == 'pending']),
                'total_traders': len(traders),
                'total_merchants': len(merchants)
            }

            return render_template(
                'admin.html',
                current_user=current_admin,
                user=current_admin,
                stats=stats,
                recent_transactions=all_transactions[:5],
                users=users,
                all_transactions=all_transactions,
                pending_transactions=[t for t in all_transactions if t['status'] == 'pending'],
                completed_transactions=[t for t in all_transactions if t['status'] == 'completed'],
                active_users=active_users,
                deposit_requests=deposit_requests,
                traders=traders,
                merchants=merchants
            )
            
        except Exception as e:
            logger.error(f"Error in admin dashboard: {str(e)}", exc_info=True)
            return render_template(
                'admin.html',
                current_user=None,
                user=None,
                stats={
                    'total_users': 0,
                    'today_transactions': 0,
                    'active_traders': 0,
                    'avg_processing_time': 0,
                    'activity': {'labels': [], 'values': []},
                    'pending_deposits': 0,
                    'total_traders': 0,
                    'total_merchants': 0
                },
                recent_transactions=[],
                users=[],
                all_transactions=[],
                pending_transactions=[],
                completed_transactions=[],
                active_users=[],
                deposit_requests=[],
                traders=[],
                merchants=[]
            )

    @app.route('/admin/users/create', methods=['GET', 'POST'])
    @app.role_required('admin')
    @app.log_request
    @app.log_response
    def admin_create_user():
        current_user = app.get_current_user()
        if not current_user:
            return redirect(url_for('login'))
            
        if request.method == 'GET':
            return render_template('admin_create_user.html', 
                               current_user=current_user,
                               user=current_user,
                               stats=None)
        
        try:
            data = request.form
            new_user = {
                'id': int(uuid.uuid4().int & (1<<31)-1),
                'email': data['email'],
                'password_hash': generate_password_hash(data['password']),
                'role': data['role'],
                'active': True,
                'created_at': datetime.now().isoformat(),
                'updated_at': datetime.now().isoformat()
            }
            
            existing_user = db.find_one('users', {'email': data['email']})
            if existing_user:
                return render_template('admin_create_user.html',
                                   current_user=current_user,
                                   user=current_user,
                                   error="Пользователь с таким email уже существует")
            
            db.insert_one('users', new_user)
            logger.info(f"Создан новый пользователь: {new_user['email']}")
            return redirect(url_for('admin_dashboard'))
        
        except Exception as e:
            logger.error(f"Ошибка при создании пользователя: {str(e)}")
            return render_template('admin_create_user.html',
                               current_user=current_user,
                               user=current_user,
                               error=str(e))

    @app.route('/admin/users/<user_id>', methods=['GET', 'POST'])
    @app.role_required('admin')
    @app.log_request
    @app.log_response
    def admin_edit_user(user_id):
        try:
            current_user = app.get_current_user()
            if not current_user:
                return redirect(url_for('login'))
                
            user_id_int = int(user_id)
            user = db.find_one('users', {'id': user_id_int})
            
            if not user:
                return render_template('404.html'), 404
            
            if request.method == 'POST':
                data = request.form
                updates = {
                    'email': data.get('email'),
                    'role': data.get('role'),
                    'active': 'active' in request.form,
                    'updated_at': datetime.now().isoformat()
                }
                
                if data.get('password'):
                    updates['password_hash'] = generate_password_hash(data['password'])
                
                db.update_one('users', {'id': user_id_int}, updates)
                db.save()
                
                return redirect(url_for('admin_dashboard'))
            
            return render_template('admin_edit_user.html', 
                               current_user=current_user,
                               user=user)
        
        except Exception as e:
            logger.error(f"Error in admin_edit_user: {str(e)}")
            return render_template('admin_edit_user.html',
                               current_user=app.get_current_user(),
                               user=app.get_current_user(),
                               error=str(e))

    @app.route('/debug/deposits')
    @app.role_required('admin')
    def debug_deposits():
        all_transactions = db.find('transactions') or []
        deposit_transactions = [
            t for t in all_transactions 
            if isinstance(t, dict) and t.get('type') == 'deposit'
        ]
        return jsonify({
            'all_transactions_count': len(all_transactions),
            'deposit_transactions': deposit_transactions,
            'pending_deposits': [
                t for t in deposit_transactions 
                if t.get('status') == 'pending'
            ]
        })

    @app.route('/admin/deposits')
    @app.role_required('admin')
    def admin_deposits():
        try:
            current_user = app.get_current_user()
            if not current_user:
                return redirect(url_for('login'))
                
            processed_deposits = []
            
            orders_deposits = [
                o for o in db.find('orders') or []
                if isinstance(o, dict) and o.get('type') == 'deposit'
            ]
            
            users = {u['id']: u for u in db.find('users') or []}
            
            for order in orders_deposits:
                trader_id = order.get('trader_id')
                trader = users.get(int(trader_id)) if trader_id else None
                
                processed_deposits.append({
                    'source': 'order',
                    'id': order.get('id'),
                    'user_id': trader_id,
                    'user_email': trader.get('email') if trader else 'Unknown',
                    'amount': float(order.get('amount', 0)),
                    'currency': 'RUB',
                    'method': order.get('method', 'unknown'),
                    'status': order.get('status', 'pending'),
                    'created_at': order.get('created_at'),
                    'requisites': {}
                })
            
            pending = [d for d in processed_deposits if d['status'] == 'pending']
            completed = [d for d in processed_deposits if d['status'] == 'completed']
            rejected = [d for d in processed_deposits if d['status'] == 'rejected']
            
            return render_template(
                'admin_deposits.html',
                current_user=current_user,
                user=current_user,
                pending_deposits=sorted(pending, key=lambda x: x['created_at'], reverse=True),
                completed_deposits=sorted(completed, key=lambda x: x.get('completed_at', '')),
                rejected_deposits=sorted(rejected, key=lambda x: x.get('rejected_at', '')))
                
        except Exception as e:
            logger.error(f"Error in admin_deposits: {str(e)}")
            return render_template('admin_deposits.html',
                                current_user=app.get_current_user(),
                                user=app.get_current_user(),
                                pending_deposits=[],
                                completed_deposits=[],
                                rejected_deposits=[])

    @app.route('/admin/withdrawals')
    @app.role_required('admin')
    @app.log_request
    @app.log_response
    def admin_withdrawals():
        user = app.get_current_user()
        
        withdrawals = [t for t in (db.find('transactions', {'type': 'withdrawal'}) or []) if isinstance(t, dict)]
        
        pending_withdrawals = [w for w in withdrawals if w.get('status') == 'pending']
        completed_withdrawals = [w for w in withdrawals if w.get('status') == 'completed']
        rejected_withdrawals = [w for w in withdrawals if w.get('status') == 'rejected']
        
        return render_template(
            'admin_withdrawals.html',
            current_user=user,
            pending_withdrawals=sorted(pending_withdrawals, key=lambda x: x.get('created_at', '')), 
            completed_withdrawals=sorted(completed_withdrawals, key=lambda x: x.get('completed_at', '')), 
            rejected_withdrawals=sorted(rejected_withdrawals, key=lambda x: x.get('rejected_at', '')))

    @app.route('/api/admin/deposits/<int:deposit_id>/complete', methods=['POST'])
    @app.role_required('admin')
    def api_complete_deposit(deposit_id):
        try:
            order = db.find_one('orders', {'id': deposit_id})
            if not order:
                return jsonify({'error': 'Order not found'}), 404
                
            db.update_one('orders', {'id': deposit_id}, {
                'status': 'completed',
                'completed_at': datetime.now().isoformat()
            })
            
            trader = db.find_one('users', {'id': int(order['trader_id'])})
            new_tx = {
                'id': int(uuid.uuid4().int & (1<<31)-1),
                'user_id': order['trader_id'],
                'user_email': trader.get('email') if trader else 'Unknown',
                'type': 'deposit',
                'amount': order['amount'],
                'currency': 'RUB',
                'method': order['method'],
                'status': 'completed',
                'created_at': order['created_at'],
                'completed_at': datetime.now().isoformat(),
                'source': 'order'
            }
            db.insert_one('transactions', new_tx)
            
            return jsonify({'success': True})
        
        except Exception as e:
            logger.error(f"Ошибка подтверждения депозита: {str(e)}")
            return jsonify({'error': str(e)}), 500

    @app.route('/api/admin/withdrawals/<int:withdrawal_id>/complete', methods=['POST'])
    @app.role_required('admin')
    @app.csrf_protect
    def api_complete_withdrawal(withdrawal_id):
        try:
            withdrawal = db.find_one('transactions', {
                'id': withdrawal_id,
                'type': 'withdrawal',
                'status': 'pending'
            })
            
            if not withdrawal:
                return jsonify({'error': 'Withdrawal not found'}), 404
                
            updates = {
                'status': 'completed',
                'completed_at': datetime.now().isoformat(),
                'completed_by': session['user_id']
            }
            db.update_one('transactions', {'id': withdrawal_id}, updates)
            
            return jsonify({'success': True})
        
        except Exception as e:
            logger.error(f"Ошибка подтверждения вывода: {str(e)}")
            return jsonify({'error': str(e)}), 500

    @app.route('/api/admin/withdrawals/<int:withdrawal_id>/reject', methods=['POST'])
    @app.role_required('admin')
    @app.csrf_protect
    def api_reject_withdrawal(withdrawal_id):
        try:
            withdrawal = db.find_one('transactions', {
                'id': withdrawal_id,
                'type': 'withdrawal',
                'status': 'pending'
            })
            
            if not withdrawal:
                return jsonify({'error': 'Withdrawal not found'}), 404
                
            updates = {
                'status': 'rejected',
                'rejected_at': datetime.now().isoformat(),
                'rejected_by': session['user_id']
            }
            db.update_one('transactions', {'id': withdrawal_id}, updates)
            
            return jsonify({'success': True})
        
        except Exception as e:
            logger.error(f"Ошибка отклонения вывода: {str(e)}")
            return jsonify({'error': str(e)}), 500

    @app.route('/admin/users/<user_id>/transactions')
    @app.role_required('admin')
    @app.log_request
    @app.log_response
    def admin_view_user_transactions(user_id):
        try:
            user = db.find_one('users', {'id': int(user_id)})
            if not user:
                return render_template('404.html'), 404
            
            transactions = db.find('transactions', {'user_id': int(user_id)})
            transactions = sorted(transactions, key=lambda x: x.get('created_at', ''), reverse=True)
            
            return render_template(
                'admin_user_transactions.html',
                current_user=app.get_current_user(),
                user=user,
                transactions=transactions
            )
        except Exception as e:
            logger.error(f"Error viewing user transactions: {str(e)}")
            return render_template('500.html'), 500

    @app.route('/admin/users/<user_id>/requisites')
    @app.role_required('admin')
    @app.log_request
    @app.log_response
    def admin_view_user_requisites(user_id):
        try:
            user = db.find_one('users', {'id': int(user_id)})
            if not user:
                return render_template('404.html'), 404
            
            requisites = []
            if user.get('role') == 'trader':
                requisites = db.find('details', {'trader_id': int(user_id)})
                requisites = sorted(requisites, key=lambda x: x.get('created_at', ''), reverse=True)
            
            return render_template(
                'admin_user_requisites.html',
                current_user=app.get_current_user(),
                user=user,
                requisites=requisites
            )
        except Exception as e:
            logger.error(f"Error viewing user requisites: {str(e)}")
            return render_template('500.html'), 500

    @app.route('/admin/requisites/<requisite_id>/approve', methods=['POST'])
    @app.role_required('admin')
    @app.csrf_protect
    @app.log_request
    @app.log_response
    def admin_approve_requisite(requisite_id):
        try:
            requisite = db.find_one('details', {'id': int(requisite_id)})
            if not requisite:
                return redirect(url_for('admin_dashboard'))
            
            db.update_one('details', {'id': int(requisite_id)}, {
                'status': 'active',
                'approved_at': datetime.now().isoformat(),
                'approved_by': int(app.get_current_user()['id'])
            })
            
            return redirect(url_for('admin_view_user_requisites', user_id=requisite['trader_id']))
        except Exception as e:
            logger.error(f"Error approving requisite: {str(e)}")
            return render_template('500.html'), 500

    @app.route('/admin/transactions/create', methods=['POST'])
    @app.role_required('admin')
    def admin_create_transaction():
        try:
            data = request.form
            user = db.find_one('users', {'id': int(data['user_id'])})
            
            new_tx = {
                'id': int(uuid.uuid4().int & (1<<31)-1),
                'user_id': user['id'],
                'type': data['type'],
                'amount': float(data['amount']),
                'currency': data['currency'],
                'status': 'completed',
                'created_at': datetime.now().isoformat(),
                'completed_at': datetime.now().isoformat()
            }
            
            if data['type'] == 'deposit':
                new_balance = float(user.get('balance', 0)) + float(data['amount'])
            else:
                new_balance = float(user.get('balance', 0)) - float(data['amount'])
            
            db.update_one('users', {'id': user['id']}, {'balance': new_balance})
            db.insert_one('transactions', new_tx)
            
            return redirect(url_for('admin_dashboard'))
            
        except Exception as e:
            logger.error(f"Error creating transaction: {str(e)}")
            return render_template('error.html', error=str(e))

    @app.route('/api/transactions/<tx_id>/complete', methods=['POST'])
    @app.role_required('admin')
    @app.csrf_protect
    def complete_transaction_api(tx_id):
        try:
            token = request.form.get('csrf_token')
            if not token or token != session.get('csrf_token'):
                return "Invalid CSRF token", 403

            tx = db.find_one('transactions', {'id': int(tx_id)})
            if not tx:
                return "Transaction not found", 404

            updates = {
                'status': 'completed',
                'completed_at': datetime.now().isoformat(),
                'completed_by': session['user_id']
            }
            
            db.update_one('transactions', {'id': int(tx_id)}, updates)
            return "Transaction completed successfully", 200

        except Exception as e:
            logger.error(f"Error completing transaction: {str(e)}")
            return f"Error: {str(e)}", 500

    @app.route('/api/admin/currency_rates', methods=['POST'])
    @app.role_required('admin')
    @app.csrf_protect
    @app.log_request
    @app.log_response
    def update_currency_rates():
        try:
            data = request.get_json()
            if not data:
                return jsonify({'error': 'No data provided'}), 400
                
            current_rates = db.find_one('system_settings', {'type': 'currency_rates'}) or {
                'type': 'currency_rates',
                'USD': 75.0,
                'EUR': 85.0,
                'USDT': 1.0
            }
            
            updates = {
                'USD': float(data.get('USD', current_rates.get('USD', 75.0))),
                'EUR': float(data.get('EUR', current_rates.get('EUR', 85.0))),
                'USDT': float(data.get('USDT', current_rates.get('USDT', 1.0))),
                'updated_at': datetime.now().isoformat()
            }
            
            db.update_one('system_settings', {'type': 'currency_rates'}, updates)
            return jsonify({'success': True, 'rates': updates})
        except Exception as e:
            return jsonify({'error': str(e)}), 400

    @app.route('/api/admin/commissions', methods=['POST'])
    @app.role_required('admin')
    @app.csrf_protect
    @app.log_request
    @app.log_response
    def update_commissions():
        try:
            data = request.get_json()
            if not data:
                return jsonify({'error': 'No data provided'}), 400
                
            current = db.find_one('system_settings', {'type': 'commissions'}) or {
                'type': 'commissions',
                'default': 0.02,
                'per_merchant': {},
                'updated_at': datetime.now().isoformat()
            }
            
            updates = {
                'default': float(data.get('default', current.get('default', 0.02))),
                'per_merchant': data.get('per_merchant', current.get('per_merchant', {})),
                'updated_at': datetime.now().isoformat()
            }
            
            db.update_one('system_settings', {'type': 'commissions'}, updates)
            return jsonify({'success': True, 'commissions': updates})
        except Exception as e:
            return jsonify({'error': str(e)}), 400

    @app.route('/api/transactions/<tx_id>/requisites', methods=['POST'])
    @app.login_required
    @app.csrf_protect
    @app.log_request
    @app.log_response
    def add_transaction_requisites_adm(tx_id):
        try:
            data = request.get_json()
            tx = db.find_one('transactions', {'id': int(tx_id)})
            
            if not tx:
                return jsonify({'error': 'Transaction not found'}), 404
            
            requisites = {
                'type_id': data['type_id'],
                'details': data['details'],
                'status': 'pending',
                'added_at': datetime.now().isoformat()
            }
            
            db.update_one('transactions', {'id': int(tx_id)}, {
                'requisites': requisites,
                'requisites_approved': False
            })
            
            return jsonify({'success': True})
        except Exception as e:
            return jsonify({'error': str(e)}), 400

    @app.route('/api/admin/requisites/<tx_id>/approve', methods=['POST'])
    @app.role_required('admin')
    @app.csrf_protect
    @app.log_request
    @app.log_response
    def approve_requisites(tx_id):
        try:
            db.update_one('transactions', {'id': int(tx_id)}, {
                'requisites_approved': True,
                'requisites.status': 'approved'
            })
            return jsonify({'success': True})
        except Exception as e:
            return jsonify({'error': str(e)}), 400

    @app.route('/api/admin/pending-trader-deposits')
    @app.role_required('admin')
    def get_pending_trader_deposits():
        try:
            pending_orders = [
                o for o in (db.find('orders') or [])
                if isinstance(o, dict) and 
                   o.get('type') == 'deposit' and 
                   o.get('status') == 'pending'
            ]
            
            traders = {u['id']: u for u in (db.find('users') or []) 
                      if isinstance(u, dict) and u.get('role') == ['trader']}
            
            details = {d['id']: d for d in (db.find('details') or []) if isinstance(d, dict)}
            
            result = []
            for order in pending_orders:
                trader = traders.get(int(order.get('trader_id', 0)))
                detail = details.get(int(order.get('details_id', 0))) if order.get('details_id') else None
                
                result.append({
                    'id': order.get('id'),
                    'trader_id': order.get('trader_id'),
                    'trader_email': trader.get('email') if trader else 'Unknown',
                    'amount': float(order.get('amount', 0)),
                    'method': order.get('method', 'unknown'),
                    'details_id': order.get('details_id'),
                    'details': detail.get('details') if detail else 'Не указаны',
                    'created_at': order.get('created_at', datetime.now().isoformat())
                })
            
            return jsonify(result)
        
        except Exception as e:
            logger.error(f"Error loading trader deposits: {str(e)}")
            return jsonify({'error': str(e)}), 500

    @app.route('/api/admin/trader-deposits/<int:deposit_id>/complete', methods=['POST'])
    @app.role_required('admin')
    def complete_trader_deposit(deposit_id):
        try:
            deposit = db.find_one('orders', {'id': deposit_id, 'type': 'deposit'})
            if not deposit:
                return jsonify({'error': 'Deposit not found'}), 404
                
            trader = db.find_one('users', {'id': int(deposit['trader_id'])})
            if not trader:
                return jsonify({'error': 'Trader not found'}), 404
                
            db.update_one('orders', {'id': deposit_id}, {
                'status': 'completed',
                'completed_at': datetime.now().isoformat()
            })
            
            current_balance = float(trader.get('balance', 0))
            deposit_amount = float(deposit['amount'])
            new_balance = current_balance + deposit_amount
            
            db.update_one('users', {'id': trader['id']}, {
                'balance': new_balance,
                'updated_at': datetime.now().isoformat()
            })
            
            transaction = {
                'id': int(uuid.uuid4().int & (1<<31)-1),
                'user_id': trader['id'],
                'user_email': trader['email'],
                'type': 'deposit',
                'amount': deposit_amount,
                'method': deposit['method'],
                'status': 'completed',
                'created_at': deposit['created_at'],
                'completed_at': datetime.now().isoformat(),
                'source': 'trader_order',
                'new_balance': new_balance
            }
            db.insert_one('transactions', transaction)
            
            return jsonify({
                'success': True, 
                'new_balance': new_balance,
                'message': f'Баланс трейдера успешно обновлен. Новый баланс: {new_balance:.2f}'
            })
        
        except Exception as e:
            logger.error(f"Error completing trader deposit: {str(e)}")
            return jsonify({'error': str(e)}), 500

    @app.route('/api/admin/trader-deposits/<int:deposit_id>/reject', methods=['POST'])
    @app.role_required('admin')
    def reject_trader_deposit(deposit_id):
        try:
            deposit = db.find_one('orders', {'id': deposit_id, 'type': 'deposit'})
            if not deposit:
                return jsonify({'error': 'Deposit not found'}), 404
                
            db.update_one('orders', {'id': deposit_id}, {
                'status': 'rejected',
                'rejected_at': datetime.now().isoformat(),
                'rejected_by': int(app.get_current_user()['id'])
            })
            
            return jsonify({'success': True})
        
        except Exception as e:
            logger.error(f"Error rejecting trader deposit: {str(e)}")
            return jsonify({'error': str(e)}), 500

    @app.route('/api/admin/pending-deposits')
    @app.role_required('admin')
    def get_pending_deposits():
        try:
            deposits = []
            pending_orders = db.find('orders', {'type': 'deposit', 'status': 'pending'}) or []
            
            for order in pending_orders:
                if not isinstance(order, dict):
                    continue
                    
                trader = db.find_one('users', {'id': int(order.get('trader_id', 0))})
                deposits.append({
                    'id': order.get('id', 'N/A'),
                    'user_email': trader.get('email') if trader else 'Unknown',
                    'amount': float(order.get('amount', 0)),
                    'currency': 'RUB',
                    'method': order.get('method', 'unknown'),
                    'created_at': order.get('created_at', datetime.now().isoformat())
                })

            return jsonify(deposits)

        except Exception as e:
            logger.error(f"Error loading deposits: {str(e)}")
            return jsonify({'error': str(e)}), 500

    @app.route('/admin/balance')
    @app.role_required('admin')
    def platform_balance():
        try:
            users = db.find('users', {})
            
            total_balance = sum(user.get('balance', 0) for user in users)
            available_balance = total_balance * 0.8
            
            distribution = [
                {'type': 'Средства пользователей', 'amount': total_balance * 0.7, 'percentage': 70},
                {'type': 'Резерв платформы', 'amount': total_balance * 0.2, 'percentage': 20},
                {'type': 'Доход платформы', 'amount': total_balance * 0.1, 'percentage': 10}
            ]
            
            users_balances = [{
                'id': user.get('id'),
                'email': user.get('email'),
                'role': user.get('role'),
                'balance': user.get('balance', 0),
                'is_active': user.get('is_active', True)
            } for user in users]
            
            return render_template('admin_balance.html',
                total_balance=total_balance,
                available_balance=available_balance,
                distribution=distribution,
                users_balances=users_balances
            )
            
        except Exception as e:
            app.logger.error(f"Ошибка при расчете баланса платформы: {str(e)}")
            return render_template('admin_balance.html',
                total_balance=0,
                available_balance=0,
                distribution=[],
                users_balances=[]
            ), 500

    @app.route('/api/admin/matches')
    @app.role_required('admin')
    @app.log_request
    @app.log_response
    def get_matches():
        try:
            matches = db.find('matches') or []
            return jsonify([m for m in matches if isinstance(m, dict)])
        except Exception as e:
            logger.error(f"Error getting matches: {str(e)}")
            return jsonify({'error': str(e)}), 500

    @app.route('/api/admin/matching/run', methods=['POST'])
    @app.role_required('admin')
    def run_matching():
        try:
            logger.info("Starting matching process")
            
            pending_deposits = [
                tx for tx in db.find('transactions') or []
                if isinstance(tx, dict) and tx.get('type') == 'deposit' and tx.get('status') == 'pending'
            ]
            pending_withdrawals = [
                tx for tx in db.find('transactions') or []
                if isinstance(tx, dict) and tx.get('type') == 'withdrawal' and tx.get('status') == 'pending'
            ]
            
            logger.info(f"Pending deposits: {len(pending_deposits)}")
            logger.info(f"Pending withdrawals: {len(pending_withdrawals)}")
            
            matched_pairs = []
            
            # Простой алгоритм матчинга - сортируем по сумме и пытаемся сопоставить
            pending_deposits.sort(key=lambda x: float(x.get('amount', 0)))
            pending_withdrawals.sort(key=lambda x: float(x.get('amount', 0)))
            
            for deposit in pending_deposits:
                for withdrawal in pending_withdrawals:
                    if float(deposit.get('amount', 0)) == float(withdrawal.get('amount', 0)):
                        match_id = int(uuid.uuid4().int & (1<<31)-1)
                        matched_pairs.append({
                            'id': match_id,
                            'deposit_ids': [deposit['id']],
                            'withdrawal_id': withdrawal['id'],
                            'amount': float(deposit.get('amount', 0)),
                            'currency': deposit.get('currency', 'RUB'),
                            'status': 'pending',
                            'created_at': datetime.now().isoformat()
                        })
                        
                        # Добавляем матч в базу данных
                        db.insert_one('matches', matched_pairs[-1])
                        
                        # Удаляем сопоставленные транзакции из списков
                        pending_withdrawals.remove(withdrawal)
                        break
            
            logger.info(f"Matching completed. Found {len(matched_pairs)} pairs")
            
            return jsonify({
                'success': True,
                'matches_count': len(matched_pairs),
                'matches': matched_pairs
            })
        except Exception as e:
            logger.error(f"Error running matching: {str(e)}", exc_info=True)
            return jsonify({'error': str(e)}), 500

    @app.route('/api/admin/transactions/pending', methods=['GET'])
    @app.role_required('admin')
    def get_pending_transactions():
        try:
            deposits = [
                tx for tx in (db.find('transactions', {'type': 'deposit', 'status': 'pending'}) or [])
                if isinstance(tx, dict) and tx.get('requisites_approved')
            ]
            
            withdrawals = [
                tx for tx in (db.find('transactions', {'type': 'withdrawal', 'status': 'pending'}) or [])
                if isinstance(tx, dict) and tx.get('requisites_approved')
            ]
            
            return jsonify({
                'deposits': deposits,
                'withdrawals': withdrawals
            })
        except Exception as e:
            return jsonify({'error': str(e)}), 500

    @app.route('/api/admin/matching/transactions', methods=['GET'])
    @app.role_required('admin')
    def get_matching_transactions():
        try:
            all_transactions = db.find('transactions') or []
            
            pending_deposits = [
                tx for tx in all_transactions 
                if isinstance(tx, dict) and 
                   tx.get('type') == 'deposit' and 
                   tx.get('status') == 'pending' and 
                   tx.get('merchant_id') is not None
            ]
            
            pending_withdrawals = [
                tx for tx in all_transactions 
                if isinstance(tx, dict) and 
                   tx.get('type') == 'withdrawal' and 
                   tx.get('status') == 'pending' and 
                   tx.get('merchant_id') is not None
            ]
            
            for tx in pending_deposits + pending_withdrawals:
                merchant = db.find_one('users', {'id': tx.get('merchant_id')})
                if merchant:
                    tx['merchant_email'] = merchant.get('email')
            
            return jsonify({
                'deposits': pending_deposits,
                'withdrawals': pending_withdrawals
            })
        except Exception as e:
            logger.error(f"Error getting matching transactions: {str(e)}")
            return jsonify({'error': str(e)}), 500

    @app.route('/api/admin/transactions/<tx_id>/approve-requisites', methods=['POST'])
    @app.role_required('admin')
    @app.csrf_protect
    def approve_transaction_requisites(tx_id):
        try:
            db.update_one('transactions', {'id': int(tx_id)}, {
                'requisites_approved': True,
                'updated_at': datetime.now().isoformat()
            })
            return jsonify({'success': True})
        except Exception as e:
            return jsonify({'error': str(e)}), 500

    @app.route('/api/admin/matches/<match_id>/confirm', methods=['POST'])
    @app.role_required('admin')
    def confirm_match(match_id):
        try:
            match = db.find_one('matches', {'id': match_id})
            if not match:
                return jsonify({'error': 'Match not found'}), 404
            
            db.update_one('matches', {'id': match_id}, {'status': 'completed'})
            
            for deposit_id in match['deposit_ids']:
                db.update_one('transactions', {'id': deposit_id}, {
                    'status': 'completed',
                    'completed_at': datetime.now().isoformat()
                })
            
            db.update_one('transactions', {'id': match['withdrawal_id']}, {
                'status': 'completed',
                'completed_at': datetime.now().isoformat()
            })
            
            return jsonify({'success': True})
            
        except Exception as e:
            return jsonify({'error': str(e)}), 500

    @app.route('/api/admin/settings')
    @app.role_required('admin')
    @app.log_request
    @app.log_response
    def get_settings():
        try:
            settings = db.find_one('system_settings', {'type': 'platform_settings'}) or {
                'type': 'platform_settings',
                'usd_rate': 75.0,
                'eur_rate': 85.0,
                'usdt_rate': 1.0,
                'default_fee': 2.0,
                'trader_fee': 1.5,
                'updated_at': datetime.now().isoformat()
            }
            return jsonify(settings)
        except Exception as e:
            return jsonify({'error': str(e)}), 500

    @app.route('/api/admin/settings', methods=['POST'])
    @app.role_required('admin')
    @app.log_request
    @app.log_response
    def update_settings():
        try:
            data = request.get_json()
            if not data:
                return jsonify({'error': 'No data provided'}), 400
                
            current_settings = db.find_one('system_settings', {'type': 'platform_settings'}) or {
                'type': 'platform_settings',
                'usd_rate': 75.0,
                'eur_rate': 85.0,
                'usdt_rate': 1.0,
                'default_fee': 2.0,
                'trader_fee': 1.5
            }
            
            updates = {
                'usd_rate': float(data.get('usd_rate', current_settings.get('usd_rate', 75.0))),
                'eur_rate': float(data.get('eur_rate', current_settings.get('eur_rate', 85.0))),
                'usdt_rate': float(data.get('usdt_rate', current_settings.get('usdt_rate', 1.0))),
                'default_fee': float(data.get('default_fee', current_settings.get('default_fee', 2.0))),
                'trader_fee': float(data.get('trader_fee', current_settings.get('trader_fee', 1.5))),
                'updated_at': datetime.now().isoformat()
            }
            
            db.update_one('system_settings', {'type': 'platform_settings'}, updates)
            return jsonify({'success': True, 'settings': updates})
        except Exception as e:
            return jsonify({'error': str(e)}), 400

    @app.route('/api/admin/pending-trader-withdrawals')
    @app.role_required('admin')
    def get_pending_trader_withdrawals():
        try:
            pending_withdrawals = [
                o for o in (db.find('orders') or [])
                if isinstance(o, dict) and 
                   o.get('type') == 'withdrawal' and 
                   o.get('status') == 'pending'
            ]
            
            traders = {u['id']: u for u in (db.find('users') or []) 
                      if isinstance(u, dict) and u.get('role') == ['trader']}
            
            details = {d['id']: d for d in (db.find('details') or []) if isinstance(d, dict)}
            
            result = []
            for withdrawal in pending_withdrawals:
                trader = traders.get(int(withdrawal.get('trader_id', 0)))
                detail = details.get(int(withdrawal.get('details_id', 0))) if withdrawal.get('details_id') else None
                
                result.append({
                    'id': withdrawal.get('id'),
                    'trader_id': withdrawal.get('trader_id'),
                    'trader_email': trader.get('email') if trader else 'Unknown',
                    'amount': float(withdrawal.get('amount', 0)),
                    'method': withdrawal.get('method', 'unknown'),
                    'details_id': withdrawal.get('details_id'),
                    'details': detail.get('details') if detail else 'Не указаны',
                    'created_at': withdrawal.get('created_at', datetime.now().isoformat())
                })
            
            return jsonify(result)
        
        except Exception as e:
            logger.error(f"Error loading trader withdrawals: {str(e)}")
            return jsonify({'error': str(e)}), 500

    @app.route('/api/admin/trader-withdrawals/<int:withdrawal_id>/complete', methods=['POST'])
    @app.role_required('admin')
    def complete_trader_withdrawal(withdrawal_id):
        try:
            withdrawal = db.find_one('orders', {'id': withdrawal_id, 'type': 'withdrawal'})
            if not withdrawal:
                return jsonify({'error': 'Withdrawal not found'}), 404
                
            trader = db.find_one('users', {'id': int(withdrawal['trader_id'])})
            if not trader:
                return jsonify({'error': 'Trader not found'}), 404
                
            current_balance = float(trader.get('balance', 0))
            withdrawal_amount = float(withdrawal['amount'])
            
            if current_balance < withdrawal_amount:
                return jsonify({
                    'error': 'Недостаточно средств',
                    'current_balance': current_balance,
                    'withdrawal_amount': withdrawal_amount
                }), 400
                
            db.update_one('orders', {'id': withdrawal_id}, {
                'status': 'completed',
                'completed_at': datetime.now().isoformat()
            })
            
            new_balance = current_balance - withdrawal_amount
            
            db.update_one('users', {'id': trader['id']}, {
                'balance': new_balance,
                'updated_at': datetime.now().isoformat()
            })
            
            transaction = {
                'id': int(uuid.uuid4().int & (1<<31)-1),
                'user_id': trader['id'],
                'user_email': trader['email'],
                'type': 'withdrawal',
                'amount': withdrawal_amount,
                'method': withdrawal['method'],
                'status': 'completed',
                'created_at': withdrawal['created_at'],
                'completed_at': datetime.now().isoformat(),
                'source': 'trader_order',
                'new_balance': new_balance
            }
            db.insert_one('transactions', transaction)
            
            return jsonify({
                'success': True, 
                'new_balance': new_balance,
                'message': f'Вывод успешно завершен. Новый баланс: {new_balance:.2f}'
            })
        
        except Exception as e:
            logger.error(f"Error completing trader withdrawal: {str(e)}")
            return jsonify({'error': str(e)}), 500

    @app.route('/api/admin/trader-withdrawals/<int:withdrawal_id>/reject', methods=['POST'])
    @app.role_required('admin')
    def reject_trader_withdrawal(withdrawal_id):
        try:
            withdrawal = db.find_one('orders', {'id': withdrawal_id, 'type': 'withdrawal'})
            if not withdrawal:
                return jsonify({'error': 'Withdrawal not found'}), 404
                
            db.update_one('orders', {'id': withdrawal_id}, {
                'status': 'rejected',
                'rejected_at': datetime.now().isoformat(),
                'rejected_by': int(app.get_current_user()['id'])
            }) 
            
            return jsonify({'success': True})
        
        except Exception as e:
            logger.error(f"Error rejecting trader withdrawal: {str(e)}")
            return jsonify({'error': str(e)}), 500

    return app
