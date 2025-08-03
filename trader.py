from datetime import datetime, timedelta
from flask import jsonify, render_template, request, redirect, url_for, session
from werkzeug.security import generate_password_hash
import logging
from functools import wraps

def admin_routes(app, db, logger):
    # ============
    # Вспомогательные функции
    # ============

    def get_user_transactions(user_id):
        """Получает транзакции пользователя с дополнительной информацией"""
        transactions = db.find('transactions', {'user_id': user_id}) or []
        users = {u['id']: u for u in db.find('users')}
        
        result = []
        for tx in transactions:
            user = users.get(tx.get('user_id'))
            result.append({
                'id': tx.get('id'),
                'type': tx.get('type'),
                'amount': float(tx.get('amount', 0)),
                'currency': tx.get('currency', 'RUB'),
                'status': tx.get('status'),
                'created_at': tx.get('created_at'),
                'completed_at': tx.get('completed_at'),
                'user_email': user.get('email') if user else 'Unknown'
            })
        return sorted(result, key=lambda x: x['created_at'], reverse=True)

    # ============
    # Маршруты администратора
    # ============

    @app.route('/admin.html')
    @app.role_required('admin')
    def admin_dashboard():
        try:
            current_admin = app.get_current_user()
            if not current_admin:
                return redirect(url_for('login'))

            users = db.find('users') or []
            users_dict = {u['id']: u for u in users}

            transactions = db.find('transactions') or []
            
            all_transactions = []
            for tx in sorted(transactions, key=lambda x: x.get('created_at', ''), reverse=True):
                user_id = tx.get('user_id') or tx.get('merchant_id')
                user_email = users_dict.get(int(user_id), {}).get('email', 'Unknown') if user_id else 'Unknown'
                
                all_transactions.append({
                    'id': tx.get('id'),
                    'user_id': user_id,
                    'user_email': user_email,
                    'type': tx.get('type'),
                    'amount': float(tx.get('amount', 0)),
                    'currency': tx.get('currency', 'RUB'),
                    'status': tx.get('status'),
                    'created_at': tx.get('created_at'),
                    'completed_at': tx.get('completed_at')
                })

            today = datetime.now().date()
            today_transactions = [
                tx for tx in all_transactions 
                if datetime.fromisoformat(tx['created_at']).date() == today
            ]

            stats = {
                'total_users': len(users),
                'today_transactions': len(today_transactions),
                'active_traders': len([u for u in users if u.get('role') == 'trader' and u.get('is_active', True)]),
                'avg_processing_time': app.calculate_avg_processing_time(),
                'activity': app.generate_activity_data(),
                'pending_deposits': len([tx for tx in all_transactions if tx['type'] == 'deposit' and tx['status'] == 'pending']),
                'total_traders': len([u for u in users if u.get('role') == 'trader']),
                'total_merchants': len([u for u in users if u.get('role') == 'merchant'])
            }

            return render_template(
                'admin.html',
                current_user=current_admin,
                user=current_admin,
                stats=stats,
                recent_transactions=all_transactions[:5],
                users=users,
                all_transactions=all_transactions,
                pending_transactions=[tx for tx in all_transactions if tx['status'] == 'pending'],
                completed_transactions=[tx for tx in all_transactions if tx['status'] == 'completed'],
                active_users=[u for u in users if u.get('is_active', True)],
                traders=[u for u in users if u.get('role') == 'trader'],
                merchants=[u for u in users if u.get('role') == 'merchant']
            )
            
        except Exception as e:
            logger.error(f"Error in admin dashboard: {str(e)}", exc_info=True)
            return render_template('error.html', error="Ошибка загрузки данных"), 500

    @app.route('/admin/users/create', methods=['GET', 'POST'])
    @app.role_required('admin')
    def admin_create_user():
        current_user = app.get_current_user()
        if not current_user:
            return redirect(url_for('login'))
            
        if request.method == 'GET':
            return render_template('admin_create_user.html', 
                               current_user=current_user,
                               user=current_user)
        
        try:
            data = request.form
            existing_user = db.find_one('users', {'email': data['email']})
            if existing_user:
                return render_template('admin_create_user.html',
                                   current_user=current_user,
                                   user=current_user,
                                   error="Пользователь с таким email уже существует")
            
            new_user = {
                'email': data['email'],
                'password_hash': generate_password_hash(data['password']),
                'role': data['role'],
                'is_active': True,
                'created_at': datetime.now().isoformat(),
                'updated_at': datetime.now().isoformat()
            }
            
            db.insert_one('users', new_user)
            logger.info(f"Created new user: {new_user['email']}")
            return redirect(url_for('admin_dashboard'))
        
        except Exception as e:
            logger.error(f"Error creating user: {str(e)}")
            return render_template('admin_create_user.html',
                               current_user=current_user,
                               user=current_user,
                               error=str(e))

    @app.route('/admin/users/<int:user_id>', methods=['GET', 'POST'])
    @app.role_required('admin')
    def admin_edit_user(user_id):
        try:
            current_user = app.get_current_user()
            if not current_user:
                return redirect(url_for('login'))
                
            user = db.find_one('users', {'id': user_id})
            if not user:
                return render_template('404.html'), 404
            
            if request.method == 'POST':
                data = request.form
                updates = {
                    'email': data.get('email'),
                    'role': data.get('role'),
                    'is_active': 'is_active' in request.form,
                    'updated_at': datetime.now().isoformat()
                }
                
                if data.get('password'):
                    updates['password_hash'] = generate_password_hash(data['password'])
                
                db.update_one('users', {'id': user_id}, updates)
                
                return redirect(url_for('admin_dashboard'))
            
            return render_template('admin_edit_user.html', 
                               current_user=current_user,
                               user=user)
        
        except Exception as e:
            logger.error(f"Error in admin_edit_user: {str(e)}")
            return render_template('admin_edit_user.html',
                               current_user=current_user,
                               user=current_user,
                               error=str(e))

    @app.route('/admin/users/<int:user_id>/transactions')
    @app.role_required('admin')
    def admin_view_user_transactions(user_id):
        try:
            user = db.find_one('users', {'id': user_id})
            if not user:
                return render_template('404.html'), 404
            
            transactions = get_user_transactions(user_id)
            
            return render_template(
                'admin_user_transactions.html',
                current_user=app.get_current_user(),
                user=user,
                transactions=transactions
            )
        except Exception as e:
            logger.error(f"Error viewing user transactions: {str(e)}")
            return render_template('500.html'), 500

    @app.route('/admin/deposits')
    @app.role_required('admin')
    def admin_deposits():
        try:
            current_user = app.get_current_user()
            if not current_user:
                return redirect(url_for('login'))
                
            deposits = [
                tx for tx in db.find('transactions') or []
                if tx.get('type') == 'deposit'
            ]
            
            pending = [d for d in deposits if d.get('status') == 'pending']
            completed = [d for d in deposits if d.get('status') == 'completed']
            rejected = [d for d in deposits if d.get('status') == 'rejected']
            
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
    def admin_withdrawals():
        current_user = app.get_current_user()
        if not current_user:
            return redirect(url_for('login'))
        
        withdrawals = [
            tx for tx in db.find('transactions') or []
            if tx.get('type') == 'withdrawal'
        ]
        
        pending = [w for w in withdrawals if w.get('status') == 'pending']
        completed = [w for w in withdrawals if w.get('status') == 'completed']
        rejected = [w for w in withdrawals if w.get('status') == 'rejected']
        
        return render_template(
            'admin_withdrawals.html',
            current_user=current_user,
            pending_withdrawals=sorted(pending, key=lambda x: x.get('created_at', '')), 
            completed_withdrawals=sorted(completed, key=lambda x: x.get('completed_at', '')), 
            rejected_withdrawals=sorted(rejected, key=lambda x: x.get('rejected_at', '')))

    @app.route('/api/admin/deposits/<int:deposit_id>/complete', methods=['POST'])
    @app.role_required('admin')
    def api_complete_deposit(deposit_id):
        try:
            deposit = db.find_one('transactions', {'id': deposit_id, 'type': 'deposit'})
            if not deposit:
                return jsonify({'error': 'Deposit not found'}), 404
                
            user = db.find_one('users', {'id': deposit['user_id']})
            if not user:
                return jsonify({'error': 'User not found'}), 404
                
            db.update_one('transactions', {'id': deposit_id}, {
                'status': 'completed',
                'completed_at': datetime.now().isoformat()
            })
            
            return jsonify({'success': True})
        
        except Exception as e:
            logger.error(f"Error completing deposit: {str(e)}")
            return jsonify({'error': str(e)}), 500

    @app.route('/api/admin/withdrawals/<int:withdrawal_id>/complete', methods=['POST'])
    @app.role_required('admin')
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
                'completed_at': datetime.now().isoformat()
            }
            db.update_one('transactions', {'id': withdrawal_id}, updates)
            
            return jsonify({'success': True})
        
        except Exception as e:
            logger.error(f"Error completing withdrawal: {str(e)}")
            return jsonify({'error': str(e)}), 500

    @app.route('/api/admin/withdrawals/<int:withdrawal_id>/reject', methods=['POST'])
    @app.role_required('admin')
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
                'rejected_at': datetime.now().isoformat()
            }
            db.update_one('transactions', {'id': withdrawal_id}, updates)
            
            return jsonify({'success': True})
        
        except Exception as e:
            logger.error(f"Error rejecting withdrawal: {str(e)}")
            return jsonify({'error': str(e)}), 500

    @app.route('/api/admin/currency_rates', methods=['POST'])
    @app.role_required('admin')
    def update_currency_rates():
        try:
            data = request.get_json()
            if not data:
                return jsonify({'error': 'No data provided'}), 400
                
            settings = db.get_settings()
            rates = settings.get('exchange_rates', {
                'USD': 75.0,
                'EUR': 85.0,
                'USDT': 1.0,
                'RUB': 1.0
            })
            
            updates = {
                'USD': float(data.get('USD', rates.get('USD', 75.0))),
                'EUR': float(data.get('EUR', rates.get('EUR', 85.0))),
                'USDT': float(data.get('USDT', rates.get('USDT', 1.0))),
                'updated_at': datetime.now().isoformat()
            }
            
            db.update_settings({'exchange_rates': updates})
            return jsonify({'success': True, 'rates': updates})
        except Exception as e:
            return jsonify({'error': str(e)}), 400

    @app.route('/api/admin/commissions', methods=['POST'])
    @app.role_required('admin')
    def update_commissions():
        try:
            data = request.get_json()
            if not data:
                return jsonify({'error': 'No data provided'}), 400
                
            settings = db.get_settings()
            commissions = settings.get('fees', {
                'deposit': 0.01,
                'withdrawal': 0.02
            })
            
            updates = {
                'deposit': float(data.get('deposit', commissions.get('deposit', 0.01))),
                'withdrawal': float(data.get('withdrawal', commissions.get('withdrawal', 0.02))),
                'updated_at': datetime.now().isoformat()
            }
            
            db.update_settings({'fees': updates})
            return jsonify({'success': True, 'commissions': updates})
        except Exception as e:
            return jsonify({'error': str(e)}), 400

    @app.route('/api/admin/matching/run', methods=['POST'])
    @app.role_required('admin')
    def run_matching():
        try:
            logger.info("Starting matching process")
            
            pending_deposits = [
                tx for tx in db.find('transactions') or []
                if tx.get('type') == 'deposit' and tx.get('status') == 'pending'
            ]
            pending_withdrawals = [
                tx for tx in db.find('transactions') or []
                if tx.get('type') == 'withdrawal' and tx.get('status') == 'pending'
            ]
            
            matched_pairs = []
            
            for deposit in pending_deposits:
                for withdrawal in pending_withdrawals:
                    if float(deposit.get('amount', 0)) == float(withdrawal.get('amount', 0)):
                        match = {
                            'deposit_id': deposit['id'],
                            'withdrawal_id': withdrawal['id'],
                            'amount': float(deposit.get('amount', 0)),
                            'currency': deposit.get('currency', 'RUB'),
                            'status': 'matched',
                            'created_at': datetime.now().isoformat()
                        }
                        
                        db.insert_one('matches', match)
                        db.update_one('transactions', {'id': deposit['id']}, {'status': 'matched'})
                        db.update_one('transactions', {'id': withdrawal['id']}, {'status': 'matched'})
                        
                        matched_pairs.append(match)
                        break
            
            logger.info(f"Matching completed. Found {len(matched_pairs)} pairs")
            return jsonify({'success': True, 'matches': matched_pairs})
        except Exception as e:
            logger.error(f"Error running matching: {str(e)}", exc_info=True)
            return jsonify({'error': str(e)}), 500

    @app.route('/api/admin/matches/<match_id>/confirm', methods=['POST'])
    @app.role_required('admin')
    def confirm_match(match_id):
        try:
            match = db.find_one('matches', {'id': match_id})
            if not match:
                return jsonify({'error': 'Match not found'}), 404
            
            db.update_one('matches', {'id': match_id}, {'status': 'completed'})
            
            db.update_one('transactions', {'id': match['deposit_id']}, {
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
    def get_settings():
        try:
            settings = db.get_settings()
            return jsonify(settings)
        except Exception as e:
            return jsonify({'error': str(e)}), 500

    @app.route('/api/admin/settings', methods=['POST'])
    @app.role_required('admin')
    def update_settings():
        try:
            data = request.get_json()
            if not data:
                return jsonify({'error': 'No data provided'}), 400
                
            db.update_settings(data)
            return jsonify({'success': True, 'settings': data})
        except Exception as e:
            return jsonify({'error': str(e)}), 400

    @app.route('/admin/balance')
    @app.role_required('admin')
    def platform_balance():
        try:
            users = db.find('users') or []
            total_balance = sum(float(u.get('balance', 0)) for u in users)
            
            distribution = [
                {'type': 'Средства пользователей', 'amount': total_balance * 0.7, 'percentage': 70},
                {'type': 'Резерв платформы', 'amount': total_balance * 0.2, 'percentage': 20},
                {'type': 'Доход платформы', 'amount': total_balance * 0.1, 'percentage': 10}
            ]
            
            return render_template('admin_balance.html',
                total_balance=total_balance,
                available_balance=total_balance * 0.8,
                distribution=distribution,
                users_balances=[{
                    'id': u.get('id'),
                    'email': u.get('email'),
                    'role': u.get('role'),
                    'balance': float(u.get('balance', 0)),
                    'is_active': u.get('is_active', True)
                } for u in users]
            )
            
        except Exception as e:
            logger.error(f"Error calculating platform balance: {str(e)}")
            return render_template('admin_balance.html',
                total_balance=0,
                available_balance=0,
                distribution=[],
                users_balances=[]
            ), 500

    return app