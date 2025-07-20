from flask import render_template, jsonify, request, session, send_from_directory
from datetime import datetime, timedelta
from flask import jsonify, render_template, request, session, redirect, url_for, send_from_directory
from werkzeug.security import generate_password_hash
import uuid
import os
import logging
from functools import wraps

def merchant_routes(app, db, logger):
    # ===============
    # Панель мерчанта
    # ===============

    @app.route('/merchant.html')
    @app.role_required('merchant')
    def merchant_dashboard():
        user = app.get_current_user()
        merchant_id = int(user['id'])

        requisites_types = db.find_one('requisites_types', {}) or {}
        if requisites_types and 'types' in requisites_types:
            requisites_types = requisites_types['types']
        else:
            requisites_types = []
        
        transactions = [t for t in (db.find('transactions', {'merchant_id': merchant_id})) or [] if isinstance(t, dict)]
        api_keys = [k for k in (db.find('api_keys', {'merchant_id': merchant_id})) or [] if isinstance(k, dict)]
        matches = [m for m in (db.find('matches', {'merchant_id': merchant_id})) or [] if isinstance(m, dict)]
        
        recent_transactions = sorted(
            [t for t in transactions if isinstance(t, dict)],
            key=lambda x: x.get('created_at', ''),
            reverse=True
        )[:5]
        
        stats = {
            'today_transactions': len([t for t in transactions 
                                     if isinstance(t.get('created_at'), str) and
                                     datetime.fromisoformat(t['created_at']).date() == datetime.now().date()]),
            'avg_amount': round(sum(float(t.get('amount', 0)) for t in transactions) / len(transactions), 2) if transactions else 0,
            'conversion_rate': app.calculate_conversion_rate(transactions),
            'weekly_stats': app.calculate_weekly_stats(transactions)
        }
        
        pending_transactions = [t for t in transactions if t.get('status') == 'pending']
        completed_transactions = [t for t in transactions if t.get('status') == 'completed']
        
        pending_matches = [m for m in matches if m.get('status') == 'pending']
        completed_matches = [m for m in matches if m.get('status') == 'completed']
        rejected_matches = [m for m in matches if m.get('status') == 'rejected']

        deposit_requests = db.find('deposit_requests', {'user_id': merchant_id}) or []
        withdrawal_requests = db.find('withdrawal_requests', {'user_id': merchant_id}) or []

        requisites_types = [
            {'id': '1', 'name': 'Банковский счет'},
            {'id': '2', 'name': 'Банковская карта'},
            {'id': '3', 'name': 'Криптокошелек'}
        ]
        
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

    @app.route('/api/merchant/transactions', methods=['POST'])
    @app.role_required('merchant')
    @app.csrf_protect
    def create_merchant_transaction():
        user = app.get_current_user()
        try:
            data = request.get_json()
            if not data:
                return jsonify({'error': 'No data provided'}), 400

            new_tx = {
                'id': int(uuid.uuid4().int & (1<<31)-1),
                'merchant_id': int(user['id']),
                'type': data.get('type'),
                'amount': float(data.get('amount', 0)),
                'currency': data.get('currency', 'RUB'), 
                'method': data.get('method'),
                'status': 'pending',
                'created_at': datetime.now().isoformat(),
                'updated_at': datetime.now().isoformat()
            }
            
            db.insert_one('transactions', new_tx)
            return jsonify({'success': True, 'transaction': new_tx})
        
        except Exception as e:
            logger.error(f"Error creating merchant transaction: {str(e)}")
            return jsonify({'error': str(e)}), 400

    @app.route('/api/merchant/transactions/<tx_id>/cancel', methods=['POST'])
    @app.role_required('merchant')
    @app.csrf_protect
    def cancel_merchant_transaction(tx_id):
        user = app.get_current_user()
        try:
            tx = db.find_one('transactions', {'id': int(tx_id), 'merchant_id': int(user['id'])})
            if not tx:
                return jsonify({'error': 'Transaction not found'}), 404
            
            if tx.get('status') != 'pending':
                return jsonify({'error': 'Only pending transactions can be canceled'}), 400
            
            db.update_one('transactions', {'id': int(tx['id'])}, {
                'status': 'cancelled',
                'cancelled_at': datetime.now().isoformat(),
                'cancelled_by': int(user['id'])
            })
            
            return jsonify({'success': True})
        
        except Exception as e:
            logger.error(f"Error canceling transaction: {str(e)}")
            return jsonify({'error': str(e)}), 500

    @app.route('/api/merchant/transactions/<int:tx_id>/requisites', methods=['POST'])
    @app.login_required
    def save_requisites(tx_id):
        try:
            data = request.get_json()
            
            tx = db.find_one('transactions', {'id': tx_id})
            if not tx:
                return jsonify({'success': False, 'error': 'Transaction not found'}), 404

            if data['type'] == 'bank':
                required = ['bank_name', 'bik', 'account_number', 'account_holder']
                if not all(data.get(field) for field in required):
                    return jsonify({'success': False, 'error': 'Missing required fields'}), 400

            requisites = {
                'transaction_id': tx_id,
                'type': data['type'],
                'bank_name': data.get('bank_name'),
                'bik': data.get('bik'),
                'account_number': data.get('account_number'),
                'account_holder': data.get('account_holder'),
                'created_at': datetime.now().isoformat()
            }
            
            db.insert_one('transaction_requisites', requisites)
            
            return jsonify({'success': True})
        
        except Exception as e:
            return jsonify({'success': False, 'error': str(e)}), 500

    @app.route('/api/merchant/transactions/<int:tx_id>/requisites', methods=['GET'])
    @app.login_required
    def get_requisites(tx_id):
        requisites = db.find('transaction_requisites', {'transaction_id': tx_id})
        return jsonify([r for r in requisites])

    @app.route('/api/merchant/api_keys', methods=['POST'])
    @app.role_required('merchant')
    @app.csrf_protect
    def generate_merchant_api_key():
        user = app.get_current_user()
        try:
            new_key = {
                'id': int(uuid.uuid4().int & (1<<31)-1),
                'merchant_id': int(user['id']),
                'key': secrets.token_hex(16),
                'secret': secrets.token_hex(32),
                'created_at': datetime.now().isoformat(),
                'active': True
            }
            
            db.insert_one('api_keys', new_key)
            return jsonify({
                'success': True,
                'api_key': new_key['key'],
                'secret_key': new_key['secret']
            })
        
        except Exception as e:
            logger.error(f"Error generating API key: {str(e)}")
            return jsonify({'error': str(e)}), 500

    @app.route('/api/merchant/api_keys/<key_id>', methods=['DELETE'])
    @app.role_required('merchant')
    @app.csrf_protect
    def revoke_merchant_api_key(key_id):
        user = app.get_current_user()
        try:
            key = db.find_one('api_keys', {'id': int(key_id), 'merchant_id': int(user['id'])})
            if not key:
                return jsonify({'error': 'API key not found'}), 404
            
            db.delete_one('api_keys', {'id': int(key_id)})
            return jsonify({'success': True})
        
        except Exception as e:
            logger.error(f"Error revoking API key: {str(e)}")
            return jsonify({'error': str(e)}), 500

    @app.route('/api/merchant/matches/perform', methods=['POST'])
    @app.role_required('merchant')
    @app.csrf_protect
    def perform_merchant_matching():
        try:
            user = app.get_current_user()
            merchant_id = int(user['id'])
            
            currency_rates = db.find_one('system_settings', {'type': 'currency_rates'}) or {
                'USD': 75.0, 'EUR': 85.0, 'USDT': 1.0
            }
            commission_settings = db.find_one('system_settings', {'type': 'commissions'}) or {
                'default': 0.02
            }

            pending_deposits = [
                tx for tx in db.find('transactions', {
                    'status': 'pending', 
                    'type': 'deposit',
                    'merchant_id': merchant_id
                }) if tx and tx.get('requisites_approved')
            ]
            
            pending_withdrawals = [
                tx for tx in db.find('transactions', {
                    'status': 'pending', 
                    'type': 'withdrawal',
                    'merchant_id': merchant_id
                }) if tx and tx.get('requisites_approved')
            ]

            for tx in pending_deposits + pending_withdrawals:
                tx['converted_amount'] = float(tx['amount']) * currency_rates.get(tx.get('currency', 'RUB'), 1)

            pending_deposits.sort(key=lambda x: -x['converted_amount'])
            pending_withdrawals.sort(key=lambda x: x['converted_amount'])

            matched_pairs = []
            used_deposit_ids = set()

            for withdrawal in pending_withdrawals:
                commission = commission_settings.get('per_merchant', {}).get(str(merchant_id), 
                              commission_settings.get('default', 0.02))
                
                required_amount = withdrawal['converted_amount'] * (1 + commission)
                matched_deposits = []
                remaining_amount = required_amount

                for deposit in pending_deposits:
                    if deposit['id'] in used_deposit_ids:
                        continue
                    
                    if deposit['converted_amount'] <= remaining_amount:
                        matched_deposits.append(deposit)
                        remaining_amount -= deposit['converted_amount']
                        used_deposit_ids.add(deposit['id'])
                        
                        if remaining_amount <= 0:
                            break

                if remaining_amount <= 0 and matched_deposits:
                    match = {
                        'id': int(uuid.uuid4().int & (1<<31)-1),
                        'deposit_ids': [d['id'] for d in matched_deposits],
                        'withdrawal_id': withdrawal['id'],
                        'amount': withdrawal['amount'],
                        'commission': commission,
                        'status': 'pending',
                        'created_at': datetime.now().isoformat(),
                        'merchant_id': merchant_id
                    }
                    db.insert_one('matches', match)
                    matched_pairs.append(match)

                    for d in matched_deposits:
                        db.update_one('transactions', {'id': d['id']}, {
                            'status': 'matched',
                            'match_id': match['id']
                        })
                    db.update_one('transactions', {'id': withdrawal['id']}, {
                        'status': 'matched',
                        'match_id': match['id']
                    })

            return jsonify({
                'success': True,
                'matches_created': len(matched_pairs)
            })
        except Exception as e:
            logger.error(f"Merchant matching error: {str(e)}")
            return jsonify({'error': str(e)}), 500

    @app.route('/api/merchant/matches', methods=['GET'])
    @app.role_required('merchant')
    def get_merchant_matches():
        try:
            user = app.get_current_user()
            status = request.args.get('status', 'pending')
            
            matches = db.find('matches', {
                'merchant_id': int(user['id']),
                'status': status
            }) or []
            
            return jsonify(matches)
        except Exception as e:
            return jsonify({'error': str(e)}), 500

    @app.route('/api/merchant/matches/<match_id>/confirm', methods=['POST'])
    @app.role_required('merchant')
    @app.csrf_protect
    def merchant_confirm_match(match_id):
        try:
            user = app.get_current_user()
            match = db.find_one('matches', {
                'id': int(match_id),
                'merchant_id': int(user['id'])
            })
            
            if not match:
                return jsonify({'error': 'Match not found or access denied'}), 404
            
            db.update_one('matches', {'id': int(match_id)}, {
                'status': 'completed',
                'completed_at': datetime.now().isoformat()
            })
            
            for dep_id in match.get('deposit_ids', []):
                db.update_one('transactions', {'id': dep_id}, {
                    'status': 'completed',
                    'completed_at': datetime.now().isoformat()
                })
            
            if match.get('withdrawal_id'):
                db.update_one('transactions', {'id': match['withdrawal_id']}, {
                    'status': 'completed',
                    'completed_at': datetime.now().isoformat()
                })
            
            return jsonify({'success': True})
        except Exception as e:
            return jsonify({'error': str(e)}), 500

    @app.route('/api/merchant/matches/<match_id>/reject', methods=['POST'])
    @app.role_required('merchant')
    @app.csrf_protect
    def reject_merchant_match(match_id):
        user = app.get_current_user()
        try:
            data = request.get_json()
            match = db.find_one('matches', {'id': int(match_id), 'merchant_id': int(user['id'])})
            if not match:
                return jsonify({'error': 'Match not found'}), 404
            
            updates = {
                'status': 'rejected',
                'rejected_at': datetime.now().isoformat(),
                'rejected_by': int(user['id']),
                'reason': data.get('reason', 'No reason provided')
            }
            
            db.update_one('matches', {'id': int(match_id)}, updates)
            
            if match.get('deposit_id'):
                db.update_one('transactions', {'id': match['deposit_id']}, {'status': 'rejected'})
            if match.get('withdrawal_id'):
                db.update_one('transactions', {'id': match['withdrawal_id']}, {'status': 'rejected'})
            
            return jsonify({'success': True})
        
        except Exception as e:
            logger.error(f"Error rejecting match: {str(e)}")
            return jsonify({'error': str(e)}), 500

    @app.route('/api/merchant/transactions/<tx_id>/verify', methods=['POST'])
    @app.role_required('merchant')
    @app.csrf_protect
    def verify_merchant_transaction_sole(tx_id):
        user = app.get_current_user()
        try:
            if 'file' not in request.files:
                return jsonify({'error': 'No file uploaded'}), 400
            
            file = request.files['file']
            if file.filename == '':
                return jsonify({'error': 'No selected file'}), 400
            
            if file and app.allowed_file(file.filename):
                filename = f"{tx_id}_{datetime.now().timestamp()}.pdf"
                file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
                
                db.update_one('transactions', {'id': int(tx_id), 'merchant_id': int(user['id'])}, {
                    'verified': True,
                    'verification_file': filename,
                    'verified_at': datetime.now().isoformat()
                })
                
                return jsonify({'success': True})
            
            return jsonify({'error': 'Invalid file type'}), 400
        
        except Exception as e:
            logger.error(f"Error verifying transaction: {str(e)}")
            return jsonify({'error': str(e)}), 500

    @app.route('/api/merchant/matches/refresh', methods=['POST'])
    @app.role_required('merchant')
    @app.csrf_protect
    def refresh_matches():
        try:
            matched_pairs = app.perform_matching()
            return jsonify({
                'success': True,
                'count': len(matched_pairs),
                'matches': matched_pairs
            })
        except Exception as e:
            logger.error(f"Ошибка при обновлении матчинга: {str(e)}")
            return jsonify({'error': str(e)}), 500

    @app.route('/api/merchant/matches/pending', methods=['GET'])
    @app.role_required('merchant')
    def get_pending_matches():
        try:
            page = int(request.args.get('page', 1))
            per_page = int(request.args.get('per_page', 10))
            
            matches = MatchingService.get_pending_matches(
                limit=per_page,
                offset=(page-1)*per_page
            )
            
            return jsonify({
                'success': True,
                'data': matches['data'],
                'total': matches['total'],
                'page': page,
                'per_page': per_page
            })
        except Exception as e:
            return jsonify({'error': str(e)}), 400

    @app.route('/api/merchant/matching/auto', methods=['POST'])
    @app.role_required('merchant')
    @app.csrf_protect
    def toggle_auto_matching():
        global AUTO_MATCHING_ENABLED
        try:
            data = request.get_json()
            AUTO_MATCHING_ENABLED = bool(data.get('enabled', False))
            
            return jsonify({
                'success': True,
                'auto_matching': AUTO_MATCHING_ENABLED
            })
        except Exception as e:
            return jsonify({'error': str(e)}), 400

    @app.route('/api/requisites/types/<method>')
    @app.role_required('merchant')
    def get_requisites_types(method):
        try:
            types = db.find_one('requisites_types', {}) or {}
            if types and 'types' in types:
                req_type = next((t for t in types['types'] if t['name'].lower() == method.lower()), None)
                if req_type:
                    return jsonify(req_type)
            return jsonify({'error': 'Type not found'}), 404
        except Exception as e:
            return jsonify({'error': str(e)}), 500

    @app.route('/api/deposit_requests', methods=['POST'])
    @app.role_required('merchant')
    @app.csrf_protect
    def create_deposit_request_merch():
        try:
            data = request.get_json()
            user = app.get_current_user()
            
            if not data or 'amount' not in data or 'payment_method' not in data:
                return jsonify({'error': 'Missing required fields'}), 400

            request_data = {
                'id': int(uuid.uuid4().int & (1<<31)-1),
                'user_id': int(user['id']),
                'amount': float(data['amount']),
                'currency': data.get('currency', 'RUB'),
                'payment_method': data['payment_method'],
                'requisites': data.get('requisites', {}),
                'status': 'pending',
                'created_at': datetime.now().isoformat()
            }
            
            db.insert_one('deposit_requests', request_data)
            return jsonify({'success': True, 'request': request_data})
        except Exception as e:
            return jsonify({'error': str(e)}), 400

    @app.route('/api/withdrawal_requests', methods=['POST'])
    @app.role_required('merchant')
    @app.csrf_protect
    def create_withdrawal_request_merch():
        try:
            data = request.get_json()
            user = app.get_current_user()
            
            if not data or 'amount' not in data or 'withdrawal_method' not in data:
                return jsonify({'error': 'Missing required fields'}), 400

            if float(data['amount']) > float(user.get('balance', 0)):
                return jsonify({'error': 'Недостаточно средств'}), 400

            request_data = {
                'id': int(uuid.uuid4().int & (1<<31)-1),
                'user_id': int(user['id']),
                'amount': float(data['amount']),
                'currency': data.get('currency', 'RUB'),
                'withdrawal_method': data['withdrawal_method'],
                'requisites': data.get('requisites', {}),
                'status': 'pending',
                'created_at': datetime.now().isoformat()
            }
            
            db.insert_one('withdrawal_requests', request_data)
            return jsonify({'success': True, 'request': request_data})
        except Exception as e:
            return jsonify({'error': str(e)}), 400

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

    @app.route('/api/requisites/types/<type_id>', methods=['GET'])
    @app.role_required('merchant')
    def get_requisites_type_fields(type_id):
        try:
            types_data = {
                '1': {
                    'fields': [
                        {'name': 'account_number', 'label': 'Номер счета', 'type': 'text'},
                        {'name': 'bik', 'label': 'БИК', 'type': 'text'},
                        {'name': 'bank_name', 'label': 'Название банка', 'type': 'text'},
                        {'name': 'owner_name', 'label': 'ФИО владельца', 'type': 'text'}
                    ]
                },
                '2': {
                    'fields': [
                        {'name': 'card_number', 'label': 'Номер карты', 'type': 'text'},
                        {'name': 'card_owner', 'label': 'ФИО владельца', 'type': 'text'},
                        {'name': 'card_expiry', 'label': 'Срок действия', 'type': 'text'},
                        {'name': 'card_cvv', 'label': 'CVV код', 'type': 'password'}
                    ]
                },
                '3': {
                    'fields': [
                        {'name': 'wallet_address', 'label': 'Адрес кошелька', 'type': 'text'},
                        {'name': 'crypto_type', 'label': 'Тип криптовалюты', 'type': 'select', 
                         'options': ['BTC', 'ETH', 'USDT', 'USDC', 'BNB']}
                    ]
                }
            }
            
            if type_id not in types_data:
                return jsonify({'error': 'Type not found'}), 404
            
            return jsonify(types_data[type_id])
        except Exception as e:
            return jsonify({'error': str(e)}), 500

    return app