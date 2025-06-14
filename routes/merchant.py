from flask import Blueprint, request, jsonify
from flask_jwt_extended import jwt_required, get_jwt_identity
from models.transaction import Transaction
from services.transaction_service import TransactionService
from utils.decorators import merchant_required

bp = Blueprint('merchant', __name__, url_prefix='/merchant')

@bp.route('/dashboard')
@jwt_required()
@merchant_required
def dashboard():
    user_id = get_jwt_identity()['id']
    stats = {
        'balance': User.get_balance(user_id),
        'pending_transactions': Transaction.count_pending(user_id),
        'today_transactions': Transaction.count_today(user_id)
    }
    return jsonify({'success': True, 'data': stats})

@bp.route('/transactions')
@login_required
@merchant_required
def transactions():
    user_id = get_jwt_identity()['id']
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 20, type=int)
    
    transactions = Transaction.get_by_merchant(
        user_id,
        page=page,
        per_page=per_page
    )
    
    return jsonify({
        'success': True,
        'data': transactions
    })

@bp.route('/deposit', methods=['POST'])
@login_required
@merchant_required
def create_deposit():
    user_id = get_jwt_identity()['id']
    data = request.get_json()
    
    transaction = TransactionService.create_deposit(
        merchant_id=user_id,
        amount=data['amount'],
        currency=data.get('currency', 'RUB'),
        method=data['method']
    )
    
    return jsonify({
        'success': True,
        'data': Transaction.to_dict(transaction)
    }), 201