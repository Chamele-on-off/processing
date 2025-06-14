from flask import Blueprint, request, jsonify
from flask_jwt_extended import jwt_required, get_jwt_identity
from models.transaction import Transaction
from models.requisites import Requisite
from services.matching_service import MatchingService
from utils.decorators import trader_required

bp = Blueprint('trader', __name__, url_prefix='/trader')

@bp.route('/dashboard')
@jwt_required()
@trader_required
def dashboard():
    user_id = get_jwt_identity()['id']
    stats = {
        'balance': User.get_balance(user_id),
        'pending_transactions': Transaction.count_pending(user_id),
        'available_requisites': Requisite.count_active(user_id)
    }
    return jsonify({'success': True, 'data': stats})

@bp.route('/transactions')
@jwt_required()
@trader_required
def transactions():
    user_id = get_jwt_identity()['id']
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 20, type=int)
    
    transactions = Transaction.get_by_trader(
        user_id,
        page=page,
        per_page=per_page
    )
    
    return jsonify({
        'success': True,
        'data': transactions
    })

@bp.route('/matches/pending')
@jwt_required()
@trader_required
def pending_matches():
    matches = MatchingService.get_pending_matches()
    return jsonify({
        'success': True,
        'data': matches
    })