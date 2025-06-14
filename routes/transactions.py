from flask import Blueprint, request, jsonify
from flask_jwt_extended import jwt_required
from models.transaction import Transaction
from services.transaction_service import TransactionService
from services.fraud_detection import FraudDetectionService
from utils.decorators import role_required

bp = Blueprint('transactions', __name__, url_prefix='/transactions')

@bp.route('/<int:tx_id>')
@jwt_required()
def get_transaction(tx_id):
    transaction = Transaction.get_by_id(tx_id)
    if not transaction:
        return jsonify({'success': False, 'error': 'Not found'}), 404
    
    return jsonify({
        'success': True,
        'data': transaction
    })

@bp.route('/<int:tx_id>/complete', methods=['POST'])
@jwt_required()
@role_required(['trader', 'admin'])
def complete_transaction(tx_id):
    try:
        TransactionService.complete_transaction(tx_id)
        return jsonify({'success': True})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 400

@bp.route('/match', methods=['POST'])
@jwt_required()
@role_required(['trader', 'admin'])
def match_transactions():
    data = request.get_json()
    try:
        match = TransactionService.match_transactions(
            data['deposit_ids'],
            data['payout_id']
        )
        return jsonify({
            'success': True,
            'data': match
        }), 201
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 400