from flask import Blueprint, jsonify, request
from flask_jwt_extended import jwt_required, get_jwt_identity
from models.user import User
from models.transaction import Transaction
from models.audit_log import AuditLog
from services.fraud_detection import FraudDetectionService
from utils.decorators import admin_required

bp = Blueprint('admin', __name__, url_prefix='/admin')

@bp.route('/stats')
@login_required
@admin_required
def stats():
    stats = {
        'total_users': User.get_count(),
        'today_transactions': Transaction.count_today(),
        'active_traders': User.get_active_traders_count(),
        'fraud_alerts': FraudDetectionService.get_active_alerts_count()
    }
    return jsonify({'success': True, 'data': stats})

@bp.route('/users')
@login_required
@admin_required
def users_list():
    users = User.get_all()
    return jsonify({
        'success': True,
        'data': [User.to_dict(u) for u in users]
    })

@bp.route('/users/<int:user_id>/toggle', methods=['POST'])
@login_required
@admin_required
def toggle_user(user_id):
    user = User.find_by_id(user_id)
    if not user:
        return jsonify({'success': False, 'error': 'User not found'}), 404
    
    new_status = not user.get('is_active', False)
    User.update_status(user_id, new_status)
    
    AuditLog.log_action(
        get_jwt_identity()['id'],
        'user_toggle',
        entity_type='user',
        entity_id=user_id,
        request=request
    )
    
    return jsonify({'success': True, 'is_active': new_status})

@bp.route('/fraud/alerts')
@login_required
@admin_required
def fraud_alerts():
    alerts = FraudDetectionService.get_active_alerts()
    return jsonify({
        'success': True,
        'data': alerts
    })