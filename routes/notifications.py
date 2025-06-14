from flask import Blueprint, request, jsonify
from flask_jwt_extended import jwt_required, get_jwt_identity
from services.notification_service import NotificationService

bp = Blueprint('notifications', __name__, url_prefix='/notifications')

@bp.route('/')
@jwt_required()
def get_notifications():
    user_id = get_jwt_identity()['id']
    unread = request.args.get('unread', 'false').lower() == 'true'
    
    notifications = NotificationService.get_for_user(
        user_id,
        unread_only=unread
    )
    
    return jsonify({
        'success': True,
        'data': notifications
    })

@bp.route('/mark-read', methods=['POST'])
@jwt_required()
def mark_as_read():
    user_id = get_jwt_identity()['id']
    notification_ids = request.get_json().get('ids', [])
    
    NotificationService.mark_as_read(user_id, notification_ids)
    
    return jsonify({'success': True})

@bp.route('/count')
@jwt_required()
def unread_count():
    user_id = get_jwt_identity()['id']
    count = NotificationService.get_unread_count(user_id)
    return jsonify({
        'success': True,
        'count': count
    })