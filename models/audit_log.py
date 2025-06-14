from datetime import datetime
from extensions import db

class AuditLog:
    @staticmethod
    def log_action(user_id, action, entity_type=None, entity_id=None, request=None):
        log = {
            'user_id': user_id,
            'action': action,
            'entity_type': entity_type,
            'entity_id': entity_id,
            'ip_address': request.remote_addr if request else None,
            'user_agent': request.headers.get('User-Agent') if request else None,
            'created_at': datetime.now().isoformat()
        }
        return db.insert_one('audit_logs', log)

    @staticmethod
    def get_by_user(user_id):
        return db.find('audit_logs', {'user_id': user_id})

    @staticmethod
    def to_dict(log):
        return {
            'id': log['id'],
            'user_id': log['user_id'],
            'action': log['action'],
            'entity_type': log.get('entity_type'),
            'entity_id': log.get('entity_id'),
            'ip_address': log.get('ip_address'),
            'created_at': log['created_at']
        }