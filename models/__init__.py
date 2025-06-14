from backend.extensions import db

# Импортируем все модели
from models.user import User
from models.transaction import Transaction
from models.dispute import Dispute
from models.triangle import TriangleTransaction
from models.requisites import Requisite
from models.audit_log import AuditLog

__all__ = ['User', 'Transaction', 'Dispute', 'TriangleTransaction', 'Requisite', 'AuditLog']