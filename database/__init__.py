from .database import JSONDatabase
from .init_db import init_db

# Инициализация DB происходит в app.py
__all__ = ['JSONDatabase', 'init_db']