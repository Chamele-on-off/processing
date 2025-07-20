# database.py
import json
import os
from threading import Lock
from datetime import datetime
from pathlib import Path
from copy import deepcopy

class JSONDatabase:
    _instance = None
    _lock = Lock()
    
    def __new__(cls, file_path='data/db.json'):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance.file_path = file_path
            cls._instance._ensure_data_dir()
            cls._instance.data = {
                'users': [],
                'transactions': [],
                'requisites': [],
                'disputes': [],
                'audit_logs': [],
                'settings': {},
                'triangle_transactions': [],
                'orders': [], 
                'details': [],
                'transaction_requisites': [],
                'deposit_requests': [],
                'withdrawal_requests': [],
                'requisites_types': []
            }
            cls._instance.load()
        return cls._instance
    
    def _ensure_data_dir(self):
        """Создает папку для данных, если ее нет"""
        Path(self.file_path).parent.mkdir(parents=True, exist_ok=True)
    
    def load(self):
        """Загружает данные из файла"""
        try:
            with self._lock:
                if os.path.exists(self.file_path):
                    with open(self.file_path, 'r', encoding='utf-8') as f:
                        self.data = json.load(f)
        except (json.JSONDecodeError, IOError) as e:
            print(f"Ошибка загрузки БД: {e}. Будет создана новая БД.")
            self.save()
    
    def save(self):
        """Сохраняет данные в файл"""
        with self._lock:
            try:
                with open(self.file_path, 'w', encoding='utf-8') as f:
                    json.dump(self.data, f, indent=2, ensure_ascii=False)
            except IOError as e:
                print(f"Ошибка сохранения БД: {e}")
    
    def insert_one(self, collection, document):
        """Добавляет один документ в коллекцию"""
        if collection not in self.data:
            self.data[collection] = []
        
        doc = deepcopy(document)
        doc['id'] = len(self.data[collection]) + 1
        doc['created_at'] = datetime.now().isoformat()
        self.data[collection].append(doc)
        self.save()
        return doc
    
    def find_one(self, collection, query):
        """Находит один документ в коллекции"""
        for item in self.data.get(collection, []):
            if all(item.get(k) == v for k, v in query.items()):
                return deepcopy(item)
        return None
    
    def find(self, collection, query=None):
        """Находит все документы в коллекции, соответствующие запросу"""
        if query is None:
            return deepcopy(self.data.get(collection, []))
        
        results = []
        for item in self.data.get(collection, []):
            if all(item.get(k) == v for k, v in query.items()):
                results.append(deepcopy(item))
        return results
    
    def update_one(self, collection, query, updates):
        """Обновляет один документ в коллекции"""
        for item in self.data.get(collection, []):
            if all(item.get(k) == v for k, v in query.items()):
                item.update(updates)
                item['updated_at'] = datetime.now().isoformat()
                self.save()
                return True
        return False
    
    def delete_one(self, collection, query):
        """Удаляет один документ из коллекции"""
        for idx, item in enumerate(self.data.get(collection, [])):
            if all(item.get(k) == v for k, v in query.items()):
                del self.data[collection][idx]
                self.save()
                return True
        return False
    
    def collection_exists(self, collection_name):
        """Проверяет существование коллекции"""
        return collection_name in self.data
    
    def create_collection(self, collection_name):
        """Создает новую коллекцию"""
        if collection_name not in self.data:
            self.data[collection_name] = []
            self.save()
            return True
        return False


class TransactionRequisitesManager:
    """Менеджер для работы с реквизитами транзакций"""
    def __init__(self, db):
        """
        Инициализация менеджера
        
        :param db: Экземпляр JSONDatabase
        """
        self.db = db
        self.collection_name = 'transaction_requisites'
        
        # Создаем коллекцию, если ее нет
        if not self.db.collection_exists(self.collection_name):
            self.db.create_collection(self.collection_name)
    
    def create(self, transaction_id, req_type, **fields):
        """
        Создает новые реквизиты для транзакции
        
        :param transaction_id: ID транзакции
        :param req_type: Тип реквизитов ('bank', 'card', 'crypto')
        :param fields: Дополнительные поля реквизитов
        :return: Созданный документ с реквизитами
        """
        requisites = {
            'transaction_id': transaction_id,
            'type': req_type,
            **fields,
            'created_at': datetime.now().isoformat()
        }
        return self.db.insert_one(self.collection_name, requisites)
    
    def get_for_transaction(self, transaction_id):
        """
        Получает все реквизиты для указанной транзакции
        
        :param transaction_id: ID транзакции
        :return: Список реквизитов
        """
        return self.db.find(self.collection_name, {'transaction_id': transaction_id})
    
    def update(self, req_id, **updates):
        """
        Обновляет реквизиты
        
        :param req_id: ID реквизитов
        :param updates: Поля для обновления
        :return: True если успешно, False если не найдено
        """
        return self.db.update_one(
            self.collection_name,
            {'id': req_id},
            {**updates, 'updated_at': datetime.now().isoformat()}
        )
    
    def delete(self, req_id):
        """
        Удаляет реквизиты
        
        :param req_id: ID реквизитов
        :return: True если успешно, False если не найдено
        """
        return self.db.delete_one(self.collection_name, {'id': req_id})


if __name__ == '__main__':
    # Пример использования
    db = JSONDatabase()
    req_manager = TransactionRequisitesManager(db)
    
    # Создаем тестовые реквизиты
    test_req = req_manager.create(
        transaction_id=1,
        req_type='bank',
        bank_name='Test Bank',
        account_number='123456789',
        bik='123456789',
        account_holder='John Doe'
    )
    
    print("Созданные реквизиты:", test_req)
    print("Реквизиты для транзакции 1:", req_manager.get_for_transaction(1))
    
    print("Все коллекции в БД:", db.data.keys())