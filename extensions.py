from flask_jwt_extended import JWTManager
from flask_socketio import SocketIO
from database.database import JSONDatabase

# Удаляем PyMongo, добавляем нашу базу данных
db = JSONDatabase()
jwt = JWTManager()
socketio = SocketIO(cors_allowed_origins="*")

def init_extensions(app):
    # Инициализируем базу данных с путем из конфига
    app.db = JSONDatabase(app.config['JSON_DB_PATH'])
    jwt.init_app(app)
    socketio.init_app(app, cors_allowed_origins="*")