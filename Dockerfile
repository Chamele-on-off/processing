FROM python:3.9-slim

# Установка системных зависимостей
RUN apt-get update && \
    apt-get install -y --no-install-recommends gcc python3-dev && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Копируем зависимости отдельно для кеширования
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Копируем остальные файлы
COPY . .

# Создаем папку для данных
RUN mkdir -p /app/data && chmod 777 /app/data

# Переменные окружения
ENV FLASK_APP=app.py
ENV FLASK_ENV=production
ENV PYTHONUNBUFFERED=1

EXPOSE 5001

# Команда запуска
CMD ["gunicorn", "--bind", "0.0.0.0:5001", "--worker-class", "gevent", "--workers", "2", "app:app"]