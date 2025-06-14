import requests
import logging
from functools import lru_cache
from datetime import datetime, timedelta
from config import Config

logger = logging.getLogger(__name__)

@lru_cache(maxsize=32)
def get_currency_rate(base='RUB', target='USD', provider='default'):
    """Получение курса валют с кэшированием и выбором провайдера"""
    if provider == 'cbr':
        return get_currency_rate_cbr(base, target)
    
    try:
        response = requests.get(
            f"{Config.EXCHANGE_RATE_API_URL}/latest/{base}",
            params={'access_key': Config.EXCHANGE_RATE_API_KEY},
            timeout=5
        )
        response.raise_for_status()
        data = response.json()
        return data['rates'].get(target, 1.0)
    except Exception as e:
        logger.error(f"Failed to get rate from API: {str(e)}")
        return get_currency_rate_cbr(base, target) or 75.0

def get_currency_rate_cbr(base='RUB', target='USD'):
    """Альтернативный источник курсов (ЦБ РФ)"""
    try:
        response = requests.get(
            'https://www.cbr-xml-daily.ru/daily_json.js',
            timeout=3
        )
        response.raise_for_status()
        data = response.json()
        
        if base == 'RUB':
            if target == 'USD':
                return data['Valute']['USD']['Value']
            elif target == 'EUR':
                return data['Valute']['EUR']['Value']
        return None
    except Exception as e:
        logger.error(f"Failed to get CBR rate: {str(e)}")
        return None

def convert_amount(amount, from_currency, to_currency):
    """Конвертация суммы между валютами"""
    if from_currency == to_currency:
        return amount
    
    rate = get_currency_rate(from_currency, to_currency)
    if not rate:
        raise ValueError(f"Cannot convert {from_currency} to {to_currency}")
    
    return round(amount * rate, 2)

def clear_rates_cache():
    """Очистка кэша курсов валют"""
    get_currency_rate.cache_clear()
    logger.info("Currency rates cache cleared")