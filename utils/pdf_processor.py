import os
import logging
import re
import subprocess
from tempfile import NamedTemporaryFile
from pdfminer.high_level import extract_text
from datetime import datetime
from config import Config
from PIL import Image
import pyzbar.pyzbar as pyzbar

logger = logging.getLogger(__name__)

class PDFProcessor:
    @staticmethod
    def process_pdf_check(file):
        """Обработка PDF чека и извлечение данных"""
        with NamedTemporaryFile(delete=False) as temp_file:
            file.save(temp_file.name)
            try:
                # Проверка подписи
                if not PDFProcessor.check_digital_signature(temp_file.name):
                    raise ValueError("Invalid digital signature")
                
                # Извлечение текста
                text = extract_text(temp_file.name)
                
                # Проверка QR кода
                qr_data = PDFProcessor.verify_qr_code(temp_file.name)
                
                # Парсинг данных
                data = PDFProcessor.parse_pdf_text(text)
                
                if qr_data:
                    data.update({'qr_verified': True, 'qr_data': qr_data})
                
                logger.info(f"PDF processed: {data.get('amount')} {data.get('currency')}")
                return data
            finally:
                os.unlink(temp_file.name)

    @staticmethod
    def parse_pdf_text(text):
        """Парсинг текста PDF для разных форматов чеков"""
        # Сбербанк
        sber_match = re.search(r'Сумма:\s*(\d+\.?\d*)\s*(\w{3})', text)
        if sber_match:
            return {
                'amount': float(sber_match.group(1)),
                'currency': sber_match.group(2),
                'bank': 'sberbank'
            }
        
        # Тинькофф
        tinkoff_match = re.search(r'Amount:\s*(\d+\.?\d*)\s*(\w{3})', text, re.IGNORECASE)
        if tinkoff_match:
            return {
                'amount': float(tinkoff_match.group(1)),
                'currency': tinkoff_match.group(2),
                'bank': 'tinkoff'
            }
        
        raise ValueError("Unsupported PDF format")

    @staticmethod
    def verify_qr_code(pdf_path):
        """Проверка QR-кода в чеке"""
        try:
            # Извлечение изображений из PDF
            images = PDFProcessor.extract_images_from_pdf(pdf_path)
            
            for img in images:
                decoded = pyzbar.decode(img)
                if decoded:
                    return decoded[0].data.decode('utf-8')
            return None
        except Exception as e:
            logger.error(f"QR verification failed: {str(e)}")
            return None

    @staticmethod
    def extract_images_from_pdf(pdf_path):
        """Извлечение изображений из PDF"""
        images = []
        try:
            # Используем pdftoppm для извлечения изображений
            output_prefix = os.path.join(Config.TEMP_FOLDER, 'pdf_image')
            subprocess.run(['pdftoppm', '-png', pdf_path, output_prefix], check=True)
            
            # Ищем созданные файлы
            for file in os.listdir(Config.TEMP_FOLDER):
                if file.startswith('pdf_image') and file.endswith('.png'):
                    img_path = os.path.join(Config.TEMP_FOLDER, file)
                    images.append(Image.open(img_path))
                    os.unlink(img_path)
        except Exception as e:
            logger.error(f"Image extraction failed: {str(e)}")
        return images

    @staticmethod
    def check_digital_signature(pdf_path):
        """Проверка цифровой подписи"""
        try:
            result = subprocess.run(
                ['pdfsig', '-v', pdf_path],
                capture_output=True,
                text=True
            )
            return "Signature VALID" in result.stdout
        except Exception as e:
            logger.error(f"Signature check failed: {str(e)}")
            return False