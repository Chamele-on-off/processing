// static/js/modules/merchant/pdf-upload.js
class PDFUploader {
  static init() {
    if (!document.getElementById('pdfUploadForm')) return;
    
    this.setupEventListeners();
  }

  static setupEventListeners() {
    const form = document.getElementById('pdfUploadForm');
    const fileInput = document.getElementById('pdfFile');

    fileInput?.addEventListener('change', (e) => {
      this.previewPDF(e.target.files[0]);
    });

    form?.addEventListener('submit', (e) => {
      e.preventDefault();
      this.uploadPDF(new FormData(form));
    });
  }

  static previewPDF(file) {
    if (!file || file.type !== 'application/pdf') return;

    const previewContainer = document.getElementById('pdfPreview');
    previewContainer.innerHTML = '';

    const reader = new FileReader();
    reader.onload = function(e) {
      const iframe = document.createElement('iframe');
      iframe.src = e.target.result;
      iframe.style.width = '100%';
      iframe.style.height = '500px';
      previewContainer.appendChild(iframe);
    };
    reader.readAsDataURL(file);
  }

  static async uploadPDF(formData) {
    const txId = formData.get('transaction_id');
    if (!txId) return;

    try {
      DomHelper.toggleLoader(true);
      await ApiService.post(`/api/merchant/transactions/${txId}/verify`, formData);
      
      DomHelper.showToast('PDF-документ успешно загружен', 'success');
      setTimeout(() => window.location.reload(), 1500);
    } catch (error) {
      DomHelper.showToast('Ошибка загрузки документа: ' + (error.message || 'Неизвестная ошибка'), 'error');
    } finally {
      DomHelper.toggleLoader(false);
    }
  }
}

document.addEventListener('DOMContentLoaded', () => PDFUploader.init());