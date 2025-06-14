// static/js/core/dom.js
class DomHelper {
  static renderTable(containerId, data, rowTemplate) {
    const container = document.getElementById(containerId);
    if (!container) return;

    if (!data || data.length === 0) {
      container.innerHTML = '<tr><td colspan="100%" class="text-center">Нет данных</td></tr>';
      return;
    }

    container.innerHTML = data.map(rowTemplate).join('');
  }

  static renderCards(containerId, data, cardTemplate) {
    const container = document.getElementById(containerId);
    if (!container) return;

    container.innerHTML = data.map(cardTemplate).join('');
  }

  static initTooltips() {
    const tooltips = [].slice.call(document.querySelectorAll('[data-bs-toggle="tooltip"]'));
    tooltips.map(el => new bootstrap.Tooltip(el));
  }

  static toggleLoader(show = true) {
    const loader = document.getElementById('pageLoader');
    if (loader) loader.style.display = show ? 'flex' : 'none';
  }

  static showToast(message, type = 'success') {
    const toastContainer = document.getElementById('toastContainer');
    if (!toastContainer) return;

    const toastId = `toast-${Date.now()}`;
    const toast = document.createElement('div');
    toast.className = `toast align-items-center text-white bg-${type} border-0`;
    toast.setAttribute('role', 'alert');
    toast.setAttribute('aria-live', 'assertive');
    toast.setAttribute('aria-atomic', 'true');
    toast.id = toastId;

    toast.innerHTML = `
      <div class="d-flex">
        <div class="toast-body">${message}</div>
        <button type="button" class="btn-close btn-close-white me-2 m-auto" data-bs-dismiss="toast" aria-label="Close"></button>
      </div>
    `;

    toastContainer.appendChild(toast);
    const bsToast = new bootstrap.Toast(toast);
    bsToast.show();

    toast.addEventListener('hidden.bs.toast', () => {
      toast.remove();
    });

    return toastId;
  }

  static switchSection(sectionId) {
    document.querySelectorAll('.page-section').forEach(section => {
      section.classList.remove('active');
    });
    document.getElementById(sectionId).classList.add('active');
  }
}