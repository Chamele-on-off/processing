// static/js/utils.js
class Utils {
  static formatCurrency(amount, currency = 'RUB') {
    return new Intl.NumberFormat('ru-RU', {
      style: 'currency',
      currency,
      minimumFractionDigits: 2,
      maximumFractionDigits: 2
    }).format(amount);
  }

  static formatDate(dateString, options = {}) {
    const defaultOptions = { 
      year: 'numeric', 
      month: 'short', 
      day: 'numeric',
      hour: '2-digit',
      minute: '2-digit'
    };
    return new Date(dateString).toLocaleString('ru-RU', { ...defaultOptions, ...options });
  }

  static debounce(func, wait = 300, immediate = false) {
    let timeout;
    return function() {
      const context = this, args = arguments;
      const later = function() {
        timeout = null;
        if (!immediate) func.apply(context, args);
      };
      const callNow = immediate && !timeout;
      clearTimeout(timeout);
      timeout = setTimeout(later, wait);
      if (callNow) func.apply(context, args);
    };
  }

  static throttle(func, limit = 300) {
    let lastFunc;
    let lastRan;
    return function() {
      const context = this;
      const args = arguments;
      if (!lastRan) {
        func.apply(context, args);
        lastRan = Date.now();
      } else {
        clearTimeout(lastFunc);
        lastFunc = setTimeout(function() {
          if ((Date.now() - lastRan) >= limit) {
            func.apply(context, args);
            lastRan = Date.now();
          }
        }, limit - (Date.now() - lastRan));
      }
    };
  }

  static async copyToClipboard(text) {
    try {
      await navigator.clipboard.writeText(text);
      return true;
    } catch (error) {
      console.error('Copy failed:', error);
      return false;
    }
  }

  static handleAPIError(error) {
    console.error('API Error:', error);
    
    if (error.response?.status === 401) {
      App.showError('Сессия истекла. Пожалуйста, войдите снова.');
      setTimeout(() => Auth.logout(), 2000);
      return;
    }

    const message = error.response?.data?.error || error.message || 'Ошибка соединения с сервером';
    App.showError(message);
  }
}