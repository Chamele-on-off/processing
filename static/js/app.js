// static/js/app.js
import { ApiService } from './core/api.js';
import { PollingService } from './core/polling.js';
import { DomHelper } from './core/dom.js';
import { Utils } from './utils.js';

class App {
  static async init() {
    try {
      this.initTooltips();
      await this.checkAuthState();
      this.setupGlobalErrorHandling();
      this.loadPageModule();
    } catch (error) {
      console.error('App initialization failed:', error);
      this.showError('Application initialization error');
    }
  }

  static async checkAuthState() {
    try {
      const response = await ApiService.get('/api/session');
      if (response.authenticated) {
        this.updateUIForAuth(response.user);
      } else {
        this.updateUIForGuest();
        if (!window.location.pathname.includes('login.html')) {
          window.location.href = '/login.html?redirect=' + encodeURIComponent(window.location.pathname);
        }
      }
    } catch (error) {
      console.error('Auth check failed:', error);
      this.updateUIForGuest();
    }
  }

  static updateUIForAuth(user) {
    document.querySelectorAll('.auth-only').forEach(el => el.style.display = '');
    document.querySelectorAll('.guest-only').forEach(el => el.style.display = 'none');
    document.querySelectorAll('.user-email').forEach(el => el.textContent = user.email);
    document.querySelectorAll('.user-role').forEach(el => el.textContent = user.role);
  }

  static updateUIForGuest() {
    document.querySelectorAll('.auth-only').forEach(el => el.style.display = 'none');
    document.querySelectorAll('.guest-only').forEach(el => el.style.display = '');
  }

  static initTooltips() {
    const tooltips = [].slice.call(document.querySelectorAll('[data-bs-toggle="tooltip"]'));
    tooltips.map(el => new bootstrap.Tooltip(el));
  }

  static setupGlobalErrorHandling() {
    window.addEventListener('unhandledrejection', (event) => {
      console.error('Unhandled rejection:', event.reason);
      this.showError(event.reason.message || 'An unexpected error occurred');
    });
  }

  static loadPageModule() {
    const path = window.location.pathname;
    
    if (path.includes('admin.html')) {
      import('./modules/admin/dashboard.js').then(module => module.AdminDashboard.init());
      import('./modules/admin/fraud.js').then(module => module.FraudMonitor.init());
      import('./modules/admin/matching.js').then(module => module.TransactionMatching.init());
    } 
    else if (path.includes('trader.html')) {
      import('./modules/trader/dashboard.js').then(module => module.TraderDashboard.init());
      import('./modules/trader/orders.js').then(module => module.TraderOrders.init());
    }
    else if (path.includes('merchant.html')) {
      import('./modules/merchant/dashboard.js').then(module => module.MerchantDashboard.init());
      import('./modules/merchant/transactions.js').then(module => module.MerchantTransactions.init());
    }
  }

  static showError(message) {
    DomHelper.showToast(message, 'error');
  }

  static showSuccess(message) {
    DomHelper.showToast(message, 'success');
  }
}

// Инициализация приложения
document.addEventListener('DOMContentLoaded', () => App.init());

// Экспорт глобальных сервисов
window.App = App;
window.ApiService = ApiService;
window.PollingService = PollingService;
window.DomHelper = DomHelper;
window.Utils = Utils;