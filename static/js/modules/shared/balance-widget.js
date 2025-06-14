// static/js/balance-widget.js
class BalanceWidget {
  static init() {
    if (!document.getElementById('balanceWidget')) return;
    
    this.pollingInterval = 30000;
    this.setupPolling();
    this.setupEventListeners();
  }

  static setupPolling() {
    PollingService.start(
      'balance',
      '/api/balance',
      (data) => this.updateBalance(data),
      this.pollingInterval
    );
  }

  static setupEventListeners() {
    document.getElementById('refreshBalance')?.addEventListener('click', () => {
      PollingService.stop('balance');
      this.loadBalance(true);
    });
  }

  static async loadBalance(force = false) {
    try {
      const data = await ApiService.get('/api/balance');
      this.updateBalance(data);
      
      if (force) {
        PollingService.start(
          'balance',
          '/api/balance',
          (data) => this.updateBalance(data),
          this.pollingInterval
        );
      }
    } catch (error) {
      App.showError('Ошибка загрузки баланса');
    }
  }

  static updateBalance(data) {
    const widget = document.getElementById('balanceWidget');
    if (!widget) return;

    widget.innerHTML = `
      <div class="card border-0 shadow-sm">
        <div class="card-body">
          <div class="d-flex justify-content-between align-items-center mb-3">
            <h5 class="card-title mb-0">Баланс</h5>
            <small class="text-muted">${Utils.formatDate(new Date(), { weekday: 'long', year: undefined })}</small>
          </div>
          <div class="balance-amount h4 mb-4">${Utils.formatCurrency(data.current)}</div>
          <div class="balance-details">
            <div class="d-flex justify-content-between mb-2">
              <span class="text-muted">Доступно:</span>
              <span class="fw-bold">${Utils.formatCurrency(data.available)}</span>
            </div>
            <div class="d-flex justify-content-between">
              <span class="text-muted">В обработке:</span>
              <span class="fw-bold">${Utils.formatCurrency(data.pending)}</span>
            </div>
          </div>
          <button id="refreshBalance" class="btn btn-sm btn-link mt-3 p-0">
            <i class="fas fa-sync-alt me-1"></i> Обновить
          </button>
        </div>
      </div>
    `;

    this.setupEventListeners();
  }
}

document.addEventListener('DOMContentLoaded', () => BalanceWidget.init());