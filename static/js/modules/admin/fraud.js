// static/js/modules/admin/fraud.js
class FraudMonitor {
  static init() {
    if (!document.getElementById('fraud-alerts')) return;
    
    this.setupPolling();
    this.setupEventListeners();
  }

  static setupPolling() {
    PollingService.start(
      'fraud-alerts',
      '/api/admin/fraud/alerts',
      (data) => this.renderAlerts(data),
      15000
    );
  }

  static renderAlerts(alerts) {
    const container = document.getElementById('fraud-alerts');
    if (!container) return;

    container.innerHTML = alerts.map(alert => `
      <div class="card mb-3 border-${alert.severity === 'high' ? 'danger' : 'warning'}">
        <div class="card-body">
          <div class="d-flex justify-content-between mb-2">
            <h5 class="card-title mb-0">#${alert.id} - ${alert.type}</h5>
            <small class="text-muted">${new Date(alert.timestamp).toLocaleString()}</small>
          </div>
          <p class="card-text">${alert.message}</p>
          <div class="d-flex justify-content-end">
            <button class="btn btn-sm btn-success me-2 resolve-btn" data-alert-id="${alert.id}">
              <i class="fas fa-check me-1"></i> Разрешить
            </button>
            <button class="btn btn-sm btn-danger block-btn" data-alert-id="${alert.id}">
              <i class="fas fa-ban me-1"></i> Блокировать
            </button>
          </div>
        </div>
      </div>
    `).join('');
  }

  static setupEventListeners() {
    document.getElementById('fraud-alerts')?.addEventListener('click', (e) => {
      const alertId = e.target.closest('button')?.dataset.alertId;
      if (!alertId) return;

      if (e.target.closest('.resolve-btn')) {
        this.resolveAlert(alertId);
      } else if (e.target.closest('.block-btn')) {
        this.blockUser(alertId);
      }
    });

    document.getElementById('refresh-fraud')?.addEventListener('click', () => {
      PollingService.stop('fraud-alerts');
      this.setupPolling();
      DomHelper.showToast('Мониторинг обновлен', 'info');
    });
  }

  static async resolveAlert(alertId) {
    try {
      await ApiService.post(`/api/admin/fraud/alerts/${alertId}/resolve`);
      DomHelper.showToast('Алерт разрешен', 'success');
    } catch (error) {
      DomHelper.showToast('Ошибка при разрешении алерта', 'error');
    }
  }

  static async blockUser(alertId) {
    try {
      await ApiService.post(`/api/admin/fraud/alerts/${alertId}/block`);
      DomHelper.showToast('Пользователь заблокирован', 'success');
    } catch (error) {
      DomHelper.showToast('Ошибка при блокировке', 'error');
    }
  }
}

document.addEventListener('DOMContentLoaded', () => FraudMonitor.init());