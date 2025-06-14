// static/js/modules/trader/notifications.js
class TraderNotifications {
  static init() {
    if (!document.getElementById('notifications-container')) return;
    
    this.setupPolling();
    this.setupEventListeners();
  }

  static setupPolling() {
    // Обновление уведомлений каждые 25 секунд
    PollingService.start(
      'trader-notifications',
      '/api/trader/notifications',
      (data) => this.renderNotifications(data),
      25000
    );
  }

  static renderNotifications(notifications) {
    const container = document.getElementById('notifications-container');
    if (!container) return;

    container.innerHTML = notifications.map(notification => `
      <div class="alert alert-${notification.type} alert-dismissible fade show">
        <div class="d-flex justify-content-between">
          <div>
            <strong>${notification.title}</strong>
            <p class="mb-0">${notification.message}</p>
          </div>
          <small>${new Date(notification.created_at).toLocaleTimeString()}</small>
        </div>
        <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
      </div>
    `).join('');
  }

  static setupEventListeners() {
    // Кнопка обновления
    document.getElementById('refresh-notifications')?.addEventListener('click', () => {
      PollingService.stop('trader-notifications');
      this.setupPolling();
      DomHelper.showToast('Уведомления обновлены', 'info');
    });

    // Пометить как прочитанные
    document.getElementById('mark-all-read')?.addEventListener('click', () => {
      this.markAllAsRead();
    });
  }

  static async markAllAsRead() {
    try {
      await ApiService.post('/api/trader/notifications/mark-read');
      DomHelper.showToast('Все уведомления прочитаны', 'success');
    } catch (error) {
      DomHelper.showToast('Ошибка при обновлении статуса', 'error');
    }
  }
}

document.addEventListener('DOMContentLoaded', () => TraderNotifications.init());