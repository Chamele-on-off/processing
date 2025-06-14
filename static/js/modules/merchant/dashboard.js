// static/js/modules/merchant/dashboard.js
class MerchantDashboard {
  static init() {
    if (!document.getElementById('merchant-dashboard')) return;
    
    this.initCharts();
    this.setupPolling();
    this.setupEventListeners();
  }

  static initCharts() {
    // Инициализация графика из данных сервера
    const ctx = document.getElementById('weeklyStatsChart');
    if (ctx) {
      this.chart = new Chart(ctx, {
        type: 'doughnut',
        data: {
          labels: JSON.parse(ctx.dataset.labels),
          datasets: [{
            data: JSON.parse(ctx.dataset.values),
            backgroundColor: [
              'rgba(40, 167, 69, 0.8)',
              'rgba(220, 53, 69, 0.8)',
              'rgba(255, 193, 7, 0.8)'
            ],
            borderWidth: 0
          }]
        },
        options: {
          maintainAspectRatio: false,
          cutout: '80%',
          plugins: {
            legend: {
              position: 'bottom'
            }
          }
        }
      });
    }
  }

  static setupPolling() {
    // Обновление статистики каждые 30 секунд
    PollingService.start(
      'merchant-stats',
      '/api/merchant/stats',
      (data) => this.updateStats(data),
      30000
    );

    // Обновление транзакций каждые 20 секунд
    PollingService.start(
      'recent-transactions',
      '/api/merchant/transactions/recent',
      (data) => this.updateRecentTransactions(data),
      20000
    );
  }

  static updateStats(data) {
    document.getElementById('available-balance').textContent = data.available_balance.toFixed(2) + ' ₽';
    document.getElementById('today-transactions').textContent = data.today_transactions;
    document.getElementById('avg-amount').textContent = data.avg_amount.toFixed(2) + ' ₽';
    document.getElementById('conversion-rate').textContent = data.conversion_rate + '%';

    // Обновление графика
    if (this.chart) {
      this.chart.data.datasets[0].data = data.weekly_stats.values;
      this.chart.update();
    }
  }

  static updateRecentTransactions(transactions) {
    const tbody = document.querySelector('#recentTransactions tbody');
    if (!tbody) return;

    tbody.innerHTML = transactions.map(tx => `
      <tr>
        <td>${tx.id}</td>
        <td>${tx.type === 'deposit' ? 'Пополнение' : 'Вывод'}</td>
        <td>${tx.amount.toFixed(2)} ₽</td>
        <td>
          <span class="badge bg-${tx.status === 'completed' ? 'success' : tx.status === 'pending' ? 'warning' : 'danger'}">
            ${tx.status === 'completed' ? 'Завершено' : tx.status === 'pending' ? 'В обработке' : 'Ошибка'}
          </span>
        </td>
        <td>${new Date(tx.created_at).toLocaleString()}</td>
      </tr>
    `).join('');
  }

  static setupEventListeners() {
    // Кнопки быстрых действий
    document.getElementById('depositBtn')?.addEventListener('click', () => {
      this.showDepositModal();
    });

    document.getElementById('withdrawalBtn')?.addEventListener('click', () => {
      this.showWithdrawalModal();
    });

    // Обновление по кнопке
    document.getElementById('refresh-dashboard')?.addEventListener('click', () => {
      PollingService.stop('merchant-stats');
      PollingService.stop('recent-transactions');
      this.setupPolling();
      DomHelper.showToast('Данные обновлены', 'success');
    });
  }

  static showDepositModal() {
    // Реализация модального окна пополнения
    const modal = new bootstrap.Modal('#depositModal');
    modal.show();
  }

  static showWithdrawalModal() {
    // Реализация модального окна вывода
    const modal = new bootstrap.Modal('#withdrawalModal');
    modal.show();
  }
}

document.addEventListener('DOMContentLoaded', () => MerchantDashboard.init());