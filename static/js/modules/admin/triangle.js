import { PollingService } from '../../core/polling.js';
import { ApiService } from '../../core/api.js';
import { DomHelper } from '../../core/dom.js';
import { Utils } from '../../utils.js';
import { platform } from '../../app.js';

class TriangleTransactions {
  static init() {
    if (!document.getElementById('triangleTransactions')) return;
    
    this.pollingInterval = 15000;
    this.initEventListeners();
    this.loadData();
  }

  static initEventListeners() {
    document.getElementById('refresh-triangle')?.addEventListener('click', () => {
      this.loadData();
    });

    document.getElementById('search-button')?.addEventListener('click', () => {
      this.searchTransactions();
    });
  }

  static async loadData() {
    try {
      DomHelper.toggleLoader(true);
      const [transactions, stats] = await Promise.all([
        ApiService.makeRequest('/api/triangle/transactions'),
        ApiService.makeRequest('/api/triangle/stats')
      ]);
      
      this.renderTransactions(transactions);
      this.updateStats(stats);
    } catch (error) {
      Utils.handleAPIError(error);
    } finally {
      DomHelper.toggleLoader(false);
    }
  }

  static renderTransactions(transactions) {
    DomHelper.renderTable(
      'triangleTransactions',
      transactions,
      (tx) => `
        <tr>
          <td>${tx.id}</td>
          <td>
            ${tx.deposits.map(d => `
              <div class="deposit-item">
                <a href="/admin/transactions/${d.id}" target="_blank">#${d.id}</a>
                <span>${Utils.formatCurrency(d.amount)}</span>
              </div>
            `).join('')}
          </td>
          <td>
            <a href="/admin/transactions/${tx.payout.id}" target="_blank">
              #${tx.payout.id}
            </a>
          </td>
          <td>${Utils.formatCurrency(tx.amount)}</td>
          <td>
            <span class="badge bg-${this.getStatusClass(tx.status)}">
              ${this.getStatusText(tx.status)}
            </span>
          </td>
          <td>${Utils.formatDate(tx.created_at)}</td>
          <td>
            <button class="btn btn-sm btn-outline-primary view-details" data-tx-id="${tx.id}">
              <i class="fas fa-eye"></i>
            </button>
            ${tx.status === 'pending' ? `
            <button class="btn btn-sm btn-outline-success confirm-transaction ms-1" data-tx-id="${tx.id}">
              <i class="fas fa-check"></i>
            </button>` : ''}
          </td>
        </tr>
      `
    );
  }

  static async searchTransactions() {
    const query = document.getElementById('triangle-search')?.value;
    if (!query || query.length < 2) return;

    try {
      const transactions = await ApiService.makeRequest(`/api/triangle/search?q=${encodeURIComponent(query)}`);
      this.renderTransactions(transactions);
    } catch (error) {
      Utils.handleAPIError(error);
    }
  }

  static async showDetails(txId) {
    try {
      const details = await ApiService.makeRequest(`/api/triangle/transaction/${txId}`);
      // Показать модальное окно с деталями
      console.log('Transaction details:', details);
    } catch (error) {
      platform.showError('Не удалось загрузить детали транзакции');
    }
  }

  static async confirmTransaction(txId) {
    try {
      await ApiService.makeRequest(`/api/triangle/transaction/${txId}/confirm`, 'POST');
      this.loadData();
      platform.showSuccess('Транзакция подтверждена');
    } catch (error) {
      platform.showError('Ошибка при подтверждении транзакции');
    }
  }

  static updateStats(stats) {
    document.getElementById('triangleEfficiency')?.textContent = `${stats.efficiency}%`;
    document.getElementById('triangleVolume')?.textContent = Utils.formatCurrency(stats.volume);
  }

  static getStatusClass(status) {
    switch (status) {
      case 'completed': return 'success';
      case 'pending': return 'warning';
      case 'failed': return 'danger';
      default: return 'secondary';
    }
  }

  static getStatusText(status) {
    switch (status) {
      case 'completed': return 'Завершено';
      case 'pending': return 'В обработке';
      case 'failed': return 'Ошибка';
      default: return status;
    }
  }
}

export { TriangleTransactions };