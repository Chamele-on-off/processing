// static/js/core/transactions.js
class TransactionService {
  static async getTransactions(params = {}) {
    const query = new URLSearchParams(params).toString();
    return ApiService.get(`/transactions?${query}`);
  }

  static async createTransaction(data) {
    return ApiService.post('/transactions', data);
  }

  static async updateTransaction(id, data) {
    return ApiService.put(`/transactions/${id}`, data);
  }

  static async matchTransactions(depositId, payoutId) {
    return ApiService.post('/transactions/match', { depositId, payoutId });
  }

  static getStatusBadge(status) {
    const statuses = {
      'completed': { class: 'success', text: 'Завершено' },
      'pending': { class: 'warning', text: 'В обработке' },
      'failed': { class: 'danger', text: 'Ошибка' }
    };
    return statuses[status] || { class: 'secondary', text: status };
  }

  static async getRecentTransactions(limit = 5) {
    return this.getTransactions({
      limit,
      sort: '-created_at'
    });
  }

  static async getActiveTransactions() {
    return this.getTransactions({
      status: ['pending', 'processing'],
      sort: '-created_at'
    });
  }
}