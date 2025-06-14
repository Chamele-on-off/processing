// static/js/modules/admin/matching.js
class TransactionMatching {
  static init() {
    if (!document.getElementById('matching-section')) return;
    
    this.setupPolling();
    this.setupEventListeners();
  }

  static setupPolling() {
    PollingService.start(
      'pending-matches',
      '/api/admin/matching/pending',
      (data) => this.renderPendingMatches(data),
      10000
    );

    PollingService.start(
      'completed-matches',
      '/api/admin/matching/completed',
      (data) => this.renderCompletedMatches(data),
      30000
    );
  }

  static renderPendingMatches(matches) {
    const container = document.getElementById('pending-matches');
    if (!container) return;

    container.innerHTML = matches.map(match => `
      <tr>
        <td>${match.id}</td>
        <td><a href="/admin/transactions/${match.deposit_id}">#${match.deposit_id}</a></td>
        <td><a href="/admin/transactions/${match.withdrawal_id}">#${match.withdrawal_id}</a></td>
        <td>${match.amount.toFixed(2)} ₽</td>
        <td>${new Date(match.created_at).toLocaleString()}</td>
        <td>
          <button class="btn btn-sm btn-success me-2 confirm-match" data-match-id="${match.id}">
            <i class="fas fa-check"></i>
          </button>
          <button class="btn btn-sm btn-danger reject-match" data-match-id="${match.id}">
            <i class="fas fa-times"></i>
          </button>
        </td>
      </tr>
    `).join('');
  }

  static renderCompletedMatches(matches) {
    const container = document.getElementById('completed-matches');
    if (!container) return;

    container.innerHTML = matches.map(match => `
      <tr>
        <td>${match.id}</td>
        <td><a href="/admin/transactions/${match.deposit_id}">#${match.deposit_id}</a></td>
        <td><a href="/admin/transactions/${match.withdrawal_id}">#${match.withdrawal_id}</a></td>
        <td>${match.amount.toFixed(2)} ₽</td>
        <td>${new Date(match.completed_at).toLocaleString()}</td>
      </tr>
    `).join('');
  }

  static setupEventListeners() {
    document.addEventListener('click', (e) => {
      const matchId = e.target.closest('button')?.dataset.matchId;
      if (!matchId) return;

      if (e.target.closest('.confirm-match')) {
        this.confirmMatch(matchId);
      } else if (e.target.closest('.reject-match')) {
        this.rejectMatch(matchId);
      }
    });

    document.getElementById('autoMatchingToggle')?.addEventListener('change', (e) => {
      this.toggleAutoMatching(e.target.checked);
    });
  }

  static async confirmMatch(matchId) {
    try {
      await ApiService.post(`/api/admin/matching/${matchId}/confirm`);
      DomHelper.showToast('Матчинг подтвержден', 'success');
    } catch (error) {
      DomHelper.showToast('Ошибка при подтверждении', 'error');
    }
  }

  static async rejectMatch(matchId) {
    try {
      await ApiService.post(`/api/admin/matching/${matchId}/reject`);
      DomHelper.showToast('Матчинг отклонен', 'success');
    } catch (error) {
      DomHelper.showToast('Ошибка при отклонении', 'error');
    }
  }

  static async toggleAutoMatching(enabled) {
    try {
      await ApiService.post('/api/admin/matching/auto', { enabled });
      DomHelper.showToast(
        `Автоматический матчинг ${enabled ? 'включен' : 'выключен'}`,
        'info'
      );
    } catch (error) {
      DomHelper.showToast('Ошибка при изменении настроек', 'error');
    }
  }
}

document.addEventListener('DOMContentLoaded', () => TransactionMatching.init());