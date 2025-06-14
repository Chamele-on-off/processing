class AdminDashboard {
  static init() {
    if (!document.getElementById('dashboard-section')) return;
    
    this.initCharts();
    this.setupPolling();
    this.setupEventListeners();
    this.initTransactionHandlers();
    this.initUserHandlers();
    DomHelper.initTooltips();
  }

  // [Все предыдущие методы остаются без изменений до setupEventListeners]

  static setupEventListeners() {
    // Обновление по кнопке
    document.getElementById('refresh-stats')?.addEventListener('click', () => {
      PollingService.stop('admin-stats');
      PollingService.stop('recent-transactions');
      PollingService.stop('pending-transactions');
      this.setupPolling();
      DomHelper.showToast('Данные обновлены', 'success');
    });

    // Переключение разделов
    document.querySelectorAll('[data-section]').forEach(item => {
      item.addEventListener('click', (e) => {
        e.preventDefault();
        const section = e.currentTarget.dataset.section;
        DomHelper.switchSection(`${section}-section`);
      });
    });

    // Обработка формы создания транзакции
    document.getElementById('newTransactionForm')?.addEventListener('submit', async (e) => {
      e.preventDefault();
      const form = e.currentTarget;
      const submitBtn = form.querySelector('button[type="submit"]');
      
      try {
        submitBtn.disabled = true;
        submitBtn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Создание...';
        
        const formData = new FormData(form);
        const response = await ApiService.post('/admin/transactions/create', formData);
        
        if (response.success) {
          DomHelper.showToast('Транзакция успешно создана', 'success');
          bootstrap.Modal.getInstance(form.closest('.modal')).hide();
          form.reset();
          
          // Обновляем списки транзакций
          const [pending, recent] = await Promise.all([
            PollingService.fetchData('/api/admin/transactions/pending'),
            PollingService.fetchData('/api/admin/transactions/recent')
          ]);
          this.updatePendingTransactions(pending);
          this.updateRecentTransactions(recent);
        }
      } catch (error) {
        DomHelper.showToast(`Ошибка: ${error.message}`, 'error');
      } finally {
        submitBtn.disabled = false;
        submitBtn.innerHTML = 'Создать';
      }
    });
  }

  static initUserHandlers() {
    // Обработка формы редактирования пользователя
    document.addEventListener('submit', async (e) => {
      if (e.target.matches('#editUserForm')) {
        e.preventDefault();
        const form = e.target;
        const submitBtn = form.querySelector('button[type="submit"]');
        
        try {
          submitBtn.disabled = true;
          submitBtn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Сохранение...';
          
          const formData = new FormData(form);
          const userId = form.dataset.userId;
          const response = await ApiService.post(`/admin/users/${userId}`, formData);
          
          if (response.success) {
            DomHelper.showToast('Пользователь успешно обновлен', 'success');
            // Можно добавить обновление списка пользователей
          }
        } catch (error) {
          DomHelper.showToast(`Ошибка: ${error.message}`, 'error');
        } finally {
          submitBtn.disabled = false;
          submitBtn.innerHTML = 'Сохранить';
        }
      }
    });
  }

  static initTransactionHandlers() {
    document.addEventListener('click', async (e) => {
      const btn = e.target.closest('.complete-tx');
      if (!btn) return;
      
      e.preventDefault();
      const txId = btn.dataset.txId;
      btn.disabled = true;
      btn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Обработка...';
      
      try {
        await this.completeTransaction(txId);
      } finally {
        btn.disabled = false;
        btn.innerHTML = '<i class="fas fa-check"></i> Подтвердить';
      }
    });
  }

static async completeTransaction(txId) {
    try {
        const btn = document.querySelector(`.complete-tx[data-tx-id="${txId}"]`);
        if (btn) {
            btn.disabled = true;
            btn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Обработка...';
        }

        const response = await ApiService.post(`/api/transactions/${txId}/complete`);
        
        if (!response.success) {
            throw new Error(response.error || 'Неизвестная ошибка');
        }

        DomHelper.showToast('Транзакция успешно подтверждена', 'success');
        
        // Обновляем конкретную строку в таблице
        const row = document.querySelector(`tr[data-tx-id="${txId}"]`);
        if (row) {
            const statusBadge = row.querySelector('.tx-status');
            if (statusBadge) {
                statusBadge.className = 'badge bg-success';
                statusBadge.textContent = 'completed';
            }
            
            const actionCell = row.querySelector('.tx-action');
            if (actionCell) actionCell.innerHTML = '';
        }

        // Полное обновление данных
        const [pending, recent] = await Promise.all([
            PollingService.fetchData('/api/admin/transactions/pending'),
            PollingService.fetchData('/api/admin/transactions/recent')
        ]);
        
        this.updatePendingTransactions(pending);
        this.updateRecentTransactions(recent);

    } catch (error) {
        console.error('Ошибка подтверждения транзакции:', error);
        DomHelper.showToast(`Ошибка: ${error.message}`, 'error');
        
        const btn = document.querySelector(`.complete-tx[data-tx-id="${txId}"]`);
        if (btn) {
            btn.disabled = false;
            btn.innerHTML = '<i class="fas fa-check"></i> Подтвердить';
        }
    }
  }
}

document.addEventListener('DOMContentLoaded', () => AdminDashboard.init());