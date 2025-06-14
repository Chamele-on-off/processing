class TraderDashboard {
  static init() {
    if (!document.getElementById('trader-dashboard')) return;
    
    this.initCharts();
    this.setupEventListeners();
  }

  static initCharts() {
    const ctx = document.getElementById('weeklyStatsChart');
    if (ctx) {
      this.chart = new Chart(ctx, {
        type: 'doughnut',
        data: {
          labels: ['Успешно', 'Отклонено', 'В процессе'],
          datasets: [{
            data: [30, 10, 5],
            backgroundColor: [
              'rgba(40, 167, 69, 0.8)',
              'rgba(220, 53, 69, 0.8)',
              'rgba(255, 193, 7, 0.8)'
            ]
          }]
        }
      });
    }
  }

  static setupEventListeners() {
    document.getElementById('enableDepositBtn')?.addEventListener('click', async () => {
      try {
        await this.toggleDeposits(true);
      } catch (error) {
        console.error('Error:', error);
      }
    });

    document.getElementById('disableDepositBtn')?.addEventListener('click', async () => {
      try {
        await this.toggleDeposits(false);
      } catch (error) {
        console.error('Error:', error);
      }
    });

    document.getElementById('addDetailsBtn')?.addEventListener('click', () => {
      bootstrap.Modal.getOrCreateInstance('#addDetailsModal').show();
    });
  }

  static async toggleDeposits(enable) {
    const response = await fetch('/api/trader/deposits/toggle', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-CSRF-Token': document.querySelector('meta[name="csrf-token"]').content
      },
      body: JSON.stringify({ enable })
    });
    
    if (!response.ok) {
      throw new Error('Failed to toggle deposits');
    }
    
    const result = await response.json();
    if (result.success) {
      alert(`Депозиты ${enable ? 'включены' : 'выключены'}`);
    }
  }
}

document.addEventListener('DOMContentLoaded', () => TraderDashboard.init());