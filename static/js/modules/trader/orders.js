class TraderOrders {
  static init() {
    if (!document.getElementById('orders-section')) return;
    
    this.setupEventListeners();
  }

  static setupEventListeners() {
    document.addEventListener('click', async (e) => {
      const btn = e.target.closest('button');
      if (!btn) return;
      
      const orderId = btn.dataset.orderId;
      if (!orderId) return;

      try {
        if (btn.classList.contains('view-order')) {
          await this.viewOrderDetails(orderId);
        } else if (btn.classList.contains('complete-order')) {
          await this.completeOrder(orderId);
        } else if (btn.classList.contains('cancel-order')) {
          await this.cancelOrder(orderId);
        }
      } catch (error) {
        console.error('Error:', error);
        alert('Ошибка: ' + error.message);
      }
    });

    document.getElementById('newOrderBtn')?.addEventListener('click', () => {
      bootstrap.Modal.getOrCreateInstance('#newOrderModal').show();
    });
  }

  static async viewOrderDetails(orderId) {
    const response = await fetch(`/api/trader/orders/${orderId}`);
    if (!response.ok) throw new Error('Failed to fetch order');
    const order = await response.json();
    console.log('Order details:', order);
  }

  static async completeOrder(orderId) {
    const response = await fetch(`/api/trader/orders/${orderId}/complete`, {
      method: 'POST',
      headers: {
        'X-CSRF-Token': document.querySelector('meta[name="csrf-token"]').content
      }
    });
    if (!response.ok) throw new Error('Failed to complete order');
    alert('Заявка завершена');
    location.reload();
  }

  static async cancelOrder(orderId) {
    const response = await fetch(`/api/trader/orders/${orderId}/cancel`, {
      method: 'POST',
      headers: {
        'X-CSRF-Token': document.querySelector('meta[name="csrf-token"]').content
      }
    });
    if (!response.ok) throw new Error('Failed to cancel order');
    alert('Заявка отменена');
    location.reload();
  }
}

document.addEventListener('DOMContentLoaded', () => TraderOrders.init());