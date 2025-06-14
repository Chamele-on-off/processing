// static/js/auth.js
class Auth {
  static async login(email, password) {
    try {
      DomHelper.toggleLoader(true);
      const response = await ApiService.post('/api/login', { email, password });
      
      if (response.success) {
        App.showSuccess('Вход выполнен успешно');
        window.location.href = response.redirect || `/${response.user.role}.html`;
        return true;
      } else {
        throw new Error(response.error || 'Ошибка входа');
      }
    } catch (error) {
      App.showError(error.message);
      return false;
    } finally {
      DomHelper.toggleLoader(false);
    }
  }

  static async logout() {
    try {
      await ApiService.post('/api/logout');
      window.location.href = '/login.html';
    } catch (error) {
      App.showError('Ошибка при выходе');
    }
  }

  static setupLoginForm() {
    const form = document.getElementById('loginForm');
    if (!form) return;

    form.addEventListener('submit', async (e) => {
      e.preventDefault();
      const email = form.querySelector('[name="email"]').value;
      const password = form.querySelector('[name="password"]').value;
      await Auth.login(email, password);
    });
  }
}

// Инициализация формы входа
document.addEventListener('DOMContentLoaded', () => {
  Auth.setupLoginForm();

  // Кнопка выхода
  document.querySelectorAll('.logout-btn').forEach(btn => {
    btn.addEventListener('click', Auth.logout);
  });
});