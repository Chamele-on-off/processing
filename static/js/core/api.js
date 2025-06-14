// static/js/core/api.js
class ApiService {
  static async request(endpoint, options = {}) {
    const defaults = {
      method: 'GET',
      headers: {
        'Content-Type': 'application/json',
        'Accept': 'application/json'
      },
      credentials: 'include'
    };

    const config = { ...defaults, ...options };
    
    if (config.body && typeof config.body === 'object') {
      config.body = JSON.stringify(config.body);
    }

    try {
      const response = await fetch(`/api${endpoint}`, config);
      
      if (!response.ok) {
        const error = new Error(response.statusText);
        error.response = response;
        throw error;
      }

      return await response.json();
    } catch (error) {
      console.error(`API request failed: ${endpoint}`, error);
      
      if (error.response) {
        const details = await error.response.json().catch(() => ({}));
        DomHelper.showToast(details.error || 'Request failed', 'error');
      } else {
        DomHelper.showToast('Network error. Please try again.', 'error');
      }
      
      throw error;
    }
  }

  static get(endpoint) {
    return this.request(endpoint);
  }

  static post(endpoint, data) {
    return this.request(endpoint, { method: 'POST', body: data });
  }

  static put(endpoint, data) {
    return this.request(endpoint, { method: 'PUT', body: data });
  }

  static delete(endpoint) {
    return this.request(endpoint, { method: 'DELETE' });
  }
}