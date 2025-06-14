// static/js/core/polling.js
class PollingService {
  static instances = new Map();

  static start(name, endpoint, callback, interval = 10000) {
    this.stop(name);
    
    const execute = async () => {
      try {
        const data = await ApiService.get(endpoint);
        callback(data);
      } catch (error) {
        console.error(`Polling error [${name}]:`, error);
        setTimeout(execute, 5000);
      }
    };

    execute();
    const timer = setInterval(execute, interval);
    
    this.instances.set(name, { timer, endpoint, callback, interval });
  }

  static stop(name) {
    const instance = this.instances.get(name);
    if (instance) {
      clearInterval(instance.timer);
      this.instances.delete(name);
    }
  }

  static stopAll() {
    this.instances.forEach((_, name) => this.stop(name));
  }
}