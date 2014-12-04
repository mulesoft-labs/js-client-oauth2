if (typeof window === 'object') {
  window.ES6Promise.polyfill();
} else {
  require('es6-promise').polyfill();
}
