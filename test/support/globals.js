if (typeof window === 'object') {
  window.ES6Promise.polyfill()
} else {
  require('es6-promise').polyfill()

  global.expect = require('chai').expect
  global.ClientOAuth2 = require('../../')

  global.btoa = function (str) {
    return new Buffer(str).toString('base64')
  }
}
