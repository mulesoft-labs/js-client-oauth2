require('es6-promise').polyfill()

if (!global.btoa) {
  global.btoa = function (str) {
    return new Buffer(str).toString('base64')
  }
}
