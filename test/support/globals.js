Object.assign = Object.assign || require('object-assign')
global.Promise = global.Promise || require('es6-promise').Promise

global.btoa = global.btoa || function (str) {
  return new Buffer(str).toString('base64')
}
