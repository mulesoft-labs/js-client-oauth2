var popsicle = require('popsicle')

/**
 * Make a request using node.
 *
 * @param   {String}  method
 * @param   {String}  url
 * @param   {String}  body
 * @param   {Object}  headers
 * @returns {Promise}
 */
module.exports = function request (method, url, body, headers) {
  return popsicle.get({
    url: url,
    body: body,
    method: method,
    headers: headers
  }).then(function (res) {
    return {
      status: res.status,
      body: res.body
    }
  })
}
