var popsicle = require('popsicle')

/**
 * Make a request using node.
 *
 * @param   {string}  method
 * @param   {string}  url
 * @param   {string}  body
 * @param   {Object}  headers
 * @returns {Promise}
 */
module.exports = function request (method, url, body, headers) {
  var request = popsicle.request(url, {
    body: body,
    method: method,
    headers: headers
  })

  return popsicle.transport({negotiateHttpVersion: 0})(request).then(function (res) {
    return res.body.text().then(function (content) {
      return {
        status: res.statusCode,
        body: content
      }
    })
  })
}
