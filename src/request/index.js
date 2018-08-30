var popsicle = require('popsicle')
var createProxy = require('popsicle-proxy-agent')
var proxy = createProxy({})

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
  return popsicle.get({
    url: url,
    body: body,
    method: method,
    headers: headers,
    transport: popsicle.createTransport({
      agent: proxy(url)
    })
  }).then(function (res) {
    return {
      status: res.status,
      body: res.body
    }
  })
}
