/**
 * Make a request using `XMLHttpRequest`.
 *
 * @param   {String}  method
 * @param   {String}  url
 * @param   {String}  body
 * @param   {Object}  headers
 * @param   {Promise} Promise
 * @returns {Promise}
 */
module.exports = function request (method, url, body, headers, Promise) {
  return new Promise(function (resolve, reject) {
    var xhr = new window.XMLHttpRequest()

    xhr.open(method, url)

    xhr.onload = function () {
      return resolve({
        status: xhr.status,
        body: xhr.responseText
      })
    }

    xhr.onerror = xhr.onabort = function () {
      return reject(new Error(xhr.statusText || 'XHR aborted: ' + url))
    }

    Object.keys(headers).forEach(function (header) {
      xhr.setRequestHeader(header, headers[header])
    })

    xhr.send(body)
  })
}
