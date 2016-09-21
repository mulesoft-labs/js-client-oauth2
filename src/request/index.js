var http = require('http')
var https = require('https')
var Url = require('url')
var createUnzip = require('zlib').createUnzip

/**
 * Make a request using node HTTP(s).
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
    var requestOptions = Url.parse(url)
    var lib = requestOptions.protocol === 'https:' ? https : http

    requestOptions.method = method
    requestOptions.headers = headers

    // Send the http request and listen for the response to finish.
    var request = lib.request(requestOptions, function (res) {
      var data = ''
      var stream = res
      var encoding = res.headers['content-encoding']

      if (encoding === 'deflate' || encoding === 'gzip') {
        var unzip = createUnzip()
        unzip.on('error', reject)
        stream.pipe(unzip)
        stream = unzip
      }

      stream.on('error', reject)

      stream.on('data', function (chunk) {
        data += chunk
      })

      stream.on('end', function () {
        return resolve({
          status: res.statusCode,
          body: data
        })
      })
    })

    request.on('error', reject)

    request.write(body)
    request.end()
  })
}
