/**
 * Support base64 in node like how it works in the browser.
 *
 * @param  {string} string
 * @return {string}
 */
function btoaBuffer (string) {
  return new Buffer(string).toString('base64')
}

module.exports = typeof Buffer === 'function' ? btoaBuffer : window.btoa
