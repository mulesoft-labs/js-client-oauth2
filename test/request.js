/* global describe, it, expect, ClientOAuth2 */

describe('request', function () {
  var githubAuth = new ClientOAuth2({
    agent: 'custom agent',
    rejectUnauthorized: true
  })

  var user = githubAuth.createToken('123', 'abc', 'bearer')

  githubAuth.request = function (opts) {
    expect(opts.agent).to.equal('custom agent')
    expect(opts.rejectUnauthorized).to.be.true

    return Promise.resolve({})
  }

  it('should pass through certain options to the request', function () {
    return user.request({
      method: 'GET',
      url: 'http://api.github.com/user'
    })
  })
})
