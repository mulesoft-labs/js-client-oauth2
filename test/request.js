/* global describe, it, expect, ClientOAuth2 */

describe('request', function () {
  var githubAuth = new ClientOAuth2({
    options: {
      agent: 'custom agent',
      rejectUnauthorized: true
    },
    body: {
      foo: 'bar'
    }
  })

  var user = githubAuth.createToken('123', 'abc', 'bearer')

  githubAuth.request = function (opts) {
    expect(opts.body).to.deep.equal({ foo: 'bar', example: 'data' })
    expect(opts.options).to.deep.equal({ agent: 'custom agent', rejectUnauthorized: true })

    return Promise.resolve({})
  }

  it('should pass through certain options to the request', function () {
    return user.request({
      method: 'GET',
      url: 'http://api.github.com/user',
      body: {
        example: 'data'
      }
    })
  })
})
