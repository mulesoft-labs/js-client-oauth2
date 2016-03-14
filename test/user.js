/* global describe, it, btoa */
var expect = require('chai').expect
var ClientOAuth2 = require('../')

describe('user', function () {
  var accessTokenUri = 'https://github.com/login/oauth/access_token'
  var authorizationUri = 'https://github.com/login/oauth/authorize'

  var accessToken = '4430eb16f4f6577c0f3a15fb6127cbf828a8e403'
  var refreshToken = accessToken.split('').reverse().join('')
  var refreshAccessToken = 'def456token'
  var refreshRefreshToken = refreshAccessToken.split('').reverse().join('')

  var githubAuth = new ClientOAuth2({
    clientId: 'abc',
    clientSecret: '123',
    accessTokenUri: accessTokenUri,
    authorizationUri: authorizationUri,
    authorizationGrants: ['code'],
    redirectUri: 'http://example.com/auth/callback',
    scopes: 'notifications'
  })

  githubAuth.request = function (req) {
    if (req.method === 'POST' && req.url === accessTokenUri) {
      expect(req.headers.Authorization).to.equal('Basic ' + btoa('abc:123'))
      expect(req.body.grant_type).to.equal('refresh_token')
      expect(req.body.refresh_token).to.equal(refreshToken)
      expect(req.body.test).to.equal(true)

      return Promise.resolve({
        status: 200,
        body: {
          access_token: refreshAccessToken,
          refresh_token: refreshRefreshToken,
          expires_in: 3000
        },
        headers: {
          'content-type': 'application/json'
        }
      })
    }

    if (req.method === 'GET' && req.url === 'http://api.github.com/user') {
      expect(req.headers.Authorization).to.equal('Bearer ' + accessToken)

      return Promise.resolve({
        status: 200,
        body: {
          username: 'blakeembrey'
        },
        headers: {
          'content-type': 'application/json'
        }
      })
    }
  }

  var user = githubAuth.createToken(accessToken, refreshToken, 'bearer')
  user.expiresIn(0)

  describe('#sign', function () {
    it('should be able to sign a standard request object', function () {
      var obj = user.sign({
        method: 'GET',
        url: 'http://api.github.com/user',
        headers: {
          'accept': '*/*'
        }
      })

      expect(obj.headers.Authorization).to.equal('Bearer ' + accessToken)
    })
  })

  describe('#request', function () {
    it('should make a request on behalf of the user', function () {
      return user.request({
        method: 'GET',
        url: 'http://api.github.com/user'
      })
        .then(function (res) {
          expect(res.status).to.equal(200)
          expect(res.body).to.deep.equal({ username: 'blakeembrey' })
          expect(res.headers).to.deep.equal({
            'content-type': 'application/json'
          })
        })
    })
  })

  describe('#refresh', function () {
    it('should make a request to get a new access token', function () {
      expect(user.accessToken).to.equal(accessToken)
      expect(user.tokenType).to.equal('bearer')

      return user.refresh({ body: { test: true } })
        .then(function (token) {
          expect(token).to.an.instanceOf(ClientOAuth2.Token)
          expect(token.accessToken).to.equal(refreshAccessToken)
          expect(token.tokenType).to.equal('bearer')
          expect(token.refreshToken).to.equal(refreshRefreshToken)
        })
    })
  })

  describe('#expired', function () {
    it('should return false when token is not expired', function () {
      user.expiresIn(10)
      expect(user.expired()).to.be.equal(false)
    })

    it('should return true when token is expired', function () {
      user.expiresIn(-10)
      expect(user.expired()).to.be.equal(true)
    })
  })
})
