/* global describe, it, btoa */
var expect = require('chai').expect
var ClientOAuth2 = require('../')

describe('credentials', function () {
  var accessTokenUri = 'https://github.com/login/oauth/access_token'

  var accessToken = '4430eb16f4f6577c0f3a15fb6127cbf828a8e403'
  var refreshToken = accessToken.split('').reverse().join('')
  var refreshAccessToken = 'def456token'

  var githubAuth = new ClientOAuth2({
    clientId: 'abc',
    clientSecret: '123',
    accessTokenUri: accessTokenUri,
    authorizationGrants: ['credentials'],
    scopes: ['notifications']
  })

  githubAuth._request = function (req) {
    if (req.method === 'POST' && req.url === accessTokenUri) {
      var isRefreshToken = req.body.grant_type === 'refresh_token'

      expect(req.headers.Authorization).to.equal('Basic ' + btoa('abc:123'))

      if (isRefreshToken) {
        expect(req.body.refresh_token).to.equal(refreshToken)
      }

      return Promise.resolve({
        status: 200,
        body: {
          access_token: isRefreshToken ? refreshAccessToken : accessToken,
          refresh_token: refreshToken,
          token_type: 'bearer',
          scope: 'notifications'
        },
        headers: {
          'content-type': 'application/json'
        }
      })
    }

    return Promise.reject(new TypeError('Not here'))
  }

  describe('#getToken', function () {
    it('should request the token', function () {
      return githubAuth.credentials.getToken()
        .then(function (user) {
          expect(user).to.an.instanceOf(ClientOAuth2.Token)
          expect(user.accessToken).to.equal(accessToken)
          expect(user.tokenType).to.equal('bearer')
        })
    })

    describe('#sign', function () {
      it('should be able to sign a standard request object', function () {
        return githubAuth.credentials.getToken()
          .then(function (token) {
            var obj = token.sign({
              method: 'GET',
              url: 'http://api.github.com/user'
            })
            expect(obj.headers.Authorization).to.equal('Bearer ' + accessToken)
          })
      })
    })

    describe('#refresh', function () {
      it('should make a request to get a new access token', function () {
        return githubAuth.credentials.getToken()
          .then(function (token) {
            return token.refresh()
          })
          .then(function (token) {
            expect(token).to.an.instanceOf(ClientOAuth2.Token)
            expect(token.accessToken).to.equal('def456token')
            expect(token.tokenType).to.equal('bearer')
          })
      })
    })
  })
})
