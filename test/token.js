/* global describe, it */
var expect = require('chai').expect
var config = require('./support/config')
var ClientOAuth2 = require('../')

describe('token', function () {
  var uri = 'http://example.com/auth/callback#access_token=' + config.accessToken + '&token_type=bearer'

  var githubAuth = new ClientOAuth2({
    clientId: config.clientId,
    authorizationUri: config.authorizationUri,
    authorizationGrants: ['token'],
    redirectUri: 'http://example.com/auth/callback',
    scopes: ['notifications']
  })

  describe('#getUri', function () {
    it('should return a valid uri', function () {
      expect(githubAuth.token.getUri()).to.equal(
        config.authorizationUri + '?client_id=abc&' +
        'redirect_uri=http%3A%2F%2Fexample.com%2Fauth%2Fcallback&' +
        'scope=notifications&response_type=token&state='
      )
    })
  })

  describe('#getToken', function () {
    it('should parse the token from the response', function () {
      return githubAuth.token.getToken(uri)
        .then(function (user) {
          expect(user).to.an.instanceOf(ClientOAuth2.Token)
          expect(user.accessToken).to.equal(config.accessToken)
          expect(user.tokenType).to.equal('bearer')
        })
    })

    describe('#sign', function () {
      it('should be able to sign a standard request object', function () {
        return githubAuth.token.getToken(uri)
          .then(function (token) {
            var obj = token.sign({
              method: 'GET',
              url: 'http://api.github.com/user'
            })

            expect(obj.headers.Authorization).to.equal('Bearer ' + config.accessToken)
          })
      })
    })
  })
})
