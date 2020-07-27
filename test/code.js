/* global describe, it, context */
var expect = require('chai').expect
var config = require('./support/config')
var ClientOAuth2 = require('../')

describe('code', function () {
  var uri = '/auth/callback?code=' + config.code + '&state=' + config.state

  var githubAuth = new ClientOAuth2({
    clientId: config.clientId,
    clientSecret: config.clientSecret,
    accessTokenUri: config.accessTokenUri,
    authorizationUri: config.authorizationUri,
    authorizationGrants: ['code'],
    redirectUri: config.redirectUri,
    scopes: 'notifications'
  })

  describe('#getUri', function () {
    it('should return a valid uri', function () {
      expect(githubAuth.code.getUri()).to.equal(
        config.authorizationUri + '?client_id=abc&' +
        'redirect_uri=http%3A%2F%2Fexample.com%2Fauth%2Fcallback&' +
        'response_type=code&state=&scope=notifications'
      )
    })
    it('should omit empty scopes', function () {
      var authWithoutScopes = new ClientOAuth2({
        clientId: config.clientId,
        clientSecret: config.clientSecret,
        accessTokenUri: config.accessTokenUri,
        authorizationUri: config.authorizationUri,
        authorizationGrants: ['code'],
        redirectUri: config.redirectUri,
        scopes: ''
      })
      expect(authWithoutScopes.code.getUri()).to.equal(
        config.authorizationUri + '?client_id=abc&' +
        'redirect_uri=http%3A%2F%2Fexample.com%2Fauth%2Fcallback&' +
        'response_type=code&state='
      )
    })
    context('when authorizationUri contains query parameters', function () {
      it('should preserve query string parameters', function () {
        const authWithParams = new ClientOAuth2({
          clientId: config.clientId,
          clientSecret: config.clientSecret,
          accessTokenUri: config.accessTokenUri,
          authorizationUri: config.authorizationUri + '?bar=qux',
          authorizationGrants: ['code'],
          redirectUri: config.redirectUri,
          scopes: 'notifications'
        })
        expect(authWithParams.code.getUri()).to.equal(
          config.authorizationUri + '?bar=qux&client_id=abc&' +
          'redirect_uri=http%3A%2F%2Fexample.com%2Fauth%2Fcallback&' +
          'scope=notifications&response_type=code&state='
        )
      })
    })
  })

  describe('#getToken', function () {
    it('should request the token', function () {
      return githubAuth.code.getToken(uri)
        .then(function (user) {
          expect(user).to.an.instanceOf(ClientOAuth2.Token)
          expect(user.accessToken).to.equal(config.accessToken)
          expect(user.tokenType).to.equal('bearer')
        })
    })

    it('should reject with auth errors', function () {
      var errored = false

      return githubAuth.code.getToken(config.redirectUri + '?error=invalid_request')
        .catch(function (err) {
          errored = true

          expect(err.code).to.equal('EAUTH')
          expect(err.body.error).to.equal('invalid_request')
        })
        .then(function () {
          expect(errored).to.equal(true)
        })
    })

    describe('#sign', function () {
      it('should be able to sign a standard request object', function () {
        return githubAuth.code.getToken(uri)
          .then(function (token) {
            var obj = token.sign({
              method: 'GET',
              url: 'http://api.github.com/user'
            })

            expect(obj.headers.Authorization).to.equal('Bearer ' + config.accessToken)
          })
      })
    })

    describe('#refresh', function () {
      it('should make a request to get a new access token', function () {
        return githubAuth.code.getToken(uri, { state: config.state })
          .then(function (token) {
            return token.refresh()
          })
          .then(function (token) {
            expect(token).to.an.instanceOf(ClientOAuth2.Token)
            expect(token.accessToken).to.equal(config.refreshAccessToken)
            expect(token.tokenType).to.equal('bearer')
          })
      })
    })
  })
})
