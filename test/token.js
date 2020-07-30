/* global describe, it, context */
var expect = require('chai').expect
var config = require('./support/config')
var ClientOAuth2 = require('../')

describe('token', function () {
  var uri = config.redirectUri + '#access_token=' + config.accessToken + '&token_type=bearer'

  var githubAuth = new ClientOAuth2({
    clientId: config.clientId,
    authorizationUri: config.authorizationUri,
    authorizationGrants: ['token'],
    redirectUri: config.redirectUri,
    scopes: ['notifications']
  })

  describe('#getUri', function () {
    it('should return a valid uri', function () {
      expect(githubAuth.token.getUri()).to.equal(
        config.authorizationUri + '?client_id=abc&' +
        'redirect_uri=http%3A%2F%2Fexample.com%2Fauth%2Fcallback&' +
        'response_type=token&state=&scope=notifications'
      )
    })
    context('when scopes are undefined', function () {
      it('should not include scope in the url', function () {
        var authWithoutScopes = new ClientOAuth2({
          clientId: config.clientId,
          authorizationUri: config.authorizationUri,
          authorizationGrants: ['token'],
          redirectUri: config.redirectUri
        })
        expect(authWithoutScopes.token.getUri()).to.equal(
          config.authorizationUri + '?client_id=abc&' +
          'redirect_uri=http%3A%2F%2Fexample.com%2Fauth%2Fcallback&' +
          'response_type=token&state='
        )
      })
    })
    it('should include empty scopes array as an empty string', function () {
      var authWithoutScopes = new ClientOAuth2({
        clientId: config.clientId,
        authorizationUri: config.authorizationUri,
        authorizationGrants: ['token'],
        redirectUri: config.redirectUri,
        scopes: []
      })
      expect(authWithoutScopes.token.getUri()).to.equal(
        config.authorizationUri + '?client_id=abc&' +
        'redirect_uri=http%3A%2F%2Fexample.com%2Fauth%2Fcallback&' +
        'response_type=token&state=&scope='
      )
    })
    it('should include empty scopes string as an empty string', function () {
      var authWithoutScopes = new ClientOAuth2({
        clientId: config.clientId,
        authorizationUri: config.authorizationUri,
        authorizationGrants: ['token'],
        redirectUri: config.redirectUri,
        scopes: ''
      })
      expect(authWithoutScopes.token.getUri()).to.equal(
        config.authorizationUri + '?client_id=abc&' +
        'redirect_uri=http%3A%2F%2Fexample.com%2Fauth%2Fcallback&' +
        'response_type=token&state=&scope='
      )
    })

    context('when authorizationUri contains query parameters', function () {
      it('should preserve query string parameters', function () {
        const authWithParams = new ClientOAuth2({
          clientId: config.clientId,
          authorizationUri: config.authorizationUri + '?bar=qux',
          authorizationGrants: ['token'],
          redirectUri: config.redirectUri,
          scopes: ['notifications']
        })
        expect(authWithParams.token.getUri()).to.equal(
          config.authorizationUri + '?bar=qux&client_id=abc&' +
          'redirect_uri=http%3A%2F%2Fexample.com%2Fauth%2Fcallback&' +
          'response_type=token&state=&scope=notifications'
        )
      })
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

    it('should fail if token not present', function (done) {
      githubAuth.token.getToken(config.redirectUri)
        .then(function (ignore) {
          done(new Error('Promise should fail'))
        }, function (reason) {
          done() // Promise is rejected - pass
        })
    })
  })
})
