/* global describe, it, context */
var expect = require('chai').expect
var config = require('./support/config')
var ClientOAuth2 = require('../')

describe('jwt', function () {
  var githubAuth = new ClientOAuth2({
    clientId: config.clientId,
    clientSecret: config.clientSecret,
    accessTokenUri: config.accessTokenUri,
    authorizationGrants: ['jwt'],
    scopes: ['notifications']
  })

  describe('#getToken', function () {
    it('should request the token', function () {
      return githubAuth.jwt.getToken(config.jwt)
        .then(function (user) {
          expect(user).to.an.instanceOf(ClientOAuth2.Token)
          expect(user.accessToken).to.equal(config.accessToken)
          expect(user.tokenType).to.equal('bearer')
          expect(user.data.scope).to.equal('notifications')
        })
    })
    context('when scopes are undefined', function () {
      it('should not send scopes to an auth server', function () {
        var scopelessAuth = new ClientOAuth2({
          clientId: config.clientId,
          clientSecret: config.clientSecret,
          accessTokenUri: config.accessTokenUri,
          authorizationGrants: ['jwt']
        })
        return scopelessAuth.jwt.getToken(config.jwt)
          .then(function (user) {
            expect(user).to.an.instanceOf(ClientOAuth2.Token)
            expect(user.accessToken).to.equal(config.accessToken)
            expect(user.tokenType).to.equal('bearer')
            expect(user.data.scope).to.equal(undefined)
          })
      })
    })
    context('when scopes are an empty array', function () {
      it('should send empty scope string to an auth server', function () {
        var scopelessAuth = new ClientOAuth2({
          clientId: config.clientId,
          clientSecret: config.clientSecret,
          accessTokenUri: config.accessTokenUri,
          authorizationGrants: ['jwt'],
          scopes: []
        })
        return scopelessAuth.jwt.getToken(config.jwt)
          .then(function (user) {
            expect(user).to.an.instanceOf(ClientOAuth2.Token)
            expect(user.accessToken).to.equal(config.accessToken)
            expect(user.tokenType).to.equal('bearer')
            expect(user.data.scope).to.equal('')
          })
      })
    })
    context('when scopes are an empty array', function () {
      it('should send empty scope string to an auth server', function () {
        var scopelessAuth = new ClientOAuth2({
          clientId: config.clientId,
          clientSecret: config.clientSecret,
          accessTokenUri: config.accessTokenUri,
          authorizationGrants: ['jwt'],
          scopes: ''
        })
        return scopelessAuth.jwt.getToken(config.jwt)
          .then(function (user) {
            expect(user).to.an.instanceOf(ClientOAuth2.Token)
            expect(user.accessToken).to.equal(config.accessToken)
            expect(user.tokenType).to.equal('bearer')
            expect(user.data.scope).to.equal('')
          })
      })
    })

    describe('#sign', function () {
      it('should be able to sign a standard request object', function () {
        return githubAuth.jwt.getToken(config.jwt)
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
        return githubAuth.jwt.getToken(config.jwt)
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
