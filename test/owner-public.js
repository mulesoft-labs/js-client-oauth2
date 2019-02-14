/* global describe, it */
var expect = require('chai').expect
var config = require('./support/config')
var ClientOAuth2 = require('../')

describe('owner public', function () {
  var githubAuth = new ClientOAuth2({
    clientId: config.clientId,
    accessTokenUri: config.accessTokenUri,
    authorizationGrants: ['owner'],
    scope: 'notifications'
  })

  describe('#getToken', function () {
    it('should get the token on behalf of the user', function () {
      return githubAuth.owner.getToken(config.username, config.password)
        .then(function (user) {
          expect(user).to.an.instanceOf(ClientOAuth2.Token)
          expect(user.accessToken).to.equal(config.accessToken)
          expect(user.tokenType).to.equal('bearer')
        })
    })

    describe('#sign', function () {
      it('should be able to sign a standard request object', function () {
        return githubAuth.owner.getToken(config.username, config.password)
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
        return githubAuth.owner.getToken(config.username, config.password)
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
