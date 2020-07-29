/* global describe, it */
var expect = require('chai').expect
var config = require('./support/config')
var ClientOAuth2 = require('../')

describe('user', function () {
  var githubAuth = new ClientOAuth2({
    clientId: config.clientId,
    clientSecret: config.clientSecret,
    accessTokenUri: config.accessTokenUri,
    authorizationUri: config.authorizationUri,
    authorizationGrants: ['code'],
    redirectUri: config.redirectUri,
    scopes: 'notifications'
  })

  var user = githubAuth.createToken(config.accessToken, config.refreshToken, 'bearer')

  user.expiresIn(0)

  describe('#sign', function () {
    it('should be able to sign a standard request object', function () {
      var obj = user.sign({
        method: 'GET',
        url: 'http://api.github.com/user',
        headers: {
          accept: '*/*'
        }
      })

      expect(obj.headers.Authorization).to.equal('Bearer ' + config.accessToken)
    })
  })

  describe('#refresh', function () {
    it('should make a request to get a new access token', function () {
      expect(user.accessToken).to.equal(config.accessToken)
      expect(user.tokenType).to.equal('bearer')

      return user.refresh({ body: { test: true } })
        .then(function (token) {
          expect(token).to.an.instanceOf(ClientOAuth2.Token)
          expect(token.accessToken).to.equal(config.testRefreshAccessToken)
          expect(token.tokenType).to.equal('bearer')
          expect(token.refreshToken).to.equal(config.refreshRefreshToken)
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
    it('should work with Date objects', function () {
      user.expiresIn(new Date(Date.now() + 10000))
      expect(user.expired()).to.be.equal(false)
      user.expiresIn(new Date(Date.now() - 10000))
      expect(user.expired()).to.be.equal(true)
    })
    it('should work with Date strings', function () {
      user.expiresIn(new Date(Date.now() + 10000).toString())
      expect(user.expired()).to.be.equal(false)
      user.expiresIn(new Date(Date.now() - 10000).toString())
      expect(user.expired()).to.be.equal(true)
    })
  })
})
