/* global describe, it, btoa */
var expect = require('chai').expect
var ClientOAuth2 = require('../')

describe('code', function () {
  var accessTokenUri = 'https://github.com/login/oauth/access_token'
  var authorizationUri = 'https://github.com/login/oauth/authorize'

  var accessToken = '4430eb16f4f6577c0f3a15fb6127cbf828a8e403'
  var refreshToken = accessToken.split('').reverse().join('')
  var refreshAccessToken = 'def456token'
  var uri = 'http://example.com/auth/callback?code=fbe55d970377e0686746&' +
    'state=7076840850058943'

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
      var auth = req.headers.Authorization

      if (auth) {
        expect(auth).to.equal('Basic ' + btoa('abc:123'))
        expect(req.body.grant_type).to.equal('refresh_token')
        expect(req.body.refresh_token).to.equal(refreshToken)
      } else {
        expect(req.body.grant_type).to.equal('authorization_code')
      }

      return Promise.resolve({
        status: 200,
        body: {
          access_token: auth ? refreshAccessToken : accessToken,
          refresh_token: refreshToken,
          token_type: 'bearer',
          scope: 'notifications'
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

  describe('#getUri', function () {
    it('should return a valid uri', function () {
      expect(githubAuth.code.getUri()).to.equal(
        'https://github.com/login/oauth/authorize?client_id=abc&' +
        'redirect_uri=http%3A%2F%2Fexample.com%2Fauth%2Fcallback&' +
        'scope=notifications&response_type=code&state='
      )
    })
  })

  describe('#getToken', function () {
    it('should request the token', function () {
      return githubAuth.code.getToken(uri)
        .then(function (user) {
          expect(user).to.an.instanceOf(ClientOAuth2.Token)
          expect(user.accessToken).to.equal(accessToken)
          expect(user.tokenType).to.equal('bearer')
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

            expect(obj.headers.Authorization).to.equal('Bearer ' + accessToken)
          })
      })
    })

    describe('#request', function () {
      it('should make a request on behalf of the user', function () {
        return githubAuth.code.getToken(uri)
          .then(function (token) {
            return token.request({
              method: 'GET',
              url: 'http://api.github.com/user'
            })
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
        return githubAuth.code.getToken(uri)
          .then(function (token) {
            return token.refresh()
          })
          .then(function (token) {
            expect(token).to.an.instanceOf(ClientOAuth2.Token)
            expect(token.accessToken).to.equal(refreshAccessToken)
            expect(token.tokenType).to.equal('bearer')
          })
      })
    })
  })
})
