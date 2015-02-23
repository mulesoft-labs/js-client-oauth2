/* global describe, it, expect, ClientOAuth2 */

describe('owner', function () {
  var accessTokenUri = 'https://github.com/login/oauth/access_token'
  var authorizationUri = 'https://github.com/login/oauth/authorize'

  var accessToken = '4430eb16f4f6577c0f3a15fb6127cbf828a8e403'
  var refreshToken = accessToken.split('').reverse().join('')
  var refreshAccessToken = 'def456token'

  var githubAuth = new ClientOAuth2({
    clientId: 'abc',
    clientSecret: '123',
    accessTokenUri: accessTokenUri,
    authorizationUri: authorizationUri,
    authorizationGrants: ['owner'],
    redirectUri: 'http://example.com/auth/callback',
    scope: 'notifications'
  })

  githubAuth.request = function (req) {
    if (req.method === 'POST' && req.url === accessTokenUri) {
      var isRefreshToken = req.body.grant_type === 'refresh_token'

      expect(req.headers.Authorization).to.equal('Basic ' + btoa('abc:123'))

      if (isRefreshToken) {
        expect(req.body.refresh_token).to.equal(refreshToken)
      } else {
        expect(req.body.grant_type).to.equal('password')
        expect(req.body.username).to.equal('blakeembrey')
        expect(req.body.password).to.equal('hunter2')
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

  describe('#getToken', function () {
    it('should get the token on behalf of the user', function () {
      return githubAuth.owner.getToken('blakeembrey', 'hunter2')
        .then(function (user) {
          expect(user).to.an.instanceOf(ClientOAuth2.Token)
          expect(user.accessToken).to.equal(accessToken)
          expect(user.tokenType).to.equal('bearer')
        })
    })

    describe('#sign', function () {
      it('should be able to sign a standard request object', function () {
        return githubAuth.owner.getToken('blakeembrey', 'hunter2')
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
        return githubAuth.owner.getToken('blakeembrey', 'hunter2')
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
        return githubAuth.owner.getToken('blakeembrey', 'hunter2')
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
