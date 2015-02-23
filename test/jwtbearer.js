/* global describe, it, expect, ClientOAuth2 */

describe('jwt', function () {
  var accessTokenUri = 'https://github.com/login/oauth/access_token'

  var token = 'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJodHRwczovL2p3dC1pZHAuZXhhbXBsZS5jb20iLCJzdWIiOiJtYWlsdG86bWlrZUBleGFtcGxlLmNvbSIsImF1ZCI6Imh0dHBzOi8vand0LXJwLmV4YW1wbGUubmV0IiwibmJmIjoxMzAwODE1NzgwLCJleHAiOjEzMDA4MTkzODAsImh0dHA6Ly9jbGFpbXMuZXhhbXBsZS5jb20vbWVtYmVyIjp0cnVlLCJpYXQiOjE0MjQwMTE1ODN9.HWUPsjnh8UgCji9phLIQMTbJZySRV33kA-47Fn6NNqw'
  var accessToken = '4430eb16f4f6577c0f3a15fb6127cbf828a8e403'
  var refreshToken = accessToken.split('').reverse().join('')
  var refreshAccessToken = 'def456token'

  var githubAuth = new ClientOAuth2({
    clientId: 'abc',
    clientSecret: '123',
    accessTokenUri: accessTokenUri,
    authorizationGrants: ['jwt'],
    scopes: ['notifications']
  })

  githubAuth.request = function (req) {
    if (req.method === 'POST' && req.url === accessTokenUri) {
      var isRefreshToken = req.body.grant_type === 'refresh_token'

      expect(req.headers.Authorization).to.equal('Basic ' + btoa('abc:123'))

      if (isRefreshToken) {
        expect(req.body.refresh_token).to.equal(refreshToken)
      } else {
        expect(req.body.scope).to.equal('notifications')
        expect(req.body.grant_type).to.equal('urn:ietf:params:oauth:grant-type:jwt-bearer')
        expect(req.body.assertion).to.equal(token)
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
    it('should request the token', function () {
      return githubAuth.jwt.getToken(token)
        .then(function (user) {
          expect(user).to.an.instanceOf(ClientOAuth2.Token)
          expect(user.accessToken).to.equal(accessToken)
          expect(user.tokenType).to.equal('bearer')
        })
    })

    describe('#sign', function () {
      it('should be able to sign a standard request object', function () {
        return githubAuth.jwt.getToken(token)
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
        return githubAuth.jwt.getToken(token)
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
        return githubAuth.jwt.getToken(token)
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
