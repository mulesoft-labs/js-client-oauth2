var nock         = require('nock');
var expect       = require('chai').expect;
var ClientOAuth2 = require('../..');

describe('jwt', function () {
  var githubAuth = new ClientOAuth2({
    clientId:            'abc',
    clientSecret:        '123',
    accessTokenUri:      'https://github.com/login/oauth/access_token',
    authorizationGrants: ['jwt'],
    scopes:              ['notifications']
  });

  describe('#getToken', function () {
    var authHeader  = 'Basic ' + new Buffer('abc:123').toString('base64');
    var token = 'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJodHRwczovL2p3dC1pZHAuZXhhbXBsZS5jb20iLCJzdWIiOiJtYWlsdG86bWlrZUBleGFtcGxlLmNvbSIsImF1ZCI6Imh0dHBzOi8vand0LXJwLmV4YW1wbGUubmV0IiwibmJmIjoxMzAwODE1NzgwLCJleHAiOjEzMDA4MTkzODAsImh0dHA6Ly9jbGFpbXMuZXhhbXBsZS5jb20vbWVtYmVyIjp0cnVlLCJpYXQiOjE0MjQwMTE1ODN9.HWUPsjnh8UgCji9phLIQMTbJZySRV33kA-47Fn6NNqw';
    var accessToken = '4430eb16f4f6577c0f3a15fb6127cbf828a8e403';
    var refreshToken = accessToken.split('').reverse().join('');

    beforeEach(function () {
      nock('https://github.com', {
        reqheaders: {
          'Authorization': authHeader
        }
      })
        .post(
          '/login/oauth/access_token',
          {
            scope:      'notifications',
            grant_type: 'urn:ietf:params:oauth:grant-type:jwt-bearer',
            assertion:  token
          }
        )
        .reply(200, {
          access_token: accessToken,
          refresh_token: refreshToken,
          token_type: 'bearer',
          scope: 'notifications'
        });
    });

    it('should request the token', function () {
      return githubAuth.jwt.getToken(token)
        .then(function (user) {
          expect(user).to.an.instanceOf(ClientOAuth2.Token);
          expect(user.accessToken).to.equal(accessToken);
          expect(user.tokenType).to.equal('bearer');
        });
    });

    describe('#sign', function () {
      it('should be able to sign a standard request object', function () {
        return githubAuth.jwt.getToken(token)
          .then(function (token) {
            var obj = token.sign({
              method: 'GET',
              uri: 'http://api.github.com/user'
            });
            expect(obj.headers.Authorization).to.equal('Bearer ' + accessToken);
          });
      });
    });

    describe('#request', function () {
      beforeEach(function () {
        nock('http://api.github.com', {
          reqheaders: {
            'Authorization': 'Bearer 4430eb16f4f6577c0f3a15fb6127cbf828a8e403'
          }
        })
          .get('/user')
          .reply(200, {
            username: 'blakeembrey'
          }, {
            'Content-Type': 'application/json'
          });
      });

      it('should make a request on behalf of the user', function () {
        return githubAuth.jwt.getToken(token)
          .then(function (token) {
            return token.request({
              method: 'GET',
              url: 'http://api.github.com/user'
            });
          })
          .then(function (res) {
            expect(res.raw).to.exist;
            expect(res.status).to.equal(200);
            expect(res.body).to.deep.equal({username: 'blakeembrey'});
            expect(res.headers).to.deep.equal({
              'content-type': 'application/json'
            });
          });
      });
    });

    describe('#refresh', function () {

      beforeEach(function () {
        nock('https://github.com', {
          reqheaders: {
            'authorization': 'Basic ' + new Buffer('abc:123').toString('base64')
          }
        })
          .post(
          '/login/oauth/access_token'
        )
          .reply(200, {
            token_type: 'bearer',
            access_token: 'def456token'
          });
      });

      it('should make a request to get a new access token', function () {
        return githubAuth.jwt.getToken(token)
          .then(function (token) {
            return token.refresh()
          })
          .then(function (token) {
            expect(token).to.an.instanceOf(ClientOAuth2.Token);
            expect(token.accessToken).to.equal('def456token');
            expect(token.tokenType).to.equal('bearer');
          });
      });
    });
  });
});
