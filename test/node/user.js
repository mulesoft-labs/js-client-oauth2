var nock         = require('nock');
var expect       = require('chai').expect;
var ClientOAuth2 = require('../..');

describe('user', function () {
  var githubAuth = new ClientOAuth2({
    clientId:            'abc',
    clientSecret:        '123',
    accessTokenUri:      'https://github.com/login/oauth/access_token',
    authorizationUri:    'https://github.com/login/oauth/authorize',
    authorizationGrants: ['code'],
    redirectUri:         'http://example.com/auth/callback',
    scopes:              'notifications'
  });

  var token       = githubAuth.createToken('abc123token');
  var tokenHeader = 'Bearer abc123token';
  var authHeader  = 'Basic ' + new Buffer('abc:123').toString('base64');

  describe('#sign', function () {
    it('should be able to sign a standard request object', function () {
      var obj = token.sign({
        method: 'GET',
        uri: 'http://api.github.com/user'
      });

      expect(obj.headers.Authorization).to.equal(tokenHeader);
    });
  });

  describe('#request', function () {
    beforeEach(function () {
      nock('http://api.github.com', {
        reqheaders: {
          'Authorization': tokenHeader
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
      return token.request({
        method: 'GET',
        url: 'http://api.github.com/user'
      })
        .then(function (res) {
          expect(res.raw).to.exist;
          expect(res.status).to.equal(200);
          expect(res.body).to.deep.equal({ username: 'blakeembrey' });
          expect(res.headers).to.deep.equal({
            'content-type': 'application/json'
          });
        });
    });
  });

  describe('#refresh', function () {
    var currentToken = githubAuth.createToken('token', 'refresh');
    var originalExpires = currentToken.expires = new Date();

    beforeEach(function () {
      nock('https://github.com', {
        reqheaders: {
          'authorization': authHeader
        }
      })
        .post(
          '/login/oauth/access_token',
          'refresh_token=refresh&grant_type=refresh_token'
        )
        .reply(200, {
          token_type: 'bearer',
          access_token: 'def456token',
          expires_in: 3000
        });
    });

    it('should make a request to get a new access token', function () {
      return currentToken.refresh()
        .then(function (token) {
          expect(token).to.an.instanceOf(ClientOAuth2.Token);
          expect(token.accessToken).to.equal('def456token');
          expect(token.tokenType).to.equal('bearer');
          expect(token.expires).to.not.equal(originalExpires);
        });
    });
  });
});
