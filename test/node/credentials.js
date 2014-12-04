var nock         = require('nock');
var expect       = require('chai').expect;
var ClientOAuth2 = require('../..');

describe('credentials', function () {
  var githubAuth = new ClientOAuth2({
    clientId:            'abc',
    clientSecret:        '123',
    accessTokenUri:      'https://github.com/login/oauth/access_token',
    authorizationUri:    'https://github.com/login/oauth/authorize',
    authorizationGrants: ['credentials'],
    redirectUri:         'http://example.com/auth/callback',
    scopes:              ['notifications']
  });

  describe('#getToken', function () {
    var authHeader  = 'Basic ' + new Buffer('abc:123').toString('base64');
    var accessToken = '4430eb16f4f6577c0f3a15fb6127cbf828a8e403';

    beforeEach(function () {
      nock('https://github.com', {
        reqheaders: {
          'Authorization': authHeader
        }
      })
        .post(
          '/login/oauth/access_token',
          'scope=notifications&grant_type=client_credentials'
        )
        .reply(200, {
          access_token: accessToken,
          token_type: 'bearer',
          scope: 'notifications'
        });
    });

    it('should request the token', function () {
      return githubAuth.credentials.getToken()
        .then(function (user) {
          expect(user).to.an.instanceOf(ClientOAuth2.Token);
          expect(user.accessToken).to.equal(accessToken);
          expect(user.tokenType).to.equal('bearer');
        });
    });
  });
});
