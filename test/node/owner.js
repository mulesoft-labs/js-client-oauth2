var nock         = require('nock');
var expect       = require('chai').expect;
var ClientOAuth2 = require('../..');

describe('owner', function () {
  var githubAuth = new ClientOAuth2({
    clientId:            'abc',
    clientSecret:        '123',
    accessTokenUri:      'https://github.com/login/oauth/access_token',
    authorizationUri:    'https://github.com/login/oauth/authorize',
    authorizationGrants: ['code'],
    redirectUri:         'http://example.com/auth/callback'
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
          'username=blakeembrey&password=hunter2&grant_type=password'
        )
        .reply(200, {
          access_token: accessToken,
          token_type: 'bearer',
          scope: 'notifications'
        });
    });

    it('should get the token on behalf of the user', function (done) {
      githubAuth.owner.getToken('blakeembrey', 'hunter2', function (err, user) {
        expect(user).to.an.instanceOf(ClientOAuth2.Token);
        expect(user.accessToken).to.equal(accessToken);
        expect(user.tokenType).to.equal('bearer');

        return done(err);
      });
    });
  });
});
