var nock         = require('nock');
var expect       = require('chai').expect;
var ClientOAuth2 = require('../..');

describe('code', function () {
  var githubAuth = new ClientOAuth2({
    clientId:            'abc',
    clientSecret:        '123',
    accessTokenUri:      'https://github.com/login/oauth/access_token',
    authorizationUri:    'https://github.com/login/oauth/authorize',
    authorizationGrants: ['code'],
    redirectUri:         'http://example.com/auth/callback',
    scopes:              'notifications'
  });

  describe('#getUri', function () {
    it('should return a valid uri', function () {
      expect(githubAuth.code.getUri()).to.equal(
        'https://github.com/login/oauth/authorize?scope=notifications&' +
        'client_id=abc&' +
        'redirect_uri=http%3A%2F%2Fexample.com%2Fauth%2Fcallback&' +
        'response_type=code'
      );
    });
  });

  describe('#getToken', function () {
    var accessToken = '4430eb16f4f6577c0f3a15fb6127cbf828a8e403';

    beforeEach(function () {
      nock('https://github.com')
        .post('/login/oauth/access_token')
        .reply(200, {
          access_token: accessToken,
          token_type: 'bearer',
          scope: 'notifications'
        });
    });

    it('should request the token', function (done) {
      var uri = 'http://example.com/auth/callback?code=fbe55d970377e0686746&' +
        'state=7076840850058943';

      githubAuth.code.getToken(uri, function (err, user) {
        expect(user).to.an.instanceOf(ClientOAuth2.Token);
        expect(user.accessToken).to.equal(accessToken);
        expect(user.tokenType).to.equal('bearer');

        return done(err);
      });
    });
  });
});
