describe('token', function () {
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
      expect(githubAuth.token.getUri()).to.equal(
        'https://github.com/login/oauth/authorize?client_id=abc&' +
        'redirect_uri=http%3A%2F%2Fexample.com%2Fauth%2Fcallback&' +
        'scope=notifications&response_type=token'
      );
    });
  });

  describe('#getToken', function () {
    var accessToken = '4430eb16f4f6577c0f3a15fb6127cbf828a8e403';
    var refreshToken = '4430eb16f4f6577c0f3a15fb6127cbf828a8e404';

    it('should parse the token from the response', function () {
      var uri = 'http://example.com/auth/callback?' +
        'refresh_token=' + refreshToken + '#access_token=' + accessToken;

      return githubAuth.token.getToken(uri)
        .then(function (user) {
          expect(user).to.an.instanceOf(ClientOAuth2.Token);
          expect(user.accessToken).to.equal(accessToken);
          expect(user.refreshToken).to.equal(refreshToken);
          expect(user.tokenType).to.equal('bearer');
        });
    });
  });
});
