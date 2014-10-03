describe('token', function () {
  var githubAuth = new ClientOAuth2({
    clientId:            'abc',
    clientSecret:        '123',
    accessTokenUri:      'https://github.com/login/oauth/access_token',
    authorizationUri:    'https://github.com/login/oauth/authorize',
    authorizationGrants: ['code'],
    redirectUri:         'http://example.com/auth/callback',
    scope:               'notifications'
  });

  describe('#getUri', function () {
    it('should return a valid uri', function () {
      expect(githubAuth.token.getUri()).to.equal(
        'https://github.com/login/oauth/authorize?scope=notifications&' +
        'client_id=abc&' +
        'redirect_uri=http%3A%2F%2Fexample.com%2Fauth%2Fcallback&' +
        'response_type=token'
      );
    });
  });

  describe('#getToken', function () {
    var accessToken = '4430eb16f4f6577c0f3a15fb6127cbf828a8e403';

    it('should parse the token from the response', function (done) {
      var uri = 'http://example.com/auth/callback#access_token=' + accessToken;

      githubAuth.token.getToken(uri, function (err, user) {
        expect(user).to.an.instanceOf(ClientOAuth2.Token);
        expect(user.accessToken).to.equal(accessToken);
        expect(user.tokenType).to.equal('bearer');

        return done(err);
      });
    });
  });
});
