describe('code', function () {
  var githubAuth = new ClientOAuth2({
    clientId:            'abc',
    clientSecret:        '123',
    accessTokenUri:      'https://github.com/login/oauth/access_token',
    authorizationUri:    'https://github.com/login/oauth/authorize',
    authorizationGrants: ['code'],
    redirectUri:         'http://example.com/auth/callback',
    scopes:              ['notifications']
  });

  describe('#getUri', function () {
    it('should return a valid uri', function () {
      expect(githubAuth.code.getUri()).to.equal(
        'https://github.com/login/oauth/authorize?client_id=abc&' +
        'redirect_uri=http%3A%2F%2Fexample.com%2Fauth%2Fcallback&' +
        'scope=notifications&response_type=code'
      );
    });
  });

  describe('#getToken', function () {
    var server;
    var accessToken = '4430eb16f4f6577c0f3a15fb6127cbf828a8e403';

    beforeEach(function () {
      server = sinon.fakeServer.create();

      server.autoRespond = true;

      server.respondWith(
        'POST',
        'https://github.com/login/oauth/access_token',
        [
          200,
          {
            'Content-Type': 'application/json'
          },
          '{"access_token":"' + accessToken + '","token_type":"bearer",' +
          '"scope":"notifications"}'
        ]
      );
    });

    afterEach(function () {
      server.restore();
    });

    it('should request the token', function () {
      var uri = 'http://example.com/auth/callback?code=fbe55d970377e0686746&' +
        'state=7076840850058943';

      return githubAuth.code.getToken(uri)
        .then(function (user) {
          expect(user).to.an.instanceOf(ClientOAuth2.Token);
          expect(user.accessToken).to.equal(accessToken);
          expect(user.tokenType).to.equal('bearer');
        });
    });
  });
});
