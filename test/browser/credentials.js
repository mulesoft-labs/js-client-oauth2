describe('credentials', function () {
  var githubAuth = new ClientOAuth2({
    clientId:            'abc',
    clientSecret:        '123',
    accessTokenUri:      'https://github.com/login/oauth/access_token',
    authorizationUri:    'https://github.com/login/oauth/authorize',
    authorizationGrants: ['credentials'],
    redirectUri:         'http://example.com/auth/callback',
    scope:               'notifications'
  });

  describe('#getToken', function () {
    var authHeader  = 'Basic ' + btoa('abc:123');
    var accessToken = '4430eb16f4f6577c0f3a15fb6127cbf828a8e403';
    var server;

    beforeEach(function () {
      server = sinon.fakeServer.create();

      server.autoRespond = true;

      server.respondWith(
        'POST',
        'https://github.com/login/oauth/access_token',
        function (xhr) {
          expect(xhr.requestBody).to.equal(
            'scope=notifications&grant_type=client_credentials'
          );
          expect(xhr.requestHeaders.Authorization).to.equal(authHeader);

          return xhr.respond(
            200,
            {
              'Content-Type': 'application/json'
            },
            '{"access_token":"' + accessToken + '","token_type":"bearer",' +
            '"scope":"notifications"}'
          );
        }
      );
    });

    afterEach(function () {
      server.restore();
    });

    it('should request the token', function (done) {
      githubAuth.credentials.getToken(function (err, user) {
        expect(user).to.an.instanceOf(ClientOAuth2.Token);
        expect(user.accessToken).to.equal(accessToken);
        expect(user.tokenType).to.equal('bearer');

        return done(err);
      });
    });
  });
});
