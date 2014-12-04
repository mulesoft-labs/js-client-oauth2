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
            'scope=&username=blakeembrey&password=hunter2&grant_type=password'
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

    it('should get the token on behalf of the user', function () {
      return githubAuth.owner.getToken('blakeembrey', 'hunter2')
        .then(function (user) {
          expect(user).to.an.instanceOf(ClientOAuth2.Token);
          expect(user.accessToken).to.equal(accessToken);
          expect(user.tokenType).to.equal('bearer');
        });
    });
  });
});
