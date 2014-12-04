describe('user', function () {
  var githubAuth = new ClientOAuth2({
    clientId:            'abc',
    clientSecret:        '123',
    accessTokenUri:      'https://github.com/login/oauth/access_token',
    authorizationUri:    'https://github.com/login/oauth/authorize',
    authorizationGrants: ['code'],
    redirectUri:         'http://example.com/auth/callback',
    scopes:              ['notifications']
  });

  var token       = githubAuth.createToken('abc123token');
  var tokenHeader = 'Bearer abc123token';
  var authHeader  = 'Basic ' + btoa('abc:123');

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
    var server;

    beforeEach(function () {
      server = sinon.fakeServer.create();

      server.autoRespond = true;

      server.respondWith(
        'GET',
        'http://api.github.com/user',
        function (xhr) {
          expect(xhr.requestHeaders.Authorization).to.equal(tokenHeader);

          return xhr.respond(
            200,
            {
              'Content-Type': 'application/json'
            },
            '{"username":"blakeembrey"}'
          );
        }
      );
    });

    afterEach(function () {
      server.restore();
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
    var server;

    beforeEach(function () {
      server = sinon.fakeServer.create();

      server.autoRespond = true;

      server.respondWith(
        'POST',
        'https://github.com/login/oauth/access_token',
        function (xhr) {
          expect(xhr.requestBody).to.equal(
            'refresh_token=refresh&grant_type=refresh_token'
          );
          expect(xhr.requestHeaders.Authorization).to.equal(authHeader);

          return xhr.respond(
            200,
            {
              'Content-Type': 'application/json'
            },
            '{"access_token":"def456token","token_type":"bearer"}'
          );
        }
      );
    });

    afterEach(function () {
      server.restore();
    });

    it('should make a request to get a new access token', function () {
      return currentToken.refresh()
        .then(function (token) {
          expect(token).to.an.instanceOf(ClientOAuth2.Token);
          expect(token.accessToken).to.equal('def456token');
          expect(token.tokenType).to.equal('bearer');
        });
    });
  });
});
