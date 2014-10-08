# Client OAuth 2.0

[![NPM version][npm-image]][npm-url]
[![Build status][travis-image]][travis-url]

A no-dependencies library for executing OAuth 2.0 grant flows and user requests in node and on the browser.

## Installation

```sh
npm install client-oauth2 --save
```

## Usage

The module supports executing all the various OAuth 2.0 flows in any JavaScript environment. To authenticate you need to create an instance of the module for your API.

```javascript
var githubAuth = new ClientOAuth2({
  clientId:         'abc',
  clientSecret:     '123',
  accessTokenUri:   'https://github.com/login/oauth/access_token',
  authorizationUri: 'https://github.com/login/oauth/authorize',
  redirectUri:      'http://example.com/auth/github/callback',
  scopes:           ['notifications', 'gist']
});
```

To re-create an access token instance and make requests on behalf on the user, you can create an access token instance by using the `createToken` method on a client instance.

```javascript
var token = githubAuth.createToken('accessToken', 'refreshToken');

// Refresh the users credentials and save the updated access token.
token.refresh(cb);

token.request({
  method: 'get',
  uri: 'https://api.github.com/users'
}, function (err, res) {
  console.log(res); //=> { raw: [Object], body: '...', status: 200, headers: { ... } }
})
```

You can even override the request mechanism if you need a custom implementation not supported by setting `githubAuth.request = function (opts, cb) {}`. You will need to take care to ensure the custom request mechanism supports the correct input and output object though.

### [Authorization Code Grant](http://tools.ietf.org/html/rfc6749#section-4.1)

> The authorization code grant type is used to obtain both access tokens and refresh tokens and is optimized for confidential clients. Since this is a redirection-based flow, the client must be capable of interacting with the resource owner's user-agent (typically a web browser) and capable of receiving incoming requests (via redirection) from the authorization server.

1. Redirect user to `githubAuth.code.getUri()`.
2. Parse response uri and get token using `githubAuth.code.getToken(uri, cb)`.

```javascript
var express = require('express');
var app     = express();

app.get('/auth/github', function (req, res) {
  var uri = githubAuth.code.getUri();

  res.redirect(uri);
});

app.get('/auth/github/callback', function (req, res) {
  githubAuth.code.getToken(req.url, function (err, user) {
    // Refresh the users access token.
    user.refresh(function (err, updatedUser) {
      console.log(updatedUser === user); //=> true
    });

    // Sign requests on behalf of the user.
    user.sign({
      method: 'get',
      uri: 'http://example.com'
    });

    // Should store this into the database.
    return res.send(user.accessToken);
  });
});
```

### [Implicit Grant](http://tools.ietf.org/html/rfc6749#section-4.2)

>  The implicit grant type is used to obtain access tokens (it does not support the issuance of refresh tokens) and is optimized for public clients known to operate a particular redirection URI. These clients are typically implemented in a browser using a scripting language such as JavaScript.

1. Redirect user to `githubAuth.token.getUri()`.
2. Parse response uri for the access token using `githubAuth.token.getToken(uri, cb)`.

```javascript
window.oauth2Callback = function (uri) {
  githubAuth.token.getToken(uri, function (err, user) {
    // Log the instance of our users token.
    console.log(user);

    // Make a HTTP request to the github API for the user.
    user.request({
      method: 'get',
      uri: 'https://api.github.com/user'
    });
  });
};

// Open the page in a new window, then redirect back to a page that calls our global `oauth2Callback` function.
window.open(githubAuth.token.getUri());
```

### [Resource Owner Password Credentials Grant](http://tools.ietf.org/html/rfc6749#section-4.3)

> The resource owner password credentials grant type is suitable in cases where the resource owner has a trust relationship with the client, such as the device operating system or a highly privileged application.  The authorization server should take special care when enabling this grant type and only allow it when other flows are not viable.

1. Make a direct request for tokens on behalf of the user using `githubAuth.owner.getToken(username, password, cb)`.

### [Client Credentials Grant](http://tools.ietf.org/html/rfc6749#section-4.4)

> The client can request an access token using only its client credentials (or other supported means of authentication) when the client is requesting access to the protected resources under its control, or those of another resource owner that have been previously arranged with the authorization server (the method of which is beyond the scope of this specification).

1. Get the access token directly for the application by using `githubAuth.credentials.getToken(cb)`.

## License

Apache 2.0

[npm-image]: https://img.shields.io/npm/v/client-oauth2.svg?style=flat
[npm-url]: https://npmjs.org/package/client-oauth2
[travis-image]: https://img.shields.io/travis/mulesoft/js-client-oauth2.svg?style=flat
[travis-url]: https://travis-ci.org/mulesoft/js-client-oauth2
