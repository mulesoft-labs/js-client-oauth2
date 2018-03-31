# Client OAuth 2.0

[![Greenkeeper badge](https://badges.greenkeeper.io/mulesoft/js-client-oauth2.svg)](https://greenkeeper.io/)

[![NPM version][npm-image]][npm-url]
[![NPM downloads][downloads-image]][downloads-url]
[![Build status][travis-image]][travis-url]

> Straight-forward execution of OAuth 2.0 flows and authenticated API requests. 7.58 kB in browsers, after minification and gzipping, 75% from `url` and `querystring` dependencies.

## Installation

```sh
npm install client-oauth2 --save
```

## Usage

The module supports executing all the various OAuth 2.0 flows in any JavaScript environment. To authenticate you need to create an instance of the module for your API.

```javascript
var ClientOAuth2 = require('client-oauth2')

var githubAuth = new ClientOAuth2({
  clientId: 'abc',
  clientSecret: '123',
  accessTokenUri: 'https://github.com/login/oauth/access_token',
  authorizationUri: 'https://github.com/login/oauth/authorize',
  redirectUri: 'http://example.com/auth/github/callback',
  scopes: ['notifications', 'gist']
})
```

**P.S.** The second argument to the constructor can inject a custom request function.

### Options (global and method-based)

* **clientId** The client id string assigned to you by the provider
* **clientSecret** The client secret string assigned to you by the provider (not required for `token`)
* **accessTokenUri** The url to request the access token (not required for `token`)
* **authorizationUri** The url to redirect users to authenticate with the provider (only required for `token` and `code`)
* **redirectUri** A custom url for the provider to redirect users back to your application (only required for `token` and `code`)
* **scopes** An array of scopes to authenticate against
* **state** Nonce sent back with the redirect when authorization is complete to verify authenticity (should be random for every request)

### Request options

* **body** An object to merge with the body of every request
* **query** An object to merge with the query parameters of every request
* **headers** An object to merge with the headers of every request

To re-create an access token instance and make requests on behalf on the user, you can create an access token instance by using the `createToken` method on a client instance.

```javascript
// Can also just pass the raw `data` object in place of an argument.
var token = githubAuth.createToken('access token', 'optional refresh token', 'optional token type', { data: 'raw user data' })

// Set the token TTL.
token.expiresIn(1234) // Seconds.
token.expiresIn(new Date('2016-11-08')) // Date.

// Refresh the users credentials and save the new access token and info.
token.refresh().then(storeNewToken)

// Sign a standard HTTP request object, updating the URL with the access token
// or adding authorization headers, depending on token type.
token.sign({
  method: 'get',
  url: 'https://api.github.com/users'
}) //=> { method, url, headers, ... }
```

**P.S.** All authorization methods accept `options` as the last argument, useful for overriding the global configuration on a per-request basis.

### [Authorization Code Grant](http://tools.ietf.org/html/rfc6749#section-4.1)

> The authorization code grant type is used to obtain both access tokens and refresh tokens and is optimized for confidential clients. Since this is a redirection-based flow, the client must be capable of interacting with the resource owner's user-agent (typically a web browser) and capable of receiving incoming requests (via redirection) from the authorization server.

1. Redirect user to `githubAuth.code.getUri([ options ])`.
2. Parse response uri and get token using `githubAuth.code.getToken(uri [, options ])`.

```javascript
var express = require('express')
var app = express()

app.get('/auth/github', function (req, res) {
  var uri = githubAuth.code.getUri()

  res.redirect(uri)
})

app.get('/auth/github/callback', function (req, res) {
  githubAuth.code.getToken(req.originalUrl)
    .then(function (user) {
      console.log(user) //=> { accessToken: '...', tokenType: 'bearer', ... }

      // Refresh the current users access token.
      user.refresh().then(function (updatedUser) {
        console.log(updatedUser !== user) //=> true
        console.log(updatedUser.accessToken)
      })

      // Sign API requests on behalf of the current user.
      user.sign({
        method: 'get',
        url: 'http://example.com'
      })

      // We should store the token into a database.
      return res.send(user.accessToken)
    })
})
```

**P.S.** The `getToken` URI parameter can be an object containing `pathname` and `query` properties.

### [Implicit Grant](http://tools.ietf.org/html/rfc6749#section-4.2)

>  The implicit grant type is used to obtain access tokens (it does not support the issuance of refresh tokens) and is optimized for public clients known to operate a particular redirection URI. These clients are typically implemented in a browser using a scripting language such as JavaScript.

1. Redirect user to `githubAuth.token.getUri([ options ])`.
2. Parse response uri for the access token using `githubAuth.token.getToken(uri [, options ])`.

```javascript
window.oauth2Callback = function (uri) {
  githubAuth.token.getToken(uri)
    .then(function (user) {
      console.log(user) //=> { accessToken: '...', tokenType: 'bearer', ... }

      // Make a request to the github API for the current user.
      return popsicle.request(user.sign({
        method: 'get',
        url: 'https://api.github.com/user'
      })).then(function (res) {
        console.log(res) //=> { body: { ... }, status: 200, headers: { ... } }
      })
    })
}

// Open the page in a new window, then redirect back to a page that calls our global `oauth2Callback` function.
window.open(githubAuth.token.getUri())
```

**P.S.** The `getToken` URI parameter can be an object containing `pathname`, `query` and `hash` properties.

### [Resource Owner Password Credentials Grant](http://tools.ietf.org/html/rfc6749#section-4.3)

> The resource owner password credentials grant type is suitable in cases where the resource owner has a trust relationship with the client, such as the device operating system or a highly privileged application.  The authorization server should take special care when enabling this grant type and only allow it when other flows are not viable.

1. Make a direct request for the access token on behalf of the user using `githubAuth.owner.getToken(username, password [, options ])`.

```javascript
githubAuth.owner.getToken('blakeembrey', 'hunter2')
  .then(function (user) {
    console.log(user) //=> { accessToken: '...', tokenType: 'bearer', ... }
  })
```

### [Client Credentials Grant](http://tools.ietf.org/html/rfc6749#section-4.4)

> The client can request an access token using only its client credentials (or other supported means of authentication) when the client is requesting access to the protected resources under its control, or those of another resource owner that have been previously arranged with the authorization server (the method of which is beyond the scope of this specification).

1. Get the access token for the application by using `githubAuth.credentials.getToken([ options ])`.

```javascript
githubAuth.credentials.getToken()
  .then(function (user) {
    console.log(user) //=> { accessToken: '...', tokenType: 'bearer', ... }
  })
```

### [JWT as Authorization Grant](https://tools.ietf.org/html/draft-ietf-oauth-jwt-bearer-12#section-2.1)

> A JSON Web Token (JWT) Bearer Token can be used to request an access token when a client wishes to utilize an existing trust relationship, expressed through the semantics of (and digital signature or Message Authentication Code calculated over) the JWT, without a direct user approval step at the authorization server.

1. Get the access token for the application by using `githubAuth.jwt.getToken(jwt [, options ])`.

```javascript
githubAuth.jwt.getToken('eyJhbGciOiJFUzI1NiJ9.eyJpc3Mi[...omitted for brevity...].J9l-ZhwP[...omitted for brevity...]')
  .then(function (user) {
    console.log(user) //=> { accessToken: '...', tokenType: 'bearer', ... }
  })
```

## Dependencies

Requires an ES5 environment with global `Promise` and `Object.assign`.

## License

Apache 2.0

[npm-image]: https://img.shields.io/npm/v/client-oauth2.svg?style=flat
[npm-url]: https://npmjs.org/package/client-oauth2
[downloads-image]: https://img.shields.io/npm/dm/client-oauth2.svg?style=flat
[downloads-url]: https://npmjs.org/package/client-oauth2
[travis-image]: https://img.shields.io/travis/mulesoft/js-client-oauth2.svg?style=flat
[travis-url]: https://travis-ci.org/mulesoft/js-client-oauth2
