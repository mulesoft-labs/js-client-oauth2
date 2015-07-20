/* global define */

(function (root, factory) {
  if (typeof define === 'function' && define.amd) {
    define(['popsicle'], factory)
  } else if (typeof exports === 'object') {
    module.exports = factory(require('popsicle'))
  } else {
    root.ClientOAuth2 = factory(root.popsicle)
  }
})(this, function (popsicle) {
  var _hasOwnProperty = Object.prototype.hasOwnProperty
  var btoa = typeof Buffer === 'function' ? btoaBuffer : window.btoa

  /**
   * Default headers for executing OAuth 2.0 flows.
   *
   * @type {Object}
   */
  var DEFAULT_HEADERS = {
    'Accept': 'application/json, application/x-www-form-urlencoded',
    'Content-Type': 'application/x-www-form-urlencoded'
  }

  /**
   * Format error response types to regular strings for displaying to clients.
   *
   * Reference: http://tools.ietf.org/html/rfc6749#section-4.1.2.1
   *
   * @type {Object}
   */
  var ERROR_RESPONSES = {
    'invalid_request': [
      'The request is missing a required parameter, includes an',
      'invalid parameter value, includes a parameter more than',
      'once, or is otherwise malformed.'
    ].join(' '),
    'invalid_client': [
      'Client authentication failed (e.g., unknown client, no',
      'client authentication included, or unsupported',
      'authentication method).'
    ].join(' '),
    'invalid_grant': [
      'The provided authorization grant (e.g., authorization',
      'code, resource owner credentials) or refresh token is',
      'invalid, expired, revoked, does not match the redirection',
      'URI used in the authorization request, or was issued to',
      'another client.'
    ].join(' '),
    'unauthorized_client': [
      'The client is not authorized to request an authorization',
      'code using this method.'
    ].join(' '),
    'unsupported_grant_type': [
      'The authorization grant type is not supported by the',
      'authorization server.'
    ].join(' '),
    'access_denied': [
      'The resource owner or authorization server denied the request.'
    ].join(' '),
    'unsupported_response_type': [
      'The authorization server does not support obtaining',
      'an authorization code using this method.'
    ].join(' '),
    'invalid_scope': [
      'The requested scope is invalid, unknown, or malformed.'
    ].join(' '),
    'server_error': [
      'The authorization server encountered an unexpected',
      'condition that prevented it from fulfilling the request.',
      '(This error code is needed because a 500 Internal Server',
      'Error HTTP status code cannot be returned to the client',
      'via an HTTP redirect.)'
    ].join(' '),
    'temporarily_unavailable': [
      'The authorization server is currently unable to handle',
      'the request due to a temporary overloading or maintenance',
      'of the server.'
    ].join(' ')
  }

  /**
   * Iterate over a source object and copy properties to the destination object.
   *
   * @param  {Object} dest
   * @param  {Object} source
   * @return {Object}
   */
  function assign (dest /*, ...source */) {
    for (var i = 1; i < arguments.length; i++) {
      var source = arguments[i]

      for (var key in source) {
        if (_hasOwnProperty.call(source, key)) {
          dest[key] = source[key]
        }
      }
    }

    return dest
  }

  /**
   * Support base64 in node like how it works in the browser.
   *
   * @param  {String} string
   * @return {String}
   */
  function btoaBuffer (string) {
    return new Buffer(string).toString('base64')
  }

  /**
   * Check if properties exist on an object and throw when they aren't.
   *
   * @throws {TypeError} If an expected property is missing.
   *
   * @param {Object} obj
   * @param {Array}  props
   */
  function expects (obj, props) {
    for (var i = 0; i < props.length; i++) {
      var prop = props[i]

      if (obj[prop] == null) {
        throw new TypeError('Expected "' + prop + '" to exist')
      }
    }
  }

  /**
   * Create a new object based on a source object with keys omitted.
   *
   * @param  {Object} source
   * @param  {Array}  keys
   * @return {Object}
   */
  function omit (source, keys) {
    var obj = {}

    // Iterate over the source object and set properties on a new object.
    Object.keys(source || {}).forEach(function (key) {
      if (keys.indexOf(key) === -1) {
        obj[key] = source[key]
      }
    })

    return obj
  }

  /**
   * Convert a query string into an object.
   *
   * @param  {String} qs
   * @param  {String} sep
   * @param  {String} eq
   * @return {Object}
   */
  function decodeQuery (qs, sep, eq) {
    eq = eq || '='
    sep = sep || '&'
    qs = qs.split(sep)

    var obj = {}
    var maxKeys = 1000
    var len = Math.min(qs.length, maxKeys)

    for (var i = 0; i < len; i++) {
      var key = qs[i].replace(/\+/g, '%20')
      var value = ''
      var index = key.indexOf(eq)

      if (index !== -1) {
        value = key.substr(index + 1)
        key = key.substr(0, index)
      }

      key = decodeURIComponent(key)
      value = decodeURIComponent(value)

      if (!_hasOwnProperty.call(obj, key)) {
        obj[key] = value
      } else if (Array.isArray(obj[key])) {
        obj[key].push(value)
      } else {
        obj[key] = [obj[key], value]
      }
    }

    return obj
  }

  /**
   * Pull an authentication error from the response data.
   *
   * @param  {Object} data
   * @return {String}
   */
  function getAuthError (data) {
    var message = ERROR_RESPONSES[data.error] ||
      data.error ||
      data.error_message

    // Return an error instance with the message if it exists.
    return message && new Error(message)
  }

  /**
   * Handle the authentication response object.
   *
   * @param  {Object}  res
   * @return {Promise}
   */
  function handleAuthResponse (res) {
    var data = res.body
    var err = getAuthError(data)

    // If the response contains an error, reject the refresh token.
    if (err) {
      return Promise.reject(err)
    }

    return data
  }

  /**
   * Sanitize the scopes option to be a string.
   *
   * @param  {Array}  scopes
   * @return {String}
   */
  function sanitizeScope (scopes) {
    if (!Array.isArray(scopes)) {
      return scopes == null ? '' : String(scopes)
    }

    return scopes.join(' ')
  }

  /**
   * Create a request uri based on an options object and token type.
   *
   * @param  {Object} options
   * @param  {String} tokenType
   * @return {String}
   */
  function createUri (options, tokenType) {
    // Check the required parameters are set.
    expects(options, [
      'clientId',
      'redirectUri',
      'authorizationUri'
    ])

    var clientId = encodeURIComponent(options.clientId)
    var redirectUri = encodeURIComponent(options.redirectUri)
    var scopes = encodeURIComponent(sanitizeScope(options.scopes))
    var uri = options.authorizationUri + '?client_id=' + clientId +
      '&redirect_uri=' + redirectUri +
      '&scope=' + scopes +
      '&response_type=' + tokenType

    if (options.state) {
      uri += '&state=' + encodeURIComponent(options.state)
    }

    return uri
  }

  /**
   * Create basic auth header.
   *
   * @param  {String} username
   * @param  {String} password
   * @return {String}
   */
  function auth (username, password) {
    return 'Basic ' + btoa(string(username) + ':' + string(password))
  }

  /**
   * Ensure a value is a string.
   *
   * @param  {String} str
   * @return {String}
   */
  function string (str) {
    return str == null ? '' : String(str)
  }

  /**
   * Construct an object that can handle the multiple OAuth 2.0 flows.
   *
   * @param {Object} options
   */
  function ClientOAuth2 (options) {
    this.options = options

    this.code = new CodeFlow(this)
    this.token = new TokenFlow(this)
    this.owner = new OwnerFlow(this)
    this.credentials = new CredentialsFlow(this)
    this.jwt = new JwtBearerFlow(this)
  }

  /**
   * Alias the token constructor.
   *
   * @type {Function}
   */
  ClientOAuth2.Token = ClientOAuth2Token

  /**
   * Create a new token from existing data.
   *
   * @param  {String} access
   * @param  {String} [refresh]
   * @param  {String} [type]
   * @param  {Object} [data]
   * @return {Object}
   */
  ClientOAuth2.prototype.createToken = function (access, refresh, type, data) {
    var options = assign(
      {},
      data,
      typeof access === 'string' ? { access_token: access } : access,
      typeof refresh === 'string' ? { refresh_token: refresh } : refresh,
      typeof type === 'string' ? { token_type: type } : type
    )

    return new ClientOAuth2Token(this, options)
  }

  /**
   * Using the built-in request method, we'll automatically attempt to parse
   * the response.
   *
   * @param  {Object}  options
   * @return {Promise}
   */
  ClientOAuth2.prototype._request = function (options) {
    return this.request(this._requestOptions(options))
      .then(function (res) {
        if (res.status < 200 || res.status >= 399) {
          var err = new Error('HTTP status ' + res.status)
          err.status = res.status
          err.body = res.body
          return Promise.reject(err)
        }

        return res
      })
  }

  ClientOAuth2.prototype._requestOptions = function (options) {
    return assign({
      agent: this.options.agent,
      rejectUnauthorized: this.options.rejectUnauthorized
    }, options, {
      body: assign({}, this.options.body, options.body),
      query: assign({}, this.options.query, options.query),
      headers: assign({}, this.options.headers, options.headers)
    })
  }

  /**
   * Set `popsicle` as the default request method.
   */
  ClientOAuth2.prototype.request = popsicle

  /**
   * General purpose client token generator.
   *
   * @param {Object} client
   * @param {Object} data
   */
  function ClientOAuth2Token (client, data) {
    this.client = client

    this.data = omit(data, [
      'access_token', 'refresh_token', 'token_type', 'expires_in', 'scope',
      'state', 'error', 'error_description', 'error_uri'
    ])

    this.tokenType = data.token_type && data.token_type.toLowerCase()
    this.accessToken = data.access_token
    this.refreshToken = data.refresh_token

    this.expiresIn(data.expires_in)
  }

  /**
   * Expire after some seconds.
   *
   * @param  {Number} duration
   * @return {Date}
   */
  ClientOAuth2Token.prototype.expiresIn = function (duration) {
    if (!isNaN(duration)) {
      this.expires = new Date()
      this.expires.setSeconds(this.expires.getSeconds() + duration)
    } else {
      this.expires = undefined
    }

    return this.expires
  }

  /**
   * Sign a standardised request object with user authentication information.
   *
   * @param  {Object} opts
   * @return {Object}
   */
  ClientOAuth2Token.prototype.sign = function (opts) {
    if (!this.accessToken) {
      throw new Error('Unable to sign without access token')
    }

    opts.headers = opts.headers || {}

    if (this.tokenType === 'bearer') {
      opts.headers.Authorization = 'Bearer ' + this.accessToken
    } else {
      var parts = opts.url.split('#')
      var token = 'access_token=' + this.accessToken
      var url = parts[0].replace(/[?&]access_token=[^&#]/, '')
      var fragment = parts[1] ? '#' + parts[1] : ''

      // Prepend the correct query string parameter to the url.
      opts.url = url + (url.indexOf('?') > -1 ? '&' : '?') + token + fragment

      // Attempt to avoid storing the url in proxies, since the access token
      // is exposed in the query parameters.
      opts.headers.Pragma = 'no-store'
      opts.headers['Cache-Control'] = 'no-store'
    }

    return opts
  }

  /**
   * Make a HTTP request as the user.
   *
   * @param  {Object}  opts
   * @return {Promise}
   */
  ClientOAuth2Token.prototype.request = function (opts) {
    return this.client.request(this.client._requestOptions(this.sign(opts)))
  }

  /**
   * Refresh a user access token with the supplied token.
   *
   * @return {Promise}
   */
  ClientOAuth2Token.prototype.refresh = function () {
    var self = this
    var options = this.client.options

    if (!this.refreshToken) {
      return Promise.reject(new Error('No refresh token set'))
    }

    return this.client._request({
      url: options.accessTokenUri,
      method: 'POST',
      headers: assign({
        Authorization: auth(options.clientId, options.clientSecret)
      }, DEFAULT_HEADERS),
      body: {
        refresh_token: this.refreshToken,
        grant_type: 'refresh_token'
      }
    })
      .then(handleAuthResponse)
      .then(function (data) {
        self.accessToken = data.access_token
        self.refreshToken = data.refresh_token

        self.expiresIn(data.expires_in)

        return self
      })
  }

  /**
   * Check whether the token has expired.
   *
   * @return {Boolean}
   */
  ClientOAuth2Token.prototype.expired = function () {
    if (this.expires) {
      return Date.now() > this.expires.getTime()
    }

    return false
  }

  /**
   * Support resource owner password credentials OAuth 2.0 grant.
   *
   * Reference: http://tools.ietf.org/html/rfc6749#section-4.3
   *
   * @param {ClientOAuth2} client
   */
  function OwnerFlow (client) {
    this.client = client
  }

  /**
   * Make a request on behalf of the user credentials to get an acces token.
   *
   * @param  {String}  username
   * @param  {String}  password
   * @return {Promise}
   */
  OwnerFlow.prototype.getToken = function (username, password, options) {
    var self = this

    options = assign({}, this.client.options, options)

    return this.client._request({
      url: options.accessTokenUri,
      method: 'POST',
      headers: assign({
        Authorization: auth(options.clientId, options.clientSecret)
      }, DEFAULT_HEADERS),
      body: {
        scope: sanitizeScope(options.scopes),
        username: username,
        password: password,
        grant_type: 'password'
      }
    })
      .then(handleAuthResponse)
      .then(function (data) {
        return new ClientOAuth2Token(self.client, data)
      })
  }

  /**
   * Support implicit OAuth 2.0 grant.
   *
   * Reference: http://tools.ietf.org/html/rfc6749#section-4.2
   *
   * @param {ClientOAuth2} client
   */
  function TokenFlow (client) {
    this.client = client
  }

  /**
   * Get the uri to redirect the user to for implicit authentication.
   *
   * @param  {Object} options
   * @return {String}
   */
  TokenFlow.prototype.getUri = function (options) {
    options = assign({}, this.client.options, options)

    return createUri(options, 'token')
  }

  /**
   * Get the user access token from the uri.
   *
   * @param  {String}  uri
   * @param  {String}  [state]
   * @return {Promise}
   */
  TokenFlow.prototype.getToken = function (uri, state) {
    var data = {}
    var options = this.client.options

    // Make sure the uri matches our expected redirect uri.
    if (uri.substr(0, options.redirectUri.length) !== options.redirectUri) {
      return Promise.reject(new Error('Should match redirect uri: ' + uri))
    }

    var queryIndex = uri.indexOf('?')
    var fragmentIndex = uri.indexOf('#')

    // If no query string or fragment exists, we won't be able to parse
    // any useful information from the uri.
    if (queryIndex === -1 && fragmentIndex === -1) {
      return Promise.reject(new Error('Unable to process uri: ' + uri))
    }

    // Extract the query string and parse. This is needed because Instagram
    // has a bug where the OAuth 2.0 state is passed back via the query string.
    if (queryIndex > -1 && queryIndex < fragmentIndex) {
      var endIndex = fragmentIndex === -1 ? uri.length : fragmentIndex
      var query = uri.slice(queryIndex + 1, endIndex)

      assign(data, decodeQuery(query))
    }

    // Extract data from the uri fragment, which is more important than the
    // query string which shouldn't hold any information.
    if (fragmentIndex > -1) {
      var fragment = uri.substr(fragmentIndex + 1)

      assign(data, decodeQuery(fragment))
    }

    var err = getAuthError(data)

    // Check if the query string was populated with a known error.
    if (err) {
      return Promise.reject(err)
    }

    // Check whether the state matches.
    if (state != null && data.state !== state) {
      return Promise.reject(new Error('Invalid state: ' + data.state))
    }

    // Initalize a new token and return.
    return Promise.resolve(new ClientOAuth2Token(this.client, data))
  }

  /**
   * Support client credentials OAuth 2.0 grant.
   *
   * Reference: http://tools.ietf.org/html/rfc6749#section-4.4
   *
   * @param {ClientOAuth2} client
   */
  function CredentialsFlow (client) {
    this.client = client
  }

  /**
   * Request an access token using the client credentials.
   *
   * @param  {Object}  [options]
   * @return {Promise}
   */
  CredentialsFlow.prototype.getToken = function (options) {
    var self = this

    options = assign({}, this.client.options, options)

    expects(options, [
      'clientId',
      'clientSecret',
      'accessTokenUri'
    ])

    return this.client._request({
      url: options.accessTokenUri,
      method: 'POST',
      headers: assign({
        Authorization: auth(options.clientId, options.clientSecret)
      }, DEFAULT_HEADERS),
      body: {
        scope: sanitizeScope(options.scopes),
        grant_type: 'client_credentials'
      }
    })
      .then(handleAuthResponse)
      .then(function (data) {
        return new ClientOAuth2Token(self.client, data)
      })
  }

  /**
   * Support authorization code OAuth 2.0 grant.
   *
   * Reference: http://tools.ietf.org/html/rfc6749#section-4.1
   *
   * @param {ClientOAuth2} client
   */
  function CodeFlow (client) {
    this.client = client
  }

  /**
   * Generate the uri for doing the first redirect.
   *
   * @return {String}
   */
  CodeFlow.prototype.getUri = function (options) {
    options = assign({}, this.client.options, options)

    return createUri(options, 'code')
  }

  /**
   * Get the code token from the redirected uri and make another request for
   * the user access token.
   *
   * @param  {String}  uri
   * @param  {String}  [state]
   * @return {Promise}
   */
  CodeFlow.prototype.getToken = function (uri, state) {
    var self = this
    var options = this.client.options

    expects(options, [
      'clientId',
      'clientSecret',
      'redirectUri',
      'accessTokenUri'
    ])

    // Make sure the uri matches our expected redirect uri.
    if (uri.substr(0, options.redirectUri.length) !== options.redirectUri) {
      return Promise.reject(new Error('Should match redirect uri: ' + uri))
    }

    var queryIndex = uri.indexOf('?')
    var fragmentIndex = uri.indexOf('#')

    if (queryIndex === -1) {
      return Promise.reject(new Error('Unable to process uri: ' + uri))
    }

    var endIndex = fragmentIndex === -1 ? uri.length : fragmentIndex
    var data = decodeQuery(uri.slice(queryIndex + 1, endIndex))
    var err = getAuthError(data)

    if (err) {
      return Promise.reject(err)
    }

    if (state && data.state !== state) {
      return Promise.reject(new Error('Invalid state:' + data.state))
    }

    // Check whether the response code is set.
    if (!data.code) {
      return Promise.reject(new Error('Missing code, unable to request token'))
    }

    return this.client._request({
      url: options.accessTokenUri,
      method: 'POST',
      headers: assign({}, DEFAULT_HEADERS),
      body: {
        code: data.code,
        grant_type: 'authorization_code',
        redirect_uri: options.redirectUri,
        client_id: options.clientId,
        client_secret: options.clientSecret
      }
    })
      .then(handleAuthResponse)
      .then(function (data) {
        return new ClientOAuth2Token(self.client, data)
      })
  }

  /**
   * Support JSON Web Token (JWT) Bearer Token OAuth 2.0 grant.
   *
   * Reference: https://tools.ietf.org/html/draft-ietf-oauth-jwt-bearer-12#section-2.1
   *
   * @param {ClientOAuth2} client
   */
  function JwtBearerFlow (client) {
    this.client = client
  }

  /**
   * Request an access token using a JWT token.
   *
   * @param  {string} token A JWT token.
   * @param  {Object}  [options]
   * @return {Promise}
   */
  JwtBearerFlow.prototype.getToken = function (token, options) {
    var self = this

    options = assign({}, this.client.options, options)

    expects(options, [
      'accessTokenUri'
    ])

    var headers = assign({}, DEFAULT_HEADERS)

    // Authentication of the client is optional, as described in
    // Section 3.2.1 of OAuth 2.0 [RFC6749]
    if (options.clientId) {
      headers['Authorization'] = auth(options.clientId, options.clientSecret)
    }

    return this.client._request({
      url: options.accessTokenUri,
      method: 'POST',
      headers: headers,
      body: {
        scope: sanitizeScope(options.scopes),
        grant_type: 'urn:ietf:params:oauth:grant-type:jwt-bearer',
        assertion: token
      }
    })
      .then(handleAuthResponse)
      .then(function (data) {
        return new ClientOAuth2Token(self.client, data)
      })
  }

  return ClientOAuth2
})
