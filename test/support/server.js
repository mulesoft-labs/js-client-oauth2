var Buffer = require('safe-buffer').Buffer
var express = require('express')
var bodyParser = require('body-parser')
var cors = require('cors')
var assert = require('assert')
var Querystring = require('querystring')
var config = require('./config')
var app = express()

var credentials = 'Basic ' + Buffer.from(config.clientId + ':' + config.clientSecret).toString('base64')

app.options('/login/oauth/access_token', cors())

app.post(
  '/login/oauth/access_token',
  cors(),
  bodyParser.urlencoded({ extended: false }),
  function (req, res) {
    var grantType = req.body.grant_type

    // Typically required header when parsing bodies.
    assert.strictEqual(typeof req.headers['content-length'], 'string')

    if (grantType === 'refresh_token') {
      assert.strictEqual(req.body.refresh_token, config.refreshToken)
      assert.strictEqual(req.headers.authorization, credentials)

      return res.send(Querystring.stringify({
        access_token: req.body.test ? config.testRefreshAccessToken : config.refreshAccessToken,
        refresh_token: config.refreshRefreshToken,
        expires_in: 3000
      }))
    }

    if (grantType === 'authorization_code') {
      assert.strictEqual(req.body.code, config.code)
      if (req.headers.authorization) {
        assert.strictEqual(req.headers.authorization, credentials)
      } else {
        assert.strictEqual(req.body.client_id, config.clientId)
        assert.strictEqual(req.body.client_secret, config.clientSecret)
      }
    } else if (grantType === 'urn:ietf:params:oauth:grant-type:jwt-bearer') {
      assert.strictEqual(req.body.assertion, config.jwt)
      assert.strictEqual(req.headers.authorization, credentials)
    } else if (grantType === 'password') {
      assert.strictEqual(req.body.username, config.username)
      assert.strictEqual(req.body.password, config.password)
      assert.strictEqual(req.headers.authorization, credentials)
    } else {
      assert.strictEqual(grantType, 'client_credentials')
      assert.strictEqual(req.headers.authorization, credentials)
    }

    return res.json({
      access_token: config.accessToken,
      refresh_token: config.refreshToken,
      token_type: 'bearer',
      scope: req.body.scope
    })
  }
)

app.listen(process.env.PORT || 7357)
