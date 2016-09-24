var express = require('express')
var bodyParser = require('body-parser')
var cors = require('cors')
var assert = require('assert')
var Querystring = require('querystring')
var config = require('./config')
var app = express()

var credentials = 'Basic ' + new Buffer(config.clientId + ':' + config.clientSecret).toString('base64')

app.options('/login/oauth/access_token', cors())

app.post(
  '/login/oauth/access_token',
  cors(),
  bodyParser.urlencoded({ extended: false }),
  function (req, res) {
    var grantType = req.body.grant_type

    // Typically required header when parsing bodies.
    assert.equal(typeof req.headers['content-length'], 'string')

    if (grantType === 'refresh_token') {
      assert.equal(req.body.refresh_token, config.refreshToken)
      assert.equal(req.headers.authorization, credentials)

      return res.send(Querystring.stringify({
        access_token: req.body.test ? config.testRefreshAccessToken : config.refreshAccessToken,
        refresh_token: config.refreshRefreshToken,
        expires_in: 3000
      }))
    }

    if (grantType === 'authorization_code') {
      assert.equal(req.body.client_id, config.clientId)
      assert.equal(req.body.client_secret, config.clientSecret)
      assert.equal(req.body.code, config.code)
    } else if (grantType === 'urn:ietf:params:oauth:grant-type:jwt-bearer') {
      assert.equal(req.body.assertion, config.jwt)
      assert.equal(req.headers.authorization, credentials)
    } else if (grantType === 'password') {
      assert.equal(req.body.username, config.username)
      assert.equal(req.body.password, config.password)
      assert.equal(req.headers.authorization, credentials)
    } else {
      assert.equal(grantType, 'client_credentials')
      assert.equal(req.headers.authorization, credentials)
    }

    return res.json({
      access_token: config.accessToken,
      refresh_token: config.refreshToken,
      token_type: 'bearer',
      scope: 'notifications'
    })
  }
)

app.listen(process.env.PORT || 7357)
