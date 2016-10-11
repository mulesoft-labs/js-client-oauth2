exports.accessTokenUri = 'http://localhost:' + process.env.PORT + '/login/oauth/access_token'
exports.authorizationUri = 'http://localhost:' + process.env.PORT + '/login/oauth/authorize'
exports.redirectUri = 'http://example.com/auth/callback'

exports.accessToken = '4430eb16f4f6577c0f3a15fb6127cbf828a8e403'
exports.refreshToken = exports.accessToken.split('').reverse().join('')
exports.refreshAccessToken = 'def456token'
exports.refreshRefreshToken = exports.refreshAccessToken.split('').reverse().join('')
exports.testRefreshAccessToken = 'testingtesting123'

exports.clientId = 'abc'
exports.clientSecret = '123'

exports.code = 'fbe55d970377e0686746'
exports.state = '7076840850058943'

exports.jwt = 'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJodHRwczovL2p3dC1pZHAuZXhhbXBsZS5jb20iLCJzdWIiOiJtYWlsdG86bWlrZUBleGFtcGxlLmNvbSIsImF1ZCI6Imh0dHBzOi8vand0LXJwLmV4YW1wbGUubmV0IiwibmJmIjoxMzAwODE1NzgwLCJleHAiOjEzMDA4MTkzODAsImh0dHA6Ly9jbGFpbXMuZXhhbXBsZS5jb20vbWVtYmVyIjp0cnVlLCJpYXQiOjE0MjQwMTE1ODN9.HWUPsjnh8UgCji9phLIQMTbJZySRV33kA-47Fn6NNqw'

exports.username = 'blakeembrey'
exports.password = 'hunter2'
