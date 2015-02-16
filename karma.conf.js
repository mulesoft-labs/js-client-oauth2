var isTravis = require('is-travis')

/**
 * Initialize Karma with config information.
 *
 * @param {Object} config
 */
module.exports = function (config) {
  config.set({
    /**
     * The base path used to resolve files.
     *
     * @type {String}
     */
    basePath: __dirname,

    /**
     * Test frameworks to use.
     *
     * @type {Array}
     */
    frameworks: ['mocha', 'sinon-chai'],

    /**
     * Preprocess files matching a given pattern.
     *
     * @type {Object}
     */
    preprocessors: {
      'client-oauth2.js': ['coverage']
    },

    /**
     * List of files and patterns to load in the browser.
     *
     * @type {Array}
     */
    files: [
      'node_modules/es6-promise/dist/es6-promise.js',
      'test/support/globals.js',
      'node_modules/popsicle/popsicle.js',
      'client-oauth2.js',
      'test/*.js'
    ],

    /**
     * List of files and patterns to exclude in the browser.
     *
     * @type {Array}
     */
    exclude: [],

    /**
     * Test results reporter to use.
     * Possible values: 'dots', 'progress', 'junit', 'growl', 'coverage'
     *
     * @type {Array}
     */
    reporters: ['progress', 'coverage'],

    /**
     * Web server port number.
     *
     * @type {Number}
     */
    port: 9876,

    /**
     * Enable or disable colors in the output (reporters and logs).
     *
     * @type {Boolean}
     */
    colors: true,

    /**
     * Level of logging.
     * Possible values:
     * - config.LOG_DISABLE
     * - config.LOG_ERROR
     * - config.LOG_WARN
     * - config.LOG_INFO
     * - config.LOG_DEBUG
     *
     * @type {Number}
     */
    logLevel: config.LOG_INFO,

    /**
     * Enable and disable file watching and execution of tests when a
     * file changes.
     *
     * @type {Boolean}
     */
    autoWatch: true,

    /**
     * Start these browsers automatically:
     * - Chrome
     * - ChromeCanary
     * - Firefox
     * - Opera
     * - Safari (Mac)
     * - PhantomJS
     * - IE (Windows)
     *
     * @type {Array}
     */
    browsers: isTravis ? ['PhantomJS'] : ['Chrome', 'Firefox', 'PhantomJS'],

    /**
     * If a browser does not capture within a given timeout, kill it.
     *
     * @type {Number}
     */
    captureTimeout: 60000,

    /**
     * Continuous Integration mode. If true, it will capture browsers, run
     * tests and exit.
     *
     * @type {Boolean}
     */
    singleRun: true
  })
}
