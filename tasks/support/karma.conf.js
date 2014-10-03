var path = require('path');

/**
 * Initialize Karma with config information.
 *
 * @param {Object} config
 */
module.exports = function (config) {
  config.set({
    /**
     * The base path that will be used to resolve files.
     *
     * @type {String}
     */
    basePath: path.join(__dirname, '../..'),

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
      'client-oauth2.js',
      'test/browser/**/*.js'
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
     * Start these browsers automatically. Currently available:
     * - Chrome
     * - ChromeCanary
     * - Firefox
     * - Opera
     * - Safari (only Mac)
     * - PhantomJS
     * - IE (only Windows)
     *
     * @type {Array}
     */
    browsers: ['Chrome', 'Firefox', 'PhantomJS'],

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
    singleRun: false
  });
};
