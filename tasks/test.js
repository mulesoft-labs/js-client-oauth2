var join  = require('path').join;
var gulp  = require('gulp');
var karma = require('karma').server;
var mocha = require('gulp-mocha');

/**
 * Test the library in the browser.
 */
gulp.task('test:browser', function (done) {
  return karma.start({
    singleRun: true,
    configFile: join(__dirname, 'support', 'karma.conf.js')
  }, done);
});

gulp.task('test:node', function () {
  return gulp.src([
    'test/support/globals.js',
    'test/node/**/*.js'
  ], { read: false })
    .pipe(mocha({ reporter: 'spec' }));
});

/**
 * Run all tests.
 */
gulp.task('test', ['test:browser', 'test:node']);
