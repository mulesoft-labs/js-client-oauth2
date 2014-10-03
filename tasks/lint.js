var gulp   = require('gulp');
var jshint = require('gulp-jshint');

/**
 * Lint all project files using JSHint.
 */
gulp.task('lint', function() {
  return gulp.src(['*.js', 'test/**/*.js'])
    .pipe(jshint())
    .pipe(jshint.reporter('default'));
});
