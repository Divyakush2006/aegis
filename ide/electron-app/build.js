/**
 * Build the Prahari IDE desktop application.
 *
 * This is `theia build` with one verification step allowed to degrade, for the
 * same reason and on the same terms as the `drivelist` substitution in
 * `esbuild.mjs`: it cannot run without a C++ toolchain, and the project builds
 * without one on every platform.
 *
 * Theia's electron build does two things with Electron's bundled FFMPEG:
 *
 *   1. `replaceFfmpeg()` downloads the codec-stripped FFMPEG that Electron
 *      publishes alongside each release and swaps it into `electron/dist`.
 *      This is the step that actually removes the proprietary codecs, and it
 *      runs here unchanged.
 *   2. `checkFfmpeg()` then re-reads that library and asserts no proprietary
 *      codec survived. It parses a native shared library, so it needs a native
 *      addon -- and `@theia/ffmpeg` ships only the C sources for it. npm would
 *      normally compile them on install via `binding.gyp`, which `../.npmrc`
 *      deliberately prevents (see the README), so the addon is absent and the
 *      check throws MODULE_NOT_FOUND before it can test anything.
 *
 * Only (2) is relaxed, and only for that one error: where the addon *has* been
 * compiled the check runs and a real failure still fails the build. What is
 * lost is the confirmation of a replacement that itself succeeded, on an
 * application that plays no media.
 *
 * Any other argument is passed through, so `node build.js --mode development`
 * and `node build.js --watch` behave as the Theia CLI does.
 */

// The package index re-exports this function with `__exportStar`, which defines
// a getter and no setter -- assigning to `require('@theia/ffmpeg').checkFfmpeg`
// is silently discarded. The defining module's export is writable, and the
// index getter reads through to it, so this is the one place the wrapper holds.
const checkModule = require('@theia/ffmpeg/lib/check-ffmpeg');

const checkFfmpeg = checkModule.checkFfmpeg;
checkModule.checkFfmpeg = async (...args) => {
    try {
        return await checkFfmpeg(...args);
    } catch (error) {
        if (error && error.code === 'MODULE_NOT_FOUND') {
            console.warn(
                'prahari: @theia/ffmpeg has no compiled addon here, so the codec check is skipped. ' +
                'Electron\'s codec-stripped FFMPEG was still installed.'
            );
            return;
        }
        throw error;
    }
};

// Theia's build resolves `@theia/ffmpeg` through the same module cache, so it
// sees the wrapper above. Its CLI runs on require, reading process.argv.
const cli = require.resolve('@theia/cli/bin/theia.js');
process.argv = [process.argv[0], cli, 'build', ...process.argv.slice(2)];
require(cli);
