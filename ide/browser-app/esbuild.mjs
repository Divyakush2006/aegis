/**
 * Aegis IDE build configuration.
 *
 * Theia generates this file once and then leaves it alone, which makes it the
 * sanctioned place to adjust the build without patching Theia. It is Theia's
 * default browser-target configuration plus one plugin, explained below.
 */
import { browserOptions, watch } from './gen-esbuild.browser.mjs';
import { nodeOptions } from './gen-esbuild.node.mjs';
import esbuild from 'esbuild';
import { copyFileSync, existsSync, mkdirSync } from 'node:fs';
import { createRequire } from 'node:module';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const here = path.dirname(fileURLToPath(import.meta.url));
const require = createRequire(import.meta.url);

/**
 * Substitute a pure-JS `drivelist` when the native module could not be built.
 *
 * Theia's backend `require`s drivelist at module load, so a missing native
 * binary does not fail the build -- the bundler marks it external -- it fails
 * the *backend at startup*. drivelist ships no prebuilt Windows binary, so on a
 * machine without the Visual Studio C++ workload that is the default outcome.
 *
 * The substitute is chosen per build, not committed as a replacement: where
 * drivelist compiled (Linux CI, or a Windows machine with the workload) the
 * native module is kept unchanged.
 */
function drivelistFallback() {
    let nativeBuilt = false;
    try {
        nativeBuilt = existsSync(require.resolve('drivelist/build/Release/drivelist.node'));
    } catch {
        nativeBuilt = false;
    }
    return {
        name: 'aegis-drivelist-fallback',
        setup(build) {
            if (nativeBuilt) {
                return;
            }
            console.log('aegis: drivelist has no native binary here; bundling shims/drivelist.js instead');
            build.onResolve({ filter: /^drivelist$/ }, () => ({
                path: path.join(here, 'shims', 'drivelist.js')
            }));
        }
    };
}

// Prepended so it resolves `drivelist` before any other plugin sees it.
nodeOptions.plugins = [drivelistFallback(), ...(nodeOptions.plugins ?? [])];

/**
 * Serve the Aegis icon at /favicon.ico.
 *
 * The backend serves `lib/frontend` as the web root, and every browser asks for
 * `/favicon.ico` on load; without this the tab has no icon and the console
 * starts every session with a 404.
 */
function copyFavicon() {
    const source = path.join(here, 'resources', 'favicon.ico');
    if (!existsSync(source)) {
        return;
    }
    const target = path.join(here, 'lib', 'frontend', 'favicon.ico');
    mkdirSync(path.dirname(target), { recursive: true });
    copyFileSync(source, target);
}

const browserContext = await esbuild.context(browserOptions);
const nodeContext = await esbuild.context(nodeOptions);

if (watch) {
    copyFavicon();
    await Promise.all([browserContext.watch(), nodeContext.watch()]);
} else {
    try {
        await browserContext.rebuild();
        await browserContext.dispose();
        copyFavicon();
        await nodeContext.rebuild();
        await nodeContext.dispose();
    } catch {
        process.exit(1);
    }
}
