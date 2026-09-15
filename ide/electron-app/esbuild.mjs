/**
 * Prahari IDE desktop build configuration.
 *
 * Theia generates this file once and then leaves it alone, which makes it the
 * sanctioned place to adjust the build without patching Theia. It is Theia's
 * default electron-target configuration -- the browser bundle, the Node
 * backend, and the Electron preload script -- plus one plugin, explained below.
 */
import { browserOptions, watch } from './gen-esbuild.browser.mjs';
import { electronOptions } from './gen-esbuild.electron.mjs';
import { nodeOptions } from './gen-esbuild.node.mjs';
import esbuild from 'esbuild';
import { existsSync } from 'node:fs';
import { createRequire } from 'node:module';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const here = path.dirname(fileURLToPath(import.meta.url));
const require = createRequire(import.meta.url);

/**
 * The native modules Theia's desktop backend loads that have no binary here,
 * and what stands in for each.
 *
 * Both publish C++ sources and no prebuilt binary, so npm compiles them on
 * install through their `binding.gyp` -- which `../.npmrc` deliberately
 * prevents, and which would otherwise make the Visual Studio C++ workload a
 * prerequisite for building this application on Windows. Theia `require`s them
 * while loading, so a missing binary is not a build-time warning: it is a
 * backend that does not start, or a bundle that cannot be produced at all.
 *
 * Each substitution is decided per build, never committed as a replacement: on
 * a machine where the module did compile, the native one is used unchanged.
 */
const NATIVE_SUBSTITUTES = [
    {
        // Theia calls one function from it, `list()`, for drive roots in file
        // dialogs. Shared with the browser application rather than copied.
        module: 'drivelist',
        binary: 'drivelist/build/Release/drivelist.node',
        shim: path.join(here, '..', 'browser-app', 'shims', 'drivelist.js')
    },
    {
        // Reports the OS keyboard layout. Desktop-only: the browser application
        // gets this from the browser instead.
        module: 'native-keymap',
        binary: 'native-keymap/build/Release/keymapping.node',
        shim: path.join(here, 'shims', 'native-keymap.js')
    }
];

function nativeFallbacks() {
    const missing = NATIVE_SUBSTITUTES.filter(substitute => {
        try {
            return !existsSync(require.resolve(substitute.binary));
        } catch {
            return true;
        }
    });
    return {
        name: 'prahari-native-fallbacks',
        setup(build) {
            for (const substitute of missing) {
                console.log(
                    `prahari: ${substitute.module} has no native binary here; bundling ${path.basename(substitute.shim)} instead`
                );
                build.onResolve({ filter: new RegExp(`^${substitute.module}$`) }, () => ({ path: substitute.shim }));
            }
        }
    };
}

// Prepended so it resolves these modules before any other plugin sees them.
nodeOptions.plugins = [nativeFallbacks(), ...(nodeOptions.plugins ?? [])];

const browserContext = await esbuild.context(browserOptions);
const nodeContext = await esbuild.context(nodeOptions);
const electronContext = await esbuild.context(electronOptions);

if (watch) {
    await Promise.all([browserContext.watch(), nodeContext.watch(), electronContext.watch()]);
} else {
    try {
        await browserContext.rebuild();
        await browserContext.dispose();
        await nodeContext.rebuild();
        await nodeContext.dispose();
        await electronContext.rebuild();
        await electronContext.dispose();
    } catch {
        process.exit(1);
    }
}
