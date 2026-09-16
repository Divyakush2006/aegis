/**
 * Substitute pure-JavaScript stand-ins for native modules that were not built.
 *
 * Both Prahari applications bundle the same Theia backend, and that backend
 * loads native modules that publish C++ sources and no prebuilt binary. npm
 * would compile them on install through their `binding.gyp`, which `../.npmrc`
 * deliberately prevents -- otherwise the Visual Studio C++ workload becomes a
 * prerequisite for building an editor, which is a barrier out of all proportion
 * to what these modules do.
 *
 * Theia `require`s them while loading, so a missing binary is not a build-time
 * warning: it is a backend that will not start, or a bundle that cannot be
 * produced at all.
 *
 * Every substitution is decided per build and never committed as a
 * replacement: where a module *did* compile -- Linux CI, or a Windows machine
 * with the C++ workload -- the native one is used untouched. Each shim
 * documents precisely what it keeps and what it gives up.
 */
import { existsSync } from 'node:fs';
import { createRequire } from 'node:module';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const here = path.dirname(fileURLToPath(import.meta.url));
const require = createRequire(import.meta.url);

const SUBSTITUTES = [
    {
        // One function is used, `list()`, for drive roots in file dialogs.
        module: 'drivelist',
        binary: 'drivelist/build/Release/drivelist.node',
        shim: 'drivelist.js'
    },
    {
        // Reports the OS keyboard layout. Desktop only; in a browser Theia asks
        // the browser instead.
        module: 'native-keymap',
        binary: 'native-keymap/build/Release/keymapping.node',
        shim: 'native-keymap.js'
    },
    {
        // Reads the Windows certificate store for VS Code's proxy agent, which
        // arrives with @theia/plugin-ext.
        module: '@vscode/windows-ca-certs',
        binary: '@vscode/windows-ca-certs/build/Release/crypt32.node',
        shim: 'windows-ca-certs.js'
    }
];

const escape = specifier => specifier.replace(/[.*+?^${}()|[\]\\/]/g, '\\$&');

function built(binary) {
    try {
        return existsSync(require.resolve(binary));
    } catch {
        return false;
    }
}

/**
 * An esbuild plugin resolving each unbuilt module to its stand-in.
 *
 * Prepend it to the Node build's plugins so it sees these specifiers before
 * any other plugin does.
 */
export function nativeFallbacks() {
    const missing = SUBSTITUTES.filter(substitute => !built(substitute.binary));
    return {
        name: 'prahari-native-fallbacks',
        setup(build) {
            for (const substitute of missing) {
                console.log(
                    `prahari: ${substitute.module} has no native binary here; bundling ${substitute.shim} instead`
                );
                build.onResolve({ filter: new RegExp(`^${escape(substitute.module)}$`) }, () => ({
                    path: path.join(here, substitute.shim)
                }));
            }
        }
    };
}
