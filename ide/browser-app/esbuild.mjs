/**
 * Prahari IDE build configuration.
 *
 * Theia generates this file once and then leaves it alone, which makes it the
 * sanctioned place to adjust the build without patching Theia. It is Theia's
 * default browser-target configuration plus two additions, explained below.
 */
import { browserOptions, watch } from './gen-esbuild.browser.mjs';
import { nodeOptions } from './gen-esbuild.node.mjs';
import { nativeFallbacks } from '../shims/native-fallbacks.mjs';
import esbuild from 'esbuild';
import { copyFileSync, existsSync, mkdirSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const here = path.dirname(fileURLToPath(import.meta.url));

// Stand-ins for native modules that were not built here, shared with the
// desktop application. Prepended so they resolve before any other plugin sees
// them. The reasoning is in ../shims/native-fallbacks.mjs.
nodeOptions.plugins = [nativeFallbacks(), ...(nodeOptions.plugins ?? [])];

/**
 * Serve the Prahari icon at /favicon.ico.
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
    } catch (error) {
        // esbuild reports its own build errors, but anything else -- an output
        // file held open by a running instance, a plugin fault -- would
        // otherwise vanish behind a bare exit code.
        console.error(error);
        process.exit(1);
    }
}
