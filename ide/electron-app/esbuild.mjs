/**
 * Prahari IDE desktop build configuration.
 *
 * Theia generates this file once and then leaves it alone, which makes it the
 * sanctioned place to adjust the build without patching Theia. It is Theia's
 * default electron-target configuration -- the browser bundle, the Node
 * backend, and the Electron preload script -- plus one plugin, shared with the
 * browser application, that stands in for native modules which were not built
 * here. The reasoning is in ../shims/native-fallbacks.mjs.
 */
import { browserOptions, watch } from './gen-esbuild.browser.mjs';
import { electronOptions } from './gen-esbuild.electron.mjs';
import { nodeOptions } from './gen-esbuild.node.mjs';
import { nativeFallbacks } from '../shims/native-fallbacks.mjs';
import esbuild from 'esbuild';

// Prepended so it resolves those modules before any other plugin sees them.
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
    } catch (error) {
        // esbuild reports its own build errors, but anything else -- an output
        // file held open by a running instance, a plugin fault -- would
        // otherwise vanish behind a bare exit code.
        console.error(error);
        process.exit(1);
    }
}
