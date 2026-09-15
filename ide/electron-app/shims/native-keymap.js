/**
 * A pure-JavaScript stand-in for the `native-keymap` native module.
 *
 * `native-keymap` reports the operating system's keyboard layout. It ships C++
 * sources and no prebuilt binary, so npm compiles it on install through
 * `binding.gyp` -- which `../../.npmrc` deliberately prevents, and which would
 * otherwise make the Visual Studio C++ workload a prerequisite for building the
 * desktop application. It is substituted only when the native binary is absent
 * (see ../esbuild.mjs); a machine that has compiled it keeps the real module.
 *
 * What is kept and what is lost:
 *
 * - `getCurrentKeyboardLayout()` reports the layout the OS has selected. On
 *   Windows that is read from the registry, so a user on a non-US layout is
 *   still reported accurately.
 * - `getKeyMap()` returns an empty mapping, which is the one real reduction.
 *   Theia treats that as "no layout information": `resolveKeyCode` is
 *   documented to return the key code unchanged, so keybindings are matched by
 *   physical key position. Ctrl+Z is the key where Z sits on a US keyboard.
 *   Producing a true mapping means asking the OS what character every key
 *   yields under every modifier, which is exactly the work the native module
 *   exists to do -- guessing it would be worse than reporting nothing.
 * - `onDidChangeKeyboardLayout()` never fires: switching layouts while the IDE
 *   is open is picked up on the next start.
 *
 * The real module degrades further on failure -- it logs and returns `[]` and
 * `null` -- so this is a strict improvement on the module's own fallback.
 */
'use strict';

const { execFileSync } = require('child_process');
const os = require('os');

/** The US layout, used when the running system cannot be asked. */
const US_WINDOWS_LAYOUT_ID = '00000409';

/**
 * The active Windows keyboard layout identifier (a KLID, e.g. `00000407` for
 * German). Windows lists the preloaded layouts under HKCU in preference order.
 */
function windowsKeyboardLayoutId() {
    try {
        const output = execFileSync('reg', ['query', 'HKCU\\Keyboard Layout\\Preload', '/v', '1'], {
            encoding: 'utf8',
            timeout: 2000,
            windowsHide: true
        });
        const match = output.match(/REG_SZ\s+([0-9a-fA-F]{8})/);
        if (match) {
            return match[1].toLowerCase();
        }
    } catch {
        // No registry, no reg.exe, or an unexpected shape: fall through.
    }
    return US_WINDOWS_LAYOUT_ID;
}

function getCurrentKeyboardLayout() {
    switch (os.platform()) {
        case 'win32':
            return { name: windowsKeyboardLayoutId(), id: '', text: '' };
        case 'darwin':
            return { id: 'com.apple.keylayout.US', localizedName: 'U.S.', lang: 'en' };
        default:
            return { model: 'pc105', group: 0, layout: 'us', variant: '', options: '', rules: 'evdev' };
    }
}

/**
 * No per-key character mapping. Theia reads this with a `for...in` loop and
 * treats an empty result as "layout unknown", which is a supported state.
 */
function getKeyMap() {
    return {};
}

/** Layout changes are not observed; the callback is never invoked. */
function onDidChangeKeyboardLayout() {
    // Intentionally empty.
}

/** Whether the physical keyboard is ISO rather than ANSI. Not detectable here. */
function isISOKeyboard() {
    return false;
}

module.exports = { getCurrentKeyboardLayout, getKeyMap, onDidChangeKeyboardLayout, isISOKeyboard };
