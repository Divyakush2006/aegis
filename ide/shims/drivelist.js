/**
 * A pure-JavaScript stand-in for the `drivelist` native module.
 *
 * Theia's backend calls exactly one function from drivelist -- `list()`, to
 * offer drive roots in file dialogs -- but drivelist publishes no prebuilt
 * Windows binary, so installing it means installing the Visual Studio C++
 * workload: a multi-gigabyte prerequisite for listing drive letters.
 *
 * This answers the same question from the file system. It is substituted only
 * when the native binary is absent (see native-fallbacks.mjs); a machine that
 * has compiled drivelist keeps the original.
 *
 * Each entry carries the field Theia reads (`mountpoints[].path`) and the
 * descriptive fields drivelist documents, so a future caller that reads more
 * than Theia does today degrades to "unknown" rather than crashing on
 * `undefined`.
 */
'use strict';

const fs = require('fs');
const os = require('os');

async function isMounted(root) {
    try {
        await fs.promises.access(root, fs.constants.F_OK);
        return true;
    } catch {
        return false;
    }
}

function describe(root, isSystem) {
    return {
        enumerator: 'prahari-drivelist-fallback',
        busType: 'UNKNOWN',
        device: root,
        devicePath: null,
        raw: root,
        description: root,
        error: null,
        size: null,
        blockSize: 512,
        logicalBlockSize: 512,
        mountpoints: [{ path: root }],
        isReadOnly: false,
        isSystem,
        isVirtual: false,
        isRemovable: false,
        isCard: false,
        isSCSI: false,
        isUSB: false,
        isUAS: false,
        partitionTableType: null
    };
}

async function list() {
    if (os.platform() !== 'win32') {
        return [describe('/', true)];
    }
    // A: and B: are floppy letters. Probing an absent floppy controller can
    // stall, and nothing mounts there on a modern machine.
    const roots = 'CDEFGHIJKLMNOPQRSTUVWXYZ'.split('').map(letter => `${letter}:\\`);
    const present = await Promise.all(roots.map(isMounted));
    const systemRoot = `${(process.env.SystemDrive || 'C:').toUpperCase()}\\`;
    return roots
        .filter((_, index) => present[index])
        .map(root => describe(root, root === systemRoot));
}

module.exports = { list };
