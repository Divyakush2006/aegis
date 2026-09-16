/**
 * A pure-JavaScript stand-in for the `@vscode/windows-ca-certs` native module.
 *
 * VS Code's proxy agent -- which arrives with `@theia/plugin-ext`, because
 * extensions make network requests -- reads the Windows certificate store so
 * that certificates installed by an enterprise proxy are trusted. The module
 * that reads it is C++ with no prebuilt binary and no JavaScript entry point at
 * all: its `main` is `build/Release/crypt32`, so npm must compile it on
 * install, which `../.npmrc` deliberately prevents.
 *
 * The contract is small. `@vscode/proxy-agent` does exactly this:
 *
 *     const store = new winCA.Crypt32();
 *     while (der = store.next()) { ders.push(der); }
 *     store.done();
 *
 * Reporting no certificates makes the agent fall back to the certificate
 * authorities Node itself ships -- which is precisely what happens on Linux and
 * macOS, where this module is never loaded. So HTTPS keeps working against the
 * public web; what is lost is the automatic trust of a *corporate* root
 * certificate injected into the Windows store by an intercepting proxy. On such
 * a network, point `NODE_EXTRA_CA_CERTS` at the certificate instead.
 *
 * Substituted only when the native binary is absent (see native-fallbacks.mjs).
 */
'use strict';

class Crypt32 {
    /** No certificate: the first call ends the caller's `while` loop. */
    next() {
        return undefined;
    }

    /** Nothing was opened, so there is nothing to close. */
    done() {
        // Intentionally empty.
    }
}

module.exports = { Crypt32 };
