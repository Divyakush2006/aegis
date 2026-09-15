/**
 * Real-browser check of the running Prahari IDE.
 *
 * `e2e-check.js` proves Node can drive the Python language server. This proves
 * the *application* works: it opens the IDE in headless Chrome, drives it the
 * way a user would over the Chrome DevTools Protocol, and fails on any console
 * error. It has already caught problems no unit test could see — an IDE with no
 * working Go to File, and a findings header that read "0 findings" before any
 * audit had run.
 *
 * Steps, each asserted:
 *   1. the Theia shell mounts with compiler/examples as the workspace;
 *   2. /favicon.ico is served;
 *   3. cmd_injection.c opens through Go to File (Ctrl+P);
 *   4. every Prahari command is registered in the command palette;
 *   5. "Prahari: Audit Current File" lists findings with their path trace;
 *   6. "Prahari: AI Adjudication Status" and "Review Findings with AI" round-trip
 *      through the backend and the language server (with no key configured the
 *      review reports that and keeps the compiler's verdicts, which also passes).
 *
 * Usage (with the IDE already running via `npm start`):
 *
 *     node browser-check.js
 *
 * Environment: PRAHARI_IDE_URL (default http://127.0.0.1:3000/), PRAHARI_CHROME
 * (path to a Chrome or Chromium binary; common install locations are searched),
 * PRAHARI_SCREENSHOT (where to save a PNG of the final state).
 */
const { spawn } = require('child_process');
const fs = require('fs');
const os = require('os');
const path = require('path');

const APP = process.env.PRAHARI_IDE_URL || 'http://127.0.0.1:3000/';
const PORT = 9300 + Math.floor(Math.random() * 500);
const SCREENSHOT = process.env.PRAHARI_SCREENSHOT || path.join(os.tmpdir(), 'prahari-ide.png');
const EXPECTED_COMMANDS = [
    'Prahari: Audit Current File',
    'Prahari: Review Findings with AI',
    'Prahari: AI Adjudication Status',
    'Prahari: Explain Function at Cursor',
    'Prahari: Show Generated LLVM IR'
];

const pause = ms => new Promise(resolve => setTimeout(resolve, ms));

function findChrome() {
    const candidates = [
        process.env.PRAHARI_CHROME,
        'C:/Program Files/Google/Chrome/Application/chrome.exe',
        'C:/Program Files (x86)/Google/Chrome/Application/chrome.exe',
        'C:/Program Files (x86)/Microsoft/Edge/Application/msedge.exe',
        '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome',
        '/usr/bin/google-chrome',
        '/usr/bin/google-chrome-stable',
        '/usr/bin/chromium',
        '/usr/bin/chromium-browser'
    ].filter(Boolean);
    const found = candidates.find(candidate => fs.existsSync(candidate));
    if (!found) {
        throw new Error('no Chrome, Chromium or Edge found; set PRAHARI_CHROME');
    }
    return found;
}

/** Theia opens a workspace from the URL hash: `#/<path>`, drive letter lower-cased. */
function workspaceHash() {
    let folder = path.resolve(__dirname, '..', 'compiler', 'examples').split(path.sep).join('/');
    if (/^[A-Za-z]:/.test(folder)) {
        folder = `/${folder[0].toLowerCase()}${folder.slice(1)}`;
    }
    return `#${encodeURI(folder)}`;
}

async function waitFor(check, timeoutMs, label) {
    const started = Date.now();
    while (Date.now() - started < timeoutMs) {
        const value = await check();
        if (value) {
            return value;
        }
        await pause(500);
    }
    throw new Error(`timed out waiting for ${label}`);
}

async function main() {
    const profile = fs.mkdtempSync(path.join(os.tmpdir(), 'prahari-browser-check-'));
    const chrome = spawn(findChrome(), [
        '--headless=new', '--disable-gpu', '--no-first-run', '--no-default-browser-check',
        `--remote-debugging-port=${PORT}`, `--user-data-dir=${profile}`, '--window-size=1500,950',
        'about:blank'
    ], { stdio: 'ignore' });

    const errors = [];
    const report = {};
    try {
        await waitFor(async () => {
            try { return (await fetch(`http://127.0.0.1:${PORT}/json/version`)).ok; } catch { return false; }
        }, 30000, 'the Chrome DevTools endpoint');

        const favicon = await fetch(new URL('favicon.ico', APP));
        if (!favicon.ok) {
            throw new Error(`favicon.ico returned HTTP ${favicon.status}`);
        }
        report.favicon = `HTTP ${favicon.status}`;

        const target = await (await fetch(
            `http://127.0.0.1:${PORT}/json/new?${encodeURIComponent(APP + workspaceHash())}`, { method: 'PUT' }
        )).json();
        const socket = new WebSocket(target.webSocketDebuggerUrl);
        await new Promise((resolve, reject) => { socket.onopen = resolve; socket.onerror = reject; });

        let nextId = 1;
        const pending = new Map();
        socket.onmessage = event => {
            const message = JSON.parse(event.data);
            if (message.id && pending.has(message.id)) {
                pending.get(message.id)(message);
                pending.delete(message.id);
                return;
            }
            if (message.method === 'Runtime.exceptionThrown') {
                const detail = message.params.exceptionDetails;
                errors.push(`exception: ${detail.exception?.description || detail.text}`.slice(0, 300));
            } else if (message.method === 'Runtime.consoleAPICalled' && message.params.type === 'error') {
                errors.push(`console.error: ${message.params.args.map(a => a.value ?? a.description).join(' ')}`.slice(0, 300));
            } else if (message.method === 'Log.entryAdded' && message.params.entry.level === 'error') {
                errors.push(`log: ${message.params.entry.text} ${message.params.entry.url || ''}`.slice(0, 300));
            }
        };
        const send = (method, params = {}) => new Promise(resolve => {
            const id = nextId++;
            pending.set(id, resolve);
            socket.send(JSON.stringify({ id, method, params }));
        });
        const evaluate = async expression => {
            const response = await send('Runtime.evaluate', { expression, returnByValue: true, awaitPromise: true });
            return response.result?.result?.value;
        };
        const key = async (keyName, code, keyCode, modifiers = 0) => {
            await send('Input.dispatchKeyEvent', { type: 'rawKeyDown', key: keyName, code, windowsVirtualKeyCode: keyCode, modifiers });
            await send('Input.dispatchKeyEvent', { type: 'keyUp', key: keyName, code, windowsVirtualKeyCode: keyCode, modifiers });
        };
        const setQuickInput = value => evaluate(
            `(() => { const i = document.querySelector('.quick-input-widget input'); i.value = ${JSON.stringify(value)}; i.dispatchEvent(new Event('input', { bubbles: true })); })()`
        );
        const firstRow = () => evaluate(
            "(document.querySelector('.quick-input-list .monaco-list-row') || {}).textContent || ''"
        );
        const quickInputOpen = () => evaluate("!!document.querySelector('.quick-input-widget input')");
        const runCommand = async label => {
            await key('Escape', 'Escape', 27);
            await key('F1', 'F1', 112);
            await waitFor(quickInputOpen, 15000, 'the command palette');
            await setQuickInput(`>${label}`);
            await waitFor(async () => (await firstRow()).includes(label.replace(/^Prahari: /, '')),
                10000, `"${label}" in the palette`);
            await key('Enter', 'Enter', 13);
        };

        await send('Runtime.enable');
        await send('Log.enable');
        await send('Page.enable');

        // 1. The shell mounts with the workspace.
        await waitFor(() => evaluate(
            "!!document.querySelector('#theia-main-content-panel') && !document.querySelector('.theia-preload')"
        ), 120000, 'the Theia shell to mount');
        report.title = await evaluate('document.title');
        await pause(5000);

        // 3. Go to File. The first query can run before the file index is ready,
        // and Quick Open only re-queries when its input changes, so re-enter it.
        await send('Input.dispatchMouseEvent', { type: 'mousePressed', x: 750, y: 480, button: 'left', clickCount: 1 });
        await send('Input.dispatchMouseEvent', { type: 'mouseReleased', x: 750, y: 480, button: 'left', clickCount: 1 });
        await key('p', 'KeyP', 80, 2);
        await waitFor(quickInputOpen, 15000, 'Go to File');
        let polls = 0;
        await waitFor(async () => {
            if (polls++ % 6 === 0) {
                await setQuickInput('');
                await setQuickInput('cmd_injection');
            }
            return (await firstRow()).includes('cmd_injection.c');
        }, 60000, 'cmd_injection.c in Go to File');
        await key('Enter', 'Enter', 13);
        report.editor = await waitFor(async () => {
            const tabs = await evaluate("[...document.querySelectorAll('.lm-TabBar-tabLabel')].map(t => t.textContent)");
            const lines = await evaluate("!!document.querySelector('.monaco-editor .view-lines .view-line')");
            return tabs && tabs.includes('cmd_injection.c') && lines ? 'cmd_injection.c' : undefined;
        }, 20000, 'the editor to open cmd_injection.c');

        // The editor recognises C: the status bar names the language, and the
        // code carries several distinct token colours rather than one.
        report.language = await waitFor(async () => {
            const status = await evaluate("(document.querySelector('#theia-statusBar') || {}).innerText || ''");
            return /(^|\s)C(\s|$)/.test(status) && !status.includes('Plain Text') ? 'C' : undefined;
        }, 15000, 'the status bar to show the C language');
        report.tokenColours = await evaluate(
            "new Set([...document.querySelectorAll('.monaco-editor .view-line span span')].map(s => s.className)).size"
        );
        if (report.tokenColours < 4) {
            throw new Error(`C is not highlighted: only ${report.tokenColours} token classes in the editor`);
        }

        // 4. The commands.
        await key('F1', 'F1', 112);
        await waitFor(quickInputOpen, 15000, 'the command palette');
        await setQuickInput('>Prahari');
        await pause(1500);
        const listed = await evaluate(
            "[...document.querySelectorAll('.quick-input-list .monaco-list-row')].map(r => (r.getAttribute('aria-label') || r.textContent).trim())"
        );
        const missing = EXPECTED_COMMANDS.filter(command => !listed.some(row => row.startsWith(command)));
        if (missing.length) {
            throw new Error(`commands missing from the palette: ${missing.join(', ')}`);
        }
        report.commands = EXPECTED_COMMANDS.length;

        // 5. Audit.
        await runCommand('Prahari: Audit Current File');
        report.audit = await waitFor(async () => {
            const count = await evaluate("document.querySelectorAll('.prahari-finding-title').length");
            return count ? evaluate("document.querySelector('.prahari-header-title').textContent") : undefined;
        }, 90000, 'findings in the Prahari panel');
        report.findings = await evaluate("[...document.querySelectorAll('.prahari-finding-title')].map(e => e.textContent)");
        const steps = await evaluate("document.querySelectorAll('.prahari-step').length");
        if (!steps) {
            throw new Error('findings rendered without a path trace');
        }

        // 6. AI status and review.
        await runCommand('Prahari: AI Adjudication Status');
        report.aiStatus = await waitFor(async () => {
            const text = await evaluate('document.body.innerText');
            const line = text && text.split('\n').find(l => l.includes('Prahari AI:'));
            return line ? line.trim() : undefined;
        }, 60000, 'the AI status notification');

        await runCommand('Prahari: Review Findings with AI');
        report.aiReview = await waitFor(async () => {
            const text = await evaluate('document.body.innerText');
            const line = text && text.split('\n').find(l =>
                /reviewed by|review unavailable|no model is configured/i.test(l)
            );
            return line && !text.includes('Reviewing findings') ? line.trim() : undefined;
        }, 180000, 'the AI review to finish');

        await key('Escape', 'Escape', 27);
        await pause(800);
        const shot = await send('Page.captureScreenshot', { format: 'png' });
        fs.writeFileSync(SCREENSHOT, Buffer.from(shot.result.data, 'base64'));
        report.screenshot = SCREENSHOT;
        socket.close();
    } finally {
        chrome.kill();
    }

    report.consoleErrors = errors;
    console.log(JSON.stringify(report, null, 2));
    console.log(errors.length ? '\nFAILED: console errors were reported.' : '\nOK — the IDE works in a real browser.');
    process.exit(errors.length ? 1 : 0);
}

main().catch(error => {
    console.error(`FAILED: ${error.message}`);
    process.exit(1);
});
