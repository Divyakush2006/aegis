/**
 * Real-application check of the Prahari IDE desktop build.
 *
 * `browser-check.js` proves the browser application works. This proves the
 * *desktop program* works, and that it behaves like the editor people already
 * know: it launches the built Electron application, drives it over the Chrome
 * DevTools Protocol the way a user would, and fails on any console error.
 *
 * It starts its own instance rather than attaching to a running one. The
 * application sets `singleInstance`, so a second launch would normally hand off
 * to the window already open and exit immediately; passing `--user-data-dir`
 * gives this run its own instance lock, its own settings and its own layout, so
 * the checks below start from a known state and cannot disturb the window you
 * are working in.
 *
 * Steps, each asserted:
 *   1. the Electron window opens and the Theia shell mounts;
 *   2. the Prahari logo is rendered in the title bar's logo slot;
 *   3. the menu bar carries the menus VS Code has;
 *   4. the activity bar carries Explorer, Search, Source Control, Run and
 *      Debug, and Extensions;
 *   5. the Explorer lists the opened folder's contents, a folder expands, and
 *      clicking a file opens it in an editor tab;
 *   6. Go to File (Ctrl+P) opens a file by name;
 *   7. every Prahari command is registered in the command palette;
 *   8. "Prahari: Audit Current File" lists findings with their path trace;
 *   9. "Prahari: AI Adjudication Status" round-trips through the backend and
 *      the language server (with no key configured it reports that, which also
 *      passes);
 *  10. Run, Audit and Prahari AI sit at the top right of the title bar, left of
 *      the window controls, and Prahari AI has its tab on the right side bar;
 *  11. the editor's Run button compiles and runs a C program — asserted by the
 *      file the program itself writes — and Stop appears while it is running;
 *  12. the title bar's Run button runs a Python script;
 *  13. Ctrl+Alt+N on a JSON file explains there is nothing to execute, and Run on
 *      an HTML page opens the preview;
 *  14. Audit on a non-C file explains what Prahari audits instead of failing;
 *  15. Prahari AI answers a question about the open file (with no key
 *      configured, the panel's setup message also passes).
 *
 * Usage, after `npm run build:desktop`:
 *
 *     node desktop-check.js
 *
 * Environment: PRAHARI_WORKSPACE (folder to open, default compiler/examples),
 * PRAHARI_SCREENSHOT (where to save a PNG of the final state).
 */
const { spawn } = require('child_process');
const fs = require('fs');
const os = require('os');
const path = require('path');

const APP = path.join(__dirname, 'electron-app');
const ELECTRON = path.join(__dirname, 'node_modules', 'electron', 'dist', 'electron.exe');
const ELECTRON_POSIX = path.join(__dirname, 'node_modules', 'electron', 'dist', 'electron');
const EXAMPLES = path.resolve(__dirname, '..', 'compiler', 'examples');
const WORKSPACE = process.env.PRAHARI_WORKSPACE || makeWorkspace();

/**
 * A scratch copy of the examples plus a `run/` folder of small programs, so the
 * Run checks can write their marker files without touching the repository.
 */
function makeWorkspace() {
    const workspace = fs.mkdtempSync(path.join(os.tmpdir(), 'prahari-desktop-workspace-'));
    for (const name of fs.readdirSync(EXAMPLES)) {
        const source = path.join(EXAMPLES, name);
        if (fs.statSync(source).isFile()) {
            fs.copyFileSync(source, path.join(workspace, name));
        }
    }
    const run = path.join(workspace, 'run');
    fs.mkdirSync(run);
    fs.writeFileSync(path.join(run, 'hello.c'), [
        '#include <stdio.h>',
        '',
        'int main(void) {',
        '    FILE *marker = fopen("ran-c.txt", "w");',
        '    if (marker) { fputs("ok", marker); fclose(marker); }',
        '    printf("Hello from C in Prahari IDE\\n");',
        '    return 0;',
        '}',
        ''
    ].join('\n'));
    fs.writeFileSync(path.join(run, 'hello.py'), 'open("ran-py.txt", "w").write("ok")\nprint("Hello from Python in Prahari IDE")\n');
    fs.writeFileSync(path.join(run, 'settings.json'), '{\n    "name": "prahari"\n}\n');
    fs.writeFileSync(path.join(run, 'page.html'), '<!doctype html>\n<title>Prahari</title>\n<h1>Preview from Prahari IDE</h1>\n');
    return workspace;
}
const PORT = 9400 + Math.floor(Math.random() * 400);
const SCREENSHOT = process.env.PRAHARI_SCREENSHOT || path.join(os.tmpdir(), 'prahari-desktop.png');

const EXPECTED_COMMANDS = [
    'Prahari: Audit Current File',
    'Prahari: Review Findings with AI',
    'Prahari: AI Adjudication Status',
    'Prahari: Explain Function at Cursor',
    'Prahari: Show Generated LLVM IR'
];
// The menus VS Code shows, minus Run, which Theia folds into Terminal on some
// layouts; it is asserted through the Run and Debug view instead.
const EXPECTED_MENUS = ['File', 'Edit', 'Selection', 'View', 'Go', 'Terminal', 'Help'];
// The activity bar entries VS Code shows. Each is matched against the tab's id,
// tooltip and label together: Theia draws the side bar as icons and leaves
// `title` empty until a tooltip is actually requested, so the id
// (`shell-tab-explorer-view-container` and friends) is the reliable identifier
// -- and "Source Control" would never match the id fragment `scm` by name.
const EXPECTED_VIEWS = [
    { name: 'Explorer', pattern: /explorer/i },
    { name: 'Search', pattern: /search/i },
    { name: 'Source Control', pattern: /scm|source.?control/i },
    { name: 'Run and Debug', pattern: /debug/i },
    { name: 'Extensions', pattern: /extension/i }
];

const pause = ms => new Promise(resolve => setTimeout(resolve, ms));

/**
 * Whether the checks ran to a verdict. Guarded on process exit: a run that ends
 * any other way -- the application dying, or the event loop simply emptying
 * because something was awaited that never settles -- must not be reported as
 * a pass. An earlier version exited 0 in silence and read as success.
 */
let completed = false;

function electronBinary() {
    for (const candidate of [ELECTRON, ELECTRON_POSIX]) {
        if (fs.existsSync(candidate)) {
            return candidate;
        }
    }
    throw new Error('Electron is not installed; run "npm run build:desktop" first');
}

async function waitFor(check, timeoutMs, label) {
    const started = Date.now();
    let lastError;
    while (Date.now() - started < timeoutMs) {
        try {
            const value = await check();
            if (value) {
                return value;
            }
        } catch (error) {
            lastError = error;
        }
        await pause(500);
    }
    throw new Error(`timed out waiting for ${label}${lastError ? ` (${lastError.message})` : ''}`);
}

async function main() {
    if (!fs.existsSync(path.join(APP, 'lib', 'backend', 'electron-main.js'))) {
        throw new Error('the desktop application is not built; run "npm run build:desktop" first');
    }
    const profile = fs.mkdtempSync(path.join(os.tmpdir(), 'prahari-desktop-check-'));

    // Claude Code and other Electron hosts export ELECTRON_RUN_AS_NODE, which
    // would make the binary behave as plain Node and never open a window.
    const env = { ...process.env };
    delete env.ELECTRON_RUN_AS_NODE;

    // Theia keeps user settings outside the Electron profile, in ~/.theia. A
    // private config directory keeps this run from reading or changing yours,
    // and marks the scratch workspace as trusted, as a folder you have already
    // opened is. (Granting trust mid-session is exercised when the dialog does
    // appear; see step 5.)
    const configDir = fs.mkdtempSync(path.join(os.tmpdir(), 'prahari-desktop-config-'));
    fs.writeFileSync(path.join(configDir, 'settings.json'), JSON.stringify({
        'security.workspace.trust.trustedFolders': [require('url').pathToFileURL(WORKSPACE).href]
    }, null, 4));
    env.THEIA_CONFIG_DIR = configDir;

    const app = spawn(electronBinary(), [
        APP,
        WORKSPACE,
        // The built-in VS Code extensions -- Git, C/C++, the language features --
        // live outside the application folder, so the directory is named
        // explicitly, exactly as `npm start` does.
        `--plugins=local-dir:${path.join(__dirname, 'plugins')}`,
        `--remote-debugging-port=${PORT}`,
        `--user-data-dir=${profile}`
    ], { env, stdio: ['ignore', 'pipe', 'pipe'] });

    let backendLog = '';
    app.stdout.on('data', chunk => { backendLog += chunk; });
    app.stderr.on('data', chunk => { backendLog += chunk; });
    // If the application dies part way through, every pending await is
    // abandoned, Node empties its event loop and exits 0 -- a failed run that
    // reads as a pass, which is worse than no check at all. Fail loudly
    // instead, and print what the application said on its way out.
    app.on('exit', code => {
        if (!completed) {
            fs.writeSync(2, `FAILED: the application exited early (code ${code}).\n`);
            fs.writeSync(2, `${backendLog.slice(-4000)}\n`);
            process.exit(1);
        }
    });

    const errors = [];
    const report = {};
    // Which step is running, so a console error names the action that caused it.
    let phase = 'startup';
    try {
        await waitFor(async () => (await fetch(`http://127.0.0.1:${PORT}/json/version`)).ok,
            60000, 'the Electron DevTools endpoint');

        const target = await waitFor(async () => {
            const targets = await (await fetch(`http://127.0.0.1:${PORT}/json/list`)).json();
            return targets.find(t => t.type === 'page' && /index\.html/.test(t.url));
        }, 60000, 'the Theia window');

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
                errors.push(`[${phase}] exception: ${detail.exception?.description || detail.text}`.slice(0, 300));
            } else if (message.method === 'Runtime.consoleAPICalled' && message.params.type === 'error') {
                errors.push(`[${phase}] console.error: ${message.params.args.map(a => a.value ?? a.description).join(' ')}`.slice(0, 300));
            } else if (message.method === 'Log.entryAdded' && message.params.entry.level === 'error') {
                errors.push(`[${phase}] log: ${message.params.entry.text} ${message.params.entry.url || ''}`.slice(0, 300));
            }
        };
        const send = (method, params = {}) => new Promise(resolve => {
            const id = nextId++;
            pending.set(id, resolve);
            socket.send(JSON.stringify({ id, method, params }));
        });
        const evaluate = async expression => {
            const response = await send('Runtime.evaluate', { expression, returnByValue: true, awaitPromise: true });
            if (response.result?.exceptionDetails) {
                throw new Error(response.result.exceptionDetails.text);
            }
            return response.result?.result?.value;
        };
        const key = async (keyName, code, keyCode, modifiers = 0) => {
            await send('Input.dispatchKeyEvent', { type: 'rawKeyDown', key: keyName, code, windowsVirtualKeyCode: keyCode, modifiers });
            await send('Input.dispatchKeyEvent', { type: 'keyUp', key: keyName, code, windowsVirtualKeyCode: keyCode, modifiers });
        };
        /**
         * Click an element the way a user would, given an expression finding it.
         *
         * A zero-sized rectangle means the element is in the document but not
         * displayed -- a collapsed side panel, say. Clicking its "centre" would
         * land in the corner of the window and do nothing, so it is reported
         * here rather than as a mysterious timeout further down.
         */
        const clickFound = async (findExpression, label, clickCount = 1) => {
            const box = await evaluate(`(() => {
                const el = ${findExpression};
                if (!el) { return null; }
                el.scrollIntoView({ block: 'center' });
                const r = el.getBoundingClientRect();
                return { x: r.left + r.width / 2, y: r.top + r.height / 2, w: r.width, h: r.height };
            })()`);
            if (!box) {
                throw new Error(`no element found for ${label}`);
            }
            if (!box.w || !box.h) {
                throw new Error(`${label} is present but not visible`);
            }
            // Chromium expects the whole sequence: a double click is a first
            // click followed by a second carrying clickCount 2.
            for (let count = 1; count <= clickCount; count++) {
                // `buttons` is the bitfield of what is held down; handlers that
                // consult it ignore an event that claims no button is pressed.
                await send('Input.dispatchMouseEvent', { type: 'mouseMoved', x: box.x, y: box.y, buttons: 0 });
                await send('Input.dispatchMouseEvent', { type: 'mousePressed', x: box.x, y: box.y, button: 'left', buttons: 1, clickCount: count });
                await send('Input.dispatchMouseEvent', { type: 'mouseReleased', x: box.x, y: box.y, button: 'left', buttons: 0, clickCount: count });
            }
        };
        const clickText = (selector, text, clickCount = 1) => clickFound(
            `[...document.querySelectorAll(${JSON.stringify(selector)})].find(e => (e.textContent || '').trim().includes(${JSON.stringify(text)}))`,
            `"${text}" in ${selector}`,
            clickCount
        );
        const clickElement = (selector, clickCount = 1) => clickFound(
            `document.querySelector(${JSON.stringify(selector)})`, selector, clickCount
        );
        const setQuickInput = value => evaluate(
            `(() => { const i = document.querySelector('.quick-input-widget input'); i.value = ${JSON.stringify(value)}; i.dispatchEvent(new Event('input', { bubbles: true })); })()`
        );
        const firstRow = () => evaluate(
            "(document.querySelector('.quick-input-list .monaco-list-row') || {}).textContent || ''"
        );
        const quickInputOpen = () => evaluate(`(() => { const w = document.querySelector('.quick-input-widget');
            return !!w && !!w.querySelector('input') && getComputedStyle(w).display !== 'none' && w.getBoundingClientRect().height > 0; })()`);
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

        // 1. The shell mounts.
        phase = '1. The shell mounts';
        await waitFor(() => evaluate(
            "!!document.querySelector('#theia-main-content-panel') && !document.querySelector('.theia-preload')"
        ), 180000, 'the Theia shell to mount');
        report.title = await evaluate('document.title');
        await pause(6000);

        // 2. The logo, in the slot Theia leaves at the far left of the menu bar.
        phase = '2. The logo, in the slot Theia leaves at the far left of the menu bar';
        report.logo = await waitFor(async () => {
            const image = await evaluate(`(() => {
                const el = document.querySelector('.theia-icon');
                if (!el) { return ''; }
                return getComputedStyle(el).backgroundImage || '';
            })()`);
            return image.includes('data:image/svg+xml') ? 'rendered' : undefined;
        }, 20000, 'the Prahari logo in the title bar');

        // 3. The menus VS Code has.
        phase = '3. The menus VS Code has';
        const menus = await evaluate(
            "[...document.querySelectorAll('.lm-MenuBar-itemLabel, .p-MenuBar-itemLabel')].map(e => e.textContent.trim())"
        );
        const missingMenus = EXPECTED_MENUS.filter(m => !menus.some(label => label.replace(/_/g, '') === m));
        if (missingMenus.length) {
            throw new Error(`menus missing from the menu bar: ${missingMenus.join(', ')} (found ${menus.join(', ')})`);
        }
        report.menus = menus;

        // 4. The activity bar views VS Code has.
        phase = '4. The activity bar views VS Code has';
        const views = await waitFor(async () => {
            const found = await evaluate(`[...document.querySelectorAll('.theia-app-left .lm-TabBar-tab, .theia-app-left .p-TabBar-tab')]
                .map(e => [e.id, e.title, e.getAttribute('aria-label') || '', (e.querySelector('.lm-TabBar-tabLabel') || {}).textContent || '']
                    .filter(Boolean).join(' ').trim())`);
            return found && found.length ? found : undefined;
        }, 60000, 'the activity bar to populate');
        const missingViews = EXPECTED_VIEWS.filter(view => !views.some(text => view.pattern.test(text)));
        if (missingViews.length) {
            throw new Error(
                `activity bar missing: ${missingViews.map(v => v.name).join(', ')}\n  found:\n    ${views.join('\n    ')}`
            );
        }
        report.views = views;

        // 5. The Explorer lists the folder, and a click opens a file.
        phase = '5. The Explorer lists the folder, and a click opens a file';
        // The Explorer tab is never clicked blindly: when its view is already
        // the active one, clicking it collapses the side panel exactly as VS
        // Code does, and every later click then lands on an element that is
        // still in the document but no longer visible.
        // `.theia-FileTree` is a wrapper that always measures 0x0 in Theia 1.75,
        // so it says nothing about whether the Explorer is showing. The elements
        // that carry real geometry are the view container and the tree's own
        // node rows, and a row only has a size once the panel is open and laid
        // out -- which is exactly the question being asked.
        const explorerExists = () => evaluate(
            "!!document.querySelector('#explorer-view-container') || !!document.querySelector('.theia-FileTree')"
        );
        const explorerVisible = () => evaluate(`(() => {
            const container = document.querySelector('#explorer-view-container');
            if (!container) { return false; }
            const c = container.getBoundingClientRect();
            if (!(c.width > 0 && c.height > 0)) { return false; }
            const node = document.querySelector('.theia-FileTree .theia-TreeNodeSegment');
            if (!node) { return false; }
            const n = node.getBoundingClientRect();
            return n.width > 0 && n.height > 0;
        })()`);
        // Existence and visibility are separate questions, and conflating them
        // is what made an earlier run collapse the panel: the view is created a
        // moment after the shell mounts, so a single "not visible yet" check
        // fires while the Explorer is merely still loading.
        await waitFor(explorerExists, 90000, 'the Explorer view to be created');
        // Each attempt is given time to take effect before the next is tried.
        // Checking too soon and immediately trying again is how an earlier run
        // opened the panel with Ctrl+Shift+E and then clicked it shut.
        const reveal = async (attempt, label) => {
            await attempt();
            try {
                await waitFor(explorerVisible, 20000, label);
                return true;
            } catch {
                return false;
            }
        };
        let showing = await explorerVisible();
        if (!showing && await reveal(() => key('e', 'KeyE', 69, 10), 'Ctrl+Shift+E to reveal the Explorer')) {
            // Ctrl+Shift+E, the binding VS Code uses.
            showing = true;
            report.explorerRevealedBy = 'Ctrl+Shift+E';
        }
        if (!showing && await reveal(
            // `:not([id$="-hidden"])` skips the shadow tabs Theia keeps for a
            // collapsed side bar, which cannot be clicked.
            () => clickElement('.theia-app-left .lm-TabBar-tab:not([id$="-hidden"])[id*="explorer"]'),
            'the Explorer tab to open the side panel'
        )) {
            showing = true;
            report.explorerRevealedBy = 'activity bar click';
        }
        if (!showing) {
            const state = await evaluate(`JSON.stringify([...document.querySelectorAll('.theia-app-left .lm-TabBar-tab')]
                .map(e => ({ id: e.id, active: e.classList.contains('lm-mod-current') })))`);
            const tree = await evaluate(`(() => { const t = document.querySelector('.theia-FileTree');
                if (!t) { return 'absent'; } const r = t.getBoundingClientRect();
                return JSON.stringify({ width: r.width, height: r.height }); })()`);
            throw new Error(`the Explorer never became visible\n  tabs: ${state}\n  tree: ${tree}`);
        }

        report.explorer = await waitFor(async () => {
            const names = await evaluate(
                "[...document.querySelectorAll('.theia-FileTree .theia-TreeNodeSegment')].map(e => e.textContent.trim()).filter(Boolean)"
            );
            return names && names.some(n => n.endsWith('.c')) ? names.slice(0, 12) : undefined;
        }, 45000, 'the Explorer to list the workspace');

        // Opening a file from the Explorer, by both routes a user has: a double
        // click, and selecting the row then pressing Enter.
        const editorOpen = async name => {
            const tabs = await evaluate(
                "[...document.querySelectorAll('.lm-TabBar-tabLabel, .p-TabBar-tabLabel')].map(t => t.textContent.trim())"
            );
            const lines = await evaluate("!!document.querySelector('.monaco-editor .view-lines .view-line')");
            return !!(tabs && tabs.some(tab => tab === name) && lines);
        };
        const tryOpen = async attempt => {
            await attempt();
            const started = Date.now();
            while (Date.now() - started < 15000) {
                if (await editorOpen('cmd_injection.c')) {
                    return true;
                }
                await pause(500);
            }
            return false;
        };

        const NODE = '.theia-FileTree .theia-TreeNodeSegment';
        // A folder opened for the first time asks whether its authors are
        // trusted, exactly as VS Code does, and the dialog is modal. Answer it
        // as a user running their own code would.
        const trustDialog = () => evaluate("!!document.querySelector('.workspace-trust-dialog')");
        try {
            await waitFor(trustDialog, 20000, 'the workspace trust dialog');
            await clickText('.workspace-trust-dialog button', 'Yes, I trust the authors');
            await waitFor(async () => !(await trustDialog()), 15000, 'the trust dialog to close');
            report.workspaceTrust = 'asked and granted';
        } catch (error) {
            if (await trustDialog()) {
                throw error;
            }
            report.workspaceTrust = 'not asked';
        }
        // A window driven over CDP has not had a real click yet: the first one
        // only moves focus into the workbench, as a first click into an
        // unfocused window does. Spend it on a folder row, which opens nothing.
        // Windows may also refuse focus to a window launched in the background,
        // so the click is repeated until the tree reacts, with a bounded budget.
        const runSelected = () => evaluate(
            "[...document.querySelectorAll('.theia-FileTree .theia-mod-selected')].some(e => e.textContent.trim() === 'run')"
        );
        await evaluate(`(() => { window.__prahariMouse = []; for (const t of ['mousedown', 'mouseup', 'click']) {
            document.addEventListener(t, e => window.__prahariMouse.push([t, e.clientX, e.clientY, e.buttons, String(e.target.className).slice(0, 40), e.defaultPrevented]), true); } })()`);
        const hasRunFolder = await evaluate(`[...document.querySelectorAll(${JSON.stringify(NODE)})].some(e => e.textContent.trim() === 'run')`);
        for (let attempt = 0; hasRunFolder && attempt < 10 && !(await runSelected()); attempt++) {
            await send('Page.bringToFront');
            await clickFound(
                `[...document.querySelectorAll(${JSON.stringify(NODE)})].find(e => e.textContent.trim() === 'run')`,
                'the run folder'
            );
            await pause(800);
        }
        if (hasRunFolder && !(await runSelected())) {
            const seen = await evaluate('JSON.stringify((window.__prahariMouse || []).slice(-6))');
            const failed = await send('Page.captureScreenshot', { format: 'png' });
            fs.writeFileSync(SCREENSHOT, Buffer.from(failed.result.data, 'base64'));
            throw new Error(`the Explorer never responded to a click; mouse events seen: ${seen}`);
        }
        if (await tryOpen(() => clickText(NODE, 'cmd_injection.c', 2))) {
            report.openedByClick = 'double click';
        } else if (await tryOpen(async () => {
            await clickText(NODE, 'cmd_injection.c');
            await key('Enter', 'Enter', 13);
        })) {
            report.openedByClick = 'select and Enter';
        } else {
            const diagnosis = await evaluate(`JSON.stringify({
                tabs: [...document.querySelectorAll('.lm-TabBar-tabLabel')].map(t => t.textContent.trim()),
                selected: [...document.querySelectorAll('.theia-mod-selected')].map(e => e.textContent.trim().slice(0, 40)),
                editors: document.querySelectorAll('.monaco-editor').length,
                activeElement: document.activeElement ? document.activeElement.className : null,
                node: (() => {
                    const n = [...document.querySelectorAll('.theia-FileTree .theia-TreeNodeSegment')]
                        .find(e => e.textContent.includes('cmd_injection.c'));
                    if (!n) { return null; }
                    const r = n.getBoundingClientRect();
                    const hit = document.elementFromPoint(r.x + r.width / 2, r.y + r.height / 2);
                    return { x: Math.round(r.x), y: Math.round(r.y), w: Math.round(r.width), h: Math.round(r.height),
                        hit: hit ? (hit.id || '') + '.' + String(hit.className).slice(0, 80) : null };
                })()
            })`);
            const failed = await send('Page.captureScreenshot', { format: 'png' });
            fs.writeFileSync(SCREENSHOT, Buffer.from(failed.result.data, 'base64'));
            throw new Error(`clicking the file did not open an editor (screenshot: ${SCREENSHOT})\n  ${diagnosis}`);
        }

        // The editor recognises C, and colours it.
        report.language = await waitFor(async () => {
            const status = await evaluate("(document.querySelector('#theia-statusBar') || {}).innerText || ''");
            return /(^|\s)C(\s|$)/.test(status) && !status.includes('Plain Text') ? 'C' : undefined;
        }, 20000, 'the status bar to show the C language');

        // 6. Go to File.
        phase = '6. Go to File';
        await key('p', 'KeyP', 80, 2);
        await waitFor(quickInputOpen, 15000, 'Go to File');
        let polls = 0;
        await waitFor(async () => {
            if (polls++ % 6 === 0) {
                await setQuickInput('');
                await setQuickInput('memory_bugs');
            }
            return (await firstRow()).includes('memory_bugs.c');
        }, 60000, 'memory_bugs.c in Go to File');
        await key('Enter', 'Enter', 13);
        report.goToFile = await waitFor(async () => {
            const tabs = await evaluate("[...document.querySelectorAll('.lm-TabBar-tabLabel, .p-TabBar-tabLabel')].map(t => t.textContent)");
            return tabs && tabs.includes('memory_bugs.c') ? 'memory_bugs.c' : undefined;
        }, 20000, 'the editor to open memory_bugs.c');

        // 7. The Prahari commands.
        phase = '7. The Prahari commands';
        await key('Escape', 'Escape', 27);
        await key('F1', 'F1', 112);
        await waitFor(quickInputOpen, 15000, 'the command palette');
        await setQuickInput('>Prahari');
        await pause(2000);
        const listed = await evaluate(
            "[...document.querySelectorAll('.quick-input-list .monaco-list-row')].map(r => (r.getAttribute('aria-label') || r.textContent).trim())"
        );
        const missing = EXPECTED_COMMANDS.filter(command => !listed.some(row => row.startsWith(command)));
        if (missing.length) {
            throw new Error(`commands missing from the palette: ${missing.join(', ')}`);
        }
        report.commands = EXPECTED_COMMANDS.length;

        // 8. Audit.
        phase = '8. Audit';
        await runCommand('Prahari: Audit Current File');
        report.audit = await waitFor(async () => {
            const count = await evaluate("document.querySelectorAll('.prahari-finding-title').length");
            return count ? evaluate("document.querySelector('.prahari-header-title').textContent") : undefined;
        }, 120000, 'findings in the Prahari panel');
        report.findings = await evaluate("[...document.querySelectorAll('.prahari-finding-title')].map(e => e.textContent)");
        const steps = await evaluate("document.querySelectorAll('.prahari-step').length");
        if (!steps) {
            throw new Error('findings rendered without a path trace');
        }
        report.pathSteps = steps;

        // 9. AI status.
        phase = '9. AI status';
        await runCommand('Prahari: AI Adjudication Status');
        report.aiStatus = await waitFor(async () => {
            const text = await evaluate('document.body.innerText');
            const line = text && text.split('\n').find(l => l.includes('Prahari AI:'));
            return line ? line.trim() : undefined;
        }, 60000, 'the AI status notification');

        // Helpers for the Run and AI steps.
        const goToFile = async name => {
            // A focused terminal keeps Ctrl+P for the shell, as it does in VS Code.
            await evaluate('document.activeElement && document.activeElement.blur()');
            await key('Escape', 'Escape', 27);
            await key('p', 'KeyP', 80, 2);
            await waitFor(quickInputOpen, 15000, 'Go to File');
            let tries = 0;
            await waitFor(async () => {
                if (tries++ % 6 === 0) {
                    await setQuickInput('');
                    await setQuickInput(name);
                }
                return (await firstRow()).includes(name);
            }, 60000, `${name} in Go to File`);
            await key('Enter', 'Enter', 13);
            await waitFor(async () => {
                const active = await evaluate(
                    "[...document.querySelectorAll('#theia-main-content-panel .lm-mod-current .lm-TabBar-tabLabel, #theia-main-content-panel .p-mod-current .p-TabBar-tabLabel')].map(t => t.textContent.trim())"
                );
                return active && active.includes(name);
            }, 20000, `the editor to show ${name}`);
            await pause(1000);
        };
        const visible = selector => `[...document.querySelectorAll(${JSON.stringify(selector)})].find(e => { const r = e.getBoundingClientRect(); return r.width > 0 && r.height > 0; })`;
        const bodyHas = pattern => async () => {
            const text = await evaluate('document.body.innerText');
            const match = text && text.match(pattern);
            return match ? match[0] : undefined;
        };
        const runDir = path.join(WORKSPACE, 'run');

        // 10. The title bar and the right side bar.
        phase = '10. The title bar and the right side bar';
        report.titleBar = await waitFor(() => evaluate(`(() => {
            const bar = document.getElementById('prahari-title-actions');
            if (!bar) { return undefined; }
            const r = bar.getBoundingClientRect();
            const controls = document.getElementById('window-controls');
            const c = controls ? controls.getBoundingClientRect() : { left: window.innerWidth };
            if (!r.width || r.left < window.innerWidth / 2 || r.right > c.left + 1) {
                return 'misplaced ' + JSON.stringify({ left: r.left, right: r.right, controls: c.left, width: window.innerWidth });
            }
            return [...bar.querySelectorAll('button')].map(b => b.textContent.trim() || b.id.replace('prahari-title-', ''));
        })()`), 20000, 'the title-bar actions');
        if (typeof report.titleBar === 'string') {
            throw new Error(`title-bar actions are ${report.titleBar}`);
        }
        await waitFor(() => evaluate(`!!(${visible('[id="shell-tab-prahari.chat"]')})`), 20000, 'the Prahari AI tab on the right side bar');
        report.aiSideBarTab = 'present';

        // 11. Run a C program from the editor's play button.
        phase = "11. Run a C program from the editor's play button";
        await goToFile('hello.c');
        await clickFound(visible('[id="prahari.toolbar.run"]'), 'the editor Run button');
        await waitFor(() => fs.existsSync(path.join(runDir, 'ran-c.txt')), 120000, 'the C program to run (its marker file)');
        report.runC = await waitFor(bodyHas(/Run: hello\.c/), 20000, 'the Run: hello.c terminal');
        report.stopButton = await waitFor(() => evaluate(`!!(${visible('[id="prahari.toolbar.stop"]')})`), 20000, 'the Stop button') && 'shown';

        // 12. Run a Python script from the title bar.
        phase = '12. Run a Python script from the title bar';
        await goToFile('hello.py');
        await clickElement('#prahari-title-run');
        await waitFor(() => fs.existsSync(path.join(runDir, 'ran-py.txt')), 120000, 'the Python script to run (its marker file)');
        report.runPython = await waitFor(bodyHas(/Run: hello\.py/), 20000, 'the Run: hello.py terminal');

        // 13. Files that are not programs.
        phase = '13. Files that are not programs';
        await goToFile('settings.json');
        await key('n', 'KeyN', 78, 2 | 1);
        report.runJson = await waitFor(bodyHas(/settings\.json is a JSON data file[^\n]*/), 30000, 'the explanation for a JSON file');
        await goToFile('page.html');
        await clickFound(visible('[id="prahari.toolbar.run"]'), 'the editor Run button');
        report.runHtml = await waitFor(() => evaluate(`!!(${visible('.theia-mini-browser')})`), 30000, 'the HTML preview') && 'preview opened';

        // 14. Audit on a file that is not C.
        phase = '14. Audit on a file that is not C';
        await goToFile('hello.py');
        await clickElement('#prahari-title-audit');
        report.auditNonC = await waitFor(bodyHas(/Prahari audits C source[^\n]*/), 30000, 'the audit explanation for Python');

        // 15. Prahari AI.
        phase = '15. Prahari AI';
        await goToFile('hello.c');
        await clickElement('#prahari-title-ai');
        await waitFor(() => evaluate(`!!(${visible('.prahari-chat-panel')})`), 20000, 'the Prahari AI panel');
        await evaluate(`(() => {
            const input = document.querySelector('.prahari-chat-input');
            Object.getOwnPropertyDescriptor(HTMLTextAreaElement.prototype, 'value').set.call(input, 'In one short sentence, what does this program print?');
            input.dispatchEvent(new Event('input', { bubbles: true }));
        })()`);
        await pause(300);
        await clickElement('.prahari-chat-send');
        const answer = JSON.parse(await waitFor(() => evaluate(`(() => {
            const m = [...document.querySelectorAll('.prahari-chat-message.assistant')].filter(e => !e.classList.contains('prahari-chat-thinking')).pop();
            return m ? JSON.stringify({ error: m.classList.contains('error'), text: m.innerText.trim().slice(0, 300) }) : undefined;
        })()`), 240000, 'a Prahari AI reply'));
        // A configured model must answer; an exhausted free quota is the network's verdict, not the IDE's.
        if (answer.error && / via /.test(report.aiStatus || '') && !/quota|rate.?limit|429|timed? ?out/i.test(answer.text)) {
            throw new Error(`Prahari AI is configured but failed to answer: ${answer.text}`);
        }
        report.chat = answer.text;

        // Replies are mostly code: a fenced block must render with its text and Copy/Insert actions.
        if (!answer.error) {
            await evaluate(`(() => {
                const input = document.querySelector('.prahari-chat-input');
                Object.getOwnPropertyDescriptor(HTMLTextAreaElement.prototype, 'value').set.call(input,
                    'Reply with only a fenced C code block containing the single line: int answer = 42;');
                input.dispatchEvent(new Event('input', { bubbles: true }));
            })()`);
            await pause(300);
            await clickElement('.prahari-chat-send');
            const block = JSON.parse(await waitFor(() => evaluate(`(() => {
                const all = [...document.querySelectorAll('.prahari-chat-message.assistant')].filter(e => !e.classList.contains('prahari-chat-thinking'));
                if (all.length < 2) { return undefined; }
                const m = all.pop();
                const pre = m.querySelector('pre.prahari-chat-code');
                return JSON.stringify({ error: m.classList.contains('error'), code: pre ? pre.querySelector('code').textContent : null,
                    actions: pre ? pre.querySelectorAll('.prahari-chat-code-actions button').length : 0, text: m.innerText.slice(0, 200) });
            })()`), 240000, 'a second Prahari AI reply'));
            if (!block.error) {
                if (!block.code || !block.code.includes('42') || block.actions !== 2) {
                    throw new Error(`a code block in a reply did not render: ${JSON.stringify(block)}`);
                }
                report.chatCodeBlock = block.code.trim();
            }
        }
        const askItem = await evaluate(`(() => { const e = ${visible('[id="prahari.toolbar.ask"]')}; return e ? e.textContent.trim() + '|' + e.className : null; })()`);
        if (!askItem || askItem.split('|')[0] !== '' || !askItem.includes('codicon-sparkle')) {
            throw new Error(`the editor's Prahari AI button should be a sparkle icon, found: ${askItem}`);
        }

        await key('Escape', 'Escape', 27);
        await pause(800);
        const shot = await send('Page.captureScreenshot', { format: 'png' });
        fs.writeFileSync(SCREENSHOT, Buffer.from(shot.result.data, 'base64'));
        report.screenshot = SCREENSHOT;
        socket.close();
    } finally {
        if (errors.length && !completed) {
            const firstLines = errors.map(e => e.split('\n')[0]);
            fs.writeSync(2, `console errors so far:\n  ${firstLines.join('\n  ')}\n`);
        }
        app.kill();
    }

    // One upstream Theia 1.75 defect is reported separately rather than hidden.
    // Opening a file by double-click can leave the VS Code extension host's tab
    // model one step behind, and its next update throws "INVALID tab" inside
    // the extension host. It has no visible effect. It reproduced on 4 of 4
    // double-clicks in a build with every Prahari frontend contribution removed,
    // and with preview tabs disabled, so it is not caused by this application.
    // Anything else, including any other message from the tab model, fails.
    const UPSTREAM = /exception: Error: INVALID tab\n\s+at TabGroupExt\.acceptTabOperation/;
    report.knownUpstream = errors.filter(e => UPSTREAM.test(e)).map(e => e.split('\n')[0]);
    errors.splice(0, errors.length, ...errors.filter(e => !UPSTREAM.test(e)));
    report.consoleErrors = errors;
    completed = true;
    // fs.writeSync rather than console.log: when stdout is a file or a pipe,
    // Node writes it asynchronously and process.exit() truncates what is still
    // queued -- which is how an earlier run produced an empty report.
    fs.writeSync(1, `${JSON.stringify(report, null, 2)}\n`);
    fs.writeSync(1, errors.length
        ? '\nFAILED: console errors were reported.\n'
        : '\nOK — the desktop application works.\n');
    process.exit(errors.length ? 1 : 0);
}

// The last line of defence: whatever happens, a run that did not reach a
// verdict reports failure rather than ending quietly with status 0.
process.on('exit', code => {
    if (!completed) {
        fs.writeSync(2, `FAILED: the check ended without reaching a verdict (exit code ${code}).\n`);
        if (code === 0) {
            process.exitCode = 1;
        }
    }
});

main().catch(error => {
    fs.writeSync(2, `FAILED: ${error.stack || error.message}\n`);
    process.exit(1);
});
