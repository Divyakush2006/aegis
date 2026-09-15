/**
 * Share the running Prahari IDE with your own devices over an authenticated HTTPS link.
 *
 * The IDE is a full development environment -- editor, file access and a
 * terminal on this computer -- and Theia has no login of its own. Publishing
 * port 3000 directly would hand all of that to anyone who found the URL. So:
 *
 *   phone / laptop  --https-->  Cloudflare quick tunnel  -->  this gateway (127.0.0.1:3100)
 *                                                               |  checks the access token
 *                                                               v
 *                                                        Prahari IDE (127.0.0.1:3000)
 *
 * - The IDE keeps listening on loopback only; nothing is opened on the local
 *   network or the Windows firewall.
 * - The gateway admits a browser only after it presents the random access token
 *   once (it is part of the printed link); the browser then holds an HttpOnly
 *   session cookie derived from it. Every HTTP request and websocket upgrade is
 *   checked. Repeated wrong tokens from one address are throttled.
 * - The token changes on every run unless PRAHARI_SHARE_TOKEN is set, and closing
 *   this process closes the tunnel.
 *
 * Usage, with the IDE already running (`npm start`):
 *
 *     node share.js
 *
 * Environment: PRAHARI_CLOUDFLARED (path to cloudflared), PRAHARI_SHARE_TOKEN,
 * PRAHARI_SHARE_PORT (gateway port, default 3100), PRAHARI_IDE_PORT (default 3000).
 */
const { spawn } = require('child_process');
const crypto = require('crypto');
const fs = require('fs');
const http = require('http');
const net = require('net');
const os = require('os');
const path = require('path');

const IDE_HOST = '127.0.0.1';
const IDE_PORT = Number(process.env.PRAHARI_IDE_PORT || 3000);
const GATEWAY_PORT = Number(process.env.PRAHARI_SHARE_PORT || 3100);
const TOKEN = process.env.PRAHARI_SHARE_TOKEN || crypto.randomBytes(24).toString('base64url');
const COOKIE = 'prahari_share';
// The cookie carries a value derived from the token, never the token itself.
const SESSION = crypto.createHash('sha256').update(`prahari-session:${TOKEN}`).digest('base64url');
const SESSION_SECONDS = 12 * 60 * 60;
const MAX_FAILURES = 20;
const FAILURE_WINDOW_MS = 10 * 60 * 1000;
// Harmless static assets a browser fetches before the user has authenticated.
const PUBLIC_PATHS = new Set(['/favicon.ico']);

// --- authentication -----------------------------------------------------------

function safeEqual(a, b) {
    const left = Buffer.from(String(a));
    const right = Buffer.from(String(b));
    return left.length === right.length && crypto.timingSafeEqual(left, right);
}

function sessionCookie(request) {
    for (const part of (request.headers.cookie || '').split(';')) {
        const [name, ...value] = part.trim().split('=');
        if (name === COOKIE) {
            return value.join('=');
        }
    }
    return '';
}

const authorised = request => safeEqual(sessionCookie(request), SESSION);
const clientAddress = request => request.headers['cf-connecting-ip'] || request.socket.remoteAddress || 'unknown';

const failures = new Map();
function throttled(address) {
    const entry = failures.get(address);
    if (!entry) {
        return false;
    }
    if (Date.now() - entry.since > FAILURE_WINDOW_MS) {
        failures.delete(address);
        return false;
    }
    return entry.count >= MAX_FAILURES;
}
function recordFailure(address) {
    const entry = failures.get(address) || { count: 0, since: Date.now() };
    entry.count += 1;
    failures.set(address, entry);
}

function deny(response, status, message) {
    response.writeHead(status, {
        'Content-Type': 'text/html; charset=utf-8',
        'Cache-Control': 'no-store',
        'Referrer-Policy': 'no-referrer'
    });
    response.end(
        `<!doctype html><meta name="viewport" content="width=device-width,initial-scale=1">` +
        `<title>Prahari IDE</title><body style="font-family:system-ui,sans-serif;background:#1e1e1e;color:#ddd;` +
        `display:grid;place-items:center;min-height:100vh;margin:0;padding:0 16px">` +
        `<div style="max-width:28rem;text-align:center"><h1 style="font-weight:600">Prahari IDE</h1>` +
        `<p>${message}</p></div></body>`
    );
}

// --- the gateway ----------------------------------------------------------------

const gateway = http.createServer((request, response) => {
    const address = clientAddress(request);
    const url = new URL(request.url, 'http://gateway');
    const offered = url.searchParams.get('prahari_token');

    if (offered !== null) {
        if (throttled(address)) {
            return deny(response, 429, 'Too many attempts. Try again later.');
        }
        if (!safeEqual(offered, TOKEN)) {
            recordFailure(address);
            return deny(response, 401, 'This access link is not valid.');
        }
        // Exchange the token for a session cookie, then drop it from the address
        // bar so it is not left in history or sent onward as a referrer.
        url.searchParams.delete('prahari_token');
        const secure = String(request.headers['x-forwarded-proto'] || '').includes('https');
        response.writeHead(302, {
            'Set-Cookie': `${COOKIE}=${SESSION}; Path=/; HttpOnly; SameSite=Lax; Max-Age=${SESSION_SECONDS}${secure ? '; Secure' : ''}`,
            Location: `${url.pathname}${url.search}`,
            'Cache-Control': 'no-store',
            'Referrer-Policy': 'no-referrer'
        });
        return response.end();
    }

    if (!authorised(request) && !PUBLIC_PATHS.has(url.pathname)) {
        return deny(response, 401, 'This Prahari IDE is private. Open it with the full access link.');
    }

    // Headers pass through unchanged -- the Host header in particular, because
    // Theia accepts a websocket only when its Origin matches the Host.
    const upstream = http.request(
        { host: IDE_HOST, port: IDE_PORT, method: request.method, path: request.url, headers: request.headers },
        ideResponse => {
            response.writeHead(ideResponse.statusCode, ideResponse.headers);
            ideResponse.pipe(response);
        }
    );
    upstream.on('error', () => {
        if (!response.headersSent) {
            deny(response, 502, 'The Prahari IDE is not running on the host computer.');
        } else {
            response.destroy();
        }
    });
    request.pipe(upstream);
});

gateway.on('upgrade', (request, socket, head) => {
    if (!authorised(request)) {
        socket.end('HTTP/1.1 401 Unauthorized\r\nConnection: close\r\n\r\n');
        return;
    }
    const upstream = net.connect(IDE_PORT, IDE_HOST, () => {
        const lines = [`${request.method} ${request.url} HTTP/${request.httpVersion}`];
        for (let index = 0; index < request.rawHeaders.length; index += 2) {
            lines.push(`${request.rawHeaders[index]}: ${request.rawHeaders[index + 1]}`);
        }
        upstream.write(`${lines.join('\r\n')}\r\n\r\n`);
        if (head && head.length) {
            upstream.write(head);
        }
        socket.pipe(upstream).pipe(socket);
    });
    upstream.on('error', () => socket.destroy());
    socket.on('error', () => upstream.destroy());
});

// --- the tunnel -----------------------------------------------------------------

function findCloudflared() {
    const candidates = [
        process.env.PRAHARI_CLOUDFLARED,
        path.join(process.env.LOCALAPPDATA || '', 'prahari', 'bin', 'cloudflared.exe'),
        'C:/Program Files (x86)/cloudflared/cloudflared.exe',
        '/usr/local/bin/cloudflared',
        '/usr/bin/cloudflared',
        '/opt/homebrew/bin/cloudflared'
    ].filter(Boolean);
    return candidates.find(candidate => fs.existsSync(candidate)) || 'cloudflared';
}

/** Theia opens a workspace from the URL hash; point shared links at the examples. */
function workspaceHash() {
    let folder = path.resolve(__dirname, '..', 'compiler', 'examples').split(path.sep).join('/');
    if (/^[A-Za-z]:/.test(folder)) {
        folder = `/${folder[0].toLowerCase()}${folder.slice(1)}`;
    }
    return `#${encodeURI(folder)}`;
}

function ideIsRunning() {
    return new Promise(resolve => {
        const probe = http.get({ host: IDE_HOST, port: IDE_PORT, path: '/', timeout: 5000 }, response => {
            response.resume();
            resolve(true);
        });
        probe.on('error', () => resolve(false));
        probe.on('timeout', () => {
            probe.destroy();
            resolve(false);
        });
    });
}

async function main() {
    if (!(await ideIsRunning())) {
        console.error(`The Prahari IDE is not running on ${IDE_HOST}:${IDE_PORT}. Start it with "npm start" first.`);
        process.exit(1);
    }

    await new Promise((resolve, reject) => {
        gateway.once('error', reject);
        gateway.listen(GATEWAY_PORT, '127.0.0.1', resolve);
    });

    const tunnel = spawn(findCloudflared(), [
        'tunnel', '--no-autoupdate', '--url', `http://127.0.0.1:${GATEWAY_PORT}`
    ], { stdio: ['ignore', 'pipe', 'pipe'] });

    let announced = false;
    const watch = chunk => {
        const match = String(chunk).match(/https:\/\/[a-z0-9-]+\.trycloudflare\.com/);
        if (match && !announced) {
            announced = true;
            const link = `${match[0]}/?prahari_token=${TOKEN}${workspaceHash()}`;
            const saved = path.join(os.tmpdir(), 'prahari-share-link.txt');
            fs.writeFileSync(saved, `${link}\n`, { mode: 0o600 });
            console.log('\nPrahari IDE is shared over HTTPS.\n');
            console.log(`  Open on any device:  ${link}\n`);
            console.log('  Anyone holding this link can use the IDE on this computer, including its');
            console.log('  terminal and files. Keep it to your own devices. Press Ctrl+C to stop sharing.');
            console.log(`  (The link is also saved to ${saved}.)\n`);
        }
    };
    tunnel.stdout.on('data', watch);
    tunnel.stderr.on('data', watch);
    tunnel.on('error', error => {
        console.error(`Could not start cloudflared (${error.message}). Set PRAHARI_CLOUDFLARED to its path.`);
        process.exit(1);
    });
    tunnel.on('exit', code => {
        console.error(`The tunnel closed (cloudflared exited with ${code}).`);
        gateway.close();
        process.exit(code || 1);
    });

    const stop = () => {
        tunnel.kill();
        gateway.close();
        process.exit(0);
    };
    process.on('SIGINT', stop);
    process.on('SIGTERM', stop);
}

main().catch(error => {
    console.error(`Could not start sharing: ${error.message}`);
    process.exit(1);
});
