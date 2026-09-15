# Aegis IDE

A development environment for the Aegis compiler, built on
[Eclipse Theia](https://theia-ide.org/).

## Why Theia rather than VS Code

Theia reuses the Monaco editor, hosts VS Code extensions, and speaks LSP and
DAP — so it looks and feels like VS Code — but it is an independently developed,
vendor-neutral platform under the Eclipse Foundation, not a fork.

That distinction is the reason it was chosen:

| | VS Code fork / extension | Theia |
|---|---|---|
| Custom views and panels | only what the extension API allows | any layer |
| Architectural change | difficult to impossible | supported by design |
| Branding, menus, shell | constrained | first-class |
| Licence | MIT code, Microsoft-controlled project | EPL-2.0, Eclipse Foundation |

Aegis needs a findings panel that renders multi-step dataflow traces, its own
backend service driving a Python compiler, and its own product identity. All
three are ordinary work in Theia.

Nothing upstream is patched — `aegis-ide` is an extension that depends on
Theia's public APIs. Upgrading Theia is a version bump.

## Layout

```
ide/
├── package.json              npm workspace root
├── aegis-ide/                the Aegis extension
│   └── src/
│       ├── common/           the TypeScript ↔ Python contract
│       │   └── aegis-protocol.ts
│       ├── node/             backend: drives the Python language server
│       │   ├── aegis-server.ts
│       │   └── aegis-backend-module.ts
│       └── browser/          frontend: panel, commands, markers
│           ├── findings-widget.tsx
│           ├── aegis-contribution.ts
│           ├── aegis-frontend-module.ts
│           └── style/index.css
└── browser-app/              the assembled application
```

`common/aegis-protocol.ts` is the entire language boundary. The frontend knows
about findings and path steps; it never learns what a lattice is.

## Build and run

```bash
npm install
npm run build
npm start          # http://127.0.0.1:3000
```

**No C++ toolchain is required, on any platform.** Two decisions make that true:

- **`ide/.npmrc` sets `ignore-scripts=true`.** Theia depends on `drivelist`,
  whose install script compiles C++ and which publishes no prebuilt Windows
  binary; without the Visual Studio C++ workload that script fails and aborts
  the whole install. Every other native module the IDE uses (`node-pty`,
  `@parcel/watcher`, `trash`) ships its binary inside the package. Not running
  third-party install scripts is also the safer default.
- **`browser-app/esbuild.mjs` substitutes a pure-JS `drivelist`** when the native
  binary is absent. Theia calls exactly one function from it, `list()`, to offer
  drive roots in file dialogs; `browser-app/shims/drivelist.js` answers that from
  the file system. Where drivelist *did* compile, the native module is kept.

Verified on Windows 11 with Node 22 and Visual Studio Build Tools **without** the
C++ workload: the build finishes with 0 errors and the IDE serves on
`http://127.0.0.1:3000`.

The extension searches upward for the `compiler/` directory — from its own
location and from the working directory — and launches it as
`python -m aegis.server.lsp_server`. Override with:

| Variable | Purpose |
|---|---|
| `AEGIS_PYTHON` | interpreter to use (default `python`) |
| `AEGIS_COMPILER_ROOT` | path to the `compiler/` directory |
| `OPENROUTER_API_KEY` | in the project-root `.env`; enables AI review. The IDE works fully without it |

The compiler process the backend spawns reads the project-root `.env` itself,
so adding a key there and restarting the IDE is the whole setup. It is never read in the browser
process and never crosses the JSON-RPC boundary — the frontend receives a
fingerprint, not a credential.

## What it contributes

| Command | Binding | Behaviour |
|---|---|---|
| **Aegis: Audit Current File** | <kbd>Ctrl</kbd>+<kbd>Alt</kbd>+<kbd>A</kbd> | Full pipeline; populates the findings panel and the Problems view |
| **Aegis: Show Findings Panel** | — | Toggles the panel |
| **Aegis: Explain Function at Cursor** | — | CFG shape, call targets and interprocedural taint summary |
| **Aegis: Show Generated LLVM IR** | — | Runs the backend over the open file |
| **Aegis: Review Findings with AI** | — | Audits, then reviews each finding through the configured model |
| **Aegis: AI Adjudication Status** | — | Model, endpoint and key fingerprint — never the key |

Plus, live from the language server as you edit: type-checker diagnostics on
save, hover showing declared types and taint summaries, and completion filtered
against the symbol table.

C files open as **C**, not Plain Text: syntax highlighting, comment toggling,
bracket matching and auto-closing come from a Monarch tokenizer the extension
registers with Monaco itself (`aegis-ide/src/browser/c-language.ts`), because
Theia ships Monaco without its bundled languages. It steps aside if a VS Code
C/C++ extension or a later Theia release provides C.

The application also includes the everyday navigation an IDE needs:
**Go to File** (<kbd>Ctrl</kbd>+<kbd>P</kbd>) and **Find in Files**
(<kbd>Ctrl</kbd>+<kbd>Shift</kbd>+<kbd>F</kbd>), both backed by ripgrep. The
ripgrep binary ships as a per-platform npm package, so this too works with
install scripts disabled.

That last one is the project's argument made visible. Completion candidates come
from the scope tree, so an identifier that is not in scope at the cursor is not
offered — not ranked low, *absent*. A test asserts it
(`compiler/tests/test_server.py::test_out_of_scope_identifiers_are_absent_not_merely_ranked_low`).

## The findings panel

LSP diagnostics can carry a message and a location; they cannot express "this
value came from `argv`, crossed `strcpy`, then `build_command`, and arrived at
`system`". So findings travel over a custom `aegis/findings` notification with
the full trace, and the panel renders it:

```
● CWE-78: OS Command Injection                        main:19

  ● SOURCE     10  int main(int argc, char **argv) {
  │                parameter is attacker-controlled
  ▼
  ○ PROPAGATE  17  strcpy(host, argv[1]);
  │                read from tainted storage, then propagated by strcpy()
  ▼
  ● SINK       19  system(cmd);
  │                argument is executed by the shell

  GUARDS ON PATH   if (argc < 2) { (line 14)
  MISSING CONTROL  input validation or an allowlist before the command is executed
```

Every row navigates to its source location. Findings are *also* mirrored into
the Problems view and the editor gutter, because a reviewer scanning code wants
a squiggle while a reviewer judging a report wants the trace.

## AI review in the panel

**Aegis: Review Findings with AI** is a separate command from **Audit** on
purpose: an audit is local and free, while review costs a network round trip per
finding. That should be a choice, not something that happens to a user.

When a review has run, each finding carries a verdict badge and the model's
reasoning:

```
● CWE-78: OS Command Injection   [DISMISSED]          main:19
  ...
  AI REVIEW  claude-sonnet-5 · confidence 0.80 — the argc guard bounds the copy
```

A dismissed finding is struck through and faded — still present, still
clickable. The compiler found the path; a reviewer who disagrees with the
dismissal has to be able to see it. A finding whose review failed is badged
`unreviewed` rather than left looking unexamined, because "no one looked" and
"someone looked and agreed" are different facts.

Design, invariants and failure semantics: [../docs/AI.md](../docs/AI.md).

## Checking it

Two checks, at different levels:

```bash
node e2e-check.js        # Node drives the Python language server directly
npm start                # then, in another terminal:
node browser-check.js    # the running IDE, driven in headless Chrome
```

`browser-check.js` opens the IDE the way a user would — workspace, Go to File,
command palette, audit, AI status and review — over the Chrome DevTools
Protocol, and fails on any console error. It has caught problems no unit test
could: an IDE without a working Go to File, and a findings header that read
"0 findings" before any audit had run. It needs Chrome, Chromium or Edge
(`AEGIS_CHROME` to point at one) and makes no model request that is not
already cached.

## Extending it

Add a command: register it in `aegis-contribution.ts`, add the corresponding
`@server.command` handler in `compiler/src/aegis/server/lsp_server.py`, and
declare its types in `common/aegis-protocol.ts`. Those three files are the whole
surface.
