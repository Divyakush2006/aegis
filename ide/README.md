# Prahari IDE

A development environment for the Prahari compiler, built on
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

Prahari needs a findings panel that renders multi-step dataflow traces, its own
backend service driving a Python compiler, and its own product identity. All
three are ordinary work in Theia.

Nothing upstream is patched — `prahari-ide` is an extension that depends on
Theia's public APIs. Upgrading Theia is a version bump.

## Layout

```
ide/
├── package.json              npm workspace root
├── prahari-ide/                the Prahari extension
│   └── src/
│       ├── common/           the TypeScript ↔ Python contract
│       │   └── prahari-protocol.ts
│       ├── node/             backend: drives the Python language server
│       │   ├── prahari-server.ts
│       │   ├── run-planner.ts        how Run runs each kind of file
│       │   └── prahari-backend-module.ts
│       └── browser/          frontend: panels, commands, buttons, markers
│           ├── findings-widget.tsx
│           ├── chat-widget.tsx       Prahari AI
│           ├── prahari-contribution.ts
│           ├── run-contribution.ts   Run and Stop
│           ├── toolbar-contribution.ts   editor and title-bar buttons
│           ├── welcome-widget.tsx
│           ├── prahari-frontend-module.ts
│           └── style/
├── browser-app/              the application, served in a browser
├── electron-app/             the same application, as a desktop program
├── shims/                    pure-JS stand-ins for native modules (see below)
└── scripts/                  the logo generator and the Start menu shortcut
```

The two applications are assemblies, not forks: both list the same Theia
packages and the same `prahari-ide` extension, and differ only in their Theia
build target. Every feature below is present in both.

`common/prahari-protocol.ts` is the entire language boundary. The frontend knows
about findings and path steps; it never learns what a lattice is.

## Build and run

```bash
npm install
npm run download:plugins   # the built-in VS Code extensions — once, ~200 MB

npm run build              # the browser application
npm start                  # http://127.0.0.1:3000

npm run build:desktop      # the desktop application
npm run start:desktop      # opens in its own window
```

`download:plugins` fetches the same built-in extension set VS Code ships — Git,
C/C++, the language features, the JavaScript debugger: 90 extensions into
`ide/plugins/`, which is git-ignored because it is downloadable content rather
than source. The IDE runs without them; it simply has no Git integration and no
Extensions to manage, so it is worth the one-time download.

### As a desktop program

`npm run start:desktop` is still a developer's entry point — it needs a terminal
that stays open. To launch Prahari IDE the way any other program is launched:

```powershell
powershell -ExecutionPolicy Bypass -File scripts\Install-Shortcut.ps1 -Desktop
```

It appears in the Start menu and can be pinned to the taskbar; `-Remove` deletes
the shortcut again. Nothing is installed or copied — the shortcut runs Electron
directly against the build in this repository, which is also why no console
window appears behind it.

The desktop build differs from the browser one in three ways that are worth
knowing:

- **Electron is downloaded by the build, not by `npm install`.** Because
  `.npmrc` disables install scripts (below), Electron's own postinstall never
  runs; Theia's build step fetches the matching binary itself, so the first
  `npm run build:desktop` is slower than later ones and needs a network
  connection.
- **One window per machine.** `singleInstance` is set, so launching it again
  focuses the window you already have rather than starting a second backend.
- **It is a program, not a page**: its own icon, taskbar entry, native menus and
  window controls, and no port to visit or leave open.

**No C++ toolchain is required, on any platform.** Two decisions make that true:

- **`ide/.npmrc` sets `ignore-scripts=true`.** Theia depends on `drivelist`,
  whose install script compiles C++ and which publishes no prebuilt Windows
  binary; without the Visual Studio C++ workload that script fails and aborts
  the whole install. Every other native module the IDE uses (`node-pty`,
  `@parcel/watcher`, `trash`) ships its binary inside the package. Not running
  third-party install scripts is also the safer default.
- **`shims/native-fallbacks.mjs` substitutes pure-JS stand-ins** for the three
  native modules that publish no prebuilt binary, and only where the binary is
  genuinely absent — a machine that compiled them keeps the real ones. Both
  applications import the one plugin, so their builds cannot drift apart:

  | Module | What it does | What the stand-in gives up |
  |---|---|---|
  | `drivelist` | drive roots in file dialogs | nothing — the same list, read from the file system |
  | `native-keymap` | the OS keyboard layout | the per-key character map; the layout itself is still read from the Windows registry, and keybindings match by physical key position |
  | `@vscode/windows-ca-certs` | Windows' certificate store, for VS Code's proxy agent | automatic trust of a *corporate* root certificate; Node's own CA list still applies, as it does on Linux and macOS |

  A fourth, `@theia/ffmpeg`, is handled in `electron-app/build.js`: its
  codec-stripping replacement runs normally, and only its *verification* — which
  needs an addon that cannot be compiled here — is skipped.

Verified on Windows 11 with Node 22 and Visual Studio Build Tools **without** the
C++ workload: the build finishes with 0 errors and the IDE serves on
`http://127.0.0.1:3000`.

The extension searches upward for the `compiler/` directory — from its own
location and from the working directory — and launches it as
`python -m prahari.server.lsp_server`. Override with:

| Variable | Purpose |
|---|---|
| `PRAHARI_PYTHON` | interpreter to use (default `python`) |
| `PRAHARI_COMPILER_ROOT` | path to the `compiler/` directory |
| `OPENROUTER_API_KEY` | in the project-root `.env`; enables AI review. The IDE works fully without it |

The compiler process the backend spawns reads the project-root `.env` itself,
so adding a key there and restarting the IDE is the whole setup. It is never read in the browser
process and never crosses the JSON-RPC boundary — the frontend receives a
fingerprint, not a credential.

## A full workbench, not a viewer

The application carries the views a VS Code user expects, assembled from the
same upstream components the Eclipse Theia IDE ships:

| | |
|---|---|
| **Explorer**, **Search** | file tree, Open Editors, ripgrep-backed search |
| **Source Control** | Git, through the built-in `vscode.git` extension |
| **Run and Debug**, **Testing** | debug views and the test explorer |
| **Extensions** | browse and install from Open VSX, as in VS Code |
| **Problems**, **Output**, **Terminal**, **Debug Console** | the full bottom panel |
| **Welcome** page, **Keyboard Shortcuts** editor, **Settings** | the usual entry points |
| Notebooks, Timeline, call and type hierarchy, editor preview tabs | the smaller VS Code behaviours |

Everything above is verified on every run of `desktop-check.js`, which drives
the built application and fails on any console error.

## Run any file

Every editor tab carries **▶ Run** (<kbd>Ctrl</kbd>+<kbd>Alt</kbd>+<kbd>N</kbd>),
and so does the title bar; **■ Stop** (<kbd>Ctrl</kbd>+<kbd>Alt</kbd>+<kbd>M</kbd>)
appears while a program is running. Both are also in the **Run** menu. VS Code
needs a separate extension per language before its play button does anything;
here the IDE decides itself, in `prahari-ide/src/node/run-planner.ts`:

| File | What Run does |
|---|---|
| `.c`, `.cpp` and friends | compile with gcc, clang or g++ to a temporary executable, then run it — only if the build succeeded |
| a C/C++ file without `main`, or a header | a syntax check, since there is nothing to execute |
| `.py`, `.js`, `.ts`, `.java`, `.go`, `.rs`, `.cs`, `.rb`, `.php`, `.pl`, `.ps1`, `.bat`, `.sh` and ~40 more | the language's own interpreter or compiler |
| a script with a `#!` line | the interpreter the line names |
| `.html`, `.svg`, `.pdf`, images | the built-in preview |
| `.md` | the Markdown preview |
| `.json`, `.yaml`, `.txt` and other data | a note that there is nothing to execute |
| anything else | the application the operating system associates with it |

Programs run in an integrated terminal named after the file, so their output
stays readable and they can read from the keyboard; one Run terminal is kept
and replaced on each run, as in VS Code. Toolchains are found on PATH and in the
places Windows installers put them without touching PATH (MSYS2, LLVM, Git for
Windows), and a toolchain that is missing produces install instructions rather
than an error. The editor is saved before it runs.

## Prahari AI

The **Prahari AI** button at the top right of the window
(<kbd>Ctrl</kbd>+<kbd>Alt</kbd>+<kbd>I</kbd>) opens the assistant on the right-hand
side bar, where VS Code keeps its chat. A question is sent with the active
editor's text (unsaved edits included), its selection and — for C — the
compiler's findings, so "why is line 19 dangerous?" needs no copying. Replies
render as Markdown, and each code block has **Copy** and **Insert at cursor**.
*Ask Prahari AI* is also on the editor's context menu.

It uses the same free-only gateway as adjudication (below), so the model is
whichever free model `.env` configures and the key never reaches the window.
With no key configured the panel says how to add one; everything else works
without it.

## What it contributes

| Command | Binding | Behaviour |
|---|---|---|
| **Prahari: Audit Current File** | <kbd>Ctrl</kbd>+<kbd>Alt</kbd>+<kbd>A</kbd> | Full pipeline; populates the findings panel and the Problems view |
| **Prahari: Show Findings Panel** | — | Toggles the panel |
| **Prahari: Explain Function at Cursor** | — | CFG shape, call targets and interprocedural taint summary |
| **Prahari: Show Generated LLVM IR** | — | Runs the backend over the open file |
| **Prahari: Review Findings with AI** | — | Audits, then reviews each finding through the configured model |
| **Prahari: AI Adjudication Status** | — | Model, endpoint and key fingerprint — never the key |
| **Run File** / **Stop Running File** | <kbd>Ctrl</kbd>+<kbd>Alt</kbd>+<kbd>N</kbd> / <kbd>M</kbd> | See [Run any file](#run-any-file) |
| **Prahari: Open Prahari AI** | <kbd>Ctrl</kbd>+<kbd>Alt</kbd>+<kbd>I</kbd> | Toggles the assistant panel |
| **Prahari: Ask Prahari AI** | editor context menu | Opens the assistant with a question about the selection |

**Audit** is also a button on the tab of every C file and in the title bar. On a
file that is not C it says what Prahari audits rather than reporting a failed
compilation.

Plus, live from the language server as you edit: type-checker diagnostics on
save, hover showing declared types and taint summaries, and completion filtered
against the symbol table.

C files open as **C**, not Plain Text: syntax highlighting, comment toggling,
bracket matching and auto-closing come from a Monarch tokenizer the extension
registers with Monaco itself (`prahari-ide/src/browser/c-language.ts`), because
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
`system`". So findings travel over a custom `prahari/findings` notification with
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

**Prahari: Review Findings with AI** is a separate command from **Audit** on
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
node run-check.js        # the Run button's planner, in every installed language
node desktop-check.js    # the desktop application, driven as a user would
npm start                # then, in another terminal:
node browser-check.js    # the running IDE, driven in headless Chrome
```

`run-check.js` writes a small program in each language, asks the planner how
to run it and executes the exact shell script the terminal would receive,
asserting the program's own output: C reading from standard input, a path
containing a space and an apostrophe, a failed compile that must not run, and a
missing toolchain that must produce install instructions.

`desktop-check.js` launches the built Electron application in an isolated
profile — its own instance lock, settings and layout, so it cannot disturb a
window you are working in — and asserts the logo renders, the VS Code menus and
the five activity-bar views exist, the Explorer lists the folder and opens a
file, Go to File works, all five Prahari commands are registered, and an audit
produces findings with their path traces. It then presses the buttons: the
editor's Run on a C program and the title bar's Run on a Python script (each
proven by a file the program itself writes), Run on JSON and HTML, Audit on a
Python file, and two questions to Prahari AI about the open file, the second
asserting that a code block in the reply renders with Copy and Insert.

One console message is reported separately, under `knownUpstream`, rather
than failing the run: Theia 1.75's VS Code extension host can throw
`INVALID tab` when a file is opened by double-click. It has no visible effect,
and it reproduces in a build with every Prahari frontend contribution removed,
so it belongs to Theia. Any other console error still fails the check. It fails on any console error, and it
fails loudly if the application exits early rather than reporting a silent pass.

`browser-check.js` opens the IDE the way a user would — workspace, Go to File,
command palette, audit, AI status and review — over the Chrome DevTools
Protocol, and fails on any console error. It has caught problems no unit test
could: an IDE without a working Go to File, and a findings header that read
"0 findings" before any audit had run. It needs Chrome, Chromium or Edge
(`PRAHARI_CHROME` to point at one) and makes no model request that is not
already cached.

## Extending it

Add a command: register it in `prahari-contribution.ts`, add the corresponding
`@server.command` handler in `compiler/src/prahari/server/lsp_server.py`, and
declare its types in `common/prahari-protocol.ts`. Those three files are the whole
surface.
