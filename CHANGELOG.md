# Changelog

All notable changes to this project are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses
[Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added

- **Prahari IDE as a desktop application.** The same IDE, assembled for
  Electron: its own window, icon, native menus and taskbar entry, with no port
  to visit and no browser tab. `npm run build:desktop` and
  `npm run start:desktop`; `ide/scripts/Install-Shortcut.ps1` adds it to the
  Windows Start menu so it launches without a terminal. The browser application
  is unchanged and both are built from the same extension.
- **A new logo**: the sentinel's shield now carries a dataflow path — a source
  node and an amber sink joined by one link, the findings panel's trace reduced
  to a mark. Drawn from geometry by `ide/scripts/make-app-icon.py`, which emits
  one shape as SVG for the in-application logo and rasterises the same geometry
  for the Windows icon and both favicons, so they cannot drift apart. It appears
  top left in the title bar of both applications, on the desktop window and its
  shortcut, and in the browser tab.
- **A full VS Code-equivalent workbench.** Both applications now carry Explorer,
  Search, Source Control, Run and Debug, Testing, Extensions, Notebooks,
  Timeline, call and type hierarchy, editor preview tabs, a Welcome page and a
  Keyboard Shortcuts editor. `npm run download:plugins` fetches the 90 built-in
  VS Code extensions — Git, C/C++, the language features — into a git-ignored
  `ide/plugins/`.
- `ide/desktop-check.js`: drives the built desktop application in an isolated
  profile and asserts the logo, the menus, the activity bar, the Explorer,
  opening files, Go to File, every Prahari command and an audit with its path
  traces, failing on any console error.
- The Explorer opens on a first run, as it does in VS Code. Theia restores a
  saved layout when there is one, so this never overrides a collapsed panel.
- **Run any file.** A ▶ Run button on every editor tab and in the title bar,
  Ctrl+Alt+N, and *Run → Run File*. C and C++ compile to a temporary executable
  and run in an integrated terminal that accepts keyboard input; Python,
  JavaScript, TypeScript, Java, Go, Rust, C#, Ruby, PHP, Perl, PowerShell,
  batch, shell scripts and some forty other languages run with their own
  toolchain, found on PATH or where Windows installers put it. A file without
  `main` gets a syntax check, web pages and images open in the preview,
  Markdown in its renderer, data files explain that there is nothing to
  execute, and a missing toolchain produces install instructions — never an
  error. ■ Stop interrupts the program. `ide/run-check.js` runs a program in
  every installed language through the exact script the terminal receives.
- **Prahari AI**, an assistant panel on the right-hand side bar, opened from
  the title bar's *Prahari AI* button or Ctrl+Alt+I. It answers with the active
  file, its selection and, for C, the compiler's findings as context; replies
  render as Markdown, and every code block can be copied or inserted at the
  cursor. It uses the same free-only gateway as adjudication
  (`prahari.chat`, `compiler/src/prahari/ai/assistant.py`).
- An **Audit** button on C editor tabs and in the title bar. Audit on a file
  that is not C now says what Prahari audits instead of reporting a failed
  compilation.
- The Welcome page offers Run, Audit and Prahari AI in place of Theia AI's
  banner, which advertised a different, paid assistant.

### Fixed

- The desktop target builds with no C++ toolchain, like the browser one. Two
  Electron-only native modules ship no prebuilt binary — `native-keymap` is
  substituted by a pure-JS shim that still reports the real Windows keyboard
  layout, and `@theia/ffmpeg`'s codec *check* (not the codec-stripping
  replacement, which runs) is skipped when its addon is absent.

## [0.1.0] — 2026-09-15

The first complete release: compiler, analyses, evaluation, IDE and optional
AI review.

### Added

**Compiler**
- Self-contained C preprocessor, parser adapter and typed AST; unsupported
  constructs are recorded per declaration in an exclusion log rather than
  aborting the compilation.
- Three-address IR, control flow graphs, SSA construction with dominance
  frontiers and dead-phi pruning.
- One generic worklist dataflow framework with edge transfer functions,
  instantiated for reaching definitions, live variables, taint propagation and
  a heap state machine.
- Interprocedural taint summaries computed bottom-up over the call graph.
- Detectors for CWE-78, CWE-120, CWE-134, CWE-476, CWE-415, CWE-416 and CWE-401,
  each reporting the full source-to-sink path, the guards on it and the missing
  control.
- SARIF 2.1.0 output with code flows, console and table renderers, and CI exit
  codes.
- LLVM code generation (IR, assembly, object files, JIT) from the same IR.

**Evaluation**
- Juliet-convention harness with per-function scoring, a generated corpus and a
  hand-written hard corpus targeting documented limitations.
- Ablation matrix attributing results to individual analyses.
- Report-level gates for determinism and for the adjudication invariants.

**IDE**
- Eclipse Theia 1.75 application with an Prahari extension: findings panel with
  navigable path traces, Problems-view markers, explain-function and LLVM IR
  commands.
- Language server (pygls) providing diagnostics, symbol-table-filtered
  completion, hover and audit commands; works with any LSP client.
- C syntax highlighting, comment toggling and bracket-aware editing, with no
  plugin host or extra dependency.
- Go to File (Ctrl+P) and Find in Files (Ctrl+Shift+F), backed by ripgrep.
- `ide/browser-check.js`: drives the running IDE in headless Chrome and fails on
  any console error.
- Builds and runs with no C++ toolchain: dependency install scripts are off, and
  a pure-JS `drivelist` is substituted where the native module is absent.
- The Prahari shield icon, served as the application favicon.

**AI review (optional)**
- Adjudication that can only demote a finding, enforced in code and tested.
- OpenRouter and Anthropic gateways on a shared HTTP layer with retries, pacing,
  fail-fast quota handling, upstream-error classification and a
  content-addressed verdict cache.
- Free-only mode for OpenRouter, per-use-case model roles (`review`,
  `interactive`) and a cross-provider fallback chain.
- `prahari ai` status, live check and free-model catalogue; `eval/model_bench.py`
  ranks models against the corpus ground truth within the free daily quota.
- Defaults chosen by published benchmarks, a live reachability probe and the
  ground-truth benchmark, with the evidence in `docs/AI.md`.

### Fixed during development

- `Store.replace_uses` did not rename the pointer operand, which hid every
  use-after-free and NULL-dereference finding.
- The heap analysis keyed state by variable name instead of allocation site,
  double-counting aliases and missing use-after-free.
- Globals were not carried through interprocedural summaries, and struct
  members passed as call arguments lost their taint.
- Live-variable analysis leaked phi operands across every edge.
- The determinism CI job compared wall-clock timings and could never pass.
- The adjudication cache shared verdicts between roles running the same model
  at different reasoning effort.

[0.1.0]: https://github.com/Divyakush2006/prahari/releases/tag/v0.1.0
