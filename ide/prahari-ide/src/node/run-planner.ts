/**
 * Decide how to run a file, for the editor's Run button.
 *
 * VS Code needs one extension per language before its play button does
 * anything; Prahari IDE answers for every file itself. Each extension maps to a
 * runner — compile-then-execute for C, C++, Rust and friends, an interpreter
 * for scripts — and the runner looks for its toolchain on PATH and in the
 * places Windows installers put one without touching PATH (MSYS2, LLVM, Git).
 *
 * The planner has no side effects. It returns program-and-argument steps, not a
 * shell string, so the IDE can wrap them for whichever shell the platform has,
 * and `ide/run-check.js` can execute exactly the same steps with no IDE at all.
 *
 * Files that are not programs still get a sensible action rather than an error:
 * web pages and images open in the preview, Markdown in its renderer, data
 * files explain that there is nothing to execute, and anything else opens in
 * the application the operating system associates with it.
 */

import { execFileSync } from 'child_process';
import * as crypto from 'crypto';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';

import { PrahariRunPlan, PrahariRunStep } from '../common/prahari-protocol';

const IS_WINDOWS = process.platform === 'win32';

/** Where Windows toolchains live when their installer did not add them to PATH. */
function extraDirectories(): string[] {
    if (!IS_WINDOWS) {
        return ['/usr/local/bin', '/opt/homebrew/bin', path.join(os.homedir(), '.cargo', 'bin'), path.join(os.homedir(), 'go', 'bin')];
    }
    const programFiles = process.env.ProgramFiles || 'C:\\Program Files';
    const local = process.env.LOCALAPPDATA || path.join(os.homedir(), 'AppData', 'Local');
    return [
        'C:\\msys64\\ucrt64\\bin',
        'C:\\msys64\\mingw64\\bin',
        'C:\\msys64\\clang64\\bin',
        'C:\\msys64\\usr\\bin',
        path.join(programFiles, 'LLVM', 'bin'),
        path.join(programFiles, 'Git', 'bin'),
        path.join(programFiles, 'Go', 'bin'),
        path.join(programFiles, 'nodejs'),
        path.join(programFiles, 'dotnet'),
        path.join(os.homedir(), '.cargo', 'bin'),
        path.join(os.homedir(), 'go', 'bin'),
        path.join(local, 'Programs', 'Python', 'Launcher')
    ];
}

/**
 * Find an executable the way a shell would, and a little further.
 *
 * Two Windows stand-ins are refused because running them is never what anyone
 * meant: the Microsoft Store `python.exe` alias, which opens the Store, and
 * `System32\bash.exe`, which is WSL and fails when no distribution is installed.
 */
export function findExecutable(name: string): string | undefined {
    const directories = [...(process.env.PATH || '').split(path.delimiter), ...extraDirectories()].filter(Boolean);
    const extensions = IS_WINDOWS
        ? path.extname(name)
            ? ['']
            : (process.env.PATHEXT || '.COM;.EXE;.BAT;.CMD').split(';').map(extension => extension.toLowerCase())
        : [''];
    for (const directory of directories) {
        for (const extension of extensions) {
            const candidate = path.join(directory.replace(/^"|"$/g, ''), name + extension);
            if (IS_WINDOWS) {
                const lower = candidate.toLowerCase();
                if (lower.includes('\\windowsapps\\') || lower.endsWith('\\system32\\bash.exe')) {
                    continue;
                }
            }
            try {
                const stat = fs.statSync(candidate);
                if (stat.isFile() && (IS_WINDOWS || (stat.mode & 0o111) !== 0)) {
                    return candidate;
                }
            } catch {
                // not here
            }
        }
    }
    return undefined;
}

function firstExecutable(names: string[]): string | undefined {
    for (const name of names) {
        const found = findExecutable(name);
        if (found) {
            return found;
        }
    }
    return undefined;
}

const versionCache = new Map<string, string>();

/** `program args`'s output, cached for the life of the backend; empty on failure. */
function probe(program: string, args: string[]): string {
    const key = [program, ...args].join('\u0000');
    if (!versionCache.has(key)) {
        let output = '';
        try {
            output = execFileSync(program, args, { encoding: 'utf8', timeout: 8000, windowsHide: true, stdio: ['ignore', 'pipe', 'ignore'] });
        } catch {
            output = '';
        }
        versionCache.set(key, output);
    }
    return versionCache.get(key)!;
}

/** Major and minor version of the Node.js on PATH, not the one Electron embeds. */
function nodeVersion(node: string): [number, number] {
    const match = /v(\d+)\.(\d+)/.exec(probe(node, ['--version']));
    return match ? [Number(match[1]), Number(match[2])] : [0, 0];
}

interface Context {
    file: string;
    directory: string;
    name: string;
    stem: string;
    extension: string;
    text: string;
}

/** A per-file output path outside the workspace, so a run never litters the project. */
function output(context: Context, extension = IS_WINDOWS ? '.exe' : ''): string {
    const directory = path.join(os.tmpdir(), 'prahari-run');
    fs.mkdirSync(directory, { recursive: true });
    const digest = crypto.createHash('sha1').update(context.file).digest('hex').slice(0, 8);
    const safeStem = context.stem.replace(/[^\w.-]/g, '_') || 'program';
    return path.join(directory, `${safeStem}-${digest}${extension}`);
}

function step(program: string, args: string[]): PrahariRunStep {
    return { program, args };
}

function terminal(runner: string, context: Context, steps: PrahariRunStep[], cwd = context.directory): PrahariRunPlan {
    // A compiler's own directory goes first on PATH so the program it builds
    // finds that toolchain's runtime DLLs (MSYS2's libstdc++, for instance).
    const pathPrefix = [...new Set(steps.map(s => path.dirname(s.program)).filter(d => path.isAbsolute(d)))];
    return { kind: 'terminal', runner, cwd, steps, pathPrefix };
}

function missing(what: string, install: string): PrahariRunPlan {
    return {
        kind: 'unavailable',
        message: `No ${what} was found on this machine. ${install} Then press Run again — no restart is needed.`
    };
}

type Planner = (context: Context) => PrahariRunPlan;

/** An interpreter that takes the file as its argument. */
function interpreter(label: string, names: string[], leading: string[], install: string): Planner {
    return context => {
        const program = firstExecutable(names);
        return program ? terminal(label, context, [step(program, [...leading, context.file])]) : missing(label, install);
    };
}

const hasMain = (text: string) => /\bmain\s*\(/.test(text);

/** C and C++: compile to a temporary executable and run it; a file with no `main` is only checked. */
function native(language: 'C' | 'C++', header: boolean): Planner {
    return context => {
        const compilers = language === 'C' ? ['gcc', 'clang', 'cc', 'tcc'] : ['g++', 'clang++', 'c++'];
        const compiler = firstExecutable(compilers);
        if (!compiler) {
            return missing(
                `${language} compiler (${compilers.join(', ')})`,
                IS_WINDOWS
                    ? 'Install MSYS2 (https://www.msys2.org) and run `pacman -S mingw-w64-ucrt-x86_64-gcc`, or install LLVM.'
                    : 'Install gcc or clang with your package manager.'
            );
        }
        const flags = language === 'C' ? ['-g', '-Wall'] : ['-g', '-Wall', '-std=c++17'];
        if (header || !hasMain(context.text)) {
            // Nothing to execute, but "does it compile?" is still the useful answer.
            const languageFlag = header ? ['-x', language === 'C' ? 'c-header' : 'c++-header'] : [];
            return terminal(`${language} syntax check (no main)`, context, [step(compiler, [...flags, '-fsyntax-only', ...languageFlag, context.file])]);
        }
        const executable = output(context);
        return terminal(`${language} (${path.basename(compiler, path.extname(compiler))})`, context, [
            step(compiler, [...flags, context.file, '-o', executable, '-lm']),
            step(executable, [])
        ]);
    };
}

function typescript(jsx: boolean): Planner {
    return context => {
        const tsx = firstExecutable(['tsx']);
        if (tsx) {
            return terminal('TypeScript (tsx)', context, [step(tsx, [context.file])]);
        }
        const bun = firstExecutable(['bun']);
        if (bun) {
            return terminal('TypeScript (bun)', context, [step(bun, ['run', context.file])]);
        }
        const deno = firstExecutable(['deno']);
        if (deno) {
            return terminal('TypeScript (deno)', context, [step(deno, ['run', '--allow-all', context.file])]);
        }
        const node = firstExecutable(['node']);
        if (!node) {
            return missing('TypeScript runtime (node, tsx, bun or deno)', 'Install Node.js 22.7 or later from https://nodejs.org.');
        }
        const [major, minor] = nodeVersion(node);
        if (!jsx && (major > 22 || (major === 22 && minor >= 7))) {
            // Node runs TypeScript itself; transform-types also covers enums and namespaces.
            return terminal(`TypeScript (node ${major}.${minor})`, context, [
                step(node, ['--experimental-transform-types', '--no-warnings', context.file])
            ]);
        }
        const npx = firstExecutable(['npx']);
        return npx
            ? terminal('TypeScript (npx tsx)', context, [step(npx, ['--yes', 'tsx', context.file])])
            : missing('TypeScript runtime', 'Install Node.js 22.7 or later from https://nodejs.org.');
    };
}

function rust(context: Context): PrahariRunPlan {
    let directory = context.directory;
    while (true) {
        if (fs.existsSync(path.join(directory, 'Cargo.toml'))) {
            const cargo = firstExecutable(['cargo']);
            return cargo ? terminal('Rust (cargo run)', context, [step(cargo, ['run'])], directory) : missing('cargo', 'Install Rust from https://rustup.rs.');
        }
        const parent = path.dirname(directory);
        if (parent === directory) {
            break;
        }
        directory = parent;
    }
    const rustc = firstExecutable(['rustc']);
    if (!rustc) {
        return missing('Rust compiler (rustc)', 'Install Rust from https://rustup.rs.');
    }
    const executable = output(context);
    return terminal('Rust (rustc)', context, [step(rustc, [context.file, '-o', executable]), step(executable, [])]);
}

function csharp(context: Context): PrahariRunPlan {
    const dotnet = firstExecutable(['dotnet']);
    const sdks = dotnet ? probe(dotnet, ['--list-sdks']) : '';
    const newest = Math.max(0, ...[...sdks.matchAll(/^(\d+)\./gm)].map(match => Number(match[1])));
    if (dotnet && newest >= 10) {
        return terminal(`C# (dotnet ${newest})`, context, [step(dotnet, ['run', context.file])]);
    }
    const script = firstExecutable(['dotnet-script']);
    if (script) {
        return terminal('C# (dotnet-script)', context, [step(script, [context.file])]);
    }
    return missing(
        'C# SDK able to run a single file',
        dotnet
            ? 'The .NET runtime is installed, but running a lone .cs file needs the .NET 10 SDK (https://dotnet.microsoft.com/download).'
            : 'Install the .NET 10 SDK from https://dotnet.microsoft.com/download.'
    );
}

function kotlin(context: Context): PrahariRunPlan {
    const kotlinc = firstExecutable(['kotlinc', 'kotlinc-jvm']);
    if (!kotlinc) {
        return missing('Kotlin compiler (kotlinc)', 'Install Kotlin from https://kotlinlang.org/docs/command-line.html.');
    }
    if (context.extension === '.kts') {
        return terminal('Kotlin script', context, [step(kotlinc, ['-script', context.file])]);
    }
    const jar = output(context, '.jar');
    const java = firstExecutable(['java']);
    return java
        ? terminal('Kotlin', context, [step(kotlinc, [context.file, '-include-runtime', '-d', jar]), step(java, ['-jar', jar])])
        : missing('Java runtime (java)', 'Install a JDK, for example from https://adoptium.net.');
}

function fortran(context: Context): PrahariRunPlan {
    const compiler = firstExecutable(['gfortran', 'flang']);
    if (!compiler) {
        return missing('Fortran compiler (gfortran)', 'Install gfortran (MSYS2: `pacman -S mingw-w64-ucrt-x86_64-gcc-fortran`).');
    }
    const executable = output(context);
    return terminal('Fortran', context, [step(compiler, [context.file, '-o', executable]), step(executable, [])]);
}

function javaClass(context: Context): PrahariRunPlan {
    const java = firstExecutable(['java']);
    return java
        ? terminal('Java class', context, [step(java, ['-cp', context.directory, context.stem])])
        : missing('Java runtime (java)', 'Install a JDK, for example from https://adoptium.net.');
}

function batch(context: Context): PrahariRunPlan {
    if (!IS_WINDOWS) {
        return { kind: 'unavailable', message: `${context.name} is a Windows batch file and can only run on Windows.` };
    }
    const cmd = process.env.ComSpec || 'C:\\Windows\\System32\\cmd.exe';
    return terminal('Windows batch', context, [step(cmd, ['/d', '/c', context.file])]);
}

function shell(label: string, names: string[]): Planner {
    return context => {
        const program = firstExecutable(names);
        return program
            ? terminal(label, context, [step(program, [context.file])])
            : missing(
                  label,
                  IS_WINDOWS ? 'Install Git for Windows (https://git-scm.com), which includes bash.' : `Install ${names[0]}.`
              );
    };
}

function binary(context: Context): PrahariRunPlan {
    return terminal('executable', context, [step(context.file, [])]);
}

const PREVIEW = new Set(['.html', '.htm', '.xhtml', '.svg', '.pdf', '.png', '.jpg', '.jpeg', '.gif', '.webp', '.bmp', '.ico']);
const MARKDOWN = new Set(['.md', '.markdown', '.mdown', '.mkd']);
const DATA = new Set([
    '.json', '.jsonc', '.json5', '.yaml', '.yml', '.toml', '.xml', '.csv', '.tsv', '.txt', '.log', '.ini', '.cfg',
    '.conf', '.env', '.properties', '.lock', '.gitignore', '.gitattributes', '.editorconfig', '.sql', '.graphql',
    '.proto', '.css', '.scss', '.sass', '.less', '.map', '.sarif', '.diff', '.patch', '.rst', '.tex', '.bib'
]);

const PLANNERS: Record<string, Planner> = {
    '.c': native('C', false),
    '.h': native('C', true),
    '.cpp': native('C++', false),
    '.cc': native('C++', false),
    '.cxx': native('C++', false),
    '.c++': native('C++', false),
    '.hpp': native('C++', true),
    '.hh': native('C++', true),
    '.hxx': native('C++', true),
    '.py': interpreter('Python', IS_WINDOWS ? ['python', 'py', 'python3'] : ['python3', 'python'], ['-u'], 'Install Python from https://python.org and tick "Add python.exe to PATH".'),
    '.pyw': interpreter('Python', IS_WINDOWS ? ['python', 'py', 'python3'] : ['python3', 'python'], ['-u'], 'Install Python from https://python.org.'),
    '.js': interpreter('Node.js', ['node', 'bun', 'deno'], [], 'Install Node.js from https://nodejs.org.'),
    '.mjs': interpreter('Node.js', ['node', 'bun'], [], 'Install Node.js from https://nodejs.org.'),
    '.cjs': interpreter('Node.js', ['node', 'bun'], [], 'Install Node.js from https://nodejs.org.'),
    '.ts': typescript(false),
    '.mts': typescript(false),
    '.cts': typescript(false),
    '.tsx': typescript(true),
    '.jsx': typescript(true),
    '.java': interpreter('Java', ['java'], [], 'Install a JDK 11 or later, for example from https://adoptium.net.'),
    '.class': javaClass,
    '.jar': interpreter('Java archive', ['java'], ['-jar'], 'Install a Java runtime, for example from https://adoptium.net.'),
    '.kt': kotlin,
    '.kts': kotlin,
    '.go': interpreter('Go', ['go'], ['run'], 'Install Go from https://go.dev/dl.'),
    '.rs': rust,
    '.cs': csharp,
    '.fsx': interpreter('F# script', ['dotnet'], ['fsi'], 'Install the .NET SDK from https://dotnet.microsoft.com/download.'),
    '.rb': interpreter('Ruby', ['ruby'], [], 'Install Ruby from https://rubyinstaller.org.'),
    '.php': interpreter('PHP', ['php'], [], 'Install PHP from https://windows.php.net/download.'),
    '.pl': interpreter('Perl', ['perl'], [], 'Install Strawberry Perl from https://strawberryperl.com.'),
    '.lua': interpreter('Lua', ['lua', 'lua54', 'luajit'], [], 'Install Lua from https://www.lua.org.'),
    '.r': interpreter('R', ['Rscript'], [], 'Install R from https://cran.r-project.org.'),
    '.jl': interpreter('Julia', ['julia'], [], 'Install Julia from https://julialang.org.'),
    '.dart': interpreter('Dart', ['dart'], ['run'], 'Install the Dart SDK from https://dart.dev.'),
    '.swift': interpreter('Swift', ['swift'], [], 'Install Swift from https://swift.org.'),
    '.scala': interpreter('Scala', ['scala-cli', 'scala'], ['run'], 'Install Scala from https://scala-lang.org.'),
    '.sc': interpreter('Scala', ['scala-cli', 'scala'], ['run'], 'Install Scala from https://scala-lang.org.'),
    '.groovy': interpreter('Groovy', ['groovy'], [], 'Install Groovy from https://groovy-lang.org.'),
    '.hs': interpreter('Haskell', ['runghc', 'runhaskell'], [], 'Install GHC from https://www.haskell.org/ghcup.'),
    '.ex': interpreter('Elixir', ['elixir'], [], 'Install Elixir from https://elixir-lang.org.'),
    '.exs': interpreter('Elixir', ['elixir'], [], 'Install Elixir from https://elixir-lang.org.'),
    '.erl': interpreter('Erlang', ['escript'], [], 'Install Erlang from https://www.erlang.org.'),
    '.clj': interpreter('Clojure', ['clojure', 'clj'], ['-M'], 'Install Clojure from https://clojure.org.'),
    '.ml': interpreter('OCaml', ['ocaml'], [], 'Install OCaml from https://ocaml.org.'),
    '.nim': interpreter('Nim', ['nim'], ['r', '--hints:off'], 'Install Nim from https://nim-lang.org.'),
    '.zig': interpreter('Zig', ['zig'], ['run'], 'Install Zig from https://ziglang.org.'),
    '.d': interpreter('D', ['rdmd'], [], 'Install DMD from https://dlang.org.'),
    '.cr': interpreter('Crystal', ['crystal'], ['run'], 'Install Crystal from https://crystal-lang.org.'),
    '.v': interpreter('V', ['v'], ['run'], 'Install V from https://vlang.io.'),
    '.tcl': interpreter('Tcl', ['tclsh'], [], 'Install Tcl.'),
    '.awk': interpreter('AWK', ['gawk', 'awk'], ['-f'], 'Install gawk.'),
    '.coffee': interpreter('CoffeeScript', ['coffee'], [], 'Install CoffeeScript with `npm install -g coffeescript`.'),
    '.f90': fortran,
    '.f95': fortran,
    '.f03': fortran,
    '.f': fortran,
    '.for': fortran,
    '.ps1': interpreter('PowerShell', ['pwsh', 'powershell'], ['-NoProfile', '-ExecutionPolicy', 'Bypass', '-File'], 'Install PowerShell from https://aka.ms/powershell.'),
    '.psm1': interpreter('PowerShell', ['pwsh', 'powershell'], ['-NoProfile', '-ExecutionPolicy', 'Bypass', '-File'], 'Install PowerShell from https://aka.ms/powershell.'),
    '.bat': batch,
    '.cmd': batch,
    '.vbs': interpreter('VBScript', ['cscript'], ['//nologo'], 'VBScript runs only on Windows.'),
    '.sh': shell('Bash', ['bash', 'sh']),
    '.bash': shell('Bash', ['bash']),
    '.zsh': shell('Zsh', ['zsh']),
    '.fish': shell('Fish', ['fish']),
    '.exe': binary,
    '.com': binary
};

/** The runner for a file name, by extension and, for extension-less files, by name. */
function plannerFor(context: Context): Planner | undefined {
    const byExtension = PLANNERS[context.extension];
    if (byExtension) {
        return byExtension;
    }
    const lowerName = context.name.toLowerCase();
    if (lowerName === 'makefile' || lowerName === 'gnumakefile' || context.extension === '.mk') {
        return ctx => {
            const make = firstExecutable(['make', 'mingw32-make', 'gmake']);
            return make ? terminal('make', ctx, [step(make, ['-f', ctx.file])]) : missing('make', 'Install make (MSYS2: `pacman -S make`).');
        };
    }
    if (lowerName === 'dockerfile' || lowerName.endsWith('.dockerfile')) {
        return ctx => {
            const docker = firstExecutable(['docker']);
            return docker
                ? terminal('Docker build', ctx, [step(docker, ['build', '-f', ctx.file, ctx.directory])])
                : missing('Docker', 'Install Docker Desktop from https://www.docker.com.');
        };
    }
    return undefined;
}

/** `#!/usr/bin/env python3` and friends: the interpreter a script names for itself. */
function shebang(context: Context): PrahariRunPlan | undefined {
    const match = /^#!\s*(\S+)(?:\s+(\S+))?/.exec(context.text);
    if (!match) {
        return undefined;
    }
    const command = path.basename(match[1]) === 'env' && match[2] ? match[2] : path.basename(match[1]);
    const program = firstExecutable(IS_WINDOWS && command === 'python3' ? ['python', 'py', 'python3'] : [command]);
    return program ? terminal(`${command} (from #!)`, context, [step(program, [context.file])]) : missing(command, `Install ${command}.`);
}

export function planRun(file: string): PrahariRunPlan {
    let stat: fs.Stats;
    try {
        stat = fs.statSync(file);
    } catch {
        return { kind: 'unavailable', message: `${path.basename(file)} does not exist on disk. Save it first.` };
    }
    if (!stat.isFile()) {
        return { kind: 'unavailable', message: `${path.basename(file)} is not a file.` };
    }

    const extension = path.extname(file).toLowerCase();
    const name = path.basename(file);
    let text = '';
    if (stat.size < 4 * 1024 * 1024) {
        try {
            text = fs.readFileSync(file, 'utf8');
        } catch {
            text = '';
        }
    }
    const context: Context = { file, directory: path.dirname(file), name, stem: path.basename(file, path.extname(file)), extension, text };

    const planner = plannerFor(context);
    if (planner) {
        return planner(context);
    }
    if (PREVIEW.has(extension)) {
        return { kind: 'preview', runner: 'Preview' };
    }
    if (MARKDOWN.has(extension)) {
        return { kind: 'markdown', runner: 'Markdown preview' };
    }
    if (extension === '.ipynb') {
        return { kind: 'info', message: `${name} is a notebook: use Run All in the notebook toolbar to execute its cells.` };
    }
    const fromShebang = shebang(context);
    if (fromShebang) {
        return fromShebang;
    }
    if (!IS_WINDOWS && !extension && (stat.mode & 0o111) !== 0) {
        return binary(context);
    }
    if (DATA.has(extension) || (!extension && name.startsWith('.'))) {
        return {
            kind: 'info',
            message: `${name} is a ${extension ? extension.slice(1).toUpperCase() + ' ' : ''}data file, not a program, so there is nothing to execute. It is open in the editor.`
        };
    }
    return { kind: 'external', runner: 'the system default application' };
}

// -- shells ----------------------------------------------------------------------

const quotePowerShell = (value: string) => `'${value.replace(/'/g, "''")}'`;
const quoteBash = (value: string) => `'${value.replace(/'/g, "'\\''")}'`;

function display(step: PrahariRunStep): string {
    const show = (value: string) => (/[\s"']/.test(value) ? `"${value}"` : value);
    return [path.basename(step.program), ...step.args.map(arg => show(path.isAbsolute(arg) && arg.includes('prahari-run') ? path.basename(arg) : arg))].join(' ');
}

/**
 * Wrap a terminal plan for the platform shell.
 *
 * The script travels as `-EncodedCommand` (PowerShell) or a single `-c`
 * argument (bash), and the shell stays open afterwards, so program output can
 * be read, the program can read from the keyboard, and the prompt that follows
 * is an ordinary terminal. Each step runs only if the previous one succeeded —
 * a C file that fails to compile is not then "run" from a stale executable.
 */
export function shellFor(plan: Extract<PrahariRunPlan, { kind: 'terminal' }>, fileName: string): { shellPath: string; shellArgs: string[] } {
    if (IS_WINDOWS) {
        const lines = [
            "$ErrorActionPreference = 'Continue'",
            'try { [Console]::OutputEncoding = [System.Text.Encoding]::UTF8 } catch {}',
            `Set-Location -LiteralPath ${quotePowerShell(plan.cwd)}`
        ];
        if (plan.pathPrefix.length) {
            lines.push(`$env:PATH = ${quotePowerShell(plan.pathPrefix.join(';') + ';')} + $env:PATH`);
        }
        lines.push(
            `Write-Host ${quotePowerShell(`[Running] ${fileName} with ${plan.runner}`)} -ForegroundColor Cyan`,
            '$prahariWatch = [Diagnostics.Stopwatch]::StartNew()',
            '$prahariCode = 0'
        );
        for (const s of plan.steps) {
            lines.push(
                'if ($prahariCode -eq 0) {',
                `  Write-Host ${quotePowerShell(`> ${display(s)}`)} -ForegroundColor DarkGray`,
                '  $global:LASTEXITCODE = $null',
                `  & ${[s.program, ...s.args].map(quotePowerShell).join(' ')}`,
                '  $prahariOk = $?',
                '  $prahariCode = if ($null -ne $LASTEXITCODE) { $LASTEXITCODE } elseif ($prahariOk) { 0 } else { 1 }',
                '}'
            );
        }
        lines.push(
            "Write-Host ''",
            "$prahariColor = if ($prahariCode -eq 0) { 'Green' } else { 'Red' }",
            "Write-Host ('[Done] exited with code {0} in {1:N2} seconds' -f $prahariCode, $prahariWatch.Elapsed.TotalSeconds) -ForegroundColor $prahariColor"
        );
        const encoded = Buffer.from(lines.join('\r\n'), 'utf16le').toString('base64');
        const root = process.env.SystemRoot || 'C:\\Windows';
        return {
            shellPath: path.join(root, 'System32', 'WindowsPowerShell', 'v1.0', 'powershell.exe'),
            shellArgs: ['-NoLogo', '-NoProfile', '-NoExit', '-ExecutionPolicy', 'Bypass', '-EncodedCommand', encoded]
        };
    }

    const lines = [`cd ${quoteBash(plan.cwd)} || exit 1`];
    if (plan.pathPrefix.length) {
        lines.push(`export PATH=${quoteBash(plan.pathPrefix.join(':') + ':')}"$PATH"`);
    }
    lines.push(`printf '\\033[36m%s\\033[0m\\n' ${quoteBash(`[Running] ${fileName} with ${plan.runner}`)}`, 'prahari_start=$(date +%s)', 'prahari_code=0');
    for (const s of plan.steps) {
        lines.push(
            `if [ "$prahari_code" -eq 0 ]; then printf '\\033[90m%s\\033[0m\\n' ${quoteBash(`> ${display(s)}`)}; ${[s.program, ...s.args].map(quoteBash).join(' ')}; prahari_code=$?; fi`
        );
    }
    lines.push(
        `printf '\\n[Done] exited with code %d in %d seconds\\n' "$prahari_code" "$(( $(date +%s) - prahari_start ))"`,
        'exec "${SHELL:-/bin/bash}" -i'
    );
    return { shellPath: '/bin/bash', shellArgs: ['-c', lines.join('\n')] };
}
