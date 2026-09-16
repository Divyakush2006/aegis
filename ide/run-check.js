/**
 * Exercise the Run button's planner against real files, with no IDE.
 *
 *   node run-check.js
 *
 * Writes a small program in every language, asks the planner how to run each
 * one, and executes the exact shell script the IDE's terminal would receive —
 * minus `-NoExit`, so the shell returns. Asserts each program's own output and
 * the "[Done] exited with code 0" trailer. A language whose toolchain is not
 * installed must produce an install message, never a crash; non-programs must
 * produce a preview, an explanation or an external open.
 *
 * Requires `npm run build` in prahari-ide first (it loads lib/node).
 */
'use strict';

const { spawnSync } = require('child_process');
const fs = require('fs');
const os = require('os');
const path = require('path');

const { planRun, shellFor, findExecutable } = require('./prahari-ide/lib/node/run-planner');

const root = fs.mkdtempSync(path.join(os.tmpdir(), 'prahari run check '));
// A directory with a space and an apostrophe: the two characters quoting gets wrong.
const work = path.join(root, "it's here");
fs.mkdirSync(work, { recursive: true });

const SAMPLES = {
    'hello.c': ['#include <stdio.h>\nint main(void) {\n  int n = 0;\n  if (scanf("%d", &n) != 1) return 2;\n  printf("C read %d\\n", n);\n  return 0;\n}\n', 'C read 42'],
    "my prog's.c": ['#include <stdio.h>\nint main(void) { puts("C quoted path ok"); return 0; }\n', 'C quoted path ok'],
    'library.c': ['int add(int a, int b) { return a + b; }\n', null],
    'api.h': ['#pragma once\nint add(int a, int b);\n', null],
    'hello.cpp': ['#include <iostream>\nint main() { std::cout << "C++ ok" << std::endl; }\n', 'C++ ok'],
    'hello.py': ['import sys\nprint("Python", sys.stdin.readline().strip())\n', 'Python 42'],
    'hello.js': ['console.log("JavaScript ok");\n', 'JavaScript ok'],
    'hello.mjs': ['const x = await Promise.resolve("ESM ok"); console.log(x);\n', 'ESM ok'],
    'hello.ts': ['enum Kind { A = 7 }\nconst k: number = Kind.A;\nconsole.log(`TypeScript ${k}`);\n', 'TypeScript 7'],
    'Hello.java': ['public class Hello { public static void main(String[] a) { System.out.println("Java ok"); } }\n', 'Java ok'],
    'hello.pl': ['print "Perl ok\\n";\n', 'Perl ok'],
    'hello.ps1': ['Write-Output "PowerShell ok"\n', 'PowerShell ok'],
    'hello.bat': ['@echo off\r\necho Batch ok\r\n', 'Batch ok'],
    'hello.sh': ['echo "Bash ok"\n', 'Bash ok'],
    'broken.c': ['int main(void) { return undefined_name; }\n', 'FAIL'],
    'data.json': ['{"a": 1}\n', 'info'],
    'notes.txt': ['hello\n', 'info'],
    'page.html': ['<h1>hi</h1>\n', 'preview'],
    'README.md': ['# hi\n', 'markdown'],
    'photo.xyz': ['binary-ish\n', 'external'],
    'hello.go': ['package main\nimport "fmt"\nfunc main() { fmt.Println("Go ok") }\n', 'Go ok'],
    'hello.rs': ['fn main() { println!("Rust ok"); }\n', 'Rust ok'],
    'hello.rb': ['puts "Ruby ok"\n', 'Ruby ok'],
    'Program.cs': ['System.Console.WriteLine("C# ok");\n', 'C# ok'],
    'script': ['#!/usr/bin/env python3\nprint("shebang ok")\n', 'shebang ok']
};

let failures = 0;
const rows = [];

for (const [name, [source, expected]] of Object.entries(SAMPLES)) {
    const file = path.join(work, name);
    fs.writeFileSync(file, source);
    let plan;
    try {
        plan = planRun(file);
    } catch (error) {
        failures++;
        rows.push([name, 'CRASH', String(error)]);
        continue;
    }

    if (plan.kind !== 'terminal') {
        const ok =
            plan.kind === expected ||
            (plan.kind === 'unavailable' && /No .* was found|needs the \.NET/.test(plan.message) && expected !== 'info');
        if (!ok) {
            failures++;
        }
        rows.push([name, ok ? 'ok' : 'FAIL', `${plan.kind}: ${plan.message || plan.runner}`]);
        continue;
    }

    const { shellPath, shellArgs } = shellFor(plan, name);
    const args = shellArgs.filter(arg => arg !== '-NoExit');
    if (process.platform !== 'win32') {
        args[1] = args[1].replace(/\nexec .*$/, '');
    }
    const result = spawnSync(shellPath, args, { input: '42\n', encoding: 'utf8', timeout: 120000, windowsHide: true });
    const out = `${result.stdout || ''}${result.stderr || ''}`;
    let ok;
    if (expected === null) {
        ok = /\[Done\] exited with code 0/.test(out) && /syntax check/.test(plan.runner);
    } else if (expected === 'FAIL') {
        // A failed compile must stop before running anything, and say so.
        ok = /\[Done\] exited with code [1-9]/.test(out) && (out.match(/^> /gm) || []).length === 1;
    } else {
        ok = out.includes(expected) && /\[Done\] exited with code 0/.test(out);
    }
    if (!ok) {
        failures++;
    }
    rows.push([name, ok ? 'ok' : 'FAIL', `${plan.runner}${ok ? '' : `\n${out.trim().split('\n').slice(-8).join('\n')}`}`]);
}

for (const [name, status, detail] of rows) {
    console.log(`${status.padEnd(5)} ${name.padEnd(14)} ${detail}`);
}
console.log(`\ntoolchains: ${['gcc', 'g++', 'python', 'node', 'java', 'perl', 'bash', 'go', 'rustc', 'ruby', 'dotnet'].map(t => `${t}=${findExecutable(t) ? 'yes' : 'no'}`).join(' ')}`);
fs.rmSync(root, { recursive: true, force: true });

if (failures) {
    console.error(`\n${failures} file type(s) failed.`);
    process.exit(1);
}
console.log('\nOK — every file type ran or was handled.');
