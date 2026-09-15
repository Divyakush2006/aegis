/**
 * C language support for the editor: registration, editing behaviour and
 * syntax highlighting.
 *
 * Theia ships Monaco without its bundled "basic languages", so a `.c` file
 * opened as Plain Text: no highlighting, no comment toggling, no bracket-aware
 * editing. For an IDE whose whole purpose is C, that is the first thing a user
 * notices. This registers C with Monaco directly -- a Monarch tokenizer and a
 * language configuration -- with no extra dependency and no plugin host.
 *
 * Registration defers to anything that already provides C. If a VS Code C/C++
 * extension or a future Theia release contributes the language, that richer
 * support wins and this does nothing.
 */

import { FrontendApplicationContribution } from '@theia/core/lib/browser';
import { injectable } from '@theia/core/shared/inversify';
import * as monaco from '@theia/monaco-editor-core';

export const C_LANGUAGE_ID = 'c';

const configuration: monaco.languages.LanguageConfiguration = {
    comments: { lineComment: '//', blockComment: ['/*', '*/'] },
    brackets: [
        ['{', '}'],
        ['[', ']'],
        ['(', ')']
    ],
    autoClosingPairs: [
        { open: '{', close: '}' },
        { open: '[', close: ']' },
        { open: '(', close: ')' },
        { open: "'", close: "'", notIn: ['string', 'comment'] },
        { open: '"', close: '"', notIn: ['string'] },
        { open: '/*', close: ' */', notIn: ['string'] }
    ],
    surroundingPairs: [
        { open: '{', close: '}' },
        { open: '[', close: ']' },
        { open: '(', close: ')' },
        { open: '"', close: '"' },
        { open: "'", close: "'" }
    ],
    folding: {
        markers: {
            start: /^\s*#\s*pragma\s+region\b/,
            end: /^\s*#\s*pragma\s+endregion\b/
        }
    }
};

/**
 * The tokenizer covers what a real C file contains, not only the subset Prahari
 * analyses: C17 and common C23 keywords, the standard and fixed-width types,
 * preprocessor lines, every literal form -- hex, octal, binary, floats with
 * exponents and suffixes, strings and characters with escapes -- and both
 * comment styles.
 */
const language: monaco.languages.IMonarchLanguage = {
    defaultToken: '',
    tokenPostfix: '.c',

    keywords: [
        'auto', 'break', 'case', 'const', 'continue', 'default', 'do', 'else', 'enum', 'extern',
        'for', 'goto', 'if', 'inline', 'register', 'restrict', 'return', 'sizeof', 'static',
        'struct', 'switch', 'typedef', 'union', 'volatile', 'while',
        '_Alignas', '_Alignof', '_Atomic', '_Generic', '_Noreturn', '_Static_assert',
        '_Thread_local', 'alignas', 'alignof', 'static_assert', 'thread_local', 'typeof',
        'true', 'false', 'nullptr', 'NULL'
    ],

    typeKeywords: [
        'void', 'char', 'short', 'int', 'long', 'float', 'double', 'signed', 'unsigned',
        '_Bool', 'bool', '_Complex', '_Imaginary', 'size_t', 'ssize_t', 'ptrdiff_t',
        'intptr_t', 'uintptr_t', 'intmax_t', 'uintmax_t', 'wchar_t', 'FILE',
        'int8_t', 'int16_t', 'int32_t', 'int64_t', 'uint8_t', 'uint16_t', 'uint32_t', 'uint64_t'
    ],

    operators: [
        '=', '>', '<', '!', '~', '?', ':', '==', '<=', '>=', '!=', '&&', '||', '++', '--',
        '+', '-', '*', '/', '&', '|', '^', '%', '<<', '>>', '+=', '-=', '*=', '/=', '&=',
        '|=', '^=', '%=', '<<=', '>>=', '->'
    ],

    symbols: /[=><!~?:&|+\-*\/\^%]+/,
    escapes: /\\(?:[abfnrtv\\"'?]|[0-7]{1,3}|x[0-9A-Fa-f]+|u[0-9A-Fa-f]{4}|U[0-9A-Fa-f]{8})/,
    integersuffix: /([uU](ll|LL|l|L)|(ll|LL|l|L)?[uU]?)/,
    floatsuffix: /[fFlL]?/,

    tokenizer: {
        root: [
            // Preprocessor lines: `#include` gets its own state so the header
            // name reads as a string, every other directive as a keyword.
            // Base token names are used deliberately: every theme colours
            // `keyword` and `string`, while more specific names such as
            // `keyword.directive` are left uncoloured by several themes.
            [/^\s*#\s*include\b/, { token: 'keyword', next: '@include' }],
            [/^\s*#\s*[a-zA-Z_]\w*/, 'keyword'],

            [/[a-zA-Z_]\w*/, {
                cases: {
                    '@typeKeywords': 'keyword.type',
                    '@keywords': 'keyword',
                    '@default': 'identifier'
                }
            }],

            { include: '@whitespace' },

            [/[{}()\[\]]/, '@brackets'],
            [/@symbols/, { cases: { '@operators': 'operator', '@default': '' } }],

            [/\d*\.\d+([eE][\-+]?\d+)?(@floatsuffix)/, 'number.float'],
            [/\d+\.\d*([eE][\-+]?\d+)?(@floatsuffix)/, 'number.float'],
            [/\d+[eE][\-+]?\d+(@floatsuffix)/, 'number.float'],
            [/0[xX][0-9a-fA-F']*[0-9a-fA-F](@integersuffix)/, 'number.hex'],
            [/0[bB][01']*[01](@integersuffix)/, 'number.binary'],
            [/0[0-7']*[0-7](@integersuffix)/, 'number.octal'],
            [/\d[\d']*\d(@integersuffix)/, 'number'],
            [/\d(@integersuffix)/, 'number'],

            [/[;,.]/, 'delimiter'],

            [/"([^"\\]|\\.)*$/, 'string.invalid'],
            [/"/, 'string', '@string'],
            [/'[^\\']'/, 'string'],
            [/(')(@escapes)(')/, ['string', 'string.escape', 'string']],
            [/'/, 'string.invalid']
        ],

        whitespace: [
            [/[ \t\r\n]+/, ''],
            [/\/\*/, 'comment', '@comment'],
            [/\/\/.*$/, 'comment']
        ],

        comment: [
            [/[^\/*]+/, 'comment'],
            [/\*\//, 'comment', '@pop'],
            [/[\/*]/, 'comment']
        ],

        string: [
            [/[^\\"]+/, 'string'],
            [/@escapes/, 'string.escape'],
            [/\\./, 'string.escape.invalid'],
            [/"/, 'string', '@pop']
        ],

        include: [
            [/[ \t]+/, ''],
            [/<[^<>]*>/, 'string', '@pop'],
            [/"[^"]*"/, 'string', '@pop'],
            [/./, '', '@pop']
        ]
    }
};

/** Register C with Monaco unless something already provides it. */
export function registerCLanguage(): boolean {
    if (monaco.languages.getLanguages().some(existing => existing.id === C_LANGUAGE_ID)) {
        return false;
    }
    monaco.languages.register({
        id: C_LANGUAGE_ID,
        extensions: ['.c', '.h'],
        aliases: ['C', 'c'],
        mimetypes: ['text/x-csrc', 'text/x-chdr']
    });
    monaco.languages.setLanguageConfiguration(C_LANGUAGE_ID, configuration);
    monaco.languages.setMonarchTokensProvider(C_LANGUAGE_ID, language);
    return true;
}

/**
 * Registers C during `initialize`, before any editor exists.
 *
 * Doing this in a contribution rather than at import time matters: by then
 * Theia's Monaco contribution has wrapped language registration so that every
 * registered language also becomes a preference override, which is what lets a
 * user set `[c]`-scoped editor settings.
 */
@injectable()
export class PrahariCLanguageContribution implements FrontendApplicationContribution {
    initialize(): void {
        registerCLanguage();
    }
}
