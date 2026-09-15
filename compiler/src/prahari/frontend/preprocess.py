"""A small, self-contained C preprocessor front end.

pycparser does not preprocess. The conventional answer is to shell out to
``gcc -E`` plus pycparser's ``fake_libc_include`` headers, but that makes the
tool unrunnable on a machine without a C toolchain and makes evaluation runs
non-reproducible across platforms.

This module instead performs the subset of preprocessing the analysed C subset
needs -- ``#include`` elision, object-like ``#define`` expansion, and
conditional compilation -- and prepends a declaration prelude for the libc
functions the taint specifications model. ``use_cpp=True`` restores the
``gcc -E`` path when a toolchain is present and full fidelity is wanted.

Line numbers are preserved exactly: every elided line is replaced by a blank
line rather than removed, so diagnostics and SARIF locations point at the
original source.
"""
from __future__ import annotations

import re
import shutil
import subprocess
from dataclasses import dataclass, field

# Declarations for the libc surface referenced by analysis/specs.py. Keeping
# this inline (rather than as header files on disk) makes the preprocessor
# hermetic.
LIBC_PRELUDE = r"""
typedef unsigned long size_t;
typedef long ssize_t;
typedef int FILE;
typedef char *va_list;

char *strcpy(char *dst, const char *src);
char *strncpy(char *dst, const char *src, size_t n);
char *strcat(char *dst, const char *src);
char *strncat(char *dst, const char *src, size_t n);
size_t strlen(const char *s);
int strcmp(const char *a, const char *b);
int strncmp(const char *a, const char *b, size_t n);
char *strchr(const char *s, int c);
char *strstr(const char *h, const char *n);
char *strdup(const char *s);
void *memcpy(void *dst, const void *src, size_t n);
void *memmove(void *dst, const void *src, size_t n);
void *memset(void *s, int c, size_t n);

int printf(const char *fmt, ...);
int fprintf(FILE *stream, const char *fmt, ...);
int sprintf(char *buf, const char *fmt, ...);
int snprintf(char *buf, size_t n, const char *fmt, ...);
int scanf(const char *fmt, ...);
int fscanf(FILE *stream, const char *fmt, ...);
int sscanf(const char *s, const char *fmt, ...);
int puts(const char *s);
int fputs(const char *s, FILE *stream);
char *gets(char *s);
char *fgets(char *s, int n, FILE *stream);
size_t fread(void *p, size_t sz, size_t n, FILE *stream);
size_t fwrite(const void *p, size_t sz, size_t n, FILE *stream);
FILE *fopen(const char *path, const char *mode);
int fclose(FILE *stream);
extern FILE *stdin;
extern FILE *stdout;
extern FILE *stderr;

void *malloc(size_t n);
void *calloc(size_t n, size_t sz);
void *realloc(void *p, size_t n);
void free(void *p);
void exit(int status);
void abort(void);

int system(const char *cmd);
FILE *popen(const char *cmd, const char *mode);
int pclose(FILE *stream);
int execl(const char *path, const char *arg, ...);
int execlp(const char *file, const char *arg, ...);
int execv(const char *path, char *const argv[]);
int execvp(const char *file, char *const argv[]);
char *getenv(const char *name);

ssize_t read(int fd, void *buf, size_t n);
ssize_t write(int fd, const void *buf, size_t n);
ssize_t recv(int fd, void *buf, size_t n, int flags);
int atoi(const char *s);
long atol(const char *s);
int rand(void);
void srand(unsigned int seed);
"""

_DIRECTIVE = re.compile(r"^\s*#\s*(\w+)\s*(.*)$")
_IDENT = re.compile(r"\b[A-Za-z_]\w*\b")


def strip_comments(source: str) -> str:
    """Remove C comments while preserving every line break.

    A regular expression cannot do this correctly: ``"/* not a comment */"``
    inside a string literal must survive, and a ``"`` inside a comment must not
    open a string. A small scanner is the honest implementation, and comments
    are far too common in real C -- Juliet test cases especially -- for this to
    be optional.

    Newlines inside block comments are preserved so every subsequent line keeps
    its original number, which the whole findings pipeline depends on.
    """
    out: list[str] = []
    index, length = 0, len(source)
    while index < length:
        char = source[index]
        nxt = source[index + 1] if index + 1 < length else ""

        if char == '"' or char == "'":
            quote = char
            out.append(char)
            index += 1
            while index < length:
                c = source[index]
                out.append(c)
                index += 1
                if c == "\\" and index < length:  # escape sequence
                    out.append(source[index])
                    index += 1
                elif c == quote:
                    break
            continue

        if char == "/" and nxt == "*":
            index += 2
            while index < length and not (source[index] == "*" and index + 1 < length and source[index + 1] == "/"):
                if source[index] == "\n":
                    out.append("\n")
                index += 1
            index += 2
            out.append(" ")
            continue

        if char == "/" and nxt == "/":
            while index < length and source[index] != "\n":
                index += 1
            continue

        out.append(char)
        index += 1
    return "".join(out)


def _join_continuations(source: str) -> str:
    """Splice backslash-newline pairs, keeping the line count unchanged.

    Multi-line macro definitions rely on continuations; joining them without
    compensating would shift every following line number.
    """
    if "\\\n" not in source:
        return source
    out: list[str] = []
    pending = 0
    for line in source.split("\n"):
        if line.endswith("\\"):
            out.append(line[:-1])
            pending += 1
            continue
        out.append(line)
        if pending:
            out[-1] = "".join(out[-(pending + 1):])
            del out[-(pending + 1):-1]
            out.extend([""] * pending)
            pending = 0
    return "\n".join(out)


@dataclass
class PreprocessResult:
    text: str
    prelude_lines: int
    dropped_includes: list[str] = field(default_factory=list)
    defines: dict[str, str] = field(default_factory=dict)

    def map_line(self, line: int) -> int:
        """Translate a line number in the preprocessed text back to the source."""
        return max(1, line - self.prelude_lines)


class Preprocessor:
    """Line-preserving preprocessor for the analysed C subset."""

    #: Macros the standard headers would have supplied. Defined here because
    #: those headers are elided rather than read.
    BUILTIN_DEFINES = {"NULL": "0", "EOF": "(-1)", "__PRAHARI__": "1"}

    def __init__(self, defines: dict[str, str] | None = None, use_cpp: bool = False) -> None:
        self.initial_defines = {**self.BUILTIN_DEFINES, **(defines or {})}
        self.use_cpp = use_cpp

    # -- public API ---------------------------------------------------------

    def run(self, source: str, filename: str = "<source>") -> PreprocessResult:
        if self.use_cpp and shutil.which("gcc"):
            return self._run_system_cpp(source, filename)
        return self._run_internal(source)

    # -- internal implementation -------------------------------------------

    def _run_internal(self, source: str) -> PreprocessResult:
        source = strip_comments(source)
        source = _join_continuations(source)
        defines = dict(self.initial_defines)
        dropped: list[str] = []
        out: list[str] = []
        # Stack of (currently_emitting, branch_already_taken)
        stack: list[tuple[bool, bool]] = []

        for raw in source.splitlines():
            emitting = all(s[0] for s in stack)
            m = _DIRECTIVE.match(raw)
            if m:
                name, rest = m.group(1), m.group(2).strip()
                self._handle_directive(name, rest, defines, stack, dropped, emitting)
                out.append("")  # preserve line numbering
                continue
            if not emitting:
                out.append("")
                continue
            out.append(self._expand(raw, defines))

        prelude = LIBC_PRELUDE.strip("\n")
        text = prelude + "\n" + "\n".join(out) + "\n"
        return PreprocessResult(
            text=text,
            prelude_lines=len(prelude.splitlines()),
            dropped_includes=dropped,
            defines=defines,
        )

    def _handle_directive(
        self,
        name: str,
        rest: str,
        defines: dict[str, str],
        stack: list[tuple[bool, bool]],
        dropped: list[str],
        emitting: bool,
    ) -> None:
        if name == "include":
            if emitting:
                dropped.append(rest.strip())
        elif name == "define" and emitting:
            parts = rest.split(None, 1)
            if parts and "(" not in parts[0]:  # object-like macros only
                defines[parts[0]] = parts[1].strip() if len(parts) > 1 else "1"
        elif name == "undef" and emitting:
            defines.pop(rest.strip(), None)
        elif name == "ifdef":
            stack.append(self._branch(rest.strip() in defines, stack))
        elif name == "ifndef":
            stack.append(self._branch(rest.strip() not in defines, stack))
        elif name == "if":
            stack.append(self._branch(self._eval_condition(rest, defines), stack))
        elif name in ("elif", "else"):
            if stack:
                _, taken = stack[-1]
                cond = True if name == "else" else self._eval_condition(rest, defines)
                outer = all(s[0] for s in stack[:-1])
                live = outer and cond and not taken
                stack[-1] = (live, taken or live)
        elif name == "endif":
            if stack:
                stack.pop()

    @staticmethod
    def _branch(cond: bool, stack: list[tuple[bool, bool]]) -> tuple[bool, bool]:
        outer = all(s[0] for s in stack)
        live = outer and cond
        return (live, live)

    def _eval_condition(self, expr: str, defines: dict[str, str]) -> bool:
        """Evaluate a ``#if`` expression conservatively.

        Handles ``defined(X)``, integer literals and boolean operators. Anything
        else evaluates to True, which keeps code rather than silently dropping
        it -- the safe direction for a security analyser.
        """
        e = re.sub(r"defined\s*\(\s*(\w+)\s*\)", lambda m: "1" if m.group(1) in defines else "0", expr)
        e = re.sub(r"defined\s+(\w+)", lambda m: "1" if m.group(1) in defines else "0", e)
        e = _IDENT.sub(lambda m: defines.get(m.group(0), "0"), e)
        e = e.replace("&&", " and ").replace("||", " or ").replace("!", " not ")
        try:
            return bool(eval(e, {"__builtins__": {}}, {}))  # noqa: S307 - numeric literals only
        except Exception:
            return True

    @staticmethod
    def _expand(line: str, defines: dict[str, str]) -> str:
        if not defines:
            return line

        def sub(m: re.Match[str]) -> str:
            return defines.get(m.group(0), m.group(0))

        # One pass is sufficient for the non-recursive macros in the subset.
        return _IDENT.sub(sub, line)

    def _run_system_cpp(self, source: str, filename: str) -> PreprocessResult:
        proc = subprocess.run(
            ["gcc", "-E", "-P", "-nostdinc", "-x", "c", "-"],
            input=source,
            capture_output=True,
            text=True,
            check=False,
        )
        text = proc.stdout if proc.returncode == 0 else source
        prelude = LIBC_PRELUDE.strip("\n")
        return PreprocessResult(
            text=prelude + "\n" + text,
            prelude_lines=len(prelude.splitlines()),
        )


def preprocess(source: str, filename: str = "<source>", **kw) -> PreprocessResult:
    """Convenience wrapper around :class:`Preprocessor`."""
    return Preprocessor(**kw).run(source, filename)
