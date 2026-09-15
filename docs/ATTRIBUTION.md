# Attribution

This document records what Aegis reuses, what it reads, and what it writes from
scratch. It is maintained from the first commit rather than assembled at the
end, and it is the authoritative statement of the reused/original boundary.

**The boundary in one sentence: parsing is reused; everything downstream of the
AST is original.**

---

## 1. Direct dependencies — code shipped and executed

| Component | Version | Licence | What Aegis uses it for |
|---|---|---|---|
| [pycparser](https://github.com/eliben/pycparser) | ≥ 2.21 | BSD-3-Clause | C99 parsing only. Its `c_ast` is consumed by `frontend/adapter.py` and by nothing else. |
| [networkx](https://github.com/networkx/networkx) | ≥ 3.0 | BSD-3-Clause | Graph storage, `immediate_dominators`, `condensation`, `topological_sort`, `shortest_path`. |
| [llvmlite](https://github.com/numba/llvmlite) | ≥ 0.42 | BSD-2-Clause | LLVM IR construction, object emission and MCJIT, used by `codegen/llvm_emitter.py`. The emitter itself — the mapping from Aegis three-address IR to LLVM IR — is original. |
| [pygls](https://github.com/openlawlibrary/pygls) | ≥ 2.0 | Apache-2.0 | LSP framework. Supplies the protocol plumbing; every handler in `server/lsp_server.py` is original. |
| [Eclipse Theia](https://github.com/eclipse-theia/theia) | 1.75.0 | EPL-2.0 | IDE platform for `ide/`: the Monaco editor, shell, DI container and RPC. The Aegis extension — findings panel, commands, backend service — is original. |
| [pytest](https://github.com/pytest-dev/pytest) | ≥ 7.0 | MIT | Test runner (development only). |

Licences are BSD-2-Clause, BSD-3-Clause, Apache-2.0, EPL-2.0 and MIT. All are
permissive or weak-copyleft and compatible with this project's MIT licence; no
strong-copyleft code is imported.

**On EPL-2.0 (Theia).** The Eclipse Public License is file-level copyleft:
modifications to Theia's own files would have to be released under EPL-2.0.
Aegis does not modify Theia. `ide/aegis-ide/` is a separate extension that
*depends on* Theia through its published APIs, which EPL-2.0 explicitly permits
under a different licence. This is also the practical argument for building a
Theia extension rather than forking an IDE: nothing upstream is patched, so
upgrading Theia is a version bump.

llvmlite is a binding, not a compiler: it exposes LLVM's IR builder and
target machine. Choosing the instruction sequence, the memory model
(`alloca` per local, letting LLVM's `mem2reg` build its own SSA), the type
mapping and the calling conventions is the work in `codegen/`, and that is
original.

### The pycparser boundary, precisely

`src/aegis/frontend/adapter.py` is the **only** module that imports pycparser.
It converts `c_ast` nodes into the AegisAST node set defined in
`frontend/ast_nodes.py`. Every subsequent phase — semantic analysis, IR
lowering, CFG, SSA, all four dataflow analyses, detectors, reporting — operates
on AegisAST and the IR, never on pycparser types.

Two consequences:

1. Replacing pycparser with a hand-written parser changes exactly one file.
2. `grep -rl pycparser src/` returns one path, which makes the boundary
   verifiable rather than merely asserted.

pycparser's own `NodeVisitor` is deliberately **not** used for analysis. The
lowering pass in `adapter.py` is written from scratch.

### The Theia boundary

`ide/aegis-ide/` contributes to Theia; it does not alter it. Three integration
points, all public API:

* `theiaExtensions` in `package.json` — the documented way to register a
  frontend and backend module;
* `ContainerModule` bindings against Theia's Inversify container;
* `RpcConnectionHandler` for the frontend/backend channel.

No Theia source file is copied or patched. The findings panel, the commands, the
backend service and the stylesheet are written from scratch.

### What pycparser does *not* provide

pycparser does not preprocess. The conventional workaround is `gcc -E` plus
pycparser's `fake_libc_include` headers; Aegis instead implements
`frontend/preprocess.py` from scratch — include elision, object-like macro
expansion, conditional compilation, comment stripping and line-continuation
splicing, all line-number-preserving — so the tool runs with no C toolchain and
evaluation is reproducible across platforms. The `--cpp` flag restores the
`gcc -E` path when full fidelity is wanted.

---

## 2. Reference implementations — read, not imported

No code from any project in this section is present in this repository. They
were consulted for algorithm structure and design decisions.

| Project | Licence | What was read | Where it influenced Aegis |
|---|---|---|---|
| [PyT](https://github.com/python-security/pyt) | copyleft — **read only** | CFG construction, fixpoint iteration, taint source/sink/sanitizer modelling, vulnerability reporting | General shape of `analysis/taint.py` and the specification-table approach in `analysis/specs.py` |
| [ShivyC](https://github.com/ShivamSarodia/ShivyC) | MIT | Symbol table design, IL structure | `semantic/symbol_table.py`, `ir/instructions.py` |
| [chibicc](https://github.com/rui314/chibicc) | MIT | Incremental compiler construction | Phase ordering and the decision to make each phase separately inspectable |
| [LLVM-Clang-Examples](https://github.com/Enna1/LLVM-Clang-Examples) | — | `taint-propagation/` transfer function shape | `analysis/taint.py` transfer functions |
| [SVF](https://github.com/SVF-tools/SVF) | GPL — **read only** | Interprocedural summary design | `analysis/callgraph.py` bottom-up summary computation |

> **Note on copyleft.** PyT and SVF are under copyleft licences. Importing
> either would impose those terms on this project. Neither is imported, and the
> dependency list above is the complete set of code that ships. This was a
> deliberate decision, not an accident of convenience.

---

## 3. Published algorithms implemented from the literature

Implementing a published algorithm from its description is original work; the
citation records where the specification came from.

| Algorithm | Source | Implementation |
|---|---|---|
| SSA construction via dominance frontiers | Cytron, Ferrante, Rosen, Wegman & Zadeck (1991), *Efficiently Computing Static Single Assignment Form and the Control Dependence Graph* | `ir/ssa.py` |
| Dominance frontier computation | Cooper, Harvey & Kennedy (2001), *A Simple, Fast Dominance Algorithm* | `ir/cfg.py::dominance_frontiers` |
| Iterative worklist dataflow analysis | Kildall (1973); Aho, Lam, Sethi & Ullman, *Compilers: Principles, Techniques and Tools*, ch. 9 | `analysis/framework.py` |
| Reaching definitions, live variables | Aho et al., ch. 9 | `analysis/reaching_defs.py`, `analysis/live_vars.py` |
| Summary-based interprocedural analysis | Sharir & Pnueli (1981), *Two Approaches to Interprocedural Data Flow Analysis* | `analysis/callgraph.py` |

`immediate_dominators` is taken from networkx rather than reimplemented; the
dominance frontier computation on top of it is implemented here and
cross-checked against networkx's independent implementation in
`tests/test_compiler.py::TestDominanceFrontiers`.

---

## 4. Standards and formats

| Standard | Use |
|---|---|
| [SARIF 2.1.0](https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html) (OASIS) | Output format. `report/sarif.py` is written from scratch against the specification; no SARIF library is used. |
| [CWE](https://cwe.mitre.org/) (MITRE) | Weakness classification, names and `helpUri` targets. |

---

## 5. Original work

Everything below is written from scratch for this project:

- `frontend/preprocess.py` — preprocessor, comment scanner, continuation splicer
- `frontend/ast_nodes.py` — the AegisAST node set and type model
- `frontend/adapter.py` — `c_ast` → AegisAST lowering
- `semantic/` — scope tree, type compatibility rules, type checker
- `ir/instructions.py` — three-address instruction set with use/def/rename protocol
- `ir/lowering.py` — AST → TAC, including short-circuit, loop, and switch lowering
- `ir/cfg.py` — basic block partitioning, CFG, dominance frontiers
- `ir/ssa.py` — phi placement, renaming, liveness-based phi pruning
- `analysis/lattice.py` — set, intersection, map and flat lattices
- `analysis/framework.py` — the generic worklist solver, including edge transfer functions
- `analysis/reaching_defs.py`, `analysis/live_vars.py` — classical instantiations
- `analysis/taint.py` — taint lattice, transfer functions, provenance graph, path reconstruction
- `analysis/memory.py` — heap state machine
- `analysis/callgraph.py` — call graph, summaries, bottom-up fixpoint
- `analysis/specs.py` — specification table and merge semantics
- `analysis/detectors/` — one module per weakness class
- `ai/` — gateway interface, path slicer, adjudicator, `NullGateway`, the
  Anthropic gateway and the content-addressed verdict cache. The live gateway
  uses **no SDK and no HTTP library**: it is one JSON POST over
  `urllib.request`, so the adjudication layer adds zero dependencies to a
  compiler whose analysis core needs no network at all
- `eval/mock_model.py` — a deterministic stand-in for the model endpoint, so the
  live path is testable without a credential
- `codegen/llvm_emitter.py` — three-address IR to LLVM IR, object and JIT output
- `server/lsp_server.py` — diagnostics, symbol-table completion, hover, commands
- `report/` — SARIF emitter, console renderer
- `ide/aegis-ide/` — the entire Theia extension: protocol, backend service,
  findings panel, commands, keybindings, stylesheet
- `index.py`, `cli.py`, the full test suite, and all example programs

---

*Last reviewed: at each release. If a dependency is added, it is added here in
the same commit.*
