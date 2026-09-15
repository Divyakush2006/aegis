# PRAHARI — Repository Catalog

Every repo worth knowing about for a security-aware compiler with an AI-native IDE.

**Verification status.** Entries marked ✅ were confirmed during research for this project. Entries marked ⚪ are from general knowledge of long-standing projects — stable and almost certainly correct, but check the URL before relying on one. Star counts and dates move; treat them as rough.

**How to read the Relevance column.** `CORE` = ships in Prahari. `READ` = study the code, don't import. `BENCH` = evaluation. `CONTEXT` = know it exists so you can position against it.

---

## 1. IDE Platforms and Editors

| Repo | Lang | Notes | Relevance |
|---|---|---|---|
| ✅ `eclipse-theia/theia` | TS | Platform for building custom IDEs. Uses Monaco, supports LSP + DAP, hosts VS Code extensions, EPL-2.0, vendor-neutral under Eclipse Foundation. **Not** a VS Code fork. | **CORE** |
| ✅ `microsoft/vscode` | TS | Code-OSS. MIT code, Microsoft-controlled. Extension API is well-defined but limited for deep customization. | CONTEXT |
| ⚪ `microsoft/monaco-editor` | TS | The editor widget alone. Inside Theia already. | CORE (transitive) |
| ⚪ `codemirror/dev` | TS | Lighter editor alternative. No IDE shell, no extension model. | CONTEXT |
| ⚪ `coder/code-server` | TS | VS Code in a browser. Shows the remote-IDE deployment pattern. | CONTEXT |
| ⚪ `gitpod-io/gitpod` | Go/TS | Built on Theia originally. Reference for cloud IDE architecture. | CONTEXT |
| ⚪ `eclipse-theia/theia-cloud` | TS | Hosting Theia-based IDEs. Relevant only if you deploy. | CONTEXT |
| ⚪ `zed-industries/zed` | Rust | Modern editor built from scratch. Read for architecture ambition, not for reuse. | CONTEXT |
| ⚪ `helix-editor/helix` | Rust | Tree-sitter-native modal editor. Good LSP client reference. | CONTEXT |

### Theia AI

| Resource | Notes | Relevance |
|---|---|---|
| ✅ Theia AI framework (in `eclipse-theia/theia`) | LLM Providers API supports **arbitrary models** including self-hosted and local. Per-use-case model assignment. Runtime configuration of new models. Ships OpenAI, Anthropic, Azure, OpenAI-compatible, Ollama, HuggingFace, LlamaFile. | **CORE** |
| ✅ `theia-ide.org` docs | LLM Provider Documentation is the page you need in week 11. | CORE |

---

## 2. Language Server Protocol

| Repo | Lang | Notes | Relevance |
|---|---|---|---|
| ⚪ `openlawlibrary/pygls` | Python | Pythonic LSP server framework. Your server is built on this. | **CORE** |
| ⚪ `microsoft/language-server-protocol` | — | The spec. Read the `textDocument/publishDiagnostics` and `$/progress` sections. | CORE |
| ✅ `microsoft/vscode-languageclient` | TS | Theia reuses this rather than maintaining a custom Monaco language client. | CORE (transitive) |
| ✅ `TypeFox/vscode-ws-jsonrpc` | TS | JSON-RPC over WebSocket. The transport under Theia's LSP. | CORE (transitive) |
| ✅ `TypeFox/monaco-languageclient` | TS | Connects Monaco to LSP servers. | CORE (transitive) |
| ⚪ `clangd/clangd` | C++ | Production C/C++ language server. Reference for what "good" looks like at scale. | READ |
| ⚪ `rust-lang/rust-analyzer` | Rust | Best-documented modern language server. Incremental analysis architecture. | READ |

---

## 3. C Compilers

### Python implementations

| Repo | Notes | Relevance |
|---|---|---|
| ✅ `ShivamSarodia/ShivyC` | C11 subset, pure Python 3, recursive descent, real x86-64 binaries with optimizations, helpful error messages. ~1,041 stars, MIT. Limited preprocessor handling comments and `#include`. Docker setup included. **Closest possible base.** | **READ** (symbol table, IL, codegen) |
| ✅ `shiyanhui/Compiler` | C compiler in Python. Alternative structure to compare. | READ |
| ⚪ `eliben/pycparser` | C99 parser, pure Python, BSD. Produces AST only. `cffi` depends on it. Needs preprocessed input or `fake_libc_include`. | **CORE** |

### C / C++ / other implementations

| Repo | Notes | Relevance |
|---|---|---|
| ✅ `rui314/chibicc` | Small C compiler, 11.7k stars, commit-by-commit pedagogical progression. The best compiler-construction reading available. | **READ** |
| ⚪ `rui314/8cc` | Predecessor to chibicc, full C11. | READ |
| ✅ `TinyCC/tinycc` | TCC. Tiny, fast, complete C compiler. Production-grade minimalism. | CONTEXT |
| ✅ `jserv/amacc` | Small C compiler emitting ARM ELF, supports JIT. | READ |
| ✅ `jserv/MazuCC` | Minimalist C compiler with x86-64 codegen. | READ |
| ✅ `hikalium/compilium` | C compiler, incremental development style. | READ |
| ✅ `Vexu/arocc` | C compiler in Zig. Modern error reporting design. | CONTEXT |
| ✅ `sheisc/ucc162.3` | Lightweight C compiler explicitly for research and education. | READ |
| ✅ `ltcmelo/psychec` | C frontend with type inference for incomplete code. Unusual and relevant if you handle partial files. | READ |
| ✅ `jiweixing/BIT-MiniCC` | C compiler framework in Java. Framework-style phase separation. | READ |
| ✅ `utam0k/r9cc` | Toy C compiler in Rust. | CONTEXT |
| ✅ `maierfelix/mini-c` | C to WebAssembly. | CONTEXT |
| ✅ `shinh/elvm` | EsoLangVM compiler infrastructure. Novel backends. | CONTEXT |
| ✅ `rabishah/Mini-C-Compiler-using-Flex-And-Yacc` | The classic course-project shape. Useful to see what the baseline expectation is. | CONTEXT |
| ⚪ `llvm/llvm-project` | Clang + LLVM. The reference for everything. | CONTEXT |

### Learning resources

| Repo | Notes | Relevance |
|---|---|---|
| ✅ `nlsandler/write_a_c_compiler` | Test suite for validating your own C compiler. Free front-end regression tests. | **CORE** (testing) |
| ⚪ `DoctorWkt/acwj` | "A Compiler Writing Journey". 60+ parts, incremental, C. Extremely thorough. | READ |
| ⚪ `munificent/craftinginterpreters` | Crafting Interpreters source. Best-written explanation of parsing and tree-walking. | READ |
| ⚪ `codecrafters-io/build-your-own-x` | Index of build-from-scratch guides including compilers. | CONTEXT |

---

## 4. IR, SSA, Code Generation

| Repo | Lang | Notes | Relevance |
|---|---|---|---|
| ✅ `numba/llvmlite` | Python | LLVM binding for JIT compilers. Pure-Python IR builder, ctypes binding layer, no C extension. Version-pinned to specific LLVM releases — check compatibility before installing. | **CORE** |
| ✅ `Jmq14/c2llvm-compiler` | Python | C to LLVM IR in pure Python using llvmlite. Direct precedent for your codegen phase. | **READ** |
| ⚪ `numba/numba` | Python | Production llvmlite consumer. Reference for IR construction patterns at scale. | READ |
| ⚪ `networkx/networkx` | Python | Graph algorithms: dominator trees, DFS, SCC for call graph cycles. | **CORE** |
| ⚪ `bytecodealliance/wasmtime` | Rust | Cranelift IR is a well-documented modern SSA IR. Design reference. | CONTEXT |

---

## 5. Static Analysis Frameworks

| Repo | Lang | Notes | Relevance |
|---|---|---|---|
| ✅ `python-security/pyt` | Python | **Primary reference.** CFG construction, fixpoint iteration, dataflow analysis, def-use and use-def chains. Detects command injection, SQL injection, XSS, directory traversal. Unmaintained since 2020. Ships READMEs in most directories plus the original Master's thesis and slides. | **READ** |
| ✅ `SVF-tools/SVF` | C++ | Static value-flow analysis on LLVM. Field-sensitive pointer analysis, whole-program analysis, typestate analysis, abstract execution. SVF-Python bindings now exist. | READ |
| ⚪ `SVF-tools/SVF-Teaching` | — | Teaching materials for SVF. Software Security Analysis course. | READ |
| ✅ `Enna1/LLVM-Clang-Examples` | C++ | Contains `taint-propagation/` (flow-sensitive, field- and context-insensitive taint via classic dataflow) and `dataflow-points-to-analysis/`. Small and readable. | **READ** |
| ⚪ `facebook/pyre-check` | OCaml/Py | Contains Pysa, Meta's taint analysis for Python. PyT's README points here as the maintained successor. | READ |
| ⚪ `facebook/infer` | OCaml | Separation-logic-based analyzer for C, C++, Java. Interprocedural summaries done properly. | READ |
| ⚪ `soot-oss/soot` / `soot-oss/SootUp` | Java | Classic dataflow framework. The textbook implementation of what you're building. | READ |
| ⚪ `wala/WALA` | Java | IBM analysis framework. Call graph construction reference. | CONTEXT |
| ⚪ `Frama-C/Frama-C` | OCaml | Sound, extensible static analyzer for C. Abstract interpretation. | CONTEXT |
| ⚪ `angr/angr` | Python | Binary analysis with symbolic execution. Python-native CFG and dataflow code worth reading. | READ |
| ⚪ `google/pytype` | Python | Type inference on Python. Good example of an inference engine in Python. | CONTEXT |

---

## 6. C/C++ Security Scanners

| Repo | Notes | Relevance |
|---|---|---|
| ✅ `danmar/cppcheck` | Static analysis of C/C++. Widely deployed. | BENCH baseline |
| ✅ `david-a-wheeler/flawfinder` | Finds possible security weaknesses. Pattern-based, simple, fast. Your AST-pattern-matching ablation row is essentially this. | **BENCH baseline** |
| ✅ `Ericsson/CodeChecker` | Analysis infrastructure over LLVM/Clang toolchain. Runs Clang Static Analyzer with cross-translation-unit analysis, Clang-Tidy, Cppcheck, GCC Static Analyzer, Infer. Defect database, web viewer, false-positive suppression with review comments, incremental analysis, diff mode. **Study its result-viewer UX — it's what your findings panel should aspire to.** | **READ** |
| ⚪ `splintchecker/splint` | Annotation-driven C checker. Historic but instructive. | CONTEXT |
| ⚪ `esbmc/esbmc` | Context-bounded model checker via SMT for C/C++. | CONTEXT |
| ⚪ `goblint/analyzer` | Static analyzer for multi-threaded C. | CONTEXT |
| ⚪ `returntocorp/semgrep` (now `semgrep/semgrep`) | Pattern-based multi-language SAST, huge rule library, LGPL. | CONTEXT / optional candidate generator |
| ⚪ `github/codeql` | Query-based analysis. The engine IRIS wraps. | CONTEXT |
| ⚪ `PyCQA/bandit` | Python security linter. No dataflow — PyT's README notes it needs heavy trimming due to false positive rate. | CONTEXT |

---

## 7. Code Property Graphs

| Repo | Notes | Relevance |
|---|---|---|
| ⚪ `joernio/joern` | CPG platform for C/C++/Java/JS/Python. The reference implementation of Yamaguchi's CPG. Scala/JVM. | **READ** / CONTEXT |
| ⚪ `joernio/joern` — CPGQL | The query language. Relevant if you later add a query interface. | CONTEXT |
| ✅ codebadger (SVM '26) | MCP server bridging Joern's CPG engine to LLMs. Exposes high-level tools (program slicing, taint tracking, dataflow) instead of making the model write CPGQL, because models hallucinate queries. **Read the paper before designing your AI tool interface.** | **READ** |
| ⚪ `tree-sitter/tree-sitter` | Incremental parsing for many languages. Relevant if you extend beyond C. | CONTEXT |

---

## 8. AI + Security Research Systems

| Repo / System | Notes | Relevance |
|---|---|---|
| ✅ `iris-sast/iris` | ICLR 2025. LLM-inferred taint specifications + CodeQL. Detects 55/120 on CWE-Bench-Java vs. CodeQL's 27. **Your Mode B spec inference is modeled on this.** | **READ** |
| ✅ `iris-sast/cwe-bench-java` | Benchmark with fetch, build, analyze scripts. 120 manually validated vulns across real projects. | **READ** (harness design) |
| ✅ vEcho (2026) | IRIS successor. 65% detection, FPR reduced from 84.82% to 59.78%. Current published state of the art. | CONTEXT |
| ✅ LLMxCPG (USENIX Security 2025) | CPG-guided slicing, 67.84–90.93% code reduction while preserving vulnerability context. `LLMxCPG-Q` fine-tune on HuggingFace generates CPGQL queries. | **READ** |
| ✅ Google Big Sleep | Found CVE-2025-6965 in SQLite, known to threat actors. Expert human review before any report is filed. | CONTEXT |
| ✅ XBOW | Reached #1 on HackerOne leaderboard, 1,060+ validated submissions. | CONTEXT |
| ⚪ `google/oss-fuzz` | Continuous fuzzing at scale. The dynamic-analysis counterpart to everything here. | CONTEXT |
| ⚪ `google/atheris`, `AFLplusplus/AFLplusplus` | Fuzzers. Relevant if your validator ever generates real PoC inputs. | CONTEXT |

---

## 9. Open-Source AI Coding Assistants

Study these for the Mode A surface, not for reuse.

| Repo | Notes | Relevance |
|---|---|---|
| ⚪ `cline/cline` | VS Code extension for multi-file and whole-repo coding. Formerly Claude Dev. | READ |
| ⚪ `continuedev/continue` | Open-source IDE assistant, model-agnostic, supports local models. **Closest analogue to your Mode A.** | **READ** |
| ⚪ `TabbyML/tabby` | Self-hosted coding assistant. Good reference for local-first architecture. | READ |
| ⚪ `sourcegraph/cody` | Repo-context-aware assistant. Context-retrieval design. | READ |
| ⚪ `Aider-AI/aider` | CLI pair programmer. Uses a repo map built from tree-sitter — relevant context-selection technique. | READ |
| ⚪ `All-Hands-AI/OpenHands` | Autonomous software agent. | CONTEXT |
| ⚪ `princeton-nlp/SWE-agent` | Agent-computer interface design. | CONTEXT |
| ✅ `sgomez/ollama-ai-provider` | Vercel AI SDK provider for Ollama. Pattern for provider abstraction. | READ |

---

## 10. Local Model Serving

Decide in week 11. All of these speak OpenAI-compatible APIs, so your gateway works with any of them.

| Repo | Notes |
|---|---|
| ⚪ `ollama/ollama` | Simplest local serving. Huge integration ecosystem. Default choice. |
| ⚪ `vllm-project/vllm` | High-throughput serving. Use if you batch adjudications. |
| ⚪ `ggml-org/llama.cpp` | CPU/GPU inference, GGUF quantization. Lowest hardware floor. |
| ⚪ `huggingface/text-generation-inference` | HF production server. |
| ⚪ `BerriAI/litellm` | Unified API across 100+ providers. **Could replace your gateway's provider layer entirely.** |
| ⚪ `mozilla-ai/any-llm` | Unified LLM interface. Alternative to LiteLLM. |

### Candidate models (do not commit yet)

| Model | Note |
|---|---|
| `Qwen/Qwen2.5-Coder-{7B,14B,32B}-Instruct` | Strongest open code models in their size classes |
| `LLMxCPG-Q` (HuggingFace) | Qwen2.5-Coder-32B fine-tuned for CPGQL generation |
| `deepseek-ai/deepseek-coder-*` | Alternative code family |
| `bigcode/starcoder2-*` | Permissive, well-documented training data |
| `meta-llama/Llama-3.1-8B-Instruct` | **Use as the weak baseline.** 0.994 FPR zero-shot on OWASP Benchmark v1.2 — 8 true negatives out of 1,325. This number is your justification for the entire architecture. |

---

## 11. Benchmarks and Datasets

| Resource | Type | Notes | Relevance |
|---|---|---|---|
| ✅ NIST Juliet Test Suite / SARD | Synthetic C/C++ | **Your primary benchmark.** Compilable, labeled, paired good/bad variants → detection rate *and* FPR from one corpus. SARD expands Juliet v1.0 across multiple languages. Constructed in isolation from known patterns, so it does not capture real-world complexity — state this limitation. | **BENCH** |
| ✅ `iris-sast/cwe-bench-java` | Real Java | 120 validated vulns, 4 CWE classes, ~300K LOC projects. Wrong language for you, right harness design. | BENCH (reference) |
| ✅ `DLVulDet/PrimeVul` | Real C/C++ | ~7k vulnerable, ~229k benign functions, 140+ CWEs. Human-level labeling accuracy, ~3× better than automatic methods. De-duplicated with chronological splits. Introduces VD-Score balancing detection against false alarms. ICSE 2025, ~252 stars. | BENCH (secondary) |
| ✅ `wagner-group/diversevul` | Real C/C++ | 18,945 vulnerable functions, 150 CWEs, 330,492 non-vulnerable. RAID 2023. ~190 stars. | BENCH (secondary) |
| ⚪ `epicosy/devign` / `code_x_glue_devign` | Real C | Manually labeled by three security researchers. Widely used, known label-noise issues. | CONTEXT |
| ⚪ Big-Vul | Real C/C++ | 3,754 bugs, 91 types, from CVE-linked GitHub fixes. PrimeVul showed 68% F1 here collapses to 3% after deduplication. | CONTEXT (cautionary) |
| ⚪ MegaVul | Real C/C++ | Expands Big-Vul, 17,380 vulnerabilities, 169 types. | CONTEXT |
| ⚪ D2A (IBM) | Real | Differential analysis over Infer output across version pairs. | CONTEXT |
| ⚪ ReVeal | Real C | Explicitly about limitations of existing datasets. | CONTEXT |
| ⚪ VulDeePecker | Semi-synthetic | Code gadgets, only two CWEs. Historic. | CONTEXT |
| ⚪ Draper | Static-labeled | Labels from Clang, Cppcheck, Flawfinder alerts. Label quality unknown and static-analyzer label accuracy tends to be low. | CONTEXT (cautionary) |
| ⚪ OWASP Benchmark | Java | Source of the 0.994 zero-shot FPR figure. | CONTEXT |
| ✅ SecVulEval | Real C/C++ | 25,440 samples, 5,867 CVEs. Best model reached 23.83% F1. | CONTEXT |
| ⚪ `google/oss-fuzz` + ARVO | Real | Reproducible crash corpus. Relevant if you build a dynamic validator. | CONTEXT |

---

## 12. Awesome Lists and Meta

| Repo | Notes |
|---|---|
| ✅ `analysis-tools-dev/static-analysis` | The most complete curated SAST/linter index. Start here when you need a tool for anything. |
| ✅ `awesome-security/awesome-static-analysis` | Older but broad. |
| ✅ `paulveillard/cybersecurity-sast` | SAST-specific collection with books, videos, guidelines. |
| ⚪ `aymericdamien/TopDeepLearning`-style compiler lists | See the JaDogg gist referenced in §3 for a long compiler-repo roll. |
| ⚪ `rust-unofficial/awesome-rust`, `sindresorhus/awesome` | General entry points. |

---

## 13. Prior Work Closest to Prahari

Nothing occupies the exact intersection. These are the nearest neighbours, and the gap between them is your contribution.

| System | Has compiler | Has analysis | Has LLM | Has IDE | Gap |
|---|---|---|---|---|---|
| ShivyC | ✅ | ✗ | ✗ | ✗ | No security, no AI |
| PyT | ✗ | ✅ | ✗ | ✗ | Python only, no compiler, unmaintained |
| Joern | ✗ | ✅ | ✗ | ✗ | Analysis platform, not a compiler |
| IRIS | ✗ | wraps CodeQL | ✅ | ✗ | No compiler, no IDE |
| codebadger | ✗ | wraps Joern | ✅ | ✗ | No compiler, no IDE |
| CodeChecker | ✗ | wraps others | ✗ | web UI | No AI, no compiler |
| Continue / Cline | ✗ | ✗ | ✅ | ✅ | No program analysis at all |
| **Prahari** | ✅ | ✅ | ✅ | ✅ | — |

The honest framing: each of the four columns individually is well-trodden. **The combination, and specifically the claim that a compiler's own dataflow framework is sufficient grounding for a small local model, is not.** That is what your ablation table tests.

---

## 14. Reading Order

Do not open all of these. In order:

1. **`nlsandler/write_a_c_compiler`** — read the test suite first. It defines "done" for your front end.
2. **`rui314/chibicc`** — first 20 commits. Compiler structure, absorbed quickly.
3. **`ShivamSarodia/ShivyC`** — `symbol_table`, `il_gen`. Python-specific patterns.
4. **`python-security/pyt`** — the thesis, then `cfg/`, then `analysis/`. **Most important single item on this list.**
5. **`Enna1/LLVM-Clang-Examples/taint-propagation`** — transfer functions in concrete form.
6. **IRIS paper + repo** — spec inference prompts.
7. **codebadger paper** — how to expose analysis to a model as tools.
8. **`Ericsson/CodeChecker`** — result viewer UX, before you design the findings panel.
9. **`continuedev/continue`** — Mode A surface patterns.

Items 1–5 cover weeks 1–8. Items 6–9 are week 9 onward. Reading 6–9 early is procrastination disguised as research.
