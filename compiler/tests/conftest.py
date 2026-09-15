"""Shared fixtures: the compiler pipeline, exposed one phase at a time."""
from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from prahari.analysis.callgraph import analyse_program  # noqa: E402
from prahari.analysis.specs import SpecTable  # noqa: E402
from prahari.frontend.adapter import parse_source  # noqa: E402
from prahari.index import build_index  # noqa: E402
from prahari.ir.cfg import build_cfgs  # noqa: E402
from prahari.ir.lowering import lower_program  # noqa: E402
from prahari.ir.ssa import build_ssa  # noqa: E402

EXAMPLES = ROOT / "examples"

# The suite must never spend money or depend on a developer's credentials. A
# real key in the project's .env, or one exported in the shell, would otherwise
# turn tests of the unconfigured path into paid API calls -- and make their
# results depend on whose machine they ran on. Subprocesses inherit this too.
os.environ["PRAHARI_NO_DOTENV"] = "1"
for _variable in (
    "PRAHARI_API_KEY",
    "OPENROUTER_API_KEY",
    "ANTHROPIC_API_KEY",
    "PRAHARI_API_BASE",
    "PRAHARI_MODEL",
    "PRAHARI_AI_PROVIDER",
):
    os.environ.pop(_variable, None)


@pytest.fixture
def compile_source():
    """Compile a source string through to SSA-form CFGs."""

    def _compile(source: str):
        program, _pre, exclusions = parse_source(source, "<test>")
        module = lower_program(program, exclusions)
        cfgs = build_cfgs(module)
        build_ssa(cfgs)
        return module, cfgs, exclusions

    return _compile


@pytest.fixture
def analyse(compile_source):
    """Compile and run the full interprocedural taint analysis."""

    def _analyse(source: str):
        module, cfgs, _ = compile_source(source)
        return cfgs, analyse_program(module, cfgs, SpecTable())

    return _analyse


@pytest.fixture
def audit():
    """Run the complete pipeline over an example file and return the index."""

    def _audit(name: str):
        return build_index([str(EXAMPLES / name)])

    return _audit


@pytest.fixture(scope="session")
def example_files() -> list[str]:
    return sorted(str(p) for p in EXAMPLES.glob("*.c"))
