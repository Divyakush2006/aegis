# Aegis — reproducible evaluation environment for the compiler.
#
# No C toolchain is installed on purpose: the preprocessor is self-contained,
# and proving that in the image is stronger than claiming it in the README.
# The IDE is not built here; it needs a Node toolchain and is documented
# separately in ide/README.md.
FROM python:3.12-slim

LABEL org.opencontainers.image.title="Aegis" \
      org.opencontainers.image.description="Security-aware C compiler with SARIF output" \
      org.opencontainers.image.licenses="MIT"

WORKDIR /app

COPY compiler/pyproject.toml ./
COPY README.md ./
COPY compiler/src/ ./src/
RUN pip install --no-cache-dir ".[codegen,lsp]"

COPY compiler/examples/ ./examples/
COPY compiler/tests/ ./tests/
COPY compiler/eval/ ./eval/

# Fail the build if the analysis regressed. The suite includes the evaluation,
# so a change in detection rate or false positive rate breaks the image.
RUN pip install --no-cache-dir pytest && python -m pytest -q

# Record the ablation matrix in the build log for provenance.
RUN python eval/ablation.py

# Adjudication is configured at run time, never baked in:
#
#   docker run -e AEGIS_API_KEY=sk-ant-... aegis audit /work --adjudicate
#
# With no key the image behaves exactly as it does above -- the audit runs and
# reports the compiler's own verdicts. A key is never copied into a layer, and
# the image needs no network for anything else it does.

WORKDIR /work
ENTRYPOINT ["aegis"]
CMD ["audit", "/work", "--format", "table"]
