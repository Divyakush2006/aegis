# Hard cases

Hand-written cases that target the *documented* limitations of the analysis:
field-insensitivity, absence of points-to analysis, path-insensitivity, and
unevaluated `sizeof`.

These are expected to produce misses. They exist so the limitations section of
the report is quantified rather than asserted, and so regressions in the other
direction are visible. Scoring them alongside the main corpus and reporting both
numbers is the honest presentation.
