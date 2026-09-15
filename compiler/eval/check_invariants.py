"""Check the adjudication invariants across two audit reports.

The invariants are claims the project makes in its documentation, so they are
checked mechanically rather than asserted:

1. Adjudication does not change which findings exist.
2. Adjudication does not raise a confidence.
3. Adjudication does not change a severity.

The unit tests check the same properties on the objects; this checks them on
the *reports*, which is what a consumer -- a CI gate, a SARIF upload, a
reviewer -- actually reads.

**The baseline must be an unadjudicated audit.** Comparing two adjudicated runs
does not test anything: a run through ``NullGateway`` records a 0.5 "no
opinion", so a later run recording 0.8 would look like a rise when the static
analysis never asserted either number. The comparison that means something is
against what the compiler alone said.

Confidence is compared in its *effective* form -- an absent value means the
analysis made no claim, which the reporting layer treats as 1.0. Reading it any
other way would let a demotion from "unstated" to 0.9 register as an increase.

    prahari audit examples --format json -o static.json
    prahari audit examples --adjudicate --format json -o adjudicated.json
    python eval/check_invariants.py static.json adjudicated.json
"""
from __future__ import annotations

import json
import sys
from pathlib import Path


def load(path: str) -> dict:
    return json.loads(Path(path).read_text(encoding="utf-8"))


def effective_confidence(finding: dict) -> float:
    """What the reporting layer shows: an absent claim is full confidence."""
    value = finding.get("confidence")
    return 1.0 if value is None else float(value)


def check(baseline: dict, adjudicated: dict) -> list[str]:
    failures: list[str] = []
    base_findings = baseline.get("findings", [])
    live_findings = adjudicated.get("findings", [])

    if not base_findings:
        failures.append("the baseline audit reported no findings at all")
    if baseline.get("adjudication"):
        failures.append(
            "the baseline is itself an adjudicated run; use a plain `prahari audit` "
            "so the comparison measures what the compiler alone reported"
        )

    base_ids = [f["fingerprint"] for f in base_findings]
    live_ids = [f["fingerprint"] for f in live_findings]
    if base_ids != live_ids:
        invented = set(live_ids) - set(base_ids)
        lost = set(base_ids) - set(live_ids)
        failures.append(
            f"the set of findings changed (invented={sorted(invented)}, lost={sorted(lost)})"
        )

    by_id = {f["fingerprint"]: f for f in base_findings}
    for finding in live_findings:
        before = by_id.get(finding["fingerprint"])
        if before is None:
            continue
        if finding["severity"] != before["severity"]:
            failures.append(
                f"{finding['fingerprint']}: severity changed "
                f"{before['severity']} -> {finding['severity']}"
            )
        prior, now = effective_confidence(before), effective_confidence(finding)
        if now > prior:
            failures.append(f"{finding['fingerprint']}: confidence rose {prior} -> {now}")
        if not 0.0 <= now <= 1.0:
            failures.append(f"{finding['fingerprint']}: confidence {now} is out of range")

    stats = adjudicated.get("adjudication") or {}
    if not stats:
        failures.append("the second report did not go through adjudication")
    if stats.get("errors"):
        failures.append(f"adjudication reported {stats['errors']} errors: {stats}")
    if stats.get("candidates") and stats.get("adjudicated") != stats.get("candidates"):
        failures.append(
            f"only {stats.get('adjudicated')} of {stats['candidates']} candidates were reviewed"
        )
    return failures


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        print(__doc__.strip().splitlines()[-1], file=sys.stderr)
        return 2

    baseline, adjudicated = load(argv[0]), load(argv[1])
    failures = check(baseline, adjudicated)

    if failures:
        print("INVARIANT VIOLATIONS", file=sys.stderr)
        for failure in failures:
            print(f"  {failure}", file=sys.stderr)
        return 1

    stats = adjudicated.get("adjudication") or {}
    lowered = sum(
        1
        for f in adjudicated.get("findings", [])
        if effective_confidence(f) < 1.0
    )
    print(
        f"invariants hold: {len(baseline.get('findings', []))} findings unchanged, "
        f"{stats.get('adjudicated', 0)} reviewed by {stats.get('model', 'null')}, "
        f"{lowered} demoted, none raised, no severity changed"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
