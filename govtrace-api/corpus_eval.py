"""
Labeled-corpus evaluator for the GovTrace engine.

Runs every case in `test_corpus.json` through `engine.analyze()` and computes
per-rule + overall confusion-matrix metrics (TP, FP, FN, TN, FPR, FNR).

USAGE
-----
At import time, the corpus file is loaded once. `evaluate()` is idempotent and
runs every case against the current engine — call it at startup and cache the
result. Re-running is cheap (~50 cases, pure regex) but avoid doing it on the
hot path of /health.

LABELING CONVENTION
-------------------
Each case's `expected_rule_ids` is the EXACT set that must fire on its text.
  - any extra rule that fires  = false positive for that rule
  - any expected rule that does not fire = false negative for that rule
A negative case has `expected_rule_ids: []` — any finding at all is a FP.
"""
from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Optional

from engine import analyze, compute_residual_risk, input_had_blocking_class, safe_for_use_after_redaction

logger = logging.getLogger(__name__)

CORPUS_PATH = Path(__file__).parent / "test_corpus.json"


def _load_corpus() -> tuple[str, list[dict]]:
    """Return (corpus_version, cases). Empty tuple if the file is missing/invalid."""
    if not CORPUS_PATH.exists():
        logger.info("Corpus file %s not found — evaluator disabled", CORPUS_PATH)
        return ("", [])
    try:
        with open(CORPUS_PATH, encoding="utf-8") as fh:
            data = json.load(fh)
        return (data.get("corpus_version", ""), data.get("cases", []))
    except (OSError, json.JSONDecodeError, ValueError):
        logger.exception("Failed to parse corpus file %s", CORPUS_PATH)
        return ("", [])


def _rate(num: int, den: int) -> float:
    return round(num / den, 4) if den > 0 else 0.0


def evaluate(profile: str = "General") -> dict:
    """Run every corpus case through analyze() and return a metrics dict.

    Returns:
        {
          corpus_version: str,
          total_cases: int,
          pass_rate: float,           # fraction of cases with exact rule-set match
          overall: {tp, fp, fn, tn, fpr, fnr},
          per_rule: { rule_id: {tp, fp, fn, tn, fpr, fnr} },
          per_category: { category: {cases, passes, pass_rate} },
          failures: [ {id, category, missing, unexpected} ]
        }
    """
    version, cases = _load_corpus()
    if not cases:
        return {
            "corpus_version": version,
            "total_cases": 0,
            "note": "corpus not loaded",
        }

    # Seed the rule-id set with every rule any case expects so TN counts include
    # rules that are never expected in the case but still produced nowhere.
    all_rules: set[str] = set()
    for c in cases:
        all_rules.update(c.get("expected_rule_ids", []))

    per_rule: dict[str, dict[str, int]] = {}
    per_category: dict[str, dict[str, int]] = {}
    failures: list[dict] = []
    exact_matches = 0

    # Accumulate residual-risk scores per category for distribution reporting.
    # Bands are engine-defined; we just count what comes back.
    risk_band_counts: dict[str, int] = {"low": 0, "medium": 0, "high": 0, "critical": 0}
    per_category_risk: dict[str, list[float]] = {}

    for c in cases:
        text = c["text"]
        expected = set(c.get("expected_rule_ids", []))
        category = c.get("category", "uncategorized")

        findings = analyze(text, profile=profile)
        produced = {f.rule_id for f in findings}
        risk = compute_residual_risk(
            findings,
            had_blocking_class=input_had_blocking_class(findings),
            safe_after_redaction=safe_for_use_after_redaction(text, profile),
        )
        risk_band_counts[risk["band"]] = risk_band_counts.get(risk["band"], 0) + 1
        per_category_risk.setdefault(category, []).append(risk["score"])

        # Every rule involved (declared + produced) gets scored for this case.
        # Rules that appear here get added to all_rules so their TN count is
        # tracked consistently across subsequent cases.
        rules_in_play = expected | produced
        all_rules.update(rules_in_play)
        for r in all_rules:
            row = per_rule.setdefault(r, {"tp": 0, "fp": 0, "fn": 0, "tn": 0})
            in_expected = r in expected
            in_produced = r in produced
            if in_expected and in_produced:
                row["tp"] += 1
            elif in_expected and not in_produced:
                row["fn"] += 1
            elif not in_expected and in_produced:
                row["fp"] += 1
            else:
                row["tn"] += 1

        cat = per_category.setdefault(category, {"cases": 0, "passes": 0})
        cat["cases"] += 1
        if produced == expected:
            exact_matches += 1
            cat["passes"] += 1
        else:
            failures.append({
                "id": c.get("id", "<no-id>"),
                "category": category,
                "missing": sorted(expected - produced),
                "unexpected": sorted(produced - expected),
            })

    # Derive rates.
    overall_tp = sum(m["tp"] for m in per_rule.values())
    overall_fp = sum(m["fp"] for m in per_rule.values())
    overall_fn = sum(m["fn"] for m in per_rule.values())
    overall_tn = sum(m["tn"] for m in per_rule.values())

    per_rule_out = {
        r: {
            **m,
            "fpr": _rate(m["fp"], m["fp"] + m["tn"]),
            "fnr": _rate(m["fn"], m["fn"] + m["tp"]),
        }
        for r, m in sorted(per_rule.items())
    }

    per_category_out = {
        cat: {
            **v,
            "pass_rate": _rate(v["passes"], v["cases"]),
            "mean_residual_risk": (
                round(sum(per_category_risk.get(cat, [])) / len(per_category_risk[cat]), 4)
                if per_category_risk.get(cat) else 0.0
            ),
        }
        for cat, v in sorted(per_category.items())
    }

    return {
        "corpus_version": version,
        "total_cases": len(cases),
        "pass_rate": _rate(exact_matches, len(cases)),
        "overall": {
            "tp": overall_tp,
            "fp": overall_fp,
            "fn": overall_fn,
            "tn": overall_tn,
            "fpr": _rate(overall_fp, overall_fp + overall_tn),
            "fnr": _rate(overall_fn, overall_fn + overall_tp),
        },
        "residual_risk_distribution": risk_band_counts,
        "per_rule": per_rule_out,
        "per_category": per_category_out,
        "failures": failures,
    }


def summary(result: Optional[dict] = None) -> dict:
    """Compact view for /health. Drops per_rule detail and the full failure list."""
    if result is None:
        result = evaluate()
    if result.get("total_cases", 0) == 0:
        return {"corpus_loaded": False}
    return {
        "corpus_loaded": True,
        "corpus_version": result.get("corpus_version", ""),
        "total_cases": result["total_cases"],
        "pass_rate": result["pass_rate"],
        "overall_fpr": result["overall"]["fpr"],
        "overall_fnr": result["overall"]["fnr"],
        "failure_count": len(result.get("failures", [])),
    }
