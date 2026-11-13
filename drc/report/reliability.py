"""Conservative evidence gates shared by report generation and legacy-result audits.

Legacy labels such as C-IntentViolation and NEEDS_EXPLANATION are observations,
not evidence of faithful replay, comparable requests, or a verified contract breach.
"""
from __future__ import annotations


def _record(value):
    return value if isinstance(value, dict) else {}


def _evidenced(record):
    return record.get("verified") is True and bool(record.get("evidence"))


def context_reliability(context):
    context = _record(context)
    raw = context.get("faithfulness", "unverified")
    status = raw.get("status", "unverified") if isinstance(raw, dict) else raw
    status = str(status or "unverified").lower()
    limitations = list(context.get("limitations") or [])
    derived = str(context.get("derived_from", "unknown"))
    origin = _record(context.get("origin"))
    synthetic = derived.startswith("synthetic") or origin.get("kind") == "synthetic"
    faithful = status in {"faithful", "verified", "verified-faithful"}
    reasons = []
    if not faithful:
        reasons.append("Context faithfulness has not been verified")
    if context.get("request_complete") is not True:
        reasons.append("Complete original request has not been preserved")
    if synthetic:
        reasons.append("Context is a synthetic perturbation")
    if not origin:
        reasons.append("Original command provenance is missing")
    if limitations:
        reasons.extend(str(x) for x in limitations)
    return {"faithfulness": status, "synthetic": synthetic,
            "faithful_replay": not reasons, "reasons": reasons,
            "origin": origin, "limitations": limitations}


def context_label(side, contexts, install_paths=None):
    """Describe the recorded operation; never invent pip install . or uv sync."""
    context = contexts.get(side.get("context"), {})
    origin = _record(context.get("origin"))
    derived = str(context.get("derived_from", side.get("derived_from", "unknown")))
    ip = None
    if derived.startswith("install-path:"):
        ip = (install_paths or {}).get(derived.split(":", 1)[1])
    origin = origin or ip or {}
    command = origin.get("command") or origin.get("original_command")
    file = origin.get("file")
    line = origin.get("line")
    location = f"{file}:{line}" if file and line else str(file or "")
    resolver = context.get("resolver", "unknown resolver")
    status = context_reliability(context)["faithfulness"]
    if command:
        return f"`{location or derived}`: `{command}` (replay faithfulness: {status})"
    if derived == "declared":
        return f"{resolver} resolution of an extracted requirement set (faithfulness: {status}; original install command not verified)"
    return f"{resolver} context `{derived}` (faithfulness: {status}; original install command not verified)"


def _validation(case, key):
    direct = _record(case.get(key))
    return direct or _record(_record(case.get("validation")).get(key))


def assess_case(case, contexts):
    """Do not promote a differential result without independently recorded evidence.

    A single faithful execution can violate an explicit contract. Only relational
    claims (stability/equivalence between paths) require a verified comparison.
    Verification records require verified=true and nonempty evidence, plus the
    contract text for a contract_violation record. Auto-mined intent is insufficient.
    """
    sides = {side: context_reliability(contexts.get(case.get(side, {}).get("context"), {}))
             for side in ("a", "b")}
    comparison = _validation(case, "comparability")
    if not comparison:
        comparison = _validation(case, "comparison")
    comparison_verified = _evidenced(comparison) and all(v["faithful_replay"] for v in sides.values())
    contract = _validation(case, "contract_violation")
    kind = contract.get("kind", contract.get("claim_kind", "relational"))
    relational = kind not in {"single-context", "single_context", "explicit", "unary"}
    target = contract.get("side")
    if not target and contract.get("context"):
        target = next((s for s in ("a", "b") if case.get(s, {}).get("context") == contract["context"]), None)
    replay_ok = all(v["faithful_replay"] for v in sides.values()) if relational else (
        target in sides and sides[target]["faithful_replay"])
    verified = _evidenced(contract) and bool(contract.get("contract"))
    reasons = []
    if not replay_ok:
        reasons.append("The affected original execution has not been faithfully replayed")
    if relational and not comparison_verified:
        reasons.append("Comparability of the two original requests has not been verified")
    if not verified:
        reasons.append("A contract violation has not been verified with contract text and evidence")
    triage = _record(case.get("triage"))
    if triage.get("label") == "BENIGN" and relational:
        reasons.append("Existing artifact triage explains the difference as benign")
    ready = verified and replay_ok and (comparison_verified or not relational) and not reasons
    insufficient = case.get("cls") == "INSUFFICIENT_EVIDENCE"
    return {"observed_difference": case.get("cls") not in {None, "SAME", "SAME_FILE_MIRROR", "INSUFFICIENT_EVIDENCE"},
            "comparison_status": "verified" if comparison_verified else "unverified",
            "contract_status": "verified" if ready else "unverified",
            "classification": "verified_contract_violation" if ready else (
                "insufficient_evidence" if insufficient else
                "comparable_difference" if comparison_verified else "difference_observed"),
            "developer_ready": ready, "reasons": reasons, "contexts": sides,
            "contract": contract, "comparability": comparison}


def verified_text(case, key, fallback):
    record = _validation(case, key)
    return str(record.get("summary") or fallback) if _evidenced(record) else fallback
