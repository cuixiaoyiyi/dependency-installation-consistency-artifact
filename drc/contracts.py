"""Conservative, scoped checks of explicit dependency-resolution contracts.

This module checks recorded evidence; it does not establish the paper's slice
adequacy or prove that arbitrary environment perturbations are irrelevant.
Unknown applicability, projected requests, and unverified selected files never
become a contract violation.  A pair need not be comparable to establish a
single, independently witnessed contract violation.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
import pathlib
import re
import tomllib

from packaging.markers import Marker, InvalidMarker
from packaging.requirements import Requirement, InvalidRequirement
from packaging.utils import canonicalize_name
from packaging.version import Version, InvalidVersion


def _get(obj, key, default=None):
    return obj.get(key, default) if isinstance(obj, dict) else getattr(obj, key, default)


def _normal_path(value):
    return str(pathlib.PurePosixPath(str(value or ".").replace("\\", "/")))


@dataclass
class ContractCheck:
    dependency: str
    kind: str
    status: str                 # pass | violation | unknown | not_applicable
    reason: str
    expected: dict = field(default_factory=dict)
    actual: dict = field(default_factory=dict)
    evidence: dict = field(default_factory=dict)

    def to_dict(self):
        return asdict(self)


@dataclass
class ContractAssessment:
    context_id: str
    checks: list[ContractCheck] = field(default_factory=list)

    @property
    def violations(self):
        return [c.to_dict() for c in self.checks if c.status == "violation"]

    @property
    def unknowns(self):
        return [c.to_dict() for c in self.checks if c.status == "unknown"]

    @property
    def status(self):
        if self.violations:
            return "violation"
        if self.unknowns or not any(c.status == "pass" for c in self.checks):
            return "unknown"
        return "pass"

    def to_dict(self):
        return {"context_id": self.context_id, "status": self.status,
                "checks": [c.to_dict() for c in self.checks],
                "violations": self.violations, "unknowns": self.unknowns,
                "theoretical_soundness_claim": False}


@dataclass
class ComparisonEligibility:
    eligible: bool
    reasons: list[str] = field(default_factory=list)

    def to_dict(self):
        return {"eligible": self.eligible, "reasons": self.reasons,
                "theoretical_soundness_claim": False,
                "meaning": "matching recorded request and policy; not an irrelevance proof"}


def _requirements(values):
    out = []
    for value in values or []:
        try:
            r = Requirement(value)
        except (InvalidRequirement, TypeError):
            return None
        out.append((canonicalize_name(r.name), tuple(sorted(canonicalize_name(x) for x in r.extras)),
                    str(r.specifier), str(r.marker or ""), r.url or ""))
    return tuple(sorted(set(out)))


def _strategy(ctx):
    explicit = _get(ctx, "index_strategy")
    if explicit:
        return explicit
    return {"pip": "version-priority", "uv": "first-index"}.get(_get(ctx, "resolver"))


def comparison_eligibility(ctx_a, ctx_b, resolution_a=None, resolution_b=None):
    """Require equality of the recorded semantic inputs before claiming stability.

    Changes to indexes/sources can still be reported as exploratory contrasts.
    They require an independent, transformation-specific certificate before being
    treated as stability tests; this function does not manufacture that proof.
    """
    reasons = []
    for name, ctx in (("a", ctx_a), ("b", ctx_b)):
        if _get(ctx, "faithfulness", "unverified") != "verified":
            reasons.append(f"{name}:request-not-verified")
        if not _get(ctx, "request_complete", False):
            reasons.append(f"{name}:request-incomplete")
        if _get(ctx, "project_extras") is None:
            reasons.append(f"{name}:project-extras-unknown")
        if _get(ctx, "lock_mode", "unknown") == "unknown":
            reasons.append(f"{name}:lock-mode-unknown")
        if _get(ctx, "source_bindings_enabled") is None:
            reasons.append(f"{name}:source-binding-mode-unknown")
    for key in ("requirements", "constraints"):
        left, right = _requirements(_get(ctx_a, key, [])), _requirements(_get(ctx_b, key, []))
        if left is None or right is None:
            reasons.append(f"{key}:unparsed")
        elif left != right:
            reasons.append(f"{key}:different")
    for key in ("resolver", "platform", "python_version", "lock_mode", "lock_file", "source_bindings_enabled", "pre", "no_index", "no_deps", "require_hashes", "only_binary"):
        if _get(ctx_a, key) != _get(ctx_b, key):
            reasons.append(f"{key}:different")
    if _strategy(ctx_a) != _strategy(ctx_b):
        reasons.append("resolver-strategy:different")
    for key in ("platform", "python_version"):
        if not _get(ctx_a, key) or not _get(ctx_b, key):
            reasons.append(f"{key}:unknown")
    if sorted(_get(ctx_a, "project_extras") or []) != sorted(_get(ctx_b, "project_extras") or []):
        reasons.append("project-extras:different")
    for key in ("scope", "project_file"):
        if _normal_path(_get(ctx_a, key)) != _normal_path(_get(ctx_b, key)):
            reasons.append(f"{key}:different")
    # Source order matters under index priority and may affect equal-version ties.
    for key in ("index_url", "extra_index_urls", "find_links", "sources", "named_indexes", "marker_environment"):
        if _get(ctx_a, key) != _get(ctx_b, key):
            reasons.append(f"{key}:different")
    for name, res in (("a", resolution_a), ("b", resolution_b)):
        if res is not None:
            if not _get(res, "ok", False):
                reasons.append(f"{name}:resolution-failed")
            if _get(res, "fallback", ""):
                reasons.append(f"{name}:resolution-used-fallback")
            if not _get(res, "resolver_version"):
                reasons.append(f"{name}:resolver-version-unknown")
            if any(not _get(artifact, "selected_artifact_verified", False)
                   for artifact in (_get(res, "artifacts", {}) or {}).values()):
                reasons.append(f"{name}:selected-artifact-not-verified")
    if resolution_a is not None and resolution_b is not None:
        if _get(resolution_a, "resolver_version") != _get(resolution_b, "resolver_version"):
            reasons.append("resolver-version:different")
        snapshots = [_get(r, "snapshot", {}) or {} for r in (resolution_a, resolution_b)]
        # A timestamp is not a repository snapshot.  The producer must record a
        # common frozen/replayed candidate-universe identifier explicitly.
        ids = [s.get("id") or s.get("snapshot_id") for s in snapshots]
        if not all(ids) or ids[0] != ids[1]:
            reasons.append("candidate-snapshot:not-proven-identical")
        if not all(s.get("frozen") is True or s.get("mode") in ("replay", "frozen") for s in snapshots):
            reasons.append("candidate-snapshot:not-frozen")
        for name, snapshot in zip(("a", "b"), snapshots):
            if not all(snapshot.get(key) is True for key in ("proxy_verified", "complete", "sealed", "frozen", "integrity_verified")):
                reasons.append(f"{name}:snapshot-evidence-incomplete")
        manifests = [snapshot.get("manifest_sha256") for snapshot in snapshots]
        if not all(manifests) or manifests[0] != manifests[1]:
            reasons.append("candidate-snapshot:manifest-not-proven-identical")
    else:
        ids = [_get(c, "snapshot_id") for c in (ctx_a, ctx_b)]
        if not all(ids) or ids[0] != ids[1]:
            reasons.append("candidate-snapshot:not-proven-identical")
        if not all(_get(c, "snapshot_mode") in ("replay", "frozen") for c in (ctx_a, ctx_b)):
            reasons.append("candidate-snapshot:not-frozen")
    return ComparisonEligibility(not reasons, list(dict.fromkeys(reasons)))


def _marker_environment(ctx):
    env = dict(_get(ctx, "marker_environment", {}) or {})
    py = _get(ctx, "python_version", "")
    if py:
        parts = str(py).split(".")
        if len(parts) >= 2:
            env.setdefault("python_version", ".".join(parts[:2]))
        if len(parts) >= 3:
            env.setdefault("python_full_version", str(py))
    platform = str(_get(ctx, "platform", ""))
    for prefix, system, os_name in (("linux", "linux", "posix"), ("windows", "win32", "nt"), ("win", "win32", "nt"), ("macos", "darwin", "posix"), ("darwin", "darwin", "posix")):
        if platform.startswith(prefix):
            env.setdefault("sys_platform", system)
            env.setdefault("os_name", os_name)
            break
    return env


_MARKER_KEYS = {"implementation_name", "implementation_version", "os_name", "platform_machine", "platform_release",
                "platform_system", "platform_version", "python_full_version", "platform_python_implementation",
                "python_version", "sys_platform", "extra", "extras", "dependency_groups"}


def _marker_applies(expression, ctx):
    if not expression:
        return True, ""
    env = _marker_environment(ctx)
    # Never let packaging silently fill absent marker variables from the host.
    unquoted = re.sub(r"(['\"]).*?\1", "", str(expression))
    variables = set(re.findall(r"\b[A-Za-z_][A-Za-z_0-9]*\b", unquoted)) & _MARKER_KEYS
    extras = _get(ctx, "project_extras")
    if "extra" in variables:
        if extras is None:
            return None, "marker-extra-unknown"
        env["extra"] = ""
    if variables - set(env):
        return None, "marker-environment-incomplete:" + ",".join(sorted(variables - set(env)))
    try:
        marker = Marker(str(expression))
        values = extras or [""] if "extra" in variables else [""]
        return any(marker.evaluate({**env, "extra": extra}) for extra in values), ""
    except (InvalidMarker, KeyError, ValueError, TypeError):
        return None, "marker-not-evaluable"


def _applicability(evidence, ctx):
    conditions = evidence.get("conditions") or {}
    scope = _normal_path(evidence.get("scope", "."))
    ctx_scope = _get(ctx, "scope")
    if ctx_scope is None:
        return None, "scope-unknown"
    if scope != _normal_path(ctx_scope):
        return False, "different-project-scope"
    project_file = conditions.get("project_file")
    if project_file and _get(ctx, "project_file") and _normal_path(project_file) != _normal_path(_get(ctx, "project_file")):
        return False, "different-project-file"
    kind = evidence.get("contract_kind")
    if kind == "lock":
        mode = _get(ctx, "lock_mode", "unknown")
        if mode in ("off", "unlocked", "none"):
            return False, "lock-not-enforced"
        if mode not in ("locked", "frozen", "require-hashes", "requirements-hashes"):
            return None, "lock-mode-unknown"
        active = _get(ctx, "lock_file")
        if not active:
            return None, "active-lock-file-unknown"
        if _normal_path(active) != _normal_path(conditions.get("lock_file")):
            return False, "different-lock-file"
    elif kind == "source-binding":
        tool = evidence.get("tool")
        if tool and _get(ctx, "resolver") != tool:
            return False, "source-binding-is-tool-specific"
        enabled = _get(ctx, "source_bindings_enabled")
        if enabled is False:
            return False, "source-bindings-disabled"
        if enabled is not True:
            return None, "source-binding-mode-unknown"
        if conditions.get("conditions_known") is not True:
            return None, "source-conditions-not-preserved"
    else:
        return None, "unsupported-contract-kind"
    extra = conditions.get("extra")
    if extra is not None:
        extras = _get(ctx, "project_extras")
        if extras is None:
            return None, "project-extras-unknown"
        if canonicalize_name(str(extra)) not in {canonicalize_name(str(value)) for value in extras}:
            return False, "source-extra-not-selected"
    group = conditions.get("group")
    if group:
        groups = _get(ctx, "groups", (_get(ctx, "factors", {}) or {}).get("groups"))
        if groups is None:
            return None, "dependency-groups-unknown"
        if group not in groups:
            return False, "source-group-not-selected"
    active, reason = _marker_applies(conditions.get("marker"), ctx)
    if active is False:
        return False, "source-marker-false"
    return active, reason


def _lock_shape_known(ir, evidence):
    """Do not enforce the legacy lock parser's last-wins flattened branches."""
    conditions = evidence.get("conditions") or {}
    kind = conditions.get("lock_kind")
    if kind not in ("uv.lock", "poetry.lock", "pylock.toml"):
        return False
    try:
        data = tomllib.loads((pathlib.Path(_get(ir, "root", "")) / evidence["file"]).read_text(encoding="utf-8"))
    except (OSError, ValueError, TypeError):
        return False
    packages = data.get("packages" if kind == "pylock.toml" else "package", [])
    matches = [p for p in packages if canonicalize_name(p.get("name", "")) == evidence["dep"]]
    return len(matches) == 1 and not any(k in matches[0] for k in ("marker", "markers", "resolution-markers"))


def _artifact_check(evidence, artifact, ir):
    expected = evidence.get("expected") or {"registry": evidence.get("registry")}
    actual = {k: _get(artifact, k) for k in ("registry", "version", "sha256", "url", "filename")}
    if not _get(artifact, "selected_artifact_verified", False):
        return "unknown", "selected-file-not-verified", expected, actual
    kind = evidence.get("contract_kind")
    if kind == "lock" and not _lock_shape_known(ir, evidence):
        return "unknown", "lock-branches-not-validated", expected, actual
    unknown_reason = ""
    registry = expected.get("registry") or evidence.get("registry")
    if registry:
        if not _get(artifact, "registry_verified", False):
            # A selected download URL is not evidence of which simple index
            # supplied it.  File selection and index attribution are distinct.
            unknown_reason = "selected-registry-attribution-not-verified"
        elif not actual["registry"] or actual["registry"] == "?":
            unknown_reason = "selected-registry-unknown"
        # Never compare only registry families: cu126, cu128 and nightly differ.
        elif actual["registry"] != registry:
            return "violation", "selected-source-outside-applicable-contract", expected, actual
    if kind == "lock":
        version = expected.get("version")
        if version:
            try:
                matches = Version(str(version)) == Version(str(actual["version"]))
            except InvalidVersion:
                return "unknown", "lock-version-not-exact", expected, actual
            if not matches:
                return "violation", "selected-version-differs-from-enforced-lock", expected, actual
        hashes = {str(h).lower().removeprefix("sha256:") for h in expected.get("hashes", []) if h and (":" not in str(h) or str(h).startswith("sha256:"))}
        if hashes:
            if not actual["sha256"]:
                return "unknown", "selected-hash-unknown", expected, actual
            if str(actual["sha256"]).lower().removeprefix("sha256:") not in hashes:
                return "violation", "selected-hash-outside-enforced-lock", expected, actual
    if unknown_reason:
        return "unknown", unknown_reason, expected, actual
    return "pass", "selected-artifact-satisfies-applicable-contract", expected, actual


def assess_contracts(ir, intents, ctx, resolution):
    """Assess explicit source/lock contracts against a resolution or one artifact."""
    assessment = ContractAssessment(str(_get(ctx, "id", "")))
    artifacts = _get(resolution, "artifacts")
    if artifacts is None:
        name = _get(resolution, "name")
        artifacts = {canonicalize_name(name): resolution} if name else {}
    artifacts = {canonicalize_name(k): v for k, v in artifacts.items()}
    verified_context = (_get(ctx, "faithfulness", "unverified") == "verified"
                        and _get(ctx, "request_complete", False))
    usable_resolution = _get(resolution, "ok", True) and not _get(resolution, "fallback", "")
    for dep, intent in intents.items():
        dep = canonicalize_name(dep)
        contracts = _get(intent, "contracts")
        if contracts is None:
            contracts = [e for e in _get(intent, "evidence", []) if e.get("enforceable")]
        active = []
        uncertain_source_registries = set()
        for evidence in contracts:
            applies, reason = _applicability(evidence, ctx)
            kind = evidence.get("contract_kind", "unknown")
            if applies is False:
                assessment.checks.append(ContractCheck(dep, kind, "not_applicable", reason, evidence=evidence))
                continue
            if applies is None:
                if kind == "source-binding":
                    uncertain_source_registries.add(evidence.get("registry"))
                assessment.checks.append(ContractCheck(dep, kind, "unknown", reason, evidence=evidence))
                continue
            if not verified_context or not usable_resolution:
                reason = "request-not-verified" if not verified_context else "resolution-failed-or-fallback"
                assessment.checks.append(ContractCheck(dep, kind, "unknown", reason, evidence=evidence))
                continue
            active.append(evidence)
        source_registries = {e.get("registry") for e in active if e.get("contract_kind") == "source-binding" and e.get("registry")}
        for evidence in active:
            kind = evidence.get("contract_kind", "unknown")
            if kind == "source-binding" and len(source_registries) > 1:
                assessment.checks.append(ContractCheck(dep, kind, "unknown", "conflicting-active-source-contracts", evidence=evidence))
            elif kind == "source-binding" and uncertain_source_registries - {evidence.get("registry")}:
                assessment.checks.append(ContractCheck(dep, kind, "unknown", "possibly-conflicting-conditional-source-contracts", evidence=evidence))
            elif dep not in artifacts:
                assessment.checks.append(ContractCheck(dep, kind, "unknown", "dependency-not-selected-or-selection-incomplete", evidence=evidence))
            else:
                status, reason, expected, actual = _artifact_check(evidence, artifacts[dep], ir)
                assessment.checks.append(ContractCheck(dep, kind, status, reason, expected, actual, evidence))
    if not assessment.checks:
        assessment.checks.append(ContractCheck("*", "none", "unknown", "no-explicit-scoped-contract"))
    return assessment
