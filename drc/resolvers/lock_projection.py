"""Project a uv lock's dependency graph onto one explicitly described target."""
from __future__ import annotations

from collections import defaultdict, deque
import re

from packaging.markers import Marker, InvalidMarker
from packaging.requirements import Requirement, InvalidRequirement
from packaging.specifiers import SpecifierSet, InvalidSpecifier
from packaging.utils import canonicalize_name
from packaging.version import Version, InvalidVersion

from ..model import Artifact, Context, registry_id


_ENVIRONMENT_KEYS = {
    "implementation_name", "implementation_version", "os_name", "platform_machine",
    "platform_release", "platform_system", "platform_version",
    "python_full_version", "platform_python_implementation", "python_version", "sys_platform",
}
_MARKER_KEYS = _ENVIRONMENT_KEYS | {"extra", "extras", "dependency_groups"}


def target_environment_reasons(ctx: Context, environment: dict):
    """Check observed target identity without filling any fields from this host."""
    if not isinstance(environment, dict):
        return ["target-environment-not-a-mapping"]
    reasons = []
    missing = _ENVIRONMENT_KEYS - set(environment)
    if missing:
        reasons.append("target-environment-incomplete:" + ",".join(sorted(missing)))
    invalid = {key for key in _ENVIRONMENT_KEYS & set(environment) if not isinstance(environment[key], str)}
    if invalid:
        reasons.append("target-environment-invalid-values:" + ",".join(sorted(invalid)))
    try:
        requested = Version(str(ctx.python_version))
        actual = Version(environment.get("python_full_version", ""))
        if len(actual.release) < 3:
            reasons.append("target-python-patch-version-missing")
        if (len(requested.release) >= 3 and requested != actual) or requested.release[:2] != actual.release[:2]:
            reasons.append("target-python-does-not-match-request")
        if environment.get("python_version") != ".".join(map(str, actual.release[:2])):
            reasons.append("target-python-marker-fields-disagree")
    except (InvalidVersion, TypeError):
        reasons.append("target-python-version-not-evaluable")
    target = {
        "linux-x86_64": ("linux", "posix", "Linux", {"x86_64", "amd64"}),
        "linux-aarch64": ("linux", "posix", "Linux", {"aarch64", "arm64"}),
        "windows-x86_64": ("win32", "nt", "Windows", {"x86_64", "amd64"}),
        "macos-arm64": ("darwin", "posix", "Darwin", {"aarch64", "arm64"}),
    }.get(ctx.platform)
    if target is None:
        reasons.append("target-platform-unsupported")
    elif ((environment.get("sys_platform"), environment.get("os_name"), environment.get("platform_system")) != target[:3]
          or str(environment.get("platform_machine", "")).lower() not in target[3]):
        reasons.append("target-platform-does-not-match-request")
    return reasons


def _marker(expression, environment, extras):
    """Never let packaging supply an unspecified target field from this host."""
    if not expression:
        return True
    unquoted = re.sub(r"(['\"]).*?\1", "", str(expression))
    variables = set(re.findall(r"\b[A-Za-z_][A-Za-z_0-9]*\b", unquoted)) & _MARKER_KEYS
    supplied = set(environment) | {"extra", "extras"}
    if variables - supplied:
        return None
    try:
        marker = Marker(str(expression))
        return any(marker.evaluate({**environment, "extra": extra, "extras": frozenset(extras)},
                                   context="lock_file") for extra in (extras or {""}))
    except (InvalidMarker, KeyError, ValueError, TypeError):
        return None


def _source(source):
    from . import unproxy_index, unproxy_url
    if not isinstance(source, dict):
        return {"unsupported": repr(source)}
    return {key: (unproxy_index(value).rstrip("/") if key == "registry" else unproxy_url(value))
            if isinstance(value, str) else value for key, value in (source or {}).items()}


def _identity(package):
    return {"name": canonicalize_name(package["name"]), "version": package.get("version", ""),
            "source": _source(package.get("source"))}


def _version_equal(left, right):
    try:
        return Version(left) == Version(right)
    except (InvalidVersion, TypeError):
        return left == right


def _expression(edge, optional_extra=None):
    name = edge["name"]
    extras = edge.get("extra", edge.get("extras", [])) or []
    if extras:
        name += "[" + ",".join(sorted(extras)) + "]"
    name += edge.get("specifier", "")
    if edge.get("version") and not edge.get("specifier"):
        name += "==" + edge["version"]
    conditions = [edge["marker"]] if edge.get("marker") else []
    if optional_extra:
        conditions.append("extra == " + repr(optional_extra))
    return name + ("; " + " and ".join("(" + item + ")" for item in conditions) if conditions else "")


def _satisfies(requirement, package):
    try:
        return requirement.specifier.contains(package.get("version", ""), prereleases=True)
    except (InvalidVersion, TypeError):
        return False


def _artifact(packages, expressions, requested, verified):
    from . import artifact_from_url, unproxy_index, unproxy_url
    first = packages[0]
    source = first.get("source") or {}
    candidates = []
    for package in packages:
        entries = [("wheel", wheel) for wheel in package.get("wheels", [])]
        if package.get("sdist"):
            entries.append(("sdist", package["sdist"]))
        for kind, entry in entries:
            url = unproxy_url(entry.get("url", ""))
            digest = (entry.get("hash") or "").removeprefix("sha256:") or None
            candidate = artifact_from_url(package["name"], package.get("version", "?"), url, digest)
            candidates.append({"kind": kind, "url": url, "filename": candidate.filename,
                               "sha256": digest, "package_version": package.get("version", "?"),
                               "registry": registry_id(unproxy_index((package.get("source") or {}).get("registry", ""))),
                               "evidence": "uv-lock-candidate"})
        if not entries and len(packages) > 1:
            candidates.append({"package_version": package.get("version", "?"),
                               "source": _source(package.get("source")), "evidence": "uv-lock-fork"})
    registry = registry_id(unproxy_index(source["registry"])) if source.get("registry") else (
        "git" if "git" in source else "direct-url" if "url" in source else
        "local" if any(key in source for key in ("path", "directory", "editable")) else "?")
    artifact = Artifact(name=first["name"], version=first.get("version", "?"), url="", filename="",
                        kind="unselected", sha256=None, registry=registry, requested=requested,
                        requires_dist=sorted(set(expressions)), candidate_artifacts=candidates,
                        selection_evidence="uv-lock-candidates", selected_artifact_verified=False,
                        registry_verified=bool(source.get("registry")), registry_evidence="uv-lock-source-registry")
    if len(packages) > 1:
        artifact.selection_evidence = "uv-lock-fork-unverified"
        artifact.registry_verified = False
        artifact.registry_evidence = "uv-lock-forks; active source unverified"
    elif not verified:
        artifact.registry_evidence += "; target graph unverified"
    return artifact


def project_uv_lock(lock_data: dict, ctx: Context, marker_environment: dict | None = None):
    """Return artifacts and a certificate for the reachable, active lock nodes.

    Selected graph nodes remain unselected files. Unknown root requests, marker
    inputs and ambiguous identities are recorded rather than inferred from a
    filename or the machine performing this projection.
    """
    environment = dict(ctx.marker_environment or {})
    environment.update(marker_environment or {})
    reasons = target_environment_reasons(ctx, environment)
    excluded = []
    active_edges = []
    packages = lock_data.get("package", [])
    evidence = {"schema": "uv-lock-target-v1", "status": "unknown", "environment": environment,
                "selected": [], "excluded": excluded, "reasons": reasons, "active_edges": active_edges}
    if not isinstance(packages, list) or any(not isinstance(package, dict) or not package.get("name") for package in packages):
        reasons.append("malformed-lock-package-list")
        return {}, evidence
    by_name = defaultdict(list)
    for index, package in enumerate(packages):
        by_name[canonicalize_name(package["name"])].append(index)
    roots = by_name.get("drc-probe", [])
    if len(roots) != 1 or packages[roots[0]].get("source") != {"virtual": "."}:
        reasons.append("generated-request-root-missing-or-ambiguous")
        artifacts = {name: _artifact([packages[i] for i in indices], [], False, False)
                     for name, indices in by_name.items() if name != "drc-probe"}
        return artifacts, evidence
    root = roots[0]
    root_extras = {canonicalize_name(extra) for extra in (ctx.project_extras or [])}
    fork_extras = root_extras | {"drc-probe:" + extra for extra in root_extras}
    if packages[root].get("optional-dependencies") and ctx.project_extras is None:
        reasons.append("root-project-extras-unknown")
    for key in ("resolution-markers", "supported-markers"):
        if lock_data.get(key):
            outcomes = [_marker(marker, environment, fork_extras) for marker in lock_data[key]]
            if True not in outcomes:
                reasons.append("lock-" + key + "-not-proven-for-target")
    if lock_data.get("requires-python"):
        try:
            if not SpecifierSet(lock_data["requires-python"]).contains(environment.get("python_full_version", ""), prereleases=True):
                reasons.append("target-outside-lock-requires-python")
        except (InvalidSpecifier, InvalidVersion):
            reasons.append("lock-requires-python-not-evaluable")
    requests = []
    for text in ctx.requirements:
        try:
            request = Requirement(text)
        except (InvalidRequirement, TypeError):
            reasons.append("request-not-representable:" + str(text))
            continue
        applies = _marker(str(request.marker) if request.marker else "", environment, root_extras)
        if applies is None:
            reasons.append("request-marker-not-evaluable:" + str(request))
        if applies is not False:
            requests.append(request)
    requested_names = {canonicalize_name(request.name) for request in requests}
    requested_extras = defaultdict(set)
    for request in requests:
        requested_extras[canonicalize_name(request.name)].update(canonicalize_name(extra) for extra in request.extras)
    root_names = {canonicalize_name(edge["name"]) for edge in packages[root].get("dependencies", [])
                  if _marker(edge.get("marker"), environment, root_extras) is not False}
    for extra, edges in packages[root].get("optional-dependencies", {}).items():
        if canonicalize_name(extra) in root_extras:
            root_names.update(canonicalize_name(edge["name"]) for edge in edges
                              if _marker(edge.get("marker"), environment, root_extras) is not False)
    if requested_names != root_names:
        reasons.append("root-dependencies-do-not-match-request")

    selected = {root: root_extras}
    queue = deque([root])
    expressions = defaultdict(set)
    while queue:
        parent = queue.popleft()
        package = packages[parent]
        extras = selected[parent]
        edges = [(edge, None) for edge in package.get("dependencies", [])]
        for extra, dependencies in package.get("optional-dependencies", {}).items():
            if canonicalize_name(extra) in extras:
                edges.extend((edge, extra) for edge in dependencies)
        for edge, optional_extra in edges:
            if not isinstance(edge, dict) or not edge.get("name"):
                reasons.append("malformed-dependency-edge:" + package["name"])
                continue
            expression = _expression(edge, optional_extra)
            expressions[parent].add(expression)
            applies = _marker(edge.get("marker"), environment, extras)
            if applies is False:
                excluded.append({"parent": _identity(package), "dependency": expression, "reason": "inactive-marker"})
                continue
            if applies is None:
                reasons.append("dependency-marker-not-evaluable:" + package["name"] + ":" + expression)
            name = canonicalize_name(edge["name"])
            matches = []
            for index in by_name.get(name, []):
                child = packages[index]
                if edge.get("version") and not _version_equal(edge["version"], child.get("version")):
                    continue
                if edge.get("source") and _source(edge["source"]) != _source(child.get("source")):
                    continue
                conditions = child.get("resolution-markers", [])
                outcomes = [_marker(marker, environment, fork_extras) for marker in conditions]
                if conditions and all(value is False for value in outcomes):
                    continue
                if conditions and True not in outcomes:
                    reasons.append("package-fork-marker-not-evaluable:" + name)
                matches.append(index)
            if len(matches) != 1:
                reasons.append(("missing" if not matches else "ambiguous") + "-lock-identity:" + name)
            child_extras = {canonicalize_name(extra) for extra in edge.get("extra", edge.get("extras", [])) or []}
            for child in matches:
                if parent == root:
                    for request in requests:
                        if canonicalize_name(request.name) != name:
                            continue
                        if not _satisfies(request, packages[child]):
                            reasons.append("root-selected-version-outside-request:" + name)
                        if request.url and _source(packages[child].get("source")).get("url") != request.url:
                            reasons.append("root-selected-url-does-not-match-request:" + name)
                    if requested_extras[name] != child_extras:
                        reasons.append("root-selected-extras-do-not-match-request:" + name)
                active_edges.append({"parent": _identity(package), "dependency": expression, "target": _identity(packages[child])})
                previous = selected.get(child)
                if previous is None or not child_extras <= previous:
                    selected[child] = (previous or set()) | child_extras
                    queue.append(child)
    selected.pop(root)
    groups = defaultdict(list)
    for index in selected:
        groups[canonicalize_name(packages[index]["name"])].append(index)
    for name, indices in groups.items():
        if len(indices) > 1:
            reasons.append("multiple-active-lock-identities:" + name)
    for text in ctx.constraints:
        try:
            constraint = Requirement(text)
        except (InvalidRequirement, TypeError):
            reasons.append("constraint-not-representable:" + str(text))
            continue
        applies = _marker(str(constraint.marker) if constraint.marker else "", environment, root_extras)
        if applies is None:
            reasons.append("constraint-marker-not-evaluable:" + str(constraint))
        if applies is not False:
            for index in groups.get(canonicalize_name(constraint.name), []):
                if not _satisfies(constraint, packages[index]):
                    reasons.append("selected-version-outside-constraint:" + constraint.name)
    reasons[:] = list(dict.fromkeys(reasons))
    evidence["status"] = "verified" if not reasons else "unknown"
    evidence["selected"] = [{**_identity(packages[index]), "extras": sorted(extras)} for index, extras in selected.items()]
    evidence["requested_extras"] = sorted(root_extras)
    evidence["unreachable_names"] = sorted(set(by_name) - set(groups) - {"drc-probe"})
    artifacts = {name: _artifact([packages[i] for i in indices],
                                [value for i in indices for value in expressions[i]],
                                name in requested_names, not reasons)
                 for name, indices in groups.items()}
    return artifacts, evidence
