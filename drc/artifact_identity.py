"""Bounded, read-only identity checks for a local wheel and optional core metadata.

No downloads, installation, extraction, imports from the wheel, or execution of
its contents occur here. A violation describes inconsistent local inputs, not a
resolver defect or malicious package. This is not a full wheel/RECORD validator.
"""
from __future__ import annotations

from dataclasses import dataclass, field, asdict
from email import policy
from email.parser import BytesParser
import hashlib
import io
from pathlib import Path, PurePosixPath
import re
import struct
from typing import Optional
import zipfile
import zlib

from packaging.markers import Marker
from packaging.requirements import Requirement, InvalidRequirement
from packaging.specifiers import SpecifierSet, InvalidSpecifier
from packaging.utils import canonicalize_name, parse_wheel_filename, InvalidName, InvalidWheelFilename
from packaging.version import Version, InvalidVersion


@dataclass(frozen=True)
class WheelVerificationLimits:
    max_archive_bytes: int = 64 * 1024 * 1024
    max_directory_bytes: int = 8 * 1024 * 1024
    max_entries: int = 4096
    max_entry_bytes: int = 32 * 1024 * 1024
    max_total_entry_bytes: int = 256 * 1024 * 1024
    max_metadata_bytes: int = 1024 * 1024
    max_requires_dist: int = 1024


@dataclass
class IdentityCheck:
    predicate: str
    status: str                   # pass | violation | unknown
    reason: str
    expected: object = None
    observed: object = None
    witness: Optional[dict] = None


@dataclass
class WheelIdentityCertificate:
    archive: dict = field(default_factory=dict)
    filename: dict = field(default_factory=dict)
    internal_metadata: dict = field(default_factory=dict)
    advertised_metadata: dict = field(default_factory=dict)
    checks: list[IdentityCheck] = field(default_factory=list)
    limits: dict = field(default_factory=dict)
    limitations: list[str] = field(default_factory=lambda: [
        "Local input consistency only; no resolver defect classification.",
        "No source-channel, publisher, installed-content, RECORD or program-behavior guarantee.",
        "Different expressions without a proved equality or distinguishing witness remain unknown.",
    ])

    @property
    def status(self):
        if any(c.status == "violation" for c in self.checks): return "violation"
        if not self.checks or any(c.status == "unknown" for c in self.checks): return "unknown"
        return "pass"

    @property
    def complete(self):
        return bool(self.checks) and not any(c.status == "unknown" for c in self.checks)

    def to_dict(self):
        return {
            "schema": "drc-local-wheel-identity-v1", "scope": "local-input-consistency",
            "resolver_defect_assessed": False, "status": self.status, "complete": self.complete,
            "archive": self.archive, "filename": self.filename,
            "internal_metadata": self.internal_metadata, "advertised_metadata": self.advertised_metadata,
            "checks": [asdict(c) for c in self.checks], "limits": self.limits,
            "limitations": list(self.limitations),
        }

    def check(self, predicate, status, reason, expected=None, observed=None, witness=None):
        self.checks.append(IdentityCheck(predicate, status, reason, expected, observed, witness))


def _version_witness(left, right):
    """A finite search can prove inequality, never universal equivalence."""
    probes = {"0", "1", "2.7", "3.7", "3.8", "3.9", "3.10", "3.11", "3.12", "3.13", "4", "10", "9999"}
    for specifier in list(left) + list(right):
        raw = specifier.version.removesuffix(".*")
        try: value = Version(raw)
        except InvalidVersion: continue
        probes.add(str(value))
        release = value.release
        if len(release) > 8: continue
        epoch = f"{value.epoch}!" if value.epoch else ""
        for index in range(len(release)):
            for delta in (-1, 0, 1):
                if release[index] + delta < 0: continue
                parts = list(release)
                parts[index] += delta
                base = epoch + ".".join(map(str, parts))
                probes.update(base + suffix for suffix in ("", ".post1", ".dev1", "a1", "rc1"))
    for raw in sorted(probes):
        try:
            a, b = left.contains(raw), right.contains(raw)
        except (InvalidVersion, ValueError): continue
        if a != b: return {"candidate_version": raw, "internal_accepts": a, "advertised_accepts": b}
    return None


def _marker_witness(expression):
    if not expression: return {}
    # Explicit example environments, not a guessed host/target environment.
    versions = ["3.8", "3.10", "3.12", "3.13", "2.7"]
    versions += re.findall(r"['\"](\d+\.\d+(?:\.\d+)?)['\"]", expression)
    extras = [""] + re.findall(r"\bextra\s*==\s*['\"]([^'\"]+)['\"]", expression)
    base = {"implementation_name": "cpython", "implementation_version": "3.12.0",
            "platform_release": "6.0", "platform_version": "1", "platform_python_implementation": "CPython"}
    marker = Marker(expression)
    for system, os_name, platform_system in (("linux", "posix", "Linux"), ("win32", "nt", "Windows"), ("darwin", "posix", "Darwin")):
        for py in dict.fromkeys(versions):
            for extra in dict.fromkeys(extras[:8]):
                env = {**base, "sys_platform": system, "os_name": os_name, "platform_system": platform_system,
                       "platform_machine": "x86_64", "python_version": ".".join(py.split(".")[:2]),
                       "python_full_version": py if len(py.split(".")) >= 3 else py + ".0", "extra": extra}
                try:
                    if marker.evaluate(env): return env
                except (KeyError, ValueError): return None
    return None


def _metadata(data, label, certificate, limits):
    predicate = label + ".parse"
    if not isinstance(data, bytes):
        certificate.check(predicate, "unknown", "metadata input must be bytes")
        return None
    view = {"sha256": hashlib.sha256(data).hexdigest(), "size_bytes": len(data)}
    if len(data) > limits.max_metadata_bytes:
        certificate.check(predicate, "unknown", "metadata byte limit exceeded")
        return view, None
    message = BytesParser(policy=policy.default).parsebytes(data, headersonly=True)
    errors = [type(defect).__name__ for defect in message.defects]
    for key in ("Name", "Version"):
        if len(message.get_all(key, [])) != 1: errors.append(key + " must occur exactly once")
    if len(message.get_all("Requires-Python", [])) > 1: errors.append("duplicate Requires-Python")
    try:
        view["name"] = canonicalize_name(str(message.get("Name", "")), validate=True)
        view["version"] = str(Version(str(message.get("Version", ""))))
        python = SpecifierSet(str(message.get("Requires-Python", "")))
        view["requires_python"] = str(python)
        values = message.get_all("Requires-Dist", [])
        if len(values) > limits.max_requires_dist:
            certificate.check(predicate, "unknown", "Requires-Dist count limit exceeded")
            return view, None
        groups = {}
        for value in values:
            requirement = Requirement(str(value))
            key = (canonicalize_name(requirement.name), tuple(sorted(canonicalize_name(e) for e in requirement.extras)),
                   requirement.url or "", str(requirement.marker or ""))
            groups.setdefault(key, set()).update(requirement.specifier)
        groups = {key: SpecifierSet(",".join(sorted(str(s) for s in specifiers))) for key, specifiers in groups.items()}
        view["requires_dist"] = [{"name": key[0], "extras": list(key[1]), "url": key[2], "marker": key[3],
                                  "specifier": str(specifiers)} for key, specifiers in sorted(groups.items())]
    except (InvalidName, InvalidVersion, InvalidSpecifier, InvalidRequirement, ValueError) as exc:
        errors.append(str(exc))
        groups, python = None, None
    if errors:
        certificate.check(predicate, "violation", "malformed or ambiguous core metadata", observed=errors)
        return view, None
    certificate.check(predicate, "pass", "required identity and dependency fields parsed")
    return view, (python, groups)


def _compare_dependencies(internal, advertised, certificate):
    if internal.keys() == advertised.keys():
        differences = [key for key in internal if internal[key] != advertised[key]]
        if not differences:
            certificate.check("requires_dist.correspondence", "pass", "canonical dependency declarations agree")
            return
        for key in differences:
            version = _version_witness(internal[key], advertised[key])
            environment = _marker_witness(key[3])
            if version is not None and environment is not None:
                certificate.check("requires_dist.correspondence", "violation", "dependency constraints accept different versions",
                                  witness={"dependency": key[0], "extras": list(key[1]), "environment": environment, **version})
                return
    else:
        # An active dependency identity wholly absent from the other document is
        # a concrete distinguishing declaration; reordered marker syntax is not.
        for own, other, side in ((internal, advertised, "internal"), (advertised, internal, "advertised")):
            identities = {(key[0], key[1], key[2]) for key in other}
            for key in own:
                if (key[0], key[1], key[2]) not in identities:
                    environment = _marker_witness(key[3])
                    if environment is not None:
                        certificate.check("requires_dist.correspondence", "violation", "active dependency identity differs",
                                          witness={"present_in": side, "dependency": key[0], "extras": list(key[1]),
                                                   "url": key[2], "environment": environment})
                        return
    certificate.check("requires_dist.correspondence", "unknown", "different dependency expressions; equivalence or a distinguishing witness not established")


def _directory_bounds(data, limits):
    """Bound central-directory work before ZipFile constructs one object per entry."""
    tail = data[-65557:]
    offset = tail.rfind(b"PK\x05\x06")
    while offset >= 0:
        if len(tail) - offset >= 22:
            comment_size = struct.unpack_from("<H", tail, offset + 20)[0]
            if offset + 22 + comment_size == len(tail): break
        offset = tail.rfind(b"PK\x05\x06", 0, offset)
    if offset < 0: raise zipfile.BadZipFile("missing end-of-directory record")
    _, disk, cd_disk, local_count, count, size, start, comment = struct.unpack_from("<4s4H2IH", tail, offset)
    if offset + 22 + comment != len(tail): raise zipfile.BadZipFile("invalid end-of-directory/comment boundary")
    if disk or cd_disk or local_count != count: raise ValueError("multi-disk ZIP is outside verification scope")
    if count == 65535 or size == 0xFFFFFFFF or start == 0xFFFFFFFF: raise ValueError("ZIP64 directory is outside bounded verification scope")
    if count > limits.max_entries or size > limits.max_directory_bytes: raise ValueError("archive directory limit exceeded")
    if start + size > len(data) - len(tail) + offset: raise zipfile.BadZipFile("directory overlaps end record")
    directory = data[start:start + size]
    pos = found = 0
    while pos < len(directory):
        if directory[pos:pos + 4] != b"PK\x01\x02" or pos + 46 > len(directory):
            raise zipfile.BadZipFile("invalid central directory entry")
        name, extra, comment = struct.unpack_from("<3H", directory, pos + 28)
        pos += 46 + name + extra + comment
        found += 1
        if found > limits.max_entries: raise ValueError("archive entry count limit exceeded")
    if pos != len(directory) or found != count: raise zipfile.BadZipFile("central directory entry count/length mismatch")


def verify_local_wheel(path, expected_sha256=None, advertised_metadata=None, *, limits=None):
    """Return a JSON-serializable certificate for one exact, bounded local file.

    ``None`` expected hash or sidecar produces unknown/incomplete evidence while
    still computing the local archive digest and inspecting available identities.
    No result asserts a resolver bug, source provenance or behavioral equivalence.
    """
    limits = limits or WheelVerificationLimits()
    certificate = WheelIdentityCertificate(limits=asdict(limits))
    if any(not isinstance(value, int) or value <= 0 for value in certificate.limits.values()):
        certificate.check("limits", "unknown", "verification limits must be positive integers")
        return certificate
    local = Path(path)
    certificate.archive["path"] = str(local.absolute())
    try:
        with local.open("rb") as stream: data = stream.read(limits.max_archive_bytes + 1)
    except OSError as exc:
        certificate.check("archive.read", "unknown", "local archive could not be read", observed=str(exc))
        return certificate
    certificate.archive["size_bytes"] = len(data)
    if len(data) > limits.max_archive_bytes:
        certificate.archive.update(size_is_lower_bound=True, sha256=None)
        certificate.check("archive.read", "unknown", "archive byte limit exceeded; complete digest not computed")
        return certificate
    digest = hashlib.sha256(data).hexdigest()
    certificate.archive.update(sha256=digest, size_is_lower_bound=False)
    expected = expected_sha256.strip().lower().removeprefix("sha256:") if isinstance(expected_sha256, str) else None
    certificate.archive["expected_sha256"] = expected
    if expected is None:
        certificate.check("archive.sha256", "unknown", "expected archive SHA-256 not supplied", observed=digest)
    elif not re.fullmatch("[0-9a-f]{64}", expected):
        certificate.check("archive.sha256", "unknown", "expected archive SHA-256 is malformed", expected=expected, observed=digest)
    else:
        certificate.check("archive.sha256", "pass" if digest == expected else "violation",
                          "archive digest agrees" if digest == expected else "archive digest differs from expected input", expected, digest)
    try:
        name, version, build, tags = parse_wheel_filename(local.name)
        certificate.filename = {"filename": local.name, "name": name, "version": str(version), "build": list(build), "tags": sorted(map(str, tags))}
        certificate.check("filename.parse", "pass", "wheel filename identity parsed")
    except (InvalidWheelFilename, InvalidVersion, ValueError) as exc:
        certificate.filename = {"filename": local.name}
        certificate.check("filename.parse", "violation", "invalid wheel filename", observed=str(exc))
    try:
        _directory_bounds(data, limits)
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            entries = archive.infolist()
            if any(i.file_size > limits.max_entry_bytes for i in entries) or sum(i.file_size for i in entries) > limits.max_total_entry_bytes:
                raise ValueError("uncompressed archive entry size limit exceeded")
            names = [i.filename for i in entries]
            metadata = [i for i in entries if len(PurePosixPath(i.filename).parts) == 2 and i.filename.split("/")[0].endswith(".dist-info") and i.filename.endswith("/METADATA")]
            if len(names) != len(set(names)) or len(metadata) != 1:
                certificate.check("archive.metadata_entry", "violation", "duplicate entries or missing/multiple root METADATA entries", observed=[i.filename for i in metadata])
                certificate.check("internal.parse", "unknown", "ambiguous archive metadata was not read")
                return certificate
            info = metadata[0]
            certificate.archive["metadata_entry"] = info.filename
            if info.file_size > limits.max_metadata_bytes: raise ValueError("METADATA entry size limit exceeded")
            with archive.open(info) as stream: core = stream.read(limits.max_metadata_bytes + 1)
            if len(core) > limits.max_metadata_bytes: raise ValueError("METADATA decompression limit exceeded")
            certificate.check("archive.metadata_entry", "pass", "one bounded root METADATA entry inspected; no extraction")
    except (zipfile.BadZipFile, EOFError, struct.error, zlib.error) as exc:
        certificate.check("archive.structure", "violation", "malformed ZIP archive", observed=str(exc))
        certificate.check("internal.parse", "unknown", "archive metadata could not be inspected")
        return certificate
    except (ValueError, RuntimeError, NotImplementedError, OSError) as exc:
        certificate.check("archive.inspection", "unknown", "bounded ZIP inspection incomplete", observed=str(exc))
        return certificate
    parsed = _metadata(core, "internal", certificate, limits)
    if parsed is None: return certificate
    certificate.internal_metadata, internal = parsed
    if internal is not None and certificate.filename.get("name"):
        for key in ("name", "version"):
            left, right = certificate.filename[key], certificate.internal_metadata[key]
            equal = left == right if key == "name" else Version(left) == Version(right)
            certificate.check("filename_internal." + key, "pass" if equal else "violation", "canonical filename and internal metadata identity comparison", left, right)
    else:
        certificate.check("filename_internal.identity", "unknown", "filename or internal identity could not be parsed")
    if advertised_metadata is None:
        certificate.check("advertised.correspondence", "unknown", "advertised core metadata not supplied")
        return certificate
    parsed = _metadata(advertised_metadata, "advertised", certificate, limits)
    if parsed is None: return certificate
    certificate.advertised_metadata, advertised = parsed
    if internal is None or advertised is None:
        certificate.check("advertised.correspondence", "unknown", "at least one metadata document could not be parsed")
        return certificate
    for key in ("name", "version"):
        left, right = certificate.internal_metadata[key], certificate.advertised_metadata[key]
        equal = left == right if key == "name" else Version(left) == Version(right)
        certificate.check("internal_advertised." + key, "pass" if equal else "violation", "canonical internal and advertised identity comparison", left, right)
    python_left, requirements_left = internal
    python_right, requirements_right = advertised
    if python_left == python_right:
        certificate.check("requires_python.correspondence", "pass", "normalized Python constraints agree")
    else:
        witness = _version_witness(python_left, python_right)
        certificate.check("requires_python.correspondence", "violation" if witness else "unknown",
                          "Python constraints accept different versions" if witness else "Python constraint equivalence not established", witness=witness)
    _compare_dependencies(requirements_left, requirements_right, certificate)
    return certificate
