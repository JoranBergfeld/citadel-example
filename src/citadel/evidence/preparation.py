"""Immutable local fixture bundles; no cloud storage or agent runtime."""

import hashlib
import json
import math
import os
import uuid
from pathlib import Path

from . import EvidenceError, ReferenceData
from .manifests import canonical_bytes, profile_manifest, sha256
from .source import SCOPED_ROWS_SHA256, SNAPSHOT, source_manifest

ARTIFACT_NAMES = frozenset({
    "source-manifest.json", "profile-manifest.json", "reference-data.json",
    "base-source-v1.json", "missing-width-replacement-v1.json", "no-alternative-v1.json",
    "gate-report.json",
})


def _read_bytes(path):
    try:
        return path.read_bytes()
    except PermissionError as exc:
        raise EvidenceError("forbidden", f"Access denied: {path.name}") from exc
    except OSError as exc:
        raise EvidenceError("temporary_unavailability", f"Artifact unavailable: {path.name}") from exc


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise EvidenceError("data_integrity", "Duplicate JSON object key")
        result[key] = value
    return result


def _reject_constant(value):
    raise EvidenceError("data_integrity", f"Non-JSON numeric literal: {value}")


def _finite_float(value):
    parsed = float(value)
    if not math.isfinite(parsed):
        raise EvidenceError("data_integrity", "Nonfinite JSON number")
    return parsed


def _read_json(path):
    try:
        return json.loads(_read_bytes(path), object_pairs_hook=_unique_object,
                          parse_constant=_reject_constant, parse_float=_finite_float)
    except (UnicodeError, ValueError) as exc:
        if isinstance(exc, EvidenceError):
            raise
        raise EvidenceError("data_integrity", f"Invalid JSON artifact: {path.name}") from exc


def _validate(actual, expected):
    if not isinstance(actual, dict):
        raise EvidenceError("data_integrity", "Expected a manifest object")
    for field in ("schema_version", "version"):
        if field in expected and (type(actual.get(field)) is not int or actual[field] != expected[field]):
            raise EvidenceError("unsupported_version", f"Unsupported manifest {field}")
    try:
        if canonical_bytes(actual) != canonical_bytes(expected):
            raise EvidenceError("data_integrity", "Manifest does not match its immutable contract")
    except (TypeError, ValueError) as exc:
        if isinstance(exc, EvidenceError):
            raise
        raise EvidenceError("data_integrity", "Manifest is not canonical JSON") from exc


def _write_immutable(path, content):
    """Publish one fully written local file without overwriting existing content."""
    pending = path.with_name(f".{path.name}.pending-{uuid.uuid4().hex}")
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        if path.exists():
            if path.read_bytes() != content:
                raise EvidenceError("data_integrity", f"Immutable artifact conflict: {path.name}")
            return
        with pending.open("xb") as stream:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        try:
            os.link(pending, path)
        except FileExistsError:
            if path.read_bytes() != content:
                raise EvidenceError("data_integrity", f"Immutable artifact conflict: {path.name}")
    except PermissionError as exc:
        raise EvidenceError("forbidden", f"Cannot publish artifact: {path.name}") from exc
    except OSError as exc:
        raise EvidenceError("temporary_unavailability", f"Artifact publication unavailable: {path.name}") from exc
    finally:
        if pending.exists():
            pending.unlink()


def _artifacts(data, rows):
    fixtures = data.fixture_manifests()
    return {
        "source-manifest.json": data.source_manifest,
        "profile-manifest.json": profile_manifest(),
        "reference-data.json": rows,
        "base-source-v1.json": data.fixture_manifest,
        **{f"{name}-v1.json": fixture for name, fixture in fixtures.items()},
        "gate-report.json": {
            "base": data.fixture_gate(),
            "fixtures": {
                name: data.with_overlay(fixture).select_candidates()
                for name, fixture in fixtures.items()
            },
        },
    }


def _bundle_manifest(artifacts):
    return {
        "kind": "citadel-evidence-bundle", "schema_version": 1, "snapshot": SNAPSHOT,
        "files": {name: sha256(value) for name, value in artifacts.items()},
    }


def prepare_bundle(source_directory, output_directory):
    """Gate the pinned source before publishing any allowlisted bundle artifacts."""
    data = ReferenceData.from_directory(source_directory)
    rows = data.export_rows()
    artifacts = _artifacts(data, rows)
    manifest = _bundle_manifest(artifacts)
    directory = Path(output_directory)
    for name, value in artifacts.items():
        _write_immutable(directory / name, canonical_bytes(value))
    _write_immutable(directory / "bundle-manifest.json", canonical_bytes(manifest))
    return manifest


def load_bundle(directory, *, fixture="base-source"):
    if not isinstance(fixture, str) or fixture not in ("base-source", "missing-width-replacement", "no-alternative"):
        raise EvidenceError("unsupported_version", "Unknown fixture identity")
    directory = Path(directory)
    manifest = _read_json(directory / "bundle-manifest.json")
    if not isinstance(manifest, dict):
        raise EvidenceError("data_integrity", "Expected a bundle manifest")
    if type(manifest.get("schema_version")) is not int or manifest["schema_version"] != 1:
        raise EvidenceError("unsupported_version", "Unsupported bundle schema version")
    if not isinstance(manifest.get("files"), dict) or set(manifest["files"]) != ARTIFACT_NAMES:
        raise EvidenceError("data_integrity", "Unexpected bundle artifact names")
    for name, digest in manifest["files"].items():
        if hashlib.sha256(_read_bytes(directory / name)).hexdigest() != digest:
            raise EvidenceError("data_integrity", f"Bundle artifact hash mismatch: {name}")
    source = _read_json(directory / "source-manifest.json")
    _validate(source, source_manifest())
    _validate(_read_json(directory / "profile-manifest.json"), profile_manifest())
    rows = _read_json(directory / "reference-data.json")
    if sha256(rows) != SCOPED_ROWS_SHA256:
        raise EvidenceError("data_integrity", "Bundle rows do not match the pinned allowlisted source")
    data = ReferenceData.from_rows(**rows)
    data._source_manifest = source
    data._fixture_manifest = data._base_fixture()
    expected = _artifacts(data, rows)
    for name in ARTIFACT_NAMES - {"reference-data.json"}:
        _validate(_read_json(directory / name), expected[name])
    _validate(manifest, _bundle_manifest(expected))
    return data if fixture == "base-source" else data.with_overlay(expected[f"{fixture}-v1.json"])
