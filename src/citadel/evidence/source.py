"""Anonymous, commit- and hash-pinned OurAirports input."""

import csv
import hashlib
import io
from pathlib import Path
from urllib.error import HTTPError
from urllib.request import urlopen
from .manifests import canonical_bytes, sha256

from . import (
    AIRPORT_FIELDS, COUNTRY_FIELDS, COUNTRIES, REGION_FIELDS, RUNWAY_FIELDS, EvidenceError,
)

SNAPSHOT = "a5a1ab8c3d9d57568c4bf9a7d398a23a60623830"
BASE_URL = f"https://raw.githubusercontent.com/davidmegginson/ourairports-data/{SNAPSHOT}"
SCOPED_ROWS_SHA256 = "139d693a56498e777861528f83a780c423455437ef983293b4c05dcbdff13a1a"
PINS = {
    "airports.csv": ("f219659218d1f27e7907c284b87778047b84102435d3483c7ee0ce6990b95e77", 12746366),
    "runways.csv": ("a1575b7885909a01824b33d69cfb9fc8f8acc106a19c192635e7a2bda464726f", 3969042),
    "countries.csv": ("2a9dbee691125b0cdb8ceb5fe227c48c903f99c488963b8e53e2ab366521c639", 24583),
    "regions.csv": ("9220d6582b804cfdec8432e5bb21456699c9df8969bf5d8886beb62ff0b1318b", 485265),
    "LICENSE": ("6b0382b16279f26ff69014300541967a356a666eb0b91b422f6862f6b7dad17e", 1211),
}


def source_manifest():
    return {
        "kind": "pinned-source", "schema_version": 1, "snapshot": SNAPSHOT,
        "repository": "https://github.com/davidmegginson/ourairports-data",
        "scoped_rows_sha256": SCOPED_ROWS_SHA256,
        "transformation_version": 1,
        "attribution": "OurAirports contributors; fictional comparison, source accuracy unverified.",
        "data_terms": {
            "url": "https://ourairports.com/data/",
            "statement": "OurAirports releases all data to the public domain.",
            "repository_license": "Unlicense",
            "license_evidence_file": "LICENSE",
        },
        "files": {
            name: {"url": f"{BASE_URL}/{name}", "sha256": digest, "bytes": size}
            for name, (digest, size) in PINS.items()
        },
    }


def _verify(name, content):
    digest, size = PINS[name]
    if len(content) != size or hashlib.sha256(content).hexdigest() != digest:
        raise EvidenceError("data_integrity", f"Pinned source hash/size mismatch: {name}")


def acquire_source(directory):
    """Acquire only approved URLs, verify before writing, never silently refresh."""
    from .preparation import _write_immutable

    directory = Path(directory)
    try:
        directory.mkdir(parents=True, exist_ok=True)
        for name, (_, size) in PINS.items():
            path = directory / name
            if path.exists():
                _verify(name, path.read_bytes())
                continue
            with urlopen(f"{BASE_URL}/{name}", timeout=30) as response:
                content = response.read(size + 1)
            _verify(name, content)
            _write_immutable(path, content)
    except HTTPError as exc:
        code = "forbidden" if exc.code in (401, 403) else "temporary_unavailability"
        raise EvidenceError(code, "Pinned source acquisition failed") from exc
    except PermissionError as exc:
        raise EvidenceError("forbidden", "Source acquisition access denied") from exc
    except OSError as exc:
        raise EvidenceError("temporary_unavailability", "Pinned source acquisition unavailable") from exc
    manifest = source_manifest()
    _write_immutable(directory / "source-manifest.json", canonical_bytes(manifest))
    return manifest


def read_source(directory):
    from .preparation import _read_json, _validate

    recorded_manifest = Path(directory) / "source-manifest.json"
    if recorded_manifest.exists():
        _validate(_read_json(recorded_manifest), source_manifest())
    content = {}
    for name in PINS:
        try:
            content[name] = (Path(directory) / name).read_bytes()
        except PermissionError as exc:
            raise EvidenceError("forbidden", f"Cannot read source file: {name}") from exc
        except OSError as exc:
            raise EvidenceError("temporary_unavailability", f"Source file unavailable: {name}") from exc
        _verify(name, content[name])
    tables = {}
    for name, fields in (
        ("airports", AIRPORT_FIELDS), ("runways", RUNWAY_FIELDS),
        ("countries", COUNTRY_FIELDS), ("regions", REGION_FIELDS),
    ):
        try:
            reader = csv.DictReader(io.StringIO(content[f"{name}.csv"].decode("utf-8-sig")), strict=True)
            headers = reader.fieldnames
            if not headers or len(headers) != len(set(headers)) or not set(fields) <= set(headers):
                raise EvidenceError("data_integrity", f"Invalid CSV header: {name}")
            tables[name] = []
            for row in reader:
                if None in row or any(row[field] is None for field in fields):
                    raise EvidenceError("data_integrity", f"Malformed CSV row: {name}")
                tables[name].append({field: row[field] for field in fields})
        except (UnicodeError, csv.Error) as exc:
            raise EvidenceError("data_integrity", f"Invalid CSV: {name}") from exc

    # Check full source structural keys before applying the geographic scope.
    for table, keys in (("airports", ("id", "ident")), ("runways", ("id",)),
                        ("countries", ("code",)), ("regions", ("code",))):
        for key in keys:
            values = [row[key] for row in tables[table]]
            if any(not value.strip() for value in values) or len(values) != len(set(values)):
                raise EvidenceError("data_integrity", f"Missing or duplicate source key: {table}.{key}")
    all_airports = {row["ident"]: row for row in tables["airports"]}
    for row in tables["runways"]:
        target = all_airports.get(row["airport_ident"])
        if target is None or row["airport_ref"] != target["id"]:
            raise EvidenceError("data_integrity", "Broken source runway identifier/ID join")

    tables["airports"] = [row for row in tables["airports"] if row["iso_country"] in COUNTRIES]
    idents = {row["ident"] for row in tables["airports"]}
    regions = {row["iso_region"] for row in tables["airports"]}
    tables["runways"] = [row for row in tables["runways"] if row["airport_ident"] in idents]
    tables["countries"] = [row for row in tables["countries"] if row["code"] in COUNTRIES]
    tables["regions"] = [row for row in tables["regions"] if row["code"] in regions]
    if sha256(tables) != SCOPED_ROWS_SHA256:
        raise EvidenceError("data_integrity", "Allowlisted source transformation differs from pinned version")
    return tables
