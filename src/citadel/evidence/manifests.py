"""Canonical, versioned manifests. Hashes use UTF-8 canonical JSON."""

import hashlib
import json


def canonical_bytes(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
                      allow_nan=False).encode("utf-8")


def sha256(value):
    return hashlib.sha256(canonical_bytes(value)).hexdigest()


def profile_manifest():
    from . import AIRPORT_FIELDS, CAVEATS, COUNTRY_FIELDS, REGION_FIELDS, RUNWAY_FIELDS

    return {
        "kind": "comparison-profile",
        "schema_version": 1,
        "id": "fictional-airport-comparison",
        "version": 1,
        "countries": ["BE", "DE", "NL"],
        "types": ["small_airport", "medium_airport", "large_airport"],
        "order": ["iso_country", "ident"],
        "pool_limit": 20,
        "runway_limit": 50,
        "target_complete": 3,
        "fixture_required_complete": 4,
        "length_unit": "ft",
        "required_airport": ["id", "ident", "name", "type", "latitude_deg", "longitude_deg",
                             "iso_country", "iso_region"],
        "required_dimensions": ["country", "region"],
        "required_open_runway": ["length_ft", "width_ft", "surface", "lighted"],
        "unknown_closed_is_gap": True,
        "require_recorded_open_runway": True,
        "closed_runways_excluded_from_comparison": True,
        "unknown_surfaces": ["", "unknown", "unk", "n/a", "na", "?"],
        "source_flags": ["0", "1"],
        "dimensions_positive_finite": True,
        "latitude_range": [-90, 90],
        "longitude_range": [-180, 180],
        "mandatory_caveats": list(CAVEATS),
        "field_allowlists": {
            "airports": list(AIRPORT_FIELDS), "runways": list(RUNWAY_FIELDS),
            "countries": list(COUNTRY_FIELDS), "regions": list(REGION_FIELDS),
        },
    }
