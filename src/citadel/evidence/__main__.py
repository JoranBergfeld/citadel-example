"""Local-only acquisition, fixture gate and immutable bundle preparation."""

import argparse
import json
import sys

from . import EvidenceError, ReferenceData
from .preparation import prepare_bundle
from .source import acquire_source


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    for command in ("acquire", "gate", "prepare"):
        subparser = commands.add_parser(command)
        subparser.add_argument("--source-dir", required=True)
        if command == "prepare":
            subparser.add_argument("--output-dir", required=True)
    verify = commands.add_parser("verify")
    verify.add_argument("--bundle-dir", required=True)
    verify.add_argument("--fixture", default="base-source")
    args = parser.parse_args(argv)
    try:
        if args.command == "acquire":
            result = acquire_source(args.source_dir)
        elif args.command == "gate":
            result = ReferenceData.from_directory(args.source_dir).fixture_gate()
        elif args.command == "prepare":
            result = prepare_bundle(args.source_dir, args.output_dir)
        else:
            result = ReferenceData.from_bundle(args.bundle_dir, fixture=args.fixture).select_candidates()
    except EvidenceError as exc:
        print(json.dumps({
            "error": {"code": exc.code, "message": str(exc)}, "provenance": exc.provenance,
        }), file=sys.stderr)
        return 1
    print(json.dumps(result, indent=2, sort_keys=True, ensure_ascii=False, allow_nan=False))
    return 2 if result.get("status") == "blocked" else 0


if __name__ == "__main__":
    raise SystemExit(main())
