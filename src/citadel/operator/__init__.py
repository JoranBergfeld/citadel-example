"""Operator CLI public boundary; child diagnostics and private inputs never reach stdout."""

import argparse
import json
import sys

from citadel.evidence import EvidenceError, ReferenceData
from citadel.evidence.preparation import prepare_bundle
from .state import Blocked, State, read_private, public_output


class SafeParser(argparse.ArgumentParser):
    def error(self, message):
        raise Blocked("invalid_cli_arguments")


def parser():
    result = SafeParser(prog="python -m citadel.operator")
    commands = result.add_subparsers(dest="command", required=True)
    prepare = commands.add_parser("prepare")
    prepare.add_argument("--source-dir", required=True)
    prepare.add_argument("--bundle-dir", required=True)
    initialize = commands.add_parser("init")
    initialize.add_argument("--config", required=True)
    initialize.add_argument("--state-dir", required=True)
    observation = commands.add_parser("record-plan-observation")
    observation.add_argument("--state-dir", required=True)
    observation.add_argument("--observation", required=True)
    observation.add_argument("--evidence", required=True)
    for name in ("check", "preflight", "deploy", "inventory", "collect", "teardown", "acceptance"):
        command = commands.add_parser(name)
        command.add_argument("--state-dir", required=True)
        if name == "deploy":
            command.add_argument("--confirm-paid", action="store_true")
            command.add_argument("--wheelhouse")
        if name == "teardown":
            command.add_argument("--confirm-deployment")
        if name == "acceptance":
            command.add_argument("--run-id", default="full-acceptance")
    for name in ("demo", "status"):
        command = commands.add_parser(name)
        command.add_argument("--state-dir", required=True)
        command.add_argument("--run-id", required=True)
        if name == "demo":
            command.add_argument("scenario", choices=("comparison", "replacement", "exhaustion", "denied-bypass"))
    rotate = commands.add_parser("rotate")
    rotate.add_argument("kind", choices=("certificate", "subscription", "context"))
    rotate.add_argument("--stage", choices=("prepare", "finalize"), required=True)
    rotate.add_argument("--target")
    rotate.add_argument("--state-dir", required=True)
    revoke = commands.add_parser("revoke")
    revoke.add_argument("--caller", required=True)
    revoke.add_argument("--state-dir", required=True)
    return result


def main(argv=None, *, stdout=None, adapter=None):
    stdout = stdout or sys.stdout
    try:
        args = parser().parse_args(argv)
        if args.command == "prepare":
            manifest = prepare_bundle(args.source_dir, args.bundle_dir)
            data = ReferenceData.from_bundle(args.bundle_dir)
            gate = data.fixture_gate()
            result = {"status": "pass", "complete": gate["complete_count"], "bundle": manifest}
        elif args.command == "init":
            with State(args.state_dir).locked(create=True) as state:
                state.initialize(read_private(args.config))
                result = {"status": "initialized", "deploymentId": state.value["config"]["deploymentId"]}
        else:
            from .lifecycle import Lifecycle
            with State(args.state_dir).locked() as state:
                lifecycle = Lifecycle(state, adapter)
                try:
                    result = lifecycle.command(args)
                    credentials = (read_private(state.directory / "credentials.json")
                                   if (state.directory / "credentials.json").exists() else None)
                    result = public_output(result, lifecycle.config, credentials)
                except Blocked as exc:
                    state.event(args.command, exc.code)
                    raise
        print(json.dumps(result, sort_keys=True), file=stdout)
        return 1 if result.get("status") == "teardown_partial" else 0
    except Blocked as exc:
        result = {"status": "blocked", "code": exc.code}
        if exc.code == "api_center_portal_observation_required":
            result["nextStep"] = (
                "Open portalUrl in private STATE/api-center-plan-request.json; observe the actual plan, "
                "save private evidence, then use record-plan-observation. Resume deploy explicitly afterwards."
            )
        print(json.dumps(result), file=stdout)
        return 2
    except EvidenceError as exc:
        print(json.dumps({"status": "fail", "code": exc.code}), file=stdout)
        return 1
    except (OSError, ValueError, TypeError, KeyError):
        print(json.dumps({"status": "blocked", "code": "invalid_or_missing_private_input"}), file=stdout)
        return 2
    except KeyboardInterrupt:
        print(json.dumps({"status": "interrupted", "code": "reconcile_before_retry"}), file=stdout)
        return 130
    except Exception:
        print(json.dumps({"status": "fail", "code": "operator_operation_failed"}), file=stdout)
        return 1
