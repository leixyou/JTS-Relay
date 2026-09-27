#!/usr/bin/env python3
"""Prepare, explicitly apply, or roll back reciprocal public-device admission.

Only named public inputs and the relay JSON are read. TLS key paths are never
opened. The relay process is never restarted by this tool. All configuration
writers must use the same admission lock while a candidate is published.
"""
import argparse
import json
import sys

from relay_admission_public import AdmissionError, public_input, require
from relay_admission_transaction import commit, prepare, read_regular


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", required=True, help="Absolute relay JSON path.")
    actions = parser.add_mutually_exclusive_group()
    actions.add_argument("--apply", metavar="MANIFEST", help="Explicitly publish this prepared transaction.")
    actions.add_argument("--rollback", metavar="MANIFEST", help="Restore its backup only if no later config change occurred.")
    controller = parser.add_mutually_exclusive_group()
    controller.add_argument("--controller-json", help="Mac public enrollmentRequest or generic public record JSON.")
    controller.add_argument("--controller-spki", help="P-256 public DER SPKI or canonical Base64 file; never a private key.")
    companion = parser.add_mutually_exclusive_group()
    companion.add_argument("--companion-json", help="Windows public enrollment bundle or generic public record JSON.")
    companion.add_argument("--companion-spki", help="P-256 public DER SPKI or canonical Base64 file; never a private key.")
    parser.add_argument("--output-dir", help="Existing directory for a new private transaction directory; default config directory.")
    args = parser.parse_args(argv)
    inputs = [args.controller_json, args.controller_spki, args.companion_json, args.companion_spki, args.output_dir]
    if args.apply or args.rollback:
        require(not any(inputs), "apply_does_not_accept_new_inputs")
        result = commit(args.config, args.apply or args.rollback, rollback=bool(args.rollback))
    else:
        require((args.controller_json or args.controller_spki) and (args.companion_json or args.companion_spki),
                "two_public_identities_required")
        records = []
        for role, json_path, spki_path in (("controller", args.controller_json, args.controller_spki),
                                           ("companion", args.companion_json, args.companion_spki)):
            raw, _ = read_regular(json_path or spki_path, limit=65536 if json_path else 1024)
            records.append(public_input(raw, role, is_json=bool(json_path)))
        result = prepare(args.config, *records, output_directory=args.output_dir)
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    try:
        main()
    except AdmissionError as error:
        print("relay_admission_failed:" + str(error), file=sys.stderr)
        sys.exit(1)
    except (OSError, ValueError, TypeError, KeyError, RecursionError):
        # No exception text, config contents, SPKI bytes, keys or secret paths in failure logs.
        print("relay_admission_failed:operator_io_or_manifest_error", file=sys.stderr)
        sys.exit(1)
