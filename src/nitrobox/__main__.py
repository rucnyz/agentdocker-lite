"""CLI entry point: python -m nitrobox <command>."""

from __future__ import annotations

import argparse
import logging
import sys


def main() -> int:
    parser = argparse.ArgumentParser(
        prog="python -m nitrobox",
        description="nitrobox management utilities",
    )
    parser.add_argument(
        "-v", "--verbose", action="store_true", help="Enable debug logging"
    )
    sub = parser.add_subparsers(dest="command")

    # -- cleanup -----------------------------------------------------------
    cleanup_parser = sub.add_parser(
        "cleanup",
        help="Clean up orphaned sandboxes left by crashed processes",
    )
    import os as _os
    cleanup_parser.add_argument(
        "--env-base-dir",
        default=f"/tmp/nitrobox_{_os.getuid()}",
        help="Base directory for sandbox state (default: /tmp/nitrobox_<uid>)",
    )

    args = parser.parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(levelname)s %(name)s: %(message)s",
    )

    if args.command == "cleanup":
        from nitrobox.sandbox import Sandbox

        cleaned = Sandbox.cleanup_stale(env_base_dir=args.env_base_dir)
        print(f"Cleaned {cleaned} stale sandbox(es).")
        return 0

    parser.print_help()
    return 1


if __name__ == "__main__":
    sys.exit(main())
