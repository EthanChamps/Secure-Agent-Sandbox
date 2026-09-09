"""Independent watchdog entry point for the gVisor adapter's labelled containers."""

import argparse
import json

from secure_agent_sandbox.sandbox.gvisor import reap_expired


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--max-age-seconds", type=int, default=2400)
    arguments = parser.parse_args()
    print(json.dumps({"reaped": list(reap_expired(arguments.max_age_seconds))}))


if __name__ == "__main__":
    main()
