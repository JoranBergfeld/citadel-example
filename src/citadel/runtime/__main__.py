import argparse
import os

import uvicorn

from .configuration import Configuration
from .hosting import ProductionHost


def main():
    parser = argparse.ArgumentParser(description="Run one configured Citadel workload")
    parser.add_argument("--check-config", action="store_true",
                        help="Validate nonsecret shape/pins; does not prove deployed access")
    args = parser.parse_args()
    try:
        config = Configuration.from_environment(os.environ)
    except (ValueError, TypeError):
        parser.exit(2, "Invalid allocated runtime configuration\n")
    if args.check_config:
        print(f"{config.target}: configuration shape valid; cloud access unverified")
        return
    uvicorn.run(ProductionHost(config), host="0.0.0.0", port=8000, lifespan="on",
                access_log=False, log_level="warning")


if __name__ == "__main__":
    main()
