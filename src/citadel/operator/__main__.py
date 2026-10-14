import logging

from . import main

logging.disable(logging.CRITICAL)
raise SystemExit(main())
