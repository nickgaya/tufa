import logging

from .cli import create_parser
from .commands import do_command
from .exceptions import TufaError

logger = logging.getLogger(__name__)


def _init_logging(args):
    """Initialize logging subsystem."""
    logging.basicConfig(level=logging.INFO)
    if args.debug:
        logger.setLevel(logging.DEBUG)


def main():
    parser = create_parser()
    args = parser.parse_args()
    _init_logging(args)
    try:
        do_command(args)
    except TufaError as e:
        logger.error("%s", e, exc_info=args.debug)
        if e.info:
            logger.info(e.info)
        return e.rc
    except KeyboardInterrupt:
        logger.info("Interrupted", exc_info=args.debug)
        return 1
