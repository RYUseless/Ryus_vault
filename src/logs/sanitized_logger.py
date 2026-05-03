import logging
import re

BLACKLIST = re.compile(
    r"(password|secret|key|token|salt|private|credential|auth)",
    re.IGNORECASE
)

class SanitizedFormatter(logging.Formatter):

    def format(self, record: logging.LogRecord) -> str:
        msg = super().format(record)
        return BLACKLIST.sub("***", msg)


def get_logger(name: str) -> logging.Logger:
    logger = logging.getLogger(name)

    if not logger.handlers:
        handler = logging.StreamHandler()
        handler.setFormatter(SanitizedFormatter(
            fmt="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S"
        ))
        logger.addHandler(handler)
        logger.setLevel(logging.INFO)

    return logger