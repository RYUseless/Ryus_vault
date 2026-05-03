import sys
import os

from flask.cli import load_dotenv

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "src"))
# bruh what?

from app import create_app
from config.settings import Settings
from logs.sanitized_logger import get_logger

logger = get_logger(__name__)

if __name__ == "__main__":
    load_dotenv()
    logger.info("Starting Ryus Vault")
    app = create_app()
    settings = Settings()
    logger.info(f"Running on {settings.host}:{settings.port}")
    app.run(host=settings.host, port=settings.port, debug=settings.debug)