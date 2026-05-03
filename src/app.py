import os
import secrets
from pathlib import Path

from flask import Flask
from config.settings import Settings
from api.errors.handlers import register_error_handlers
from api.middleware.middleware import register_middleware
from api.routes.auth import auth_bp
from api.routes.vault import vault_bp
from api.routes.web import web_bp
from backend.implementation.database import SQLiteDatabase
from logs.sanitized_logger import get_logger

logger = get_logger(__name__)


def create_app() -> Flask:
    app = Flask(__name__, template_folder="web/templates", static_folder="web/static")
    env_path = Path(__file__).parent.parent / ".env"

    if not os.getenv("JWT_SECRET"):
        jwt_secret = secrets.token_hex(32)
        with open(env_path, "a") as f:
            f.write(f"\nJWT_SECRET={jwt_secret}\n")
        os.environ["JWT_SECRET"] = jwt_secret
        logger.info("Generated new JWT_SECRET")

    if not os.getenv("VAULT_MASTER_SECRET"):
        vault_master_secret = secrets.token_hex(32)
        with open(env_path, "a") as f:
            f.write(f"\nVAULT_MASTER_SECRET={vault_master_secret}\n")
        os.environ["VAULT_MASTER_SECRET"] = vault_master_secret
        logger.info("Generated new VAULT_MASTER_SECRET")

    settings = Settings()
    app.config["JWT_SECRET"] = settings.jwt_secret
    app.config["VAULT_MASTER_SECRET"] = settings.vault_master_secret

    logger.info("Initializing database")
    db = SQLiteDatabase()
    db.init_db()

    logger.info("Registering middleware")
    register_middleware(app, settings)
    register_error_handlers(app)

    logger.info("Registering blueprints")
    app.register_blueprint(web_bp)
    app.register_blueprint(auth_bp, url_prefix="/api/auth")
    app.register_blueprint(vault_bp, url_prefix="/api/vault")

    logger.info("App ready")
    return app

if __name__ == "__main__":
    app = create_app()
    settings = Settings()
    app.run(host=settings.host, port=settings.port, debug=settings.debug)