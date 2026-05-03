from dataclasses import dataclass
import os


@dataclass
class Settings:
    jwt_secret: str = os.getenv("JWT_SECRET", "change-me-in-production")
    db_path: str = os.getenv("DB_PATH", "data/vault.db")
    host: str = os.getenv("HOST", "0.0.0.0")
    port: int = int(os.getenv("PORT", "5000"))
    debug: bool = os.getenv("DEBUG", "false").lower() == "true"