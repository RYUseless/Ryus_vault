import os
from dataclasses import dataclass, field


@dataclass
class Settings:
    jwt_secret: str = field(default_factory=lambda: os.getenv("JWT_SECRET", ""))
    vault_master_secret: str = field(default_factory=lambda: os.getenv("VAULT_MASTER_SECRET", ""))
    host: str = field(default_factory=lambda: os.getenv("HOST", "0.0.0.0"))
    port: int = field(default_factory=lambda: int(os.getenv("PORT", "5000")))
    debug: bool = field(default_factory=lambda: os.getenv("DEBUG", "false").lower() == "true")