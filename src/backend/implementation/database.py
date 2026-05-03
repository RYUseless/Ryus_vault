import sqlite3
from pathlib import Path
from ..domain.database import Database

DB_PATH = Path(__file__).parent.parent.parent.parent / "data" / "vault.db"


class SQLiteDatabase(Database):

    def get_connection(self) -> sqlite3.Connection:
        DB_PATH.parent.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA foreign_keys=ON")
        return conn

    def init_db(self) -> None:
        with self.get_connection() as conn:
            conn.executescript("""
                CREATE TABLE IF NOT EXISTS users (
                    id TEXT PRIMARY KEY,
                    username TEXT UNIQUE NOT NULL,
                    public_key_x TEXT NOT NULL,
                    public_key_y TEXT NOT NULL,
                    salt BLOB NOT NULL
                );

                CREATE TABLE IF NOT EXISTS vault_entries (
                    id TEXT PRIMARY KEY,
                    owner_id TEXT NOT NULL,
                    title TEXT NOT NULL,
                    ciphertext TEXT NOT NULL,
                    nonce TEXT NOT NULL,
                    FOREIGN KEY (owner_id) REFERENCES users(id)
                );
            """)