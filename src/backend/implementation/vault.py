from ..domain.vault import VaultRepository
from ..domain.models import VaultEntry
from .database import SQLiteDatabase


class VaultRepositoryImpl(VaultRepository):

    def __init__(self):
        self.db = SQLiteDatabase()

    def save_entry(self, entry: VaultEntry) -> None:
        with self.db.get_connection() as conn:
            conn.execute(
                """
                INSERT INTO vault_entries (id, owner_id, title, ciphertext, nonce)
                VALUES (?, ?, ?, ?, ?)
                """,
                (entry.id, entry.owner_id, entry.title,
                 entry.ciphertext.hex(),
                 entry.nonce.hex())
            )

    def find_entry(self, entry_id: str, owner_id: str) -> VaultEntry | None:
        with self.db.get_connection() as conn:
            row = conn.execute(
                "SELECT * FROM vault_entries WHERE id = ? AND owner_id = ?",
                (entry_id, owner_id)
            ).fetchone()

        if row is None:
            return None

        return VaultEntry(
            id=row["id"],
            owner_id=row["owner_id"],
            title=row["title"],
            ciphertext=bytes.fromhex(row["ciphertext"]),
            nonce=bytes.fromhex(row["nonce"])
        )

    def find_entries(self, owner_id: str) -> list[VaultEntry]:
        with self.db.get_connection() as conn:
            rows = conn.execute(
                "SELECT * FROM vault_entries WHERE owner_id = ?", (owner_id,)
            ).fetchall()

        return [
            VaultEntry(
                id=row["id"],
                owner_id=row["owner_id"],
                title=row["title"],
                ciphertext=bytes.fromhex(row["ciphertext"]),
                nonce=bytes.fromhex(row["nonce"])
            )
            for row in rows
        ]

    def delete_entry(self, entry_id: str, owner_id: str) -> None:
        with self.db.get_connection() as conn:
            conn.execute(
                "DELETE FROM vault_entries WHERE id = ? AND owner_id = ?",
                (entry_id, owner_id)
            )