from ..domain.auth import AuthRepository
from ..domain.models import User
from .database import SQLiteDatabase


class AuthRepositoryImpl(AuthRepository):

    def __init__(self):
        self.db = SQLiteDatabase()

    def save_user(self, user: User) -> None:
        with self.db.get_connection() as conn:
            conn.execute(
                """
                INSERT INTO users (id, username, public_key_x, public_key_y,
                                   dummy_public_key_x, dummy_public_key_y,
                                   salt, encrypted_secret)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    user.id,
                    user.username,
                    str(user.public_key[0]),
                    str(user.public_key[1]),
                    str(user.dummy_public_key[0]),
                    str(user.dummy_public_key[1]),
                    user.salt,
                    user.encrypted_secret
                )
            )

    def find_user(self, username: str) -> User | None:
        with self.db.get_connection() as conn:
            row = conn.execute(
                "SELECT * FROM users WHERE username = ?", (username,)
            ).fetchone()

        if row is None:
            return None

        return User(
            id=row["id"],
            username=row["username"],
            public_key=(int(row["public_key_x"]), int(row["public_key_y"])),
            dummy_public_key=(int(row["dummy_public_key_x"]), int(row["dummy_public_key_y"])),
            salt=row["salt"],
            encrypted_secret=row["encrypted_secret"]
        )

    def find_user_by_id(self, user_id: str) -> User | None:
        with self.db.get_connection() as conn:
            row = conn.execute(
                "SELECT * FROM users WHERE id = ?", (user_id,)
            ).fetchone()

        if row is None:
            return None

        return User(
            id=row["id"],
            username=row["username"],
            public_key=(int(row["public_key_x"]), int(row["public_key_y"])),
            dummy_public_key=(int(row["dummy_public_key_x"]), int(row["dummy_public_key_y"])),
            salt=row["salt"],
            encrypted_secret=row["encrypted_secret"]
        )