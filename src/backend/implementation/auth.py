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
                INSERT INTO users (id, username, public_key_x, public_key_y, salt)
                VALUES (?, ?, ?, ?, ?)
                """,
                (
                    user.id,
                    user.username,
                    str(user.public_key[0]),
                    str(user.public_key[1]),
                    user.salt
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
            salt=row["salt"]
        )