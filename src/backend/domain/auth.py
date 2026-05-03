from abc import ABC, abstractmethod
from .models import User


class AuthRepository(ABC):

    @abstractmethod
    def save_user(self, user: User) -> None:
        """Uloží nového uživatele do DB."""
        ...

    @abstractmethod
    def find_user(self, username: str) -> User | None:
        """Najde uživatele dle username. Vrací None pokud neexistuje."""
        ...