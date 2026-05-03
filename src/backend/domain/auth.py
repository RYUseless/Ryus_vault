from abc import ABC, abstractmethod
from .models import User


class AuthRepository(ABC):

    @abstractmethod
    def save_user(self, user: User) -> None:
        ...

    @abstractmethod
    def find_user(self, username: str) -> User | None:
        ...

    @abstractmethod
    def find_user_by_id(self, user_id: str) -> User | None:
        ...