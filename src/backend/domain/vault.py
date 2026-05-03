from abc import ABC, abstractmethod
from .models import VaultEntry


class VaultRepository(ABC):

    @abstractmethod
    def save_entry(self, entry: VaultEntry) -> None:
        """Uloží nový záznam do vaultu."""
        ...

    @abstractmethod
    def find_entries(self, owner_id: str) -> list[VaultEntry]:
        """Vrátí všechny záznamy daného uživatele."""
        ...

    @abstractmethod
    def find_entry(self, entry_id: str, owner_id: str) -> VaultEntry | None:
        """Vrátí konkrétní záznam. Vrací None pokud neexistuje."""
        ...

    @abstractmethod
    def delete_entry(self, entry_id: str, owner_id: str) -> None:
        """Smaže záznam."""
        ...