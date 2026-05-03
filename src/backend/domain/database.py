from abc import ABC, abstractmethod


class Database(ABC):

    @abstractmethod
    def get_connection(self):
        """Vrátí aktivní DB spojení."""
        ...

    @abstractmethod
    def init_db(self) -> None:
        """Inicializuje schéma databáze."""
        ...