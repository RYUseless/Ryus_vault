from abc import ABC, abstractmethod


class Memory(ABC):

    @abstractmethod
    def scrub_bytes(self, data: bytearray) -> None:
        """Přepíše citlivá data v paměti nulami."""
        ...

    @abstractmethod
    def scrub_int(self, value: int) -> None:
        """Přepíše integer v paměti."""
        ...