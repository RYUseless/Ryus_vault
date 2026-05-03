from abc import ABC, abstractmethod
from .models import VaultKey


class VaultCipher(ABC):

    @abstractmethod
    def derive_key(self, secret: int, salt: bytes) -> VaultKey:
        """Odvodí šifrovací klíč z master secret pomocí HKDF."""
        ...

    @abstractmethod
    def encrypt(self, plaintext: bytes, vault_key: VaultKey) -> tuple[bytes, bytes]:
        """AES-256-GCM šifrování. Vrací (ciphertext, nonce)."""
        ...

    @abstractmethod
    def decrypt(self, ciphertext: bytes, nonce: bytes, vault_key: VaultKey) -> bytes:
        """AES-256-GCM dešifrování."""
        ...