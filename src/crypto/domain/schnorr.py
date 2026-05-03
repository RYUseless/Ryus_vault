from abc import ABC, abstractmethod
from .models import OrProof, PublicKey


class SchnorrProtocol(ABC):

    @abstractmethod
    def generate_public_key(self, secret: int) -> PublicKey:
        """Odvodí EC veřejný klíč: secret * G"""
        ...

    @abstractmethod
    def generate_dummy_keypair(self) -> tuple[int, PublicKey]:
        """Server generuje dummy EC pár pro OR-Schnorr simulaci."""
        ...

    @abstractmethod
    def generate_or_proof(self, secret: int, real_pk: PublicKey, dummy_pk: PublicKey, username: str) -> OrProof:
        """Generuje OR-Schnorr proof — Fiat-Shamir non-interactive."""
        ...

    @abstractmethod
    def verify_or_proof(self, proof: OrProof, real_pk: PublicKey, dummy_pk: PublicKey, username: str) -> bool:
        """Ověří OR-Schnorr proof."""
        ...