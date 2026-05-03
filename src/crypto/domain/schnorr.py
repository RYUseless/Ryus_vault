from abc import ABC, abstractmethod
from .models import Commitment, Proof, PublicKey


class SchnorrProtocol(ABC):

    @abstractmethod
    def generate_public_key(self, secret: int) -> PublicKey:
        """Odvodí EC veřejný klíč: secret * G"""
        ...

    @abstractmethod
    def generate_proof(self, secret: int, public_key: PublicKey, username: str) -> Proof:
        """Fiat-Shamir Schnorr proof přes secp256k1."""
        ...

    @abstractmethod
    def verify_proof(self, proof: Proof, public_key: PublicKey, username: str) -> bool:
        """Ověří proof: s*G + c*PK == R"""
        ...