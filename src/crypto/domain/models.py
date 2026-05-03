from dataclasses import dataclass
from typing import Optional


@dataclass
class ECPoint:
    x: int
    y: int


@dataclass
class OrProofBranch:
    commitment: ECPoint
    challenge: int
    response: int


@dataclass
class OrProof:
    branch0: OrProofBranch
    branch1: OrProofBranch


@dataclass
class PublicKey:
    point: Optional[tuple[int, int]]


@dataclass
class VaultKey:
    key: bytes
    salt: bytes