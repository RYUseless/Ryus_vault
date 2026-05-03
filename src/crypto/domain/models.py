from dataclasses import dataclass


@dataclass
class Commitment:
    point: tuple[int, int]


@dataclass
class Challenge:
    value: int


@dataclass
class Proof:
    commitment: Commitment
    challenge: Challenge
    response: int


@dataclass
class PublicKey:
    point: tuple[int, int]


@dataclass
class VaultKey:
    key: bytes
    salt: bytes