from dataclasses import dataclass


@dataclass
class User:
    id: str
    username: str
    public_key: tuple[int, int]
    dummy_public_key: tuple[int, int]
    salt: bytes
    encrypted_secret: bytes


@dataclass
class VaultEntry:
    id: str
    owner_id: str
    title: str
    ciphertext: bytes
    nonce: bytes


@dataclass
class SessionToken:
    token: str
    user_id: str
    expires_at: int