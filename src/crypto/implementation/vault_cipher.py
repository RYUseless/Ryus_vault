import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from ..domain.vault_cipher import VaultCipher
from ..domain.models import VaultKey


class VaultCipherImpl(VaultCipher):

    def derive_key(self, secret: int, salt: bytes) -> VaultKey:
        secret_bytes = secret.to_bytes(256, "big")
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            info=b"ryus-vault-key"
        )
        key = hkdf.derive(secret_bytes)
        return VaultKey(key=key, salt=salt)

    def encrypt(self, plaintext: bytes, vault_key: VaultKey) -> tuple[bytes, bytes]:
        nonce = os.urandom(12)
        aesgcm = AESGCM(vault_key.key)
        ciphertext = aesgcm.encrypt(nonce, plaintext, None)
        return ciphertext, nonce

    def decrypt(self, ciphertext: bytes, nonce: bytes, vault_key: VaultKey) -> bytes:
        aesgcm = AESGCM(vault_key.key)
        return aesgcm.decrypt(nonce, ciphertext, None)