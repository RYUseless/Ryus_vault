import hashlib
import os
from py_ecc.secp256k1 import secp256k1
from ..domain.schnorr import SchnorrProtocol
from ..domain.models import Commitment, Challenge, Proof, PublicKey

ORDER = secp256k1.N
BASE_POINT = secp256k1.G


class SchnorrProtocolImpl(SchnorrProtocol):

    def generate_public_key(self, secret: int) -> PublicKey:
        point = secp256k1.multiply(BASE_POINT, secret)
        if point is None:
            raise ValueError("Invalid secret")
        return PublicKey(point=point)

    def generate_proof(self, secret: int, public_key: PublicKey, username: str) -> Proof:
        r = int.from_bytes(os.urandom(32), "big") % ORDER
        r_point = secp256k1.multiply(BASE_POINT, r)
        if r_point is None:
            raise ValueError("Invalid nonce")
        commitment = Commitment(point=r_point)

        h = hashlib.sha256(
            f"{r_point[0]}{r_point[1]}{public_key.point[0]}{public_key.point[1]}{username}".encode()
        ).digest()
        challenge = Challenge(value=int.from_bytes(h, "big") % ORDER)
        response = (r - challenge.value * secret) % ORDER

        return Proof(commitment=commitment, challenge=challenge, response=response)

    def verify_proof(self, proof: Proof, public_key: PublicKey, username: str) -> bool:
        r_point = proof.commitment.point

        h = hashlib.sha256(
            f"{r_point[0]}{r_point[1]}{public_key.point[0]}{public_key.point[1]}{username}".encode()
        ).digest()
        expected_challenge = int.from_bytes(h, "big") % ORDER

        if expected_challenge != proof.challenge.value:
            return False

        lhs = secp256k1.add(
            secp256k1.multiply(BASE_POINT, proof.response),
            secp256k1.multiply(public_key.point, proof.challenge.value)
        )
        if lhs is None:
            return False

        return lhs == r_point