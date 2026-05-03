import hashlib
import os
from py_ecc.secp256k1 import secp256k1
from ..domain.schnorr import SchnorrProtocol
from ..domain.models import OrProof, OrProofBranch, ECPoint, PublicKey

ORDER = secp256k1.N
BASE_POINT = secp256k1.G


class SchnorrProtocolImpl(SchnorrProtocol):

    def generate_public_key(self, secret: int) -> PublicKey:
        point = secp256k1.multiply(BASE_POINT, secret)
        if point is None:
            raise ValueError("Invalid secret")
        return PublicKey(point=point)

    def generate_dummy_keypair(self) -> tuple[int, PublicKey]:
        dummy_secret = int.from_bytes(os.urandom(32), "big") % ORDER
        point = secp256k1.multiply(BASE_POINT, dummy_secret)
        if point is None:
            raise ValueError("Invalid dummy secret")
        return dummy_secret, PublicKey(point=point)

    def generate_or_proof(self, secret: int, real_pk: PublicKey, dummy_pk: PublicKey, username: str) -> OrProof:
        if real_pk.point is None or dummy_pk.point is None:
            raise ValueError("Invalid public keys")

        # Simuluj dummy větev (branch1) — vyber náhodné c1, s1
        c1 = int.from_bytes(os.urandom(32), "big") % ORDER
        s1 = int.from_bytes(os.urandom(32), "big") % ORDER

        # R1 = s1*G + c1*dummy_pk  ← zpětně vypočítaný commitment pro simulaci
        r1 = secp256k1.add(
            secp256k1.multiply(BASE_POINT, s1),
            secp256k1.multiply(dummy_pk.point, c1)
        )
        if r1 is None:
            raise ValueError("Invalid dummy branch")

        # Real větev (branch0) — náhodný nonce
        r = int.from_bytes(os.urandom(32), "big") % ORDER
        r0 = secp256k1.multiply(BASE_POINT, r)
        if r0 is None:
            raise ValueError("Invalid nonce")

        # c_total = H(R0 || R1 || real_pk || dummy_pk || username)
        h = hashlib.sha256(
            f"{r0[0]}{r0[1]}{r1[0]}{r1[1]}"
            f"{real_pk.point[0]}{real_pk.point[1]}"
            f"{dummy_pk.point[0]}{dummy_pk.point[1]}"
            f"{username}".encode()
        ).digest()
        c_total = int.from_bytes(h, "big") % ORDER

        # c0 = c_total - c1 mod ORDER
        c0 = (c_total - c1) % ORDER

        # s0 = r - c0 * secret mod ORDER
        s0 = (r - c0 * secret) % ORDER

        return OrProof(
            branch0=OrProofBranch(commitment=ECPoint(x=r0[0], y=r0[1]), challenge=c0, response=s0),
            branch1=OrProofBranch(commitment=ECPoint(x=r1[0], y=r1[1]), challenge=c1, response=s1)
        )

    def verify_or_proof(self, proof: OrProof, real_pk: PublicKey, dummy_pk: PublicKey, username: str) -> bool:
        if real_pk.point is None or dummy_pk.point is None:
            return False

        r0 = (proof.branch0.commitment.x, proof.branch0.commitment.y)
        r1 = (proof.branch1.commitment.x, proof.branch1.commitment.y)

        h = hashlib.sha256(
            f"{r0[0]}{r0[1]}{r1[0]}{r1[1]}"
            f"{real_pk.point[0]}{real_pk.point[1]}"
            f"{dummy_pk.point[0]}{dummy_pk.point[1]}"
            f"{username}".encode()
        ).digest()
        c_total = int.from_bytes(h, "big") % ORDER

        if (proof.branch0.challenge + proof.branch1.challenge) % ORDER != c_total:
            return False

        lhs0 = secp256k1.add(
            secp256k1.multiply(BASE_POINT, proof.branch0.response),
            secp256k1.multiply(real_pk.point, proof.branch0.challenge)
        )
        if lhs0 is None or lhs0 != r0:
            return False

        lhs1 = secp256k1.add(
            secp256k1.multiply(BASE_POINT, proof.branch1.response),
            secp256k1.multiply(dummy_pk.point, proof.branch1.challenge)
        )
        if lhs1 is None or lhs1 != r1:
            return False

        return True