import os
import uuid
from flask import Blueprint, request, jsonify, make_response, current_app
from pydantic import ValidationError
from backend.implementation.auth import AuthRepositoryImpl
from backend.domain.models import User
from crypto.implementation.schnorr import SchnorrProtocolImpl
from crypto.implementation.vault_cipher import VaultCipherImpl
from crypto.domain.models import OrProof, OrProofBranch, ECPoint, PublicKey
from api.middleware.middleware import create_token
from api.schemas.auth import RegisterRequest, LoginRequest

auth_bp = Blueprint("auth", __name__)
auth_repo = AuthRepositoryImpl()
schnorr = SchnorrProtocolImpl()
cipher = VaultCipherImpl()


def _encrypt_secret(secret: int, master: bytes) -> bytes:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    nonce = os.urandom(12)
    aesgcm = AESGCM(master)
    ciphertext = aesgcm.encrypt(nonce, secret.to_bytes(32, "big"), None)
    return nonce + ciphertext


def _decrypt_secret(encrypted: bytes, master: bytes) -> int:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    nonce, ciphertext = encrypted[:12], encrypted[12:]
    aesgcm = AESGCM(master)
    return int.from_bytes(aesgcm.decrypt(nonce, ciphertext, None), "big")


@auth_bp.route("/init/<username>", methods=["GET"])
def init(username: str):
    user = auth_repo.find_user(username)
    if not user:
        _, dummy_pk = schnorr.generate_dummy_keypair()
        if dummy_pk.point is None:
            return jsonify({"error": "Internal error"}), 500
        return jsonify({
            "salt": os.urandom(32).hex(),
            "dummy_public_key_x": str(dummy_pk.point[0]),
            "dummy_public_key_y": str(dummy_pk.point[1])
        }), 200

    return jsonify({
        "salt": user.salt.hex(),
        "dummy_public_key_x": str(user.dummy_public_key[0]),
        "dummy_public_key_y": str(user.dummy_public_key[1])
    }), 200


@auth_bp.route("/register", methods=["POST"])
def register():
    try:
        req = RegisterRequest(**request.get_json())
    except ValidationError:
        return jsonify({"error": "Bad request"}), 400

    if auth_repo.find_user(req.username):
        return jsonify({"error": "User already exists"}), 409

    master = bytes.fromhex(current_app.config["VAULT_MASTER_SECRET"])
    encrypted_secret = _encrypt_secret(int(req.secret), master)

    _, dummy_pk = schnorr.generate_dummy_keypair()
    if dummy_pk.point is None:
        return jsonify({"error": "Internal error"}), 500

    user = User(
        id=str(uuid.uuid4()),
        username=req.username,
        public_key=(int(req.public_key_x), int(req.public_key_y)),
        dummy_public_key=dummy_pk.point,
        salt=bytes.fromhex(req.salt),
        encrypted_secret=encrypted_secret
    )
    auth_repo.save_user(user)

    return jsonify({
        "dummy_public_key_x": str(dummy_pk.point[0]),
        "dummy_public_key_y": str(dummy_pk.point[1])
    }), 201


@auth_bp.route("/login", methods=["POST"])
def login():
    try:
        req = LoginRequest(**request.get_json())
    except ValidationError:
        return jsonify({"error": "Bad request"}), 400

    user = auth_repo.find_user(req.username)
    if not user:
        return jsonify({"error": "Unauthorized"}), 401

    proof = OrProof(
        branch0=OrProofBranch(
            commitment=ECPoint(x=int(req.branch0.commitment_x), y=int(req.branch0.commitment_y)),
            challenge=int(req.branch0.challenge),
            response=int(req.branch0.response)
        ),
        branch1=OrProofBranch(
            commitment=ECPoint(x=int(req.branch1.commitment_x), y=int(req.branch1.commitment_y)),
            challenge=int(req.branch1.challenge),
            response=int(req.branch1.response)
        )
    )

    real_pk = PublicKey(point=user.public_key)
    dummy_pk = PublicKey(point=user.dummy_public_key)

    if not schnorr.verify_or_proof(proof, real_pk, dummy_pk, req.username):
        return jsonify({"error": "Unauthorized"}), 401

    token = create_token(user.id, current_app.config["JWT_SECRET"])
    resp = make_response(jsonify({"message": "OK"}), 200)
    resp.set_cookie("session", token, httponly=True, samesite="Strict")
    return resp


@auth_bp.route("/logout", methods=["POST"])
def logout():
    resp = make_response(jsonify({"message": "OK"}), 200)
    resp.delete_cookie("session")
    return resp