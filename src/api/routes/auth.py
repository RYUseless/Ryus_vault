import uuid
from flask import Blueprint, request, jsonify, make_response, current_app
from pydantic import ValidationError
from backend.implementation.auth import AuthRepositoryImpl
from crypto.implementation.schnorr import SchnorrProtocolImpl
from crypto.domain.models import Proof, Commitment, Challenge, PublicKey
from backend.domain.models import User
from api.middleware.middleware import create_token
from api.schemas.auth import RegisterRequest, LoginRequest

auth_bp = Blueprint("auth", __name__)
auth_repo = AuthRepositoryImpl()
schnorr = SchnorrProtocolImpl()


@auth_bp.route("/register", methods=["POST"])
def register():
    try:
        req = RegisterRequest(**request.get_json())
    except ValidationError:
        return jsonify({"error": "Bad request"}), 400

    if auth_repo.find_user(req.username):
        return jsonify({"error": "User already exists"}), 409

    user = User(
        id=str(uuid.uuid4()),
        username=req.username,
        public_key=(int(req.public_key_x), int(req.public_key_y)),
        salt=bytes.fromhex(req.salt)
    )
    auth_repo.save_user(user)
    return jsonify({"message": "Registered"}), 201


@auth_bp.route("/salt/<username>", methods=["GET"])
def get_salt(username: str):
    user = auth_repo.find_user(username)
    if not user:
        return jsonify({"error": "Not found"}), 404
    return jsonify({
        "salt": user.salt.hex(),
        "public_key_x": str(user.public_key[0]),
        "public_key_y": str(user.public_key[1])
    }), 200


@auth_bp.route("/login", methods=["POST"])
def login():
    try:
        req = LoginRequest(**request.get_json())
    except ValidationError:
        return jsonify({"error": "Bad request"}), 400

    user = auth_repo.find_user(req.username)
    if not user:
        return jsonify({"error": "Unauthorized"}), 401

    print(f"DB public_key: {user.public_key}")
    print(f"commitment: ({req.commitment_x}, {req.commitment_y})")
    print(f"challenge: {req.challenge}")
    print(f"response: {req.response}")

    proof = Proof(
        commitment=Commitment(point=(req.commitment_x, req.commitment_y)),
        challenge=Challenge(value=req.challenge),
        response=req.response
    )

    result = schnorr.verify_proof(proof, PublicKey(point=user.public_key), req.username)
    print(f"verify result: {result}")

    if not result:
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