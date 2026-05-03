import uuid
from flask import Blueprint, request, jsonify, g
from pydantic import ValidationError
from backend.implementation.vault import VaultRepositoryImpl
from backend.domain.models import VaultEntry
from api.middleware.middleware import require_auth
from api.schemas.vault import CreateEntryRequest, EntryResponse, EntriesResponse

vault_bp = Blueprint("vault", __name__)
vault_repo = VaultRepositoryImpl()


@vault_bp.route("/entries", methods=["GET"])
@require_auth
def get_entries():
    entries = vault_repo.find_entries(g.user_id)
    response = EntriesResponse(entries=[
        EntryResponse(
            id=e.id,
            title=e.title,
            ciphertext=e.ciphertext.hex(),
            nonce=e.nonce.hex()
        ) for e in entries
    ])
    return jsonify(response.model_dump()), 200


@vault_bp.route("/entries", methods=["POST"])
@require_auth
def create_entry():
    try:
        req = CreateEntryRequest(**request.get_json())
    except ValidationError:
        return jsonify({"error": "Bad request"}), 400

    entry = VaultEntry(
        id=str(uuid.uuid4()),
        owner_id=g.user_id,
        title=req.title,
        ciphertext=bytes.fromhex(req.ciphertext),
        nonce=bytes.fromhex(req.nonce)
    )
    vault_repo.save_entry(entry)
    return jsonify({"message": "Created", "id": entry.id}), 201


@vault_bp.route("/entries/<entry_id>", methods=["GET"])
@require_auth
def get_entry(entry_id: str):
    entry = vault_repo.find_entry(entry_id, g.user_id)
    if not entry:
        return jsonify({"error": "Not found"}), 404
    response = EntryResponse(
        id=entry.id,
        title=entry.title,
        ciphertext=entry.ciphertext.hex(),
        nonce=entry.nonce.hex()
    )
    return jsonify(response.model_dump()), 200


@vault_bp.route("/entries/<entry_id>", methods=["DELETE"])
@require_auth
def delete_entry(entry_id: str):
    vault_repo.delete_entry(entry_id, g.user_id)
    return jsonify({"message": "Deleted"}), 200