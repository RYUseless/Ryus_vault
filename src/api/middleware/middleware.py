import os
import base64
import jwt
import datetime
from functools import wraps
from flask import Flask, request, jsonify, g, abort
from flask_cors import CORS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from config.settings import Settings

def register_middleware(app: Flask, settings: Settings) -> None:
    CORS(app, supports_credentials=True, origins=[f"http://{settings.host}:{settings.port}"])

    Limiter(
        get_remote_address,
        app=app,
        default_limits=["200 per hour"],
        storage_uri="memory://"
    )

    @app.before_request
    def generate_nonce():
        g.csp_nonce = base64.b64encode(os.urandom(16)).decode()

    @app.after_request
    def set_csp_header(response):
        nonce = g.get("csp_nonce", "")
        response.headers["Content-Security-Policy"] = (
            f"default-src 'none'; "
            f"script-src 'nonce-{nonce}'; "
            f"style-src 'nonce-{nonce}'; "
            f"connect-src 'self'; "
            f"form-action 'self'; "
            f"img-src 'self' data:;"
        )
        return response

    @app.before_request
    def sanitize_request():
        if request.content_type and "application/json" not in request.content_type:
            if request.method in ["POST", "PUT", "PATCH"]:
                abort(400)
        content_length = request.content_length
        if content_length is not None and content_length > 1_048_576:
            abort(400)

def create_token(user_id: str, secret: str) -> str:
    payload = {
        "sub": user_id,
        "exp": datetime.datetime.now(datetime.UTC) + datetime.timedelta(hours=1),
        "iat": datetime.datetime.now(datetime.UTC)
    }
    return jwt.encode(payload, secret, algorithm="HS256")


def require_auth(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        from flask import current_app
        token = request.cookies.get("session")
        if not token:
            return jsonify({"error": "Unauthorized"}), 401
        try:
            payload = jwt.decode(token, current_app.config["JWT_SECRET"], algorithms=["HS256"])
            g.user_id = payload["sub"]
        except jwt.ExpiredSignatureError:
            return jsonify({"error": "Session expired"}), 401
        except jwt.InvalidTokenError:
            return jsonify({"error": "Unauthorized"}), 401
        return f(*args, **kwargs)
    return wrapper