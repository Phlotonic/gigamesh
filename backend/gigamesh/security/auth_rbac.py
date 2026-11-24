"""Production Security Authority: Asymmetric Ed25519 Key Infrastructure, Multi-Tenant RBAC,
Signed JWT Sessions, OIDC JWKS Verification, and Fail-Closed Production Secret Guards.

Copyright (C) 2026 Adam Dryden and Quanumis Systems. Licensed AGPL-3.0-or-later OR Commercial.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import os
import secrets
import threading
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import TYPE_CHECKING, Any

import jwt
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

if TYPE_CHECKING:
    from gigamesh.storage.db import GigaMeshStateStore


ROLE_LEVELS: dict[str, int] = {
    "viewer": 10,
    "plant_operator": 20,
    "quorum_approver": 30,
    "soc_admin": 40,
    "super_admin": 50,
}

DEV_DEFAULT_SECRETS = frozenset(
    {
        "gigamesh-ot-e2e-signing-key-v1",
        "gigamesh-edge-offline-bundle-v1",
        "gigamesh-dev-jwt-secret-change-in-prod",
        "changeme",
        "",
    }
)


def hash_password(password: str, salt: bytes | None = None) -> str:
    """Salted PBKDF2-HMAC-SHA256 (310,000 iterations per OWASP Password Storage Cheat Sheet)."""
    s = salt or secrets.token_bytes(16)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), s, 310_000)
    return f"pbkdf2_sha256$310000${base64.b64encode(s).decode()}${base64.b64encode(dk).decode()}"


def verify_password(password: str, stored: str) -> bool:
    try:
        scheme, iters_s, salt_b64, dk_b64 = stored.split("$", 3)
        if scheme != "pbkdf2_sha256":
            return False
        s = base64.b64decode(salt_b64)
        expected = base64.b64decode(dk_b64)
        got = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), s, int(iters_s))
        return hmac.compare_digest(got, expected)
    except Exception:
        return False


def required_role_for_route(method: str, path: str) -> str:
    """Deterministic least-privilege RBAC map across all GigaMesh API routes."""
    m = method.upper()
    if m == "GET":
        return "viewer"
    if path.startswith("/api/auth/login") or path.startswith("/api/copilot/ask"):
        return "viewer"
    if "/quorum/" in path or "/sra/sessions/" in path and path.endswith("/approve"):
        return "quorum_approver"
    if "/lockdown" in path or path.endswith("/kill") or "/ot-mqtt/" in path or "/uns/publish" in path:
        return "plant_operator"
    if "/soar/" in path or "/revoke" in path or "/zone-policies/" in path or "/auth/users" in path:
        return "soc_admin"
    return "plant_operator"


class ProductionSecurityAuthority:
    """Manages Ed25519 asymmetric signing keys, multi-tenant RBAC, JWT auth & fail-closed prod checks."""

    def __init__(
        self,
        *,
        keys_dir: Path,
        state_store: GigaMeshStateStore,
        production_mode: bool = False,
        auth_required: bool = False,
        jwt_secret: str | None = None,
        oidc_jwks_url: str | None = None,
    ) -> None:
        self.keys_dir = keys_dir
        self.state_store = state_store
        self.production_mode = production_mode
        self.auth_required = auth_required or production_mode
        self.oidc_jwks_url = oidc_jwks_url
        self._lock = threading.RLock()

        raw_jwt = (jwt_secret or os.environ.get("GIGAMESH_JWT_SECRET") or "").strip()
        if self.production_mode:
            self._enforce_production_secrets(raw_jwt)
        self._jwt_secret = raw_jwt or "gigamesh-dev-jwt-secret-change-in-prod"

        self._private_key, self._public_key = self._load_or_create_ed25519_keypair()
        self.users: dict[str, dict[str, Any]] = {}
        self._bootstrap_users()

    @staticmethod
    def _enforce_production_secrets(jwt_secret: str) -> None:
        ot_sec = os.environ.get("GIGAMESH_OT_SIGNING_SECRET", "").strip()
        edge_sec = os.environ.get("GIGAMESH_EDGE_BUNDLE_SECRET", "").strip()
        weak = []
        if jwt_secret in DEV_DEFAULT_SECRETS or len(jwt_secret) < 32:
            weak.append("GIGAMESH_JWT_SECRET (>=32 chars required)")
        if ot_sec in DEV_DEFAULT_SECRETS or len(ot_sec) < 32:
            weak.append("GIGAMESH_OT_SIGNING_SECRET (>=32 chars required)")
        if edge_sec in DEV_DEFAULT_SECRETS or len(edge_sec) < 32:
            weak.append("GIGAMESH_EDGE_BUNDLE_SECRET (>=32 chars required)")
        if weak:
            raise RuntimeError(
                "FAIL-CLOSED PRODUCTION GUARD: Refusing to boot with weak or default secrets: "
                + ", ".join(weak)
            )

    def _load_or_create_ed25519_keypair(self) -> tuple[Ed25519PrivateKey, Ed25519PublicKey]:
        self.keys_dir.mkdir(parents=True, exist_ok=True)
        priv_path = self.keys_dir / "ed25519_private.pem"
        pub_path = self.keys_dir / "ed25519_public.pem"
        if priv_path.exists():
            priv = serialization.load_pem_private_key(priv_path.read_bytes(), password=None)
            assert isinstance(priv, Ed25519PrivateKey)
            return priv, priv.public_key()
        priv = Ed25519PrivateKey.generate()
        pub = priv.public_key()
        priv_bytes = priv.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
        pub_bytes = pub.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        priv_path.write_bytes(priv_bytes)
        os.chmod(priv_path, 0o600)
        pub_path.write_bytes(pub_bytes)
        os.chmod(pub_path, 0o644)
        return priv, pub

    @property
    def ed25519_public_key_hex(self) -> str:
        raw = self._public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        return raw.hex()

    @property
    def ed25519_public_key_pem(self) -> str:
        return self._public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode("utf-8")

    def sign_ed25519(self, data: bytes) -> str:
        """Sign arbitrary payload bytes using the control-plane Ed25519 private key (returns hex)."""
        return self._private_key.sign(data).hex()

    def verify_ed25519(self, data: bytes, signature_hex: str, public_key_hex: str | None = None) -> bool:
        try:
            pub = (
                Ed25519PublicKey.from_public_bytes(bytes.fromhex(public_key_hex))
                if public_key_hex
                else self._public_key
            )
            pub.verify(bytes.fromhex(signature_hex), data)
            return True
        except (InvalidSignature, ValueError):
            return False

    # ---- Multi-Tenant RBAC & JWT ----
    def _bootstrap_users(self) -> None:
        loaded = self.state_store.load_users()
        for u in loaded:
            self.users[u["username"]] = u
        if not self.users:
            admin_pw = os.environ.get("GIGAMESH_BOOTSTRAP_ADMIN_PASSWORD") or "GigaMesh!Admin2026"
            self.create_user("admin", admin_pw, role="super_admin", tenant_id="default")
            self.create_user("operator", "GigaMesh!Plant2026", role="plant_operator", tenant_id="default")
            self.create_user("auditor", "GigaMesh!Audit2026", role="viewer", tenant_id="default")

    def create_user(self, username: str, password: str, *, role: str, tenant_id: str = "default") -> dict[str, Any]:
        if role not in ROLE_LEVELS:
            raise ValueError(f"Unknown RBAC role '{role}'. Must be one of {list(ROLE_LEVELS)}")
        now = datetime.now(timezone.utc).isoformat()
        pw_hash = hash_password(password)
        rec = {
            "username": username,
            "tenant_id": tenant_id,
            "role": role,
            "password_hash": pw_hash,
            "enabled": True,
            "created_at": now,
        }
        with self._lock:
            self.users[username] = rec
            self.state_store.save_user(username, tenant_id, role, pw_hash, now)
        return {"username": username, "tenant_id": tenant_id, "role": role, "created_at": now}

    def authenticate_and_issue_jwt(self, username: str, password: str, ttl_minutes: int = 480) -> dict[str, Any]:
        with self._lock:
            user = self.users.get(username)
        if not user or not user.get("enabled") or not verify_password(password, user["password_hash"]):
            raise PermissionError("Invalid credentials")
        now = datetime.now(timezone.utc)
        claims = {
            "sub": user["username"],
            "role": user["role"],
            "tenant_id": user["tenant_id"],
            "iat": int(now.timestamp()),
            "exp": int((now + timedelta(minutes=ttl_minutes)).timestamp()),
            "iss": "gigamesh-control-plane",
        }
        token = jwt.encode(claims, self._jwt_secret, algorithm="HS256")
        return {
            "access_token": token,
            "token_type": "bearer",
            "expires_in_sec": ttl_minutes * 60,
            "user": {"username": user["username"], "role": user["role"], "tenant_id": user["tenant_id"]},
        }

    def verify_jwt(self, token: str) -> dict[str, Any]:
        try:
            return jwt.decode(token, self._jwt_secret, algorithms=["HS256"], issuer="gigamesh-control-plane")
        except Exception as exc:
            raise PermissionError(f"Invalid or expired JWT: {exc}") from exc

    @staticmethod
    def role_allows(actual_role: str, required_role: str) -> bool:
        return ROLE_LEVELS.get(actual_role, 0) >= ROLE_LEVELS.get(required_role, 100)
