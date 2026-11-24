"""Hardened FastAPI Security Perimeter Middleware (OWASP Web Top 10:2025 A01, A02, A06, A07, A09, A10).

Copyright (C) 2026 Adam Dryden and Quanumis Systems. Licensed AGPL-3.0-or-later OR Commercial.
"""

from __future__ import annotations

import hmac
import threading
import time
from collections import deque
from typing import TYPE_CHECKING, Any
from uuid import uuid4

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware

if TYPE_CHECKING:
    from gigamesh.engine import GigaMeshEngine


DEFAULT_CSP = (
    "default-src 'self'; "
    "script-src 'self'; "
    "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
    "font-src 'self' https://fonts.gstatic.com data:; "
    "img-src 'self' data:; "
    "connect-src 'self' ws: wss:; "
    "frame-ancestors 'none'; "
    "base-uri 'self'; "
    "form-action 'self'"
)


class SlidingWindowRateLimiter:
    """Thread-safe per-client sliding-window HTTP rate limiter."""

    def __init__(self, limit_per_minute: int = 240, window_sec: float = 60.0) -> None:
        self.limit = limit_per_minute
        self.window_sec = window_sec
        self._lock = threading.Lock()
        self._buckets: dict[str, deque[float]] = {}

    def allow(self, client_key: str) -> tuple[bool, int]:
        now = time.monotonic()
        cutoff = now - self.window_sec
        with self._lock:
            q = self._buckets.setdefault(client_key, deque())
            while q and q[0] < cutoff:
                q.popleft()
            if len(q) >= self.limit:
                return False, 0
            q.append(now)
            return True, max(0, self.limit - len(q))


class SecurityHardeningMiddleware(BaseHTTPMiddleware):
    """Applies OWASP Web 2025 defense-in-depth controls to every HTTP request/response:
    - A02: CSP, X-Content-Type-Options, X-Frame-Options, Referrer-Policy, Permissions-Policy, HSTS, Cache-Control
    - A06: Max request body size cap (413) + sliding-window rate limiting (429 + X-RateLimit-* headers)
    - A07: Constant-time API key authentication on mutating routes when `api_auth_key` is configured
    - A09: Records all security rejections into the SHA-256 hash-chained SecurityAuditLog
    - A10: Fail-closed error handling with zero stack-trace or internal path disclosure
    """

    def __init__(
        self,
        app: Any,
        *,
        engine: GigaMeshEngine,
        max_body_bytes: int = 1_048_576,
        rate_limit_per_min: int = 240,
    ) -> None:
        super().__init__(app)
        self.engine = engine
        self.max_body_bytes = max_body_bytes
        self.limiter = SlidingWindowRateLimiter(limit_per_minute=rate_limit_per_min)

    @staticmethod
    def _apply_security_headers(response: Any, path: str, limit: int, remaining: int) -> Any:
        is_hmi_embed = path == "/embed/hmi" or path.startswith("/embed/hmi/")
        response.headers["Content-Security-Policy"] = (
            DEFAULT_CSP.replace("frame-ancestors 'none'", "frame-ancestors 'self' https:")
            if is_hmi_embed
            else DEFAULT_CSP
        )
        response.headers["X-Content-Type-Options"] = "nosniff"
        if not is_hmi_embed:
            response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
        response.headers["Strict-Transport-Security"] = "max-age=63072000; includeSubDomains"
        response.headers["X-RateLimit-Limit"] = str(limit)
        response.headers["X-RateLimit-Remaining"] = str(remaining)
        if path.startswith("/api/"):
            response.headers["Cache-Control"] = "no-store, max-age=0"
            response.headers["Pragma"] = "no-cache"
        return response

    async def dispatch(self, request: Request, call_next: Any) -> Any:
        path = request.url.path
        client_host = request.client.host if request.client else "unknown"

        # 1. Sliding-window rate limit check (A06)
        allowed, remaining = self.limiter.allow(client_host)
        if not allowed:
            self.engine.security_audit_log.record(
                category="rate_limit",
                severity="medium",
                actor=client_host,
                summary=f"HTTP rate limit exceeded on {request.method} {path}",
            )
            resp = JSONResponse({"error": "rate_limit_exceeded"}, status_code=429)
            return self._apply_security_headers(resp, path, self.limiter.limit, 0)

        # 2. Request body size cap (A06) — check Content-Length and actual body length
        cl_raw = request.headers.get("content-length")
        if cl_raw:
            try:
                if int(cl_raw) > self.max_body_bytes:
                    self.engine.security_audit_log.record(
                        category="rate_limit",
                        severity="medium",
                        actor=client_host,
                        summary=f"Rejected oversized request body ({cl_raw} bytes) on {path}",
                    )
                    resp = JSONResponse({"error": "payload_too_large"}, status_code=413)
                    return self._apply_security_headers(resp, path, self.limiter.limit, remaining)
            except ValueError:
                pass
        if request.method in ("POST", "PUT", "PATCH"):
            body = await request.body()
            if len(body) > self.max_body_bytes:
                self.engine.security_audit_log.record(
                    category="rate_limit",
                    severity="medium",
                    actor=client_host,
                    summary=f"Rejected oversized streamed body ({len(body)} bytes) on {path}",
                )
                resp = JSONResponse({"error": "payload_too_large"}, status_code=413)
                return self._apply_security_headers(resp, path, self.limiter.limit, remaining)

        # 3. Authentication & Multi-Tenant RBAC Enforcement (A01/A07)
        configured_key = self.engine.config.api_auth_key
        auth_required = hasattr(self.engine, "security_authority") and self.engine.security_authority.auth_required
        is_public_route = path in ("/healthz", "/readyz", "/metrics", "/api/auth/login", "/api/auth/public-key")

        if path.startswith("/api/") and not is_public_route:
            auth_hdr = request.headers.get("authorization", "")
            bearer = auth_hdr[7:].strip() if auth_hdr.lower().startswith("bearer ") else ""
            api_key_hdr = request.headers.get("x-gigamesh-api-key", "").strip()

            # 3a. Legacy static API key on mutating routes (backward compatible)
            if configured_key and request.method in ("POST", "PUT", "PATCH", "DELETE"):
                provided = api_key_hdr or bearer
                if not provided or not hmac.compare_digest(provided, configured_key):
                    # Fall through to JWT check if bearer looks like a JWT (3 dot-separated parts)
                    if not (bearer and bearer.count(".") == 2 and hasattr(self.engine, "security_authority")):
                        self.engine.security_audit_log.record(
                            category="auth_failure",
                            severity="high",
                            actor=client_host,
                            summary=f"Rejected unauthenticated {request.method} {path}",
                        )
                        resp = JSONResponse({"error": "unauthorized"}, status_code=401)
                        return self._apply_security_headers(resp, path, self.limiter.limit, remaining)

            # 3b. Production JWT + Least-Privilege RBAC Enforcement
            if hasattr(self.engine, "security_authority") and (auth_required or (bearer and bearer.count(".") == 2)):
                from gigamesh.security.auth_rbac import required_role_for_route

                if not bearer:
                    self.engine.security_audit_log.record(
                        category="auth_failure",
                        severity="high",
                        actor=client_host,
                        summary=f"Missing Bearer JWT on protected route {request.method} {path}",
                    )
                    resp = JSONResponse({"error": "unauthorized", "detail": "Bearer JWT required"}, status_code=401)
                    return self._apply_security_headers(resp, path, self.limiter.limit, remaining)
                try:
                    claims = self.engine.security_authority.verify_jwt(bearer)
                except PermissionError:
                    self.engine.security_audit_log.record(
                        category="auth_failure",
                        severity="high",
                        actor=client_host,
                        summary=f"Invalid/expired Bearer JWT on {request.method} {path}",
                    )
                    resp = JSONResponse({"error": "unauthorized", "detail": "Invalid or expired JWT"}, status_code=401)
                    return self._apply_security_headers(resp, path, self.limiter.limit, remaining)

                req_role = required_role_for_route(request.method, path)
                actual_role = str(claims.get("role", "viewer"))
                if not self.engine.security_authority.role_allows(actual_role, req_role):
                    self.engine.security_audit_log.record(
                        category="access_denied",
                        severity="high",
                        actor=str(claims.get("sub", client_host)),
                        summary=f"RBAC denied {actual_role} on {request.method} {path} (requires {req_role})",
                    )
                    resp = JSONResponse(
                        {"error": "forbidden", "required_role": req_role, "actual_role": actual_role},
                        status_code=403,
                    )
                    return self._apply_security_headers(resp, path, self.limiter.limit, remaining)
                request.state.user = claims

        # 4. Execute route with fail-closed sanitized error boundary (A10)
        try:
            response = await call_next(request)
        except Exception as exc:
            ref = f"err-{uuid4().hex[:8]}"
            self.engine.security_audit_log.record(
                category="exception",
                severity="high",
                actor=client_host,
                summary=f"Fail-closed exception boundary triggered ({ref}) on {request.method} {path}",
                details={"reference_id": ref, "error_type": type(exc).__name__},
            )
            response = JSONResponse(
                {"error": "internal_security_boundary", "reference_id": ref},
                status_code=500,
            )

        return self._apply_security_headers(response, path, self.limiter.limit, remaining)


def install_fail_closed_exception_handlers(app: FastAPI, engine: GigaMeshEngine) -> None:
    """Register global exception handler guaranteeing zero stack-trace/path disclosure (A10)."""
    app.state.fail_closed_exception_handler = True

    @app.exception_handler(Exception)
    async def _fail_closed_handler(request: Request, exc: Exception) -> JSONResponse:
        ref = f"err-{uuid4().hex[:8]}"
        engine.security_audit_log.record(
            category="exception",
            severity="high",
            actor=request.client.host if request.client else "unknown",
            summary=f"Sanitized unhandled exception ({ref}) on {request.method} {request.url.path}",
            details={"reference_id": ref, "error_type": type(exc).__name__},
        )
        return JSONResponse(
            {"error": "internal_security_boundary", "reference_id": ref},
            status_code=500,
        )
