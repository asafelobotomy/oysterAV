"""Structured RPC error types."""

from __future__ import annotations


class RpcError(Exception):
    """Client-visible RPC error with stable code."""

    def __init__(self, code: str, message: str) -> None:
        self.code = code
        self.message = message
        super().__init__(message)

    def to_dict(self) -> dict[str, str]:
        return {"code": self.code, "message": self.message}


class RpcAuthError(RpcError):
    def __init__(self, message: str = "RPC authentication failed") -> None:
        super().__init__("auth_failed", message)


class RpcValidationError(RpcError):
    def __init__(self, message: str) -> None:
        super().__init__("validation_error", message)


class RpcNotFoundError(RpcError):
    def __init__(self, message: str) -> None:
        super().__init__("not_found", message)
