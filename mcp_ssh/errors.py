from typing import Any, Dict


class MCPError(Exception):
    def __init__(self, code: int, message: str, data: Any = None):
        super().__init__(message)
        self.code = code
        self.message = message
        self.data = data


def error_to_dict(exc: Exception) -> Dict[str, Any]:
    if isinstance(exc, MCPError):
        out: Dict[str, Any] = {"code": exc.code, "message": exc.message}
        if exc.data is not None:
            out["data"] = exc.data
        return out
    return {"code": -32000, "message": str(exc)}
