from typing import Any, Dict


def jsonrpc_result(id_value: Any, result: Any) -> Dict[str, Any]:
    return {"jsonrpc": "2.0", "id": id_value, "result": result}


def jsonrpc_error(
    id_value: Any, code: int, message: str, data: Any = None
) -> Dict[str, Any]:
    err: Dict[str, Any] = {"code": code, "message": message}
    if data is not None:
        err["data"] = data
    return {"jsonrpc": "2.0", "id": id_value, "error": err}


def handle_initialize(params: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "protocolVersion": params.get("protocolVersion", "2024-11-05"),
        "capabilities": {"tools": {}},
        "serverInfo": {"name": "mcp-ssh", "version": "0.6.0"},
    }
