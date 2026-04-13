import json
import os
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

from mcp_ssh.config import load_config
from mcp_ssh.errors import MCPError
from mcp_ssh.handlers import handle_initialize, jsonrpc_error, jsonrpc_result
from mcp_ssh.tools import handle_tools_call, handle_tools_list


def main(argv: Optional[List[str]] = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)

    config_path = os.environ.get("MCP_SSH_CONFIG")
    if "--config" in argv:
        idx = argv.index("--config")
        if idx + 1 >= len(argv):
            sys.stderr.write("mcp-ssh: missing value for --config\n")
            return 2
        config_path = argv[idx + 1]

    if not config_path:
        config_path = "servers.json"

    try:
        config = load_config(config_path)
    except MCPError as exc:
        sys.stderr.write(f"mcp-ssh: {exc.message}\n")
        return 2

    try:
        mtime_ns = Path(config_path).stat().st_mtime_ns
    except Exception:
        mtime_ns = 0

    config_state: Dict[str, Any] = {"config": config, "mtime_ns": mtime_ns}

    def reload_if_changed(force: bool = False) -> None:
        try:
            current_mtime_ns = Path(config_path).stat().st_mtime_ns
        except Exception:
            current_mtime_ns = 0

        if force or (
            current_mtime_ns and current_mtime_ns != config_state.get("mtime_ns")
        ):
            config_state["config"] = load_config(config_path)
            config_state["mtime_ns"] = current_mtime_ns

    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue

        try:
            msg = json.loads(line)
        except Exception as exc:
            sys.stdout.write(
                json.dumps(jsonrpc_error(0, -32700, f"Parse error: {exc}")) + "\n"
            )
            sys.stdout.flush()
            continue

        has_id = "id" in msg
        raw_id = msg.get("id") if has_id else None
        id_value = raw_id if isinstance(raw_id, (str, int)) else 0

        method = msg.get("method")
        params = msg.get("params")

        if not has_id:
            continue

        try:
            reload_if_changed()

            if method == "initialize":
                if not isinstance(params, dict):
                    raise MCPError(-32602, "initialize params must be an object")
                out = handle_initialize(params)
                sys.stdout.write(json.dumps(jsonrpc_result(id_value, out)) + "\n")
            elif method == "tools/list":
                out = handle_tools_list(config_state["config"])
                sys.stdout.write(json.dumps(jsonrpc_result(id_value, out)) + "\n")
            elif method == "tools/call":
                if not isinstance(params, dict):
                    raise MCPError(-32602, "tools/call params must be an object")
                out = handle_tools_call(
                    config_state, config_path, params, request_id=id_value
                )
                sys.stdout.write(json.dumps(jsonrpc_result(id_value, out)) + "\n")
            else:
                raise MCPError(-32601, f"Method not found: {method}")
        except MCPError as exc:
            sys.stdout.write(
                json.dumps(jsonrpc_error(id_value, exc.code, exc.message, exc.data))
                + "\n"
            )
        except Exception as exc:
            sys.stdout.write(
                json.dumps(jsonrpc_error(id_value, -32000, "Internal error", str(exc)))
                + "\n"
            )

        sys.stdout.flush()

    return 0
