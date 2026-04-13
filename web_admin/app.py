import argparse
import os
from http.server import ThreadingHTTPServer
from pathlib import Path
from typing import List, Optional

from mcp_ssh_server import load_config
from web_admin.controller import AdminController
from web_admin.model import AdminModel
from web_admin.view import AdminView


def build_handler(model: AdminModel, view: AdminView):
    class Handler(AdminController):
        pass

    Handler.model = model
    Handler.view = view
    return Handler


def resolve_ui_path() -> Path:
    package_ui = Path(__file__).resolve().parents[1] / "web_admin_ui.html"
    return package_ui


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="MCP SSH web admin")
    parser.add_argument(
        "--config",
        default=os.environ.get("MCP_SSH_CONFIG", "servers.json"),
        help="Path to servers.json",
    )
    parser.add_argument(
        "--host", default="127.0.0.1", help="Bind host (default: 127.0.0.1)"
    )
    parser.add_argument(
        "--port", type=int, default=8787, help="Bind port (default: 8787)"
    )
    args = parser.parse_args(argv)

    config_path = Path(args.config).resolve()
    _ = load_config(str(config_path))

    ui_path = resolve_ui_path()
    if not ui_path.exists():
        raise FileNotFoundError(f"UI file not found: {ui_path}")

    model = AdminModel(config_path)
    view = AdminView(ui_path)
    server = ThreadingHTTPServer((args.host, args.port), build_handler(model, view))

    print(f"[web-admin] running on http://{args.host}:{args.port}")
    print(f"[web-admin] config: {config_path}")

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0
