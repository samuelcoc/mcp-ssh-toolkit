import json
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler
from typing import Any, Dict
from urllib.parse import parse_qs, urlparse

from mcp_ssh_server import MCPError
from web_admin.model import AdminModel
from web_admin.view import AdminView


class AdminController(BaseHTTPRequestHandler):
    model: AdminModel
    view: AdminView

    def _send_json(self, status: int, payload: Any) -> None:
        raw = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def _send_html(self, status: int, html: str) -> None:
        raw = html.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def _read_json_body(self) -> Dict[str, Any]:
        length = int(self.headers.get("Content-Length", "0") or "0")
        if length <= 0:
            raise MCPError(-32602, "Request body is required")
        raw = self.rfile.read(length)
        try:
            obj = json.loads(raw.decode("utf-8"))
        except Exception as exc:
            raise MCPError(-32700, f"Invalid JSON body: {exc}")
        if not isinstance(obj, dict):
            raise MCPError(-32602, "Body must be a JSON object")
        return obj

    def do_GET(self) -> None:  # noqa: N802
        parsed = urlparse(self.path)
        try:
            if parsed.path == "/":
                return self._send_html(HTTPStatus.OK, self.view.render_index())

            if parsed.path == "/api/config/raw":
                return self._send_json(HTTPStatus.OK, self.model.read_raw_config())

            if parsed.path == "/api/config/summary":
                return self._send_json(HTTPStatus.OK, self.model.load_summary())

            if parsed.path == "/api/history":
                query = parse_qs(parsed.query)
                limit_s = (query.get("limit") or ["200"])[0]
                try:
                    limit = int(limit_s)
                except Exception:
                    limit = 200
                events = self.model.load_history(limit=limit)
                return self._send_json(
                    HTTPStatus.OK, {"events": events, "count": len(events)}
                )

            if parsed.path == "/api/fileops/history":
                query = parse_qs(parsed.query)
                limit_s = (query.get("limit") or ["200"])[0]
                try:
                    limit = int(limit_s)
                except Exception:
                    limit = 200
                events = self.model.load_file_ops_history(limit=limit)
                return self._send_json(
                    HTTPStatus.OK, {"events": events, "count": len(events)}
                )

            return self._send_json(HTTPStatus.NOT_FOUND, {"error": "Not found"})
        except Exception as exc:
            return self._send_json(
                HTTPStatus.BAD_REQUEST, {"error": self.model.safe_error(exc)}
            )

    def do_PUT(self) -> None:  # noqa: N802
        parsed = urlparse(self.path)
        try:
            if parsed.path != "/api/config/raw":
                return self._send_json(HTTPStatus.NOT_FOUND, {"error": "Not found"})

            payload = self._read_json_body()
            out = self.model.save_config_payload(payload)
            return self._send_json(HTTPStatus.OK, out)
        except Exception as exc:
            return self._send_json(
                HTTPStatus.BAD_REQUEST, {"error": self.model.safe_error(exc)}
            )

    def do_POST(self) -> None:  # noqa: N802
        parsed = urlparse(self.path)
        try:
            if parsed.path == "/api/exec":
                payload = self._read_json_body()
                out = self.model.execute(payload)
                return self._send_json(HTTPStatus.OK, out)

            if parsed.path == "/api/fileops/upload":
                payload = self._read_json_body()
                out = self.model.upload(payload)
                return self._send_json(HTTPStatus.OK, out)

            if parsed.path == "/api/fileops/delete":
                payload = self._read_json_body()
                out = self.model.delete(payload)
                return self._send_json(HTTPStatus.OK, out)

            if parsed.path == "/api/status":
                payload = self._read_json_body()
                out = self.model.status(payload)
                return self._send_json(HTTPStatus.OK, out)

            return self._send_json(HTTPStatus.NOT_FOUND, {"error": "Not found"})
        except Exception as exc:
            return self._send_json(
                HTTPStatus.BAD_REQUEST, {"error": self.model.safe_error(exc)}
            )

    def log_message(self, fmt: str, *args: Any) -> None:
        return
