import json
import os
import tempfile
import threading
import time
from collections import deque
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from mcp_ssh.audit import file_ops_log
from mcp_ssh_server import (
    MCPError,
    delete_remote_path,
    load_config,
    run_ssh,
    upload_file,
)


class AdminModel:
    def __init__(self, config_path: Path):
        self.config_path = config_path
        self._write_lock = threading.Lock()

    @staticmethod
    def utc_now_iso() -> str:
        return (
            datetime.now(timezone.utc)
            .isoformat(timespec="seconds")
            .replace("+00:00", "Z")
        )

    @staticmethod
    def safe_error(exc: Exception) -> Dict[str, Any]:
        if isinstance(exc, MCPError):
            out: Dict[str, Any] = {"code": exc.code, "message": exc.message}
            if exc.data is not None:
                out["data"] = exc.data
            return out
        return {"code": -32000, "message": str(exc)}

    def read_raw_config(self) -> Dict[str, Any]:
        if not self.config_path.exists():
            raise MCPError(-32002, f"Config file not found: {self.config_path}")
        try:
            data = json.loads(self.config_path.read_text(encoding="utf-8"))
        except Exception as exc:
            raise MCPError(-32700, f"Invalid JSON in config: {exc}")
        if not isinstance(data, dict):
            raise MCPError(-32002, "Config root must be an object")
        return data

    def write_raw_config(self, data: Dict[str, Any]) -> None:
        parent = self.config_path.parent
        parent.mkdir(parents=True, exist_ok=True)

        with tempfile.NamedTemporaryFile(
            "w", encoding="utf-8", dir=str(parent), suffix=".tmp", delete=False
        ) as tmp:
            tmp.write(json.dumps(data, ensure_ascii=False, indent=2) + "\n")
            tmp_path = Path(tmp.name)

        try:
            _ = load_config(str(tmp_path))
            os.replace(str(tmp_path), str(self.config_path))
        finally:
            if tmp_path.exists():
                try:
                    tmp_path.unlink()
                except Exception:
                    pass

    def load_summary(self) -> Dict[str, Any]:
        cfg = load_config(str(self.config_path))
        return {
            "configPath": str(self.config_path),
            "defaultServer": cfg.default_server,
            "servers": sorted(cfg.servers.keys()),
            "groups": {
                k: list(v) for k, v in sorted(cfg.groups.items(), key=lambda kv: kv[0])
            },
            "audit": {
                "enabled": cfg.logging.enabled,
                "file": cfg.logging.file,
                "includeResult": cfg.logging.include_result,
                "includeStdout": cfg.logging.include_stdout,
                "includeStderr": cfg.logging.include_stderr,
            },
            "fileOpsAudit": {
                "enabled": cfg.file_ops_logging.enabled,
                "file": cfg.file_ops_logging.file,
            },
        }

    def load_history(self, limit: int = 200) -> List[Dict[str, Any]]:
        cfg = load_config(str(self.config_path))
        log_file = cfg.logging.file
        if not log_file:
            return []

        path = Path(log_file)
        if not path.exists():
            return []

        rows: deque[Dict[str, Any]] = deque(maxlen=max(1, min(limit, 1000)))
        try:
            with path.open("r", encoding="utf-8") as fp:
                for line in fp:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        obj = json.loads(line)
                    except Exception:
                        continue
                    if isinstance(obj, dict):
                        rows.append(obj)
        except Exception:
            return []

        return list(reversed(list(rows)))

    def load_file_ops_history(self, limit: int = 200) -> List[Dict[str, Any]]:
        cfg = load_config(str(self.config_path))
        log_file = cfg.file_ops_logging.file
        if not log_file:
            return []

        path = Path(log_file)
        if not path.exists():
            return []

        rows: deque[Dict[str, Any]] = deque(maxlen=max(1, min(limit, 1000)))
        try:
            with path.open("r", encoding="utf-8") as fp:
                for line in fp:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        obj = json.loads(line)
                    except Exception:
                        continue
                    if isinstance(obj, dict):
                        rows.append(obj)
        except Exception:
            return []

        return list(reversed(list(rows)))

    @staticmethod
    def _status_command() -> str:
        return (
            "mem_total=$(awk '/MemTotal/ {print $2}' /proc/meminfo 2>/dev/null); "
            "mem_avail=$(awk '/MemAvailable/ {print $2}' /proc/meminfo 2>/dev/null); "
            'cpu_pct=$(awk \'NR==1 {u=$2+$4; t=$2+$4+$5; if (t>0) printf("%.2f", (u*100)/t); else printf("0.00")}\' /proc/stat 2>/dev/null); '
            "disk_line=$(df -Pk / 2>/dev/null | awk 'NR==2 {print $2, $3, $4, $5}'); "
            "set -- $disk_line; "
            "load1=$(awk '{print $1}' /proc/loadavg 2>/dev/null); "
            "uptime_s=$(cut -d. -f1 /proc/uptime 2>/dev/null); "
            "hostn=$(hostname 2>/dev/null); "
            "echo host=$hostn; "
            "echo mem_total_kb=${mem_total:-0}; "
            "echo mem_avail_kb=${mem_avail:-0}; "
            "echo cpu_busy_pct=${cpu_pct:-0}; "
            "echo disk_total_kb=${1:-0}; "
            "echo disk_used_kb=${2:-0}; "
            "echo disk_avail_kb=${3:-0}; "
            "echo disk_use_pct=${4:-0}; "
            "echo load1=${load1:-0}; "
            "echo uptime_s=${uptime_s:-0}"
        )

    @staticmethod
    def _parse_status_output(stdout: str) -> Dict[str, Any]:
        data: Dict[str, str] = {}
        for line in (stdout or "").splitlines():
            line = line.strip()
            if not line or "=" not in line:
                continue
            k, v = line.split("=", 1)
            data[k.strip()] = v.strip()

        def as_int(key: str) -> int:
            raw = data.get(key, "0").replace("%", "").strip()
            try:
                return int(float(raw))
            except Exception:
                return 0

        def as_float(key: str) -> float:
            raw = data.get(key, "0").replace("%", "").strip()
            try:
                return float(raw)
            except Exception:
                return 0.0

        mem_total_kb = as_int("mem_total_kb")
        mem_avail_kb = as_int("mem_avail_kb")
        mem_used_kb = max(0, mem_total_kb - mem_avail_kb)
        mem_used_pct = (mem_used_kb * 100.0 / mem_total_kb) if mem_total_kb > 0 else 0.0

        disk_total_kb = as_int("disk_total_kb")
        disk_used_kb = as_int("disk_used_kb")
        disk_avail_kb = as_int("disk_avail_kb")
        disk_use_pct = as_float("disk_use_pct")

        return {
            "host": data.get("host") or None,
            "cpu_busy_pct": round(as_float("cpu_busy_pct"), 2),
            "load1": round(as_float("load1"), 2),
            "uptime_s": as_int("uptime_s"),
            "memory": {
                "total_kb": mem_total_kb,
                "used_kb": mem_used_kb,
                "avail_kb": mem_avail_kb,
                "used_pct": round(mem_used_pct, 2),
            },
            "disk_root": {
                "total_kb": disk_total_kb,
                "used_kb": disk_used_kb,
                "avail_kb": disk_avail_kb,
                "used_pct": round(disk_use_pct, 2),
            },
        }

    def status(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        cfg = load_config(str(self.config_path))
        timeout_ms = payload.get("timeout_ms", 15000)
        if not isinstance(timeout_ms, int) or timeout_ms <= 0:
            raise MCPError(-32602, "'timeout_ms' must be a positive integer")

        server_name = payload.get("server")
        group_name = payload.get("group")
        all_targets = bool(payload.get("all", False))
        if server_name is not None and (
            not isinstance(server_name, str) or not server_name.strip()
        ):
            raise MCPError(-32602, "'server' must be a non-empty string")
        if group_name is not None and (
            not isinstance(group_name, str) or not group_name.strip()
        ):
            raise MCPError(-32602, "'group' must be a non-empty string")

        parallel = bool(payload.get("parallel", True))
        max_parallel = payload.get("max_parallel", 8)
        if not isinstance(max_parallel, int) or max_parallel <= 0:
            raise MCPError(-32602, "'max_parallel' must be a positive integer")

        if server_name or group_name:
            targets, _ = self._resolve_targets(cfg, server_name, group_name)
        elif all_targets:
            targets = [cfg.servers[name] for name in sorted(cfg.servers.keys())]
        elif cfg.default_server:
            targets = [cfg.servers[cfg.default_server]]
        else:
            targets = [cfg.servers[name] for name in sorted(cfg.servers.keys())]

        command = self._status_command()
        started = time.time()
        results: Dict[str, Any] = {}
        ok = True

        def _one(target: Any) -> Tuple[str, Dict[str, Any]]:
            try:
                res = run_ssh(target, command, timeout_ms)
                if res.get("exit_code") != 0:
                    return target.name, {
                        "error": {
                            "code": -32000,
                            "message": "Status command failed",
                            "data": res,
                        }
                    }
                parsed = self._parse_status_output(res.get("stdout") or "")
                parsed["elapsed_ms"] = res.get("elapsed_ms")
                return target.name, {"ok": True, "status": parsed}
            except Exception as exc:
                return target.name, {"error": self.safe_error(exc)}

        if parallel and len(targets) > 1:
            from concurrent.futures import ThreadPoolExecutor, as_completed

            with ThreadPoolExecutor(max_workers=min(max_parallel, len(targets))) as ex:
                futs = {ex.submit(_one, t): t for t in targets}
                for fut in as_completed(futs):
                    name, res = fut.result()
                    results[name] = res
        else:
            for t in targets:
                name, res = _one(t)
                results[name] = res

        for t in targets:
            if "error" in results.get(t.name, {}):
                ok = False

        return {
            "ok": ok,
            "targets": [t.name for t in targets],
            "elapsed_ms": int((time.time() - started) * 1000),
            "results": results,
        }

    def execute(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        cfg = load_config(str(self.config_path))

        command = payload.get("command")
        if not isinstance(command, str) or not command.strip():
            raise MCPError(-32602, "'command' must be a non-empty string")

        timeout_ms = payload.get("timeout_ms")
        if timeout_ms is not None and (
            not isinstance(timeout_ms, int) or timeout_ms <= 0
        ):
            raise MCPError(-32602, "'timeout_ms' must be a positive integer")

        server_name = payload.get("server")
        if server_name is not None and (
            not isinstance(server_name, str) or not server_name.strip()
        ):
            raise MCPError(-32602, "'server' must be a non-empty string")

        group_name = payload.get("group")
        if group_name is not None and (
            not isinstance(group_name, str) or not group_name.strip()
        ):
            raise MCPError(-32602, "'group' must be a non-empty string")

        parallel = bool(payload.get("parallel", False))
        max_parallel = payload.get("max_parallel", 8)
        if not isinstance(max_parallel, int) or max_parallel <= 0:
            raise MCPError(-32602, "'max_parallel' must be a positive integer")

        targets, resolved_group = self._resolve_targets(cfg, server_name, group_name)

        started = time.time()
        results: Dict[str, Any] = {}
        ok = True

        if parallel and len(targets) > 1:
            from concurrent.futures import ThreadPoolExecutor, as_completed

            def worker(target: Any) -> Tuple[str, Dict[str, Any]]:
                try:
                    return target.name, run_ssh(target, command, timeout_ms)
                except Exception as exc:
                    return target.name, {"error": self.safe_error(exc)}

            with ThreadPoolExecutor(max_workers=min(max_parallel, len(targets))) as ex:
                futures = {ex.submit(worker, t): t for t in targets}
                for fut in as_completed(futures):
                    name, res = fut.result()
                    results[name] = res
        else:
            for target in targets:
                try:
                    results[target.name] = run_ssh(target, command, timeout_ms)
                except Exception as exc:
                    results[target.name] = {"error": self.safe_error(exc)}

        for target in targets:
            item = results.get(target.name, {})
            if "error" in item:
                ok = False
            elif item.get("exit_code") != 0:
                ok = False

            self._append_audit_event(
                cfg,
                {
                    "ts": self.utc_now_iso(),
                    "event": "web_exec_parallel"
                    if (parallel and len(targets) > 1)
                    else "web_exec",
                    "server": target.name,
                    "host": target.host,
                    "port": target.port,
                    "user": target.user,
                    "group": resolved_group,
                    "ok": False if "error" in item else item.get("exit_code") == 0,
                    "elapsed_ms": item.get("elapsed_ms"),
                    "error": item.get("error"),
                    "exit_code": item.get("exit_code"),
                    "command": command if cfg.logging.include_command else None,
                    "stdout": item.get("stdout")
                    if cfg.logging.include_stdout
                    else None,
                    "stderr": item.get("stderr")
                    if cfg.logging.include_stderr
                    else None,
                },
            )

        return {
            "ok": ok,
            "command": command,
            "targets": [t.name for t in targets],
            "elapsed_ms": int((time.time() - started) * 1000),
            "results": results,
        }

    def save_config_payload(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        with self._write_lock:
            self.write_raw_config(payload)
        return {"ok": True, "savedAt": self.utc_now_iso()}

    def upload(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        cfg = load_config(str(self.config_path))
        local_path = payload.get("local_path")
        remote_path = payload.get("remote_path")
        if not isinstance(local_path, str) or not local_path.strip():
            raise MCPError(-32602, "'local_path' must be a non-empty string")
        if not isinstance(remote_path, str) or not remote_path.strip():
            raise MCPError(-32602, "'remote_path' must be a non-empty string")

        timeout_ms = payload.get("timeout_ms")
        if timeout_ms is not None and (
            not isinstance(timeout_ms, int) or timeout_ms <= 0
        ):
            raise MCPError(-32602, "'timeout_ms' must be a positive integer")

        server_name = payload.get("server")
        group_name = payload.get("group")
        if server_name is not None and (
            not isinstance(server_name, str) or not server_name.strip()
        ):
            raise MCPError(-32602, "'server' must be a non-empty string")
        if group_name is not None and (
            not isinstance(group_name, str) or not group_name.strip()
        ):
            raise MCPError(-32602, "'group' must be a non-empty string")
        parallel = bool(payload.get("parallel", False))
        max_parallel = payload.get("max_parallel", 8)
        if not isinstance(max_parallel, int) or max_parallel <= 0:
            raise MCPError(-32602, "'max_parallel' must be a positive integer")

        targets, resolved_group = self._resolve_targets(cfg, server_name, group_name)
        make_dirs = bool(payload.get("make_dirs", True))
        overwrite = bool(payload.get("overwrite", True))

        started = time.time()
        results: Dict[str, Any] = {}
        ok = True

        def _one(target: Any) -> Tuple[str, Dict[str, Any]]:
            try:
                return (
                    target.name,
                    upload_file(
                        target,
                        local_path,
                        remote_path,
                        timeout_ms,
                        make_dirs=make_dirs,
                        overwrite=overwrite,
                    ),
                )
            except Exception as exc:
                return target.name, {"error": self.safe_error(exc)}

        if parallel and len(targets) > 1:
            from concurrent.futures import ThreadPoolExecutor, as_completed

            with ThreadPoolExecutor(max_workers=min(max_parallel, len(targets))) as ex:
                futs = {ex.submit(_one, t): t for t in targets}
                for fut in as_completed(futs):
                    name, res = fut.result()
                    results[name] = res
        else:
            for target in targets:
                name, res = _one(target)
                results[name] = res

        for target in targets:
            item = results.get(target.name, {})
            if "error" in item:
                ok = False
            file_ops_log(
                cfg.file_ops_logging,
                {
                    "ts": self.utc_now_iso(),
                    "event": "web_upload",
                    "server": target.name,
                    "host": target.host,
                    "port": target.port,
                    "user": target.user,
                    "group": resolved_group,
                    "ok": "error" not in item,
                    "local_path": local_path,
                    "remote_path": remote_path,
                    "bytes": item.get("bytes"),
                    "elapsed_ms": item.get("elapsed_ms"),
                    "error": item.get("error"),
                },
            )

        return {
            "ok": ok,
            "operation": "upload",
            "targets": [t.name for t in targets],
            "elapsed_ms": int((time.time() - started) * 1000),
            "results": results,
        }

    def delete(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        cfg = load_config(str(self.config_path))
        remote_path = payload.get("remote_path")
        if not isinstance(remote_path, str) or not remote_path.strip():
            raise MCPError(-32602, "'remote_path' must be a non-empty string")

        timeout_ms = payload.get("timeout_ms")
        if timeout_ms is not None and (
            not isinstance(timeout_ms, int) or timeout_ms <= 0
        ):
            raise MCPError(-32602, "'timeout_ms' must be a positive integer")

        server_name = payload.get("server")
        group_name = payload.get("group")
        if server_name is not None and (
            not isinstance(server_name, str) or not server_name.strip()
        ):
            raise MCPError(-32602, "'server' must be a non-empty string")
        if group_name is not None and (
            not isinstance(group_name, str) or not group_name.strip()
        ):
            raise MCPError(-32602, "'group' must be a non-empty string")
        parallel = bool(payload.get("parallel", False))
        max_parallel = payload.get("max_parallel", 8)
        if not isinstance(max_parallel, int) or max_parallel <= 0:
            raise MCPError(-32602, "'max_parallel' must be a positive integer")

        targets, resolved_group = self._resolve_targets(cfg, server_name, group_name)
        recursive = bool(payload.get("recursive", False))
        missing_ok = bool(payload.get("missing_ok", False))

        started = time.time()
        results: Dict[str, Any] = {}
        ok = True

        def _one(target: Any) -> Tuple[str, Dict[str, Any]]:
            try:
                return (
                    target.name,
                    delete_remote_path(
                        target,
                        remote_path,
                        timeout_ms,
                        recursive=recursive,
                        missing_ok=missing_ok,
                    ),
                )
            except Exception as exc:
                return target.name, {"error": self.safe_error(exc)}

        if parallel and len(targets) > 1:
            from concurrent.futures import ThreadPoolExecutor, as_completed

            with ThreadPoolExecutor(max_workers=min(max_parallel, len(targets))) as ex:
                futs = {ex.submit(_one, t): t for t in targets}
                for fut in as_completed(futs):
                    name, res = fut.result()
                    results[name] = res
        else:
            for target in targets:
                name, res = _one(target)
                results[name] = res

        for target in targets:
            item = results.get(target.name, {})
            if "error" in item:
                ok = False
            file_ops_log(
                cfg.file_ops_logging,
                {
                    "ts": self.utc_now_iso(),
                    "event": "web_delete",
                    "server": target.name,
                    "host": target.host,
                    "port": target.port,
                    "user": target.user,
                    "group": resolved_group,
                    "ok": "error" not in item,
                    "remote_path": remote_path,
                    "removed": item.get("removed"),
                    "elapsed_ms": item.get("elapsed_ms"),
                    "error": item.get("error"),
                },
            )

        return {
            "ok": ok,
            "operation": "delete",
            "targets": [t.name for t in targets],
            "elapsed_ms": int((time.time() - started) * 1000),
            "results": results,
        }

    @staticmethod
    def _resolve_targets(
        config: Any, server_name: Optional[str], group_name: Optional[str]
    ) -> Tuple[List[Any], Optional[str]]:
        if server_name and group_name:
            raise MCPError(-32602, "Provide only one of 'server' or 'group'")
        if group_name:
            members = config.groups.get(group_name)
            if not members:
                raise MCPError(-32602, f"Unknown group: {group_name}")
            return [config.servers[name] for name in members], group_name
        if server_name:
            srv = config.servers.get(server_name)
            if srv is None:
                raise MCPError(-32602, f"Unknown server: {server_name}")
            return [srv], None
        if config.default_server:
            return [config.servers[config.default_server]], None
        raise MCPError(
            -32602, "Missing 'server' or 'group' (and no defaultServer configured)"
        )

    def _append_audit_event(self, cfg: Any, event: Dict[str, Any]) -> None:
        if not cfg.logging.enabled or not cfg.logging.file:
            return
        try:
            event = {k: v for k, v in event.items() if v is not None}
            p = Path(cfg.logging.file)
            p.parent.mkdir(parents=True, exist_ok=True)
            with self._write_lock:
                with p.open("a", encoding="utf-8") as fp:
                    fp.write(json.dumps(event, ensure_ascii=False) + "\n")
        except Exception:
            return
