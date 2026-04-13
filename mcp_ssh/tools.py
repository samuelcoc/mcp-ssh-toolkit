import json
import os
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Any, Dict, List, Optional

from mcp_ssh.audit import audit_log, file_ops_log, utc_now_iso
from mcp_ssh.config import load_config
from mcp_ssh.errors import MCPError, error_to_dict
from mcp_ssh.models import LoggingConfig, MCPConfig, ServerConfig
from mcp_ssh.ssh_exec import (
    delete_remote_path,
    run_ssh,
    safe_server_info,
    ssh_test,
    upload_file,
)


def select_targets(
    config: MCPConfig, server_name: Optional[str], group_name: Optional[str]
) -> List[ServerConfig]:
    if server_name and group_name:
        raise MCPError(-32602, "Provide only one of 'server' or 'group'")

    if group_name:
        if group_name not in config.groups:
            raise MCPError(-32602, f"Unknown group: {group_name}")
        return [config.servers[m] for m in config.groups[group_name]]

    if server_name:
        if server_name not in config.servers:
            raise MCPError(-32602, f"Unknown server: {server_name}")
        return [config.servers[server_name]]

    if config.default_server:
        return [config.servers[config.default_server]]

    raise MCPError(
        -32602, "Missing 'server' or 'group' (and no defaultServer configured)"
    )


def handle_tools_list(config: MCPConfig) -> Dict[str, Any]:
    server_names = sorted(config.servers.keys())
    group_names = sorted(config.groups.keys())
    return {
        "tools": [
            {
                "name": "ssh_reload",
                "description": "Reload servers.json from disk",
                "inputSchema": {
                    "type": "object",
                    "properties": {},
                    "additionalProperties": False,
                },
            },
            {
                "name": "ssh_add_server",
                "description": "Add or update a server in servers.json (prefer passwordEnv/passwordCommand/passwordKeyring)",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "server": {"type": "string"},
                        "host": {"type": "string"},
                        "port": {"type": "integer"},
                        "user": {"type": "string"},
                        "identityFile": {"type": "string"},
                        "strictHostKeyChecking": {"type": "string"},
                        "knownHostsFile": {"type": "string"},
                        "extraArgs": {"type": "array", "items": {"type": "string"}},
                        "passwordEnv": {"type": "string"},
                        "passwordCommand": {
                            "anyOf": [
                                {"type": "string"},
                                {"type": "array", "items": {"type": "string"}},
                            ]
                        },
                        "passwordKeyring": {
                            "type": "object",
                            "properties": {
                                "service": {"type": "string"},
                                "username": {"type": "string"},
                            },
                            "required": ["service", "username"],
                            "additionalProperties": False,
                        },
                        "groups": {"type": "array", "items": {"type": "string"}},
                        "setDefault": {"type": "boolean"},
                    },
                    "required": ["server", "host"],
                    "additionalProperties": False,
                },
            },
            {
                "name": "ssh_list",
                "description": "List configured servers, groups and defaults",
                "inputSchema": {
                    "type": "object",
                    "properties": {},
                    "additionalProperties": False,
                },
            },
            {
                "name": "ssh_info",
                "description": "Show sanitized configuration for a server",
                "inputSchema": {
                    "type": "object",
                    "properties": {"server": {"type": "string", "enum": server_names}},
                    "required": ["server"],
                    "additionalProperties": False,
                },
            },
            {
                "name": "ssh_test",
                "description": "Test connectivity/auth for a server or group",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "server": {"type": "string", "enum": server_names},
                        "group": {"type": "string", "enum": group_names},
                        "timeout_ms": {"type": "integer"},
                    },
                    "additionalProperties": False,
                },
            },
            {
                "name": "ssh_exec",
                "description": "Execute a command on a named SSH server (or group) from servers.json",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "server": {"type": "string", "enum": server_names},
                        "group": {"type": "string", "enum": group_names},
                        "command": {"type": "string"},
                        "timeout_ms": {"type": "integer"},
                    },
                    "required": ["command"],
                    "additionalProperties": False,
                },
            },
            {
                "name": "ssh_exec_parallel",
                "description": "Execute a command on a group in parallel",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "group": {"type": "string", "enum": group_names},
                        "command": {"type": "string"},
                        "timeout_ms": {"type": "integer"},
                        "max_parallel": {"type": "integer"},
                    },
                    "required": ["group", "command"],
                    "additionalProperties": False,
                },
            },
            {
                "name": "ssh_upload",
                "description": "Upload a local file to remote path via SFTP (server/group)",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "server": {"type": "string", "enum": server_names},
                        "group": {"type": "string", "enum": group_names},
                        "local_path": {"type": "string"},
                        "remote_path": {"type": "string"},
                        "timeout_ms": {"type": "integer"},
                        "make_dirs": {"type": "boolean"},
                        "overwrite": {"type": "boolean"},
                        "parallel": {"type": "boolean"},
                        "max_parallel": {"type": "integer"},
                    },
                    "required": ["local_path", "remote_path"],
                    "additionalProperties": False,
                },
            },
            {
                "name": "ssh_delete",
                "description": "Delete remote file or directory via SFTP (server/group)",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "server": {"type": "string", "enum": server_names},
                        "group": {"type": "string", "enum": group_names},
                        "remote_path": {"type": "string"},
                        "timeout_ms": {"type": "integer"},
                        "recursive": {"type": "boolean"},
                        "missing_ok": {"type": "boolean"},
                        "parallel": {"type": "boolean"},
                        "max_parallel": {"type": "integer"},
                    },
                    "required": ["remote_path"],
                    "additionalProperties": False,
                },
            },
        ]
    }


def _handle_ssh_list(config: MCPConfig) -> Dict[str, Any]:
    return {
        "defaultServer": config.default_server,
        "servers": sorted(config.servers.keys()),
        "groups": {
            k: list(v) for k, v in sorted(config.groups.items(), key=lambda kv: kv[0])
        },
        "defaults": {
            "user": config.defaults.user,
            "port": config.defaults.port,
            "identityFile": config.defaults.identity_file,
            "strictHostKeyChecking": config.defaults.strict_host_key_checking,
            "knownHostsFile": config.defaults.known_hosts_file,
            "extraArgs": list(config.defaults.extra_args),
        },
        "policy": {
            "allow": list(config.policy.allow),
            "deny": list(config.policy.deny),
        },
    }


def _handle_ssh_info(config: MCPConfig, arguments: Dict[str, Any]) -> Dict[str, Any]:
    server_name = arguments.get("server")
    if not isinstance(server_name, str) or not server_name.strip():
        raise MCPError(-32602, "'server' must be a non-empty string")
    server = config.servers.get(server_name)
    if server is None:
        raise MCPError(-32602, f"Unknown server: {server_name}")
    return safe_server_info(server)


def _load_config_json(config_path: str) -> Dict[str, Any]:
    path = Path(config_path)
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        raise MCPError(-32700, f"Invalid JSON in config: {exc}")


def _atomic_write_and_validate_config(config_path: str, data: Dict[str, Any]) -> None:
    path = Path(config_path)
    tmp_path = path.with_suffix(path.suffix + ".tmp")
    tmp_path.write_text(
        json.dumps(data, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    _ = load_config(str(tmp_path))
    os.replace(str(tmp_path), str(path))


def _handle_ssh_add_server(
    config_path: str, arguments: Dict[str, Any]
) -> Dict[str, Any]:
    name = arguments.get("server")
    host = arguments.get("host")
    if not isinstance(name, str) or not name.strip():
        raise MCPError(-32602, "'server' must be a non-empty string")
    if not isinstance(host, str) or not host.strip():
        raise MCPError(-32602, "'host' must be a non-empty string")

    if (
        "password" in arguments
        and os.environ.get("MCP_SSH_ALLOW_PLAINTEXT_PASSWORD") != "1"
    ):
        raise MCPError(
            -32602,
            "Plaintext 'password' is disabled; use passwordEnv/passwordCommand/passwordKeyring",
        )

    raw = _load_config_json(config_path)
    if raw.get("version", 1) != 1:
        raise MCPError(-32002, "Unsupported config version")

    servers = raw.get("servers")
    if not isinstance(servers, dict):
        raw["servers"] = {}
        servers = raw["servers"]

    server_obj = (
        dict(servers.get(name, {})) if isinstance(servers.get(name), dict) else {}
    )
    server_obj["host"] = host

    for key in [
        "port",
        "user",
        "identityFile",
        "strictHostKeyChecking",
        "knownHostsFile",
        "extraArgs",
        "passwordEnv",
        "passwordCommand",
        "passwordKeyring",
    ]:
        if key in arguments and arguments[key] is not None:
            server_obj[key] = arguments[key]

    servers[name] = server_obj

    groups = raw.get("groups")
    if groups is None:
        groups = {}
        raw["groups"] = groups
    if not isinstance(groups, dict):
        raise MCPError(-32002, "'groups' must be an object")

    group_list = arguments.get("groups")
    if group_list is not None:
        if not isinstance(group_list, list) or any(
            not isinstance(g, str) or not g.strip() for g in group_list
        ):
            raise MCPError(-32602, "'groups' must be a list of strings")
        for group_name in group_list:
            members = groups.get(group_name, [])
            if members is None:
                members = []
            if not isinstance(members, list):
                raise MCPError(-32002, f"Group '{group_name}' must be a list")
            if name not in members:
                members.append(name)
            groups[group_name] = members

    if arguments.get("setDefault") is True:
        raw["defaultServer"] = name

    _atomic_write_and_validate_config(config_path, raw)
    return {"ok": True, "server": name, "written": True}


def _exec_targets_sequential(
    targets: List[ServerConfig],
    command: str,
    timeout_ms: Optional[int],
    logging_cfg: LoggingConfig,
    *,
    tool: str,
    request_id: Any,
    group: Optional[str],
) -> Dict[str, Any]:
    results: Dict[str, Any] = {}
    ok = True

    for server in targets:
        start = time.time()
        try:
            res = run_ssh(server, command, timeout_ms)
            results[server.name] = res
            exit_code = res.get("exit_code")
            if exit_code != 0:
                ok = False

            event = {
                "ts": utc_now_iso(),
                "event": tool,
                "request_id": request_id,
                "server": server.name,
                "host": server.host,
                "port": server.port,
                "user": server.user,
                "group": group,
                "ok": exit_code == 0,
                "elapsed_ms": int((time.time() - start) * 1000),
                "transport": res.get("transport"),
            }
            if logging_cfg.include_command:
                event["command"] = command
            if logging_cfg.include_result:
                event["exit_code"] = exit_code
            if logging_cfg.include_stdout and "stdout" in res:
                event["stdout"] = res.get("stdout")
            if logging_cfg.include_stderr and "stderr" in res:
                event["stderr"] = res.get("stderr")
            audit_log(logging_cfg, event)
        except Exception as exc:
            ok = False
            results[server.name] = {"error": error_to_dict(exc)}
            event = {
                "ts": utc_now_iso(),
                "event": tool,
                "request_id": request_id,
                "server": server.name,
                "host": server.host,
                "port": server.port,
                "user": server.user,
                "group": group,
                "ok": False,
                "elapsed_ms": int((time.time() - start) * 1000),
                "error": error_to_dict(exc),
            }
            if logging_cfg.include_command:
                event["command"] = command
            audit_log(logging_cfg, event)

    return {"ok": ok, "results": results}


def _exec_targets_parallel(
    targets: List[ServerConfig],
    command: str,
    timeout_ms: Optional[int],
    max_parallel: int,
    logging_cfg: LoggingConfig,
    *,
    tool: str,
    request_id: Any,
    group: Optional[str],
) -> Dict[str, Any]:
    if max_parallel <= 0:
        raise MCPError(-32602, "'max_parallel' must be a positive integer")

    results: Dict[str, Any] = {}
    ok = True
    started = {s.name: time.time() for s in targets}

    with ThreadPoolExecutor(max_workers=max_parallel) as ex:
        fut_to_server = {ex.submit(run_ssh, s, command, timeout_ms): s for s in targets}
        for fut in as_completed(fut_to_server):
            server = fut_to_server[fut]
            start_t = started.get(server.name, time.time())
            try:
                res = fut.result()
                results[server.name] = res
                exit_code = res.get("exit_code")
                if exit_code != 0:
                    ok = False

                event = {
                    "ts": utc_now_iso(),
                    "event": tool,
                    "request_id": request_id,
                    "server": server.name,
                    "host": server.host,
                    "port": server.port,
                    "user": server.user,
                    "group": group,
                    "ok": exit_code == 0,
                    "elapsed_ms": int((time.time() - start_t) * 1000),
                    "transport": res.get("transport"),
                }
                if logging_cfg.include_command:
                    event["command"] = command
                if logging_cfg.include_result:
                    event["exit_code"] = exit_code
                if logging_cfg.include_stdout and "stdout" in res:
                    event["stdout"] = res.get("stdout")
                if logging_cfg.include_stderr and "stderr" in res:
                    event["stderr"] = res.get("stderr")
                audit_log(logging_cfg, event)
            except Exception as exc:
                ok = False
                results[server.name] = {"error": error_to_dict(exc)}
                event = {
                    "ts": utc_now_iso(),
                    "event": tool,
                    "request_id": request_id,
                    "server": server.name,
                    "host": server.host,
                    "port": server.port,
                    "user": server.user,
                    "group": group,
                    "ok": False,
                    "elapsed_ms": int((time.time() - start_t) * 1000),
                    "error": error_to_dict(exc),
                }
                if logging_cfg.include_command:
                    event["command"] = command
                audit_log(logging_cfg, event)

    return {"ok": ok, "results": results}


def handle_tools_call(
    config_state: Dict[str, Any],
    config_path: str,
    params: Dict[str, Any],
    *,
    request_id: Any,
) -> Dict[str, Any]:
    config: MCPConfig = config_state["config"]
    name = params.get("name")
    arguments = params.get("arguments")
    if not isinstance(arguments, dict):
        raise MCPError(-32602, "'arguments' must be an object")

    if name == "ssh_reload":
        config_state["config"] = load_config(config_path)
        try:
            config_state["mtime_ns"] = Path(config_path).stat().st_mtime_ns
        except Exception:
            config_state["mtime_ns"] = 0
        return {
            "content": [
                {
                    "type": "text",
                    "text": json.dumps(
                        {"ok": True, "reloaded": True}, ensure_ascii=False, indent=2
                    ),
                }
            ]
        }

    if name == "ssh_add_server":
        out = _handle_ssh_add_server(config_path, arguments)
        config_state["config"] = load_config(config_path)
        try:
            config_state["mtime_ns"] = Path(config_path).stat().st_mtime_ns
        except Exception:
            config_state["mtime_ns"] = 0
        return {
            "content": [
                {"type": "text", "text": json.dumps(out, ensure_ascii=False, indent=2)}
            ]
        }

    if name == "ssh_list":
        return {
            "content": [
                {
                    "type": "text",
                    "text": json.dumps(
                        _handle_ssh_list(config), ensure_ascii=False, indent=2
                    ),
                }
            ]
        }

    if name == "ssh_info":
        return {
            "content": [
                {
                    "type": "text",
                    "text": json.dumps(
                        _handle_ssh_info(config, arguments),
                        ensure_ascii=False,
                        indent=2,
                    ),
                }
            ]
        }

    if name == "ssh_test":
        timeout_ms = arguments.get("timeout_ms")
        if timeout_ms is not None and not isinstance(timeout_ms, int):
            raise MCPError(-32602, "'timeout_ms' must be an integer")

        server_name_obj = arguments.get("server")
        server_name = (
            server_name_obj
            if isinstance(server_name_obj, str) and server_name_obj.strip()
            else None
        )
        group_name_obj = arguments.get("group")
        group_name = (
            group_name_obj
            if isinstance(group_name_obj, str) and group_name_obj.strip()
            else None
        )

        targets = select_targets(config, server_name, group_name)
        results: Dict[str, Any] = {}
        ok = True
        for server in targets:
            start_s = time.time()
            try:
                result = ssh_test(server, timeout_ms)
                results[server.name] = result
                if not result.get("ok"):
                    ok = False

                if config.logging.log_tests:
                    event = {
                        "ts": utc_now_iso(),
                        "event": "ssh_test",
                        "request_id": request_id,
                        "server": server.name,
                        "host": server.host,
                        "port": server.port,
                        "user": server.user,
                        "group": group_name,
                        "ok": bool(result.get("ok")),
                        "elapsed_ms": int((time.time() - start_s) * 1000),
                        "transport": result.get("transport"),
                    }
                    if config.logging.include_result and "exit_code" in result:
                        event["exit_code"] = result.get("exit_code")
                    if config.logging.include_stderr and "stderr" in result:
                        event["stderr"] = result.get("stderr")
                    audit_log(config.logging, event)
            except Exception as exc:
                ok = False
                results[server.name] = {"error": error_to_dict(exc)}
                if config.logging.log_tests:
                    audit_log(
                        config.logging,
                        {
                            "ts": utc_now_iso(),
                            "event": "ssh_test",
                            "request_id": request_id,
                            "server": server.name,
                            "host": server.host,
                            "port": server.port,
                            "user": server.user,
                            "group": group_name,
                            "ok": False,
                            "elapsed_ms": int((time.time() - start_s) * 1000),
                            "error": error_to_dict(exc),
                        },
                    )

        out = {"ok": ok, "targets": [t.name for t in targets], "results": results}
        return {
            "content": [
                {"type": "text", "text": json.dumps(out, ensure_ascii=False, indent=2)}
            ]
        }

    if name in {"ssh_exec", "ssh_exec_parallel"}:
        command_obj = arguments.get("command")
        if not isinstance(command_obj, str) or not command_obj.strip():
            raise MCPError(-32602, "'command' must be a non-empty string")
        timeout_ms = arguments.get("timeout_ms")
        if timeout_ms is not None and not isinstance(timeout_ms, int):
            raise MCPError(-32602, "'timeout_ms' must be an integer")

        server_name_obj = arguments.get("server")
        server_name = (
            server_name_obj
            if isinstance(server_name_obj, str) and server_name_obj.strip()
            else None
        )
        group_name_obj = arguments.get("group")
        group_name = (
            group_name_obj
            if isinstance(group_name_obj, str) and group_name_obj.strip()
            else None
        )

        if name == "ssh_exec_parallel" and not group_name:
            raise MCPError(-32602, "'group' is required for ssh_exec_parallel")

        targets = select_targets(config, server_name, group_name)
        start = time.time()
        if name == "ssh_exec_parallel":
            max_parallel = arguments.get("max_parallel", 8)
            if not isinstance(max_parallel, int):
                raise MCPError(-32602, "'max_parallel' must be an integer")
            exec_out = _exec_targets_parallel(
                targets,
                command_obj,
                timeout_ms,
                max_parallel,
                config.logging,
                tool=name,
                request_id=request_id,
                group=group_name,
            )
        else:
            exec_out = _exec_targets_sequential(
                targets,
                command_obj,
                timeout_ms,
                config.logging,
                tool=name,
                request_id=request_id,
                group=group_name,
            )

        out = {
            "ok": exec_out["ok"],
            "command": command_obj,
            "targets": [t.name for t in targets],
            "elapsed_ms": int((time.time() - start) * 1000),
            "results": exec_out["results"],
        }
        return {
            "content": [
                {"type": "text", "text": json.dumps(out, ensure_ascii=False, indent=2)}
            ]
        }

    if name in {"ssh_upload", "ssh_delete"}:
        if name == "ssh_upload":
            local_path_arg = arguments.get("local_path")
            if not isinstance(local_path_arg, str) or not local_path_arg.strip():
                raise MCPError(-32602, "'local_path' must be a non-empty string")
        remote_path_arg = arguments.get("remote_path")
        if not isinstance(remote_path_arg, str) or not remote_path_arg.strip():
            raise MCPError(-32602, "'remote_path' must be a non-empty string")

        timeout_ms = arguments.get("timeout_ms")
        if timeout_ms is not None and not isinstance(timeout_ms, int):
            raise MCPError(-32602, "'timeout_ms' must be an integer")

        server_name_obj = arguments.get("server")
        server_name = (
            server_name_obj
            if isinstance(server_name_obj, str) and server_name_obj.strip()
            else None
        )
        group_name_obj = arguments.get("group")
        group_name = (
            group_name_obj
            if isinstance(group_name_obj, str) and group_name_obj.strip()
            else None
        )
        targets = select_targets(config, server_name, group_name)

        parallel = bool(arguments.get("parallel", False))
        max_parallel = arguments.get("max_parallel", 8)
        if not isinstance(max_parallel, int) or max_parallel <= 0:
            raise MCPError(-32602, "'max_parallel' must be a positive integer")

        started = time.time()
        results: Dict[str, Any] = {}
        ok = True

        def _upload_for(server: ServerConfig) -> Dict[str, Any]:
            return upload_file(
                server,
                local_path_arg,
                remote_path_arg,
                timeout_ms,
                make_dirs=bool(arguments.get("make_dirs", True)),
                overwrite=bool(arguments.get("overwrite", True)),
            )

        def _delete_for(server: ServerConfig) -> Dict[str, Any]:
            return delete_remote_path(
                server,
                remote_path_arg,
                timeout_ms,
                recursive=bool(arguments.get("recursive", False)),
                missing_ok=bool(arguments.get("missing_ok", False)),
            )

        def _run_one(server: ServerConfig) -> Dict[str, Any]:
            if name == "ssh_upload":
                return _upload_for(server)
            return _delete_for(server)

        if parallel and len(targets) > 1:
            with ThreadPoolExecutor(max_workers=min(max_parallel, len(targets))) as ex:
                fut_to_server = {ex.submit(_run_one, s): s for s in targets}
                for fut in as_completed(fut_to_server):
                    srv = fut_to_server[fut]
                    try:
                        res = fut.result()
                        results[srv.name] = res
                        event = {
                            "ts": utc_now_iso(),
                            "event": name,
                            "request_id": request_id,
                            "server": srv.name,
                            "host": srv.host,
                            "port": srv.port,
                            "user": srv.user,
                            "group": group_name,
                            "ok": True,
                            "elapsed_ms": res.get("elapsed_ms"),
                            "remote_path": arguments.get("remote_path"),
                        }
                        if name == "ssh_upload":
                            event["local_path"] = arguments.get("local_path")
                            event["bytes"] = res.get("bytes")
                        else:
                            event["removed"] = res.get("removed")
                        file_ops_log(config.file_ops_logging, event)
                    except Exception as exc:
                        ok = False
                        err = error_to_dict(exc)
                        results[srv.name] = {"error": err}
                        file_ops_log(
                            config.file_ops_logging,
                            {
                                "ts": utc_now_iso(),
                                "event": name,
                                "request_id": request_id,
                                "server": srv.name,
                                "host": srv.host,
                                "port": srv.port,
                                "user": srv.user,
                                "group": group_name,
                                "ok": False,
                                "remote_path": arguments.get("remote_path"),
                                "local_path": arguments.get("local_path")
                                if name == "ssh_upload"
                                else None,
                                "error": err,
                            },
                        )
        else:
            for srv in targets:
                try:
                    res = _run_one(srv)
                    results[srv.name] = res
                    event = {
                        "ts": utc_now_iso(),
                        "event": name,
                        "request_id": request_id,
                        "server": srv.name,
                        "host": srv.host,
                        "port": srv.port,
                        "user": srv.user,
                        "group": group_name,
                        "ok": True,
                        "elapsed_ms": res.get("elapsed_ms"),
                        "remote_path": arguments.get("remote_path"),
                    }
                    if name == "ssh_upload":
                        event["local_path"] = arguments.get("local_path")
                        event["bytes"] = res.get("bytes")
                    else:
                        event["removed"] = res.get("removed")
                    file_ops_log(config.file_ops_logging, event)
                except Exception as exc:
                    ok = False
                    err = error_to_dict(exc)
                    results[srv.name] = {"error": err}
                    file_ops_log(
                        config.file_ops_logging,
                        {
                            "ts": utc_now_iso(),
                            "event": name,
                            "request_id": request_id,
                            "server": srv.name,
                            "host": srv.host,
                            "port": srv.port,
                            "user": srv.user,
                            "group": group_name,
                            "ok": False,
                            "remote_path": arguments.get("remote_path"),
                            "local_path": arguments.get("local_path")
                            if name == "ssh_upload"
                            else None,
                            "error": err,
                        },
                    )

        out = {
            "ok": ok,
            "operation": name,
            "targets": [t.name for t in targets],
            "elapsed_ms": int((time.time() - started) * 1000),
            "results": results,
        }
        return {
            "content": [
                {"type": "text", "text": json.dumps(out, ensure_ascii=False, indent=2)}
            ]
        }

    raise MCPError(-32601, f"Unknown tool: {name}")
