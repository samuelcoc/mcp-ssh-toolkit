import getpass
import json
import os
import re
import shlex
import subprocess
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple


@dataclass(frozen=True)
class CommandPolicy:
    allow: Tuple[str, ...] = ()
    deny: Tuple[str, ...] = ()

    def validate(self, command: str) -> None:
        if self.allow:
            if not any(re.search(p, command) for p in self.allow):
                raise MCPError(
                    -32602,
                    "Command not allowed by allowlist policy",
                    {"allow": list(self.allow)},
                )
        if self.deny:
            for p in self.deny:
                if re.search(p, command):
                    raise MCPError(
                        -32602,
                        "Command blocked by denylist policy",
                        {"deny": list(self.deny), "matched": p},
                    )


@dataclass(frozen=True)
class Defaults:
    user: Optional[str] = None
    port: Optional[int] = None
    identity_file: Optional[str] = None
    strict_host_key_checking: Optional[str] = None
    known_hosts_file: Optional[str] = None
    extra_args: Tuple[str, ...] = ()


@dataclass(frozen=True)
class LoggingConfig:
    # Audit logging is ON by default. Disable explicitly if needed.
    enabled: bool = True
    file: Optional[str] = None
    format: str = "jsonl"

    # Audit details
    include_command: bool = True
    include_result: bool = True
    include_stdout: bool = False
    include_stderr: bool = False
    log_tests: bool = False


@dataclass(frozen=True)
class ServerConfig:
    name: str
    host: str
    user: Optional[str] = None
    port: Optional[int] = None
    identity_file: Optional[str] = None
    strict_host_key_checking: Optional[str] = None
    known_hosts_file: Optional[str] = None
    extra_args: Tuple[str, ...] = ()

    # Password-based auth options (prefer env/command, avoid plaintext in JSON)
    password: Optional[str] = None
    password_env: Optional[str] = None
    password_command: Optional[Tuple[str, ...]] = None
    password_keyring: Optional[Dict[str, str]] = None

    policy: CommandPolicy = CommandPolicy()


@dataclass(frozen=True)
class MCPConfig:
    servers: Dict[str, ServerConfig]
    groups: Dict[str, Tuple[str, ...]]
    default_server: Optional[str]
    defaults: Defaults
    policy: CommandPolicy
    logging: LoggingConfig


class MCPError(Exception):
    def __init__(self, code: int, message: str, data: Any = None):
        super().__init__(message)
        self.code = code
        self.message = message
        self.data = data


def _expand_path(p: Optional[str]) -> Optional[str]:
    if not p:
        return None
    return str(Path(os.path.expandvars(os.path.expanduser(p))).resolve())


def _as_str_tuple(v: Any, field_name: str) -> Tuple[str, ...]:
    if v is None:
        return ()
    if isinstance(v, list) and all(isinstance(x, str) for x in v):
        return tuple(v)
    raise MCPError(-32002, f"'{field_name}' must be a list of strings")


def _load_policy(obj: Any, field_name: str) -> CommandPolicy:
    if obj is None:
        return CommandPolicy()
    if not isinstance(obj, dict):
        raise MCPError(-32002, f"'{field_name}' must be an object")
    allow = _as_str_tuple(obj.get("allow"), f"{field_name}.allow")
    deny = _as_str_tuple(obj.get("deny"), f"{field_name}.deny")
    try:
        for p in allow + deny:
            re.compile(p)
    except re.error as e:
        raise MCPError(-32002, f"Invalid regex in '{field_name}': {e}")
    return CommandPolicy(allow=allow, deny=deny)


def _merge_policy(global_policy: CommandPolicy, server_policy: CommandPolicy) -> CommandPolicy:
    return CommandPolicy(
        allow=global_policy.allow + server_policy.allow,
        deny=global_policy.deny + server_policy.deny,
    )


def _parse_password_command(v: Any) -> Optional[Tuple[str, ...]]:
    if v is None:
        return None
    if isinstance(v, list) and v and all(isinstance(x, str) and x.strip() for x in v):
        return tuple(v)
    if isinstance(v, str) and v.strip():
        return tuple(shlex.split(v))
    raise MCPError(-32002, "'passwordCommand' must be a non-empty string or a non-empty string list")


def _resolve_password(server: ServerConfig) -> Optional[str]:
    if server.password is not None:
        return server.password

    if server.password_env:
        val = os.environ.get(server.password_env)
        if val is None:
            raise MCPError(-32002, f"passwordEnv not set for server '{server.name}': {server.password_env}")
        return val

    if server.password_command:
        try:
            completed = subprocess.run(
                list(server.password_command),
                text=True,
                capture_output=True,
                shell=False,
            )
        except Exception as e:
            raise MCPError(-32000, f"passwordCommand failed for server '{server.name}': {e}")

        if completed.returncode != 0:
            raise MCPError(
                -32000,
                f"passwordCommand returned non-zero for server '{server.name}'",
                {"exit_code": completed.returncode, "stderr": completed.stderr},
            )

        pwd = (completed.stdout or "").strip()
        if not pwd:
            raise MCPError(-32000, f"passwordCommand produced empty output for server '{server.name}'")
        return pwd

    if server.password_keyring:
        try:
            import keyring  # type: ignore
        except Exception:
            raise MCPError(-32002, "passwordKeyring requires 'keyring' (pip install keyring)")

        service = server.password_keyring.get("service")
        username = server.password_keyring.get("username")
        if not service or not username:
            raise MCPError(-32002, f"Server '{server.name}' passwordKeyring must include service and username")

        pwd = keyring.get_password(service, username)
        if not pwd:
            raise MCPError(-32000, f"No password found in keyring for server '{server.name}'")
        return pwd

    return None


def load_config(config_path: str) -> MCPConfig:
    path = Path(config_path)
    if not path.exists():
        raise MCPError(-32002, f"Config file not found: {config_path}")

    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except Exception as e:
        raise MCPError(-32700, f"Invalid JSON in config: {e}")

    version = raw.get("version", 1)
    if version != 1:
        raise MCPError(-32002, f"Unsupported config version: {version}")

    defaults_obj = raw.get("defaults", {})
    if defaults_obj is None:
        defaults_obj = {}
    if not isinstance(defaults_obj, dict):
        raise MCPError(-32002, "'defaults' must be an object")

    defaults = Defaults(
        user=defaults_obj.get("user") if isinstance(defaults_obj.get("user"), str) else None,
        port=defaults_obj.get("port") if isinstance(defaults_obj.get("port"), int) else None,
        identity_file=_expand_path(defaults_obj.get("identityFile")) if isinstance(defaults_obj.get("identityFile"), str) else None,
        strict_host_key_checking=defaults_obj.get("strictHostKeyChecking")
        if isinstance(defaults_obj.get("strictHostKeyChecking"), str)
        else None,
        known_hosts_file=_expand_path(defaults_obj.get("knownHostsFile")) if isinstance(defaults_obj.get("knownHostsFile"), str) else None,
        extra_args=_as_str_tuple(defaults_obj.get("extraArgs"), "defaults.extraArgs"),
    )

    global_policy = _load_policy(raw.get("policy"), "policy")

    servers_obj = raw.get("servers")
    if not isinstance(servers_obj, dict) or not servers_obj:
        raise MCPError(-32002, "Config must contain non-empty 'servers' object")

    servers: Dict[str, ServerConfig] = {}
    for name, cfg in servers_obj.items():
        if not isinstance(name, str) or not name.strip():
            raise MCPError(-32002, "Server names must be non-empty strings")
        if not isinstance(cfg, dict):
            raise MCPError(-32002, f"Server '{name}' must be an object")

        host = cfg.get("host")
        if not isinstance(host, str) or not host.strip():
            raise MCPError(-32002, f"Server '{name}' missing valid 'host'")

        user = cfg.get("user")
        if user is None:
            user = defaults.user
        if user is not None and (not isinstance(user, str) or not user.strip()):
            raise MCPError(-32002, f"Server '{name}' has invalid 'user'")

        port = cfg.get("port")
        if port is None:
            port = defaults.port
        if port is not None:
            if not isinstance(port, int) or not (1 <= port <= 65535):
                raise MCPError(-32002, f"Server '{name}' has invalid 'port'")

        identity_file = cfg.get("identityFile")
        if identity_file is None:
            identity_file = defaults.identity_file
        else:
            if identity_file is not None and not isinstance(identity_file, str):
                raise MCPError(-32002, f"Server '{name}' has invalid 'identityFile'")
            identity_file = _expand_path(identity_file)

        strict = cfg.get("strictHostKeyChecking")
        if strict is None:
            strict = defaults.strict_host_key_checking
        if strict is not None and (not isinstance(strict, str) or not strict.strip()):
            raise MCPError(-32002, f"Server '{name}' has invalid 'strictHostKeyChecking'")

        known_hosts = cfg.get("knownHostsFile")
        if known_hosts is None:
            known_hosts = defaults.known_hosts_file
        else:
            if known_hosts is not None and not isinstance(known_hosts, str):
                raise MCPError(-32002, f"Server '{name}' has invalid 'knownHostsFile'")
            known_hosts = _expand_path(known_hosts)

        extra = cfg.get("extraArgs", None)
        if extra is None:
            extra_args = defaults.extra_args
        else:
            if not isinstance(extra, list) or any(not isinstance(x, str) for x in extra):
                raise MCPError(-32002, f"Server '{name}' has invalid 'extraArgs' (must be string list)")
            extra_args = tuple(extra)

        password = cfg.get("password")
        if password is not None and not isinstance(password, str):
            raise MCPError(-32002, f"Server '{name}' has invalid 'password'")

        password_env = cfg.get("passwordEnv")
        if password_env is not None and (not isinstance(password_env, str) or not password_env.strip()):
            raise MCPError(-32002, f"Server '{name}' has invalid 'passwordEnv'")

        password_command = _parse_password_command(cfg.get("passwordCommand"))

        password_keyring = cfg.get("passwordKeyring")
        if password_keyring is not None and not isinstance(password_keyring, dict):
            raise MCPError(-32002, f"Server '{name}' has invalid 'passwordKeyring'")

        password_fields = [x for x in [password, password_env, password_command, password_keyring] if x is not None]
        if len(password_fields) > 1:
            raise MCPError(
                -32002,
                f"Server '{name}' must set only one of password/passwordEnv/passwordCommand/passwordKeyring",
            )

        server_policy = _load_policy(cfg.get("policy"), f"servers.{name}.policy")
        merged_policy = _merge_policy(global_policy, server_policy)

        servers[name] = ServerConfig(
            name=name,
            host=host,
            user=user,
            port=port,
            identity_file=identity_file,
            strict_host_key_checking=strict,
            known_hosts_file=known_hosts,
            extra_args=extra_args,
            password=password,
            password_env=password_env,
            password_command=password_command,
            password_keyring=password_keyring,
            policy=merged_policy,
        )

    groups_obj = raw.get("groups", {})
    if groups_obj is None:
        groups_obj = {}
    if not isinstance(groups_obj, dict):
        raise MCPError(-32002, "'groups' must be an object")

    groups: Dict[str, Tuple[str, ...]] = {}
    for group_name, members in groups_obj.items():
        if not isinstance(group_name, str) or not group_name.strip():
            raise MCPError(-32002, "Group names must be non-empty strings")
        if not isinstance(members, list) or any(not isinstance(x, str) or not x.strip() for x in members):
            raise MCPError(-32002, f"Group '{group_name}' must be a list of server name strings")
        if not members:
            raise MCPError(-32002, f"Group '{group_name}' must not be empty")

        unknown = [x for x in members if x not in servers]
        if unknown:
            raise MCPError(-32002, f"Group '{group_name}' references unknown servers: {unknown}")

        groups[group_name] = tuple(members)

    default_server = raw.get("defaultServer")
    if default_server is not None:
        if not isinstance(default_server, str) or not default_server.strip():
            raise MCPError(-32002, "'defaultServer' must be a non-empty string")
        if default_server not in servers:
            raise MCPError(-32002, f"defaultServer not found in servers: {default_server}")

    logging_obj = raw.get("logging")
    if logging_obj is None:
        logging_obj = {}
    if not isinstance(logging_obj, dict):
        raise MCPError(-32002, "'logging' must be an object")

    # Audit logging is enabled by default; disable explicitly.
    logging_enabled = bool(logging_obj.get("enabled", True))
    logging_disabled = os.environ.get("MCP_SSH_AUDIT_LOG_DISABLE") == "1"

    logging_file = logging_obj.get("file")
    if logging_file is not None and (not isinstance(logging_file, str) or not logging_file.strip()):
        raise MCPError(-32002, "'logging.file' must be a non-empty string")

    env_log_file = os.environ.get("MCP_SSH_AUDIT_LOG_FILE")
    if env_log_file and not logging_disabled:
        logging_enabled = True
        logging_file = env_log_file

    if logging_disabled:
        logging_enabled = False

    if logging_enabled and not logging_file:
        logging_file = "~/.mcp-ssh-toolkit/audit.jsonl"

    logging_format = logging_obj.get("format", "jsonl")
    if not isinstance(logging_format, str) or not logging_format.strip():
        raise MCPError(-32002, "'logging.format' must be a string")
    if logging_format != "jsonl":
        raise MCPError(-32002, f"Unsupported logging.format: {logging_format}")

    # Command logging is mandatory when audit logging is enabled.
    include_command = True
    include_result = bool(logging_obj.get("includeResult", True))
    include_stdout = bool(logging_obj.get("includeStdout", False))
    include_stderr = bool(logging_obj.get("includeStderr", False))
    log_tests = bool(logging_obj.get("logTests", False))

    logging_cfg = LoggingConfig(
        enabled=logging_enabled,
        file=_expand_path(logging_file) if isinstance(logging_file, str) else None,
        format=logging_format,
        include_command=include_command,
        include_result=include_result,
        include_stdout=include_stdout,
        include_stderr=include_stderr,
        log_tests=log_tests,
    )

    return MCPConfig(
        servers=servers,
        groups=groups,
        default_server=default_server,
        defaults=defaults,
        policy=global_policy,
        logging=logging_cfg,
    )


def ssh_command_args(server: ServerConfig, remote_command: str) -> List[str]:
    args: List[str] = ["ssh"]

    args += ["-o", "ConnectTimeout=10"]

    if server.port is not None:
        args += ["-p", str(server.port)]

    if server.identity_file:
        args += ["-i", server.identity_file]

    strict = server.strict_host_key_checking or "yes"
    args += ["-o", f"StrictHostKeyChecking={strict}"]

    if server.known_hosts_file:
        args += ["-o", f"UserKnownHostsFile={server.known_hosts_file}"]

    if server.extra_args:
        args += list(server.extra_args)

    target = server.host
    if server.user:
        target = f"{server.user}@{target}"

    args += [target, "--", remote_command]
    return args


def _strict_policy_value(v: Optional[str]) -> str:
    if not v:
        return "yes"
    return v.strip().lower()


def _safe_server_info(server: ServerConfig) -> Dict[str, Any]:
    auth = "key"
    if server.password_env:
        auth = "passwordEnv"
    elif server.password_command:
        auth = "passwordCommand"
    elif server.password_keyring:
        auth = "passwordKeyring"
    elif server.password is not None:
        auth = "password"

    return {
        "name": server.name,
        "host": server.host,
        "port": server.port,
        "user": server.user,
        "identityFile": server.identity_file,
        "strictHostKeyChecking": server.strict_host_key_checking,
        "knownHostsFile": server.known_hosts_file,
        "extraArgs": list(server.extra_args),
        "auth": auth,
        "policy": {"allow": list(server.policy.allow), "deny": list(server.policy.deny)},
    }


def _error_to_dict(e: Exception) -> Dict[str, Any]:
    if isinstance(e, MCPError):
        d: Dict[str, Any] = {"code": e.code, "message": e.message}
        if e.data is not None:
            d["data"] = e.data
        return d
    return {"code": -32000, "message": str(e)}


_AUDIT_LOCK = threading.Lock()


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def _audit_log(logging_cfg: LoggingConfig, event: Dict[str, Any]) -> None:
    if not logging_cfg.enabled:
        return
    if logging_cfg.format != "jsonl":
        return
    if not logging_cfg.file:
        return

    try:
        log_path = Path(logging_cfg.file)
        log_path.parent.mkdir(parents=True, exist_ok=True)
        line = json.dumps(event, ensure_ascii=False)
        with _AUDIT_LOCK:
            with log_path.open("a", encoding="utf-8") as f:
                f.write(line + "\n")
    except Exception:
        # Never break the MCP flow because of logging errors.
        return


def _paramiko_exec(server: ServerConfig, password: str, command: str, timeout_s: Optional[float]) -> Dict[str, Any]:
    try:
        import paramiko  # type: ignore
    except Exception:
        raise MCPError(-32002, "Password auth requires 'paramiko' (pip install paramiko) or switch to key-based auth")

    username = server.user or getpass.getuser()
    port = server.port or 22

    client = paramiko.SSHClient()

    kh_policy = _strict_policy_value(server.strict_host_key_checking)
    if kh_policy in {"yes", "true"}:
        client.set_missing_host_key_policy(paramiko.RejectPolicy())
    else:
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    if server.known_hosts_file:
        try:
            client.load_host_keys(server.known_hosts_file)
        except Exception:
            pass
    else:
        try:
            client.load_system_host_keys()
        except Exception:
            pass

    try:
        client.connect(
            hostname=server.host,
            port=port,
            username=username,
            password=password,
            key_filename=server.identity_file,
            allow_agent=True,
            look_for_keys=(server.identity_file is None),
            timeout=timeout_s,
            banner_timeout=timeout_s,
            auth_timeout=timeout_s,
        )

        stdin, stdout, stderr = client.exec_command(command, timeout=timeout_s)
        out_text = stdout.read().decode("utf-8", errors="replace")
        err_text = stderr.read().decode("utf-8", errors="replace")
        exit_code = stdout.channel.recv_exit_status()

        if server.known_hosts_file and kh_policy not in {"yes", "true"}:
            try:
                client.save_host_keys(server.known_hosts_file)
            except Exception:
                pass

    except Exception as e:
        raise MCPError(-32000, f"SSH (paramiko) failed: {e}")
    finally:
        try:
            client.close()
        except Exception:
            pass

    return {
        "exit_code": int(exit_code),
        "stdout": out_text,
        "stderr": err_text,
        "transport": "paramiko",
        "host": server.host,
        "port": port,
        "user": username,
    }


def run_ssh(server: ServerConfig, command: str, timeout_ms: Optional[int]) -> Dict[str, Any]:
    server.policy.validate(command)

    timeout_s = None
    if timeout_ms is not None:
        if not isinstance(timeout_ms, int) or timeout_ms <= 0:
            raise MCPError(-32602, "'timeout_ms' must be a positive integer")
        timeout_s = timeout_ms / 1000.0

    password = _resolve_password(server)

    start = time.time()
    if password is not None:
        res = _paramiko_exec(server, password, command, timeout_s)
        res["elapsed_ms"] = int((time.time() - start) * 1000)
        return res

    args = ssh_command_args(server, command)

    try:
        completed = subprocess.run(
            args,
            text=True,
            capture_output=True,
            timeout=timeout_s,
        )
    except FileNotFoundError:
        raise MCPError(-32002, "'ssh' executable not found on PATH")
    except subprocess.TimeoutExpired:
        raise MCPError(-32000, f"SSH command timed out after {timeout_ms}ms")

    return {
        "exit_code": completed.returncode,
        "stdout": completed.stdout,
        "stderr": completed.stderr,
        "ssh_args": " ".join(shlex.quote(a) for a in args),
        "transport": "openssh",
        "elapsed_ms": int((time.time() - start) * 1000),
    }


def ssh_test(server: ServerConfig, timeout_ms: Optional[int]) -> Dict[str, Any]:
    timeout_s = None
    if timeout_ms is not None:
        if not isinstance(timeout_ms, int) or timeout_ms <= 0:
            raise MCPError(-32602, "'timeout_ms' must be a positive integer")
        timeout_s = timeout_ms / 1000.0

    password = _resolve_password(server)

    start = time.time()
    if password is not None:
        try:
            import paramiko  # type: ignore
        except Exception:
            raise MCPError(-32002, "Password auth requires 'paramiko' (pip install paramiko)")

        username = server.user or getpass.getuser()
        port = server.port or 22
        client = paramiko.SSHClient()
        kh_policy = _strict_policy_value(server.strict_host_key_checking)
        if kh_policy in {"yes", "true"}:
            client.set_missing_host_key_policy(paramiko.RejectPolicy())
        else:
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        if server.known_hosts_file:
            try:
                client.load_host_keys(server.known_hosts_file)
            except Exception:
                pass

        err = ""
        try:
            client.connect(
                hostname=server.host,
                port=port,
                username=username,
                password=password,
                key_filename=server.identity_file,
                allow_agent=True,
                look_for_keys=(server.identity_file is None),
                timeout=timeout_s,
                banner_timeout=timeout_s,
                auth_timeout=timeout_s,
            )
            ok = True
        except Exception as e:
            ok = False
            err = str(e)
        finally:
            try:
                client.close()
            except Exception:
                pass

        out: Dict[str, Any] = {
            "ok": ok,
            "transport": "paramiko",
            "elapsed_ms": int((time.time() - start) * 1000),
        }
        if not ok:
            out["error"] = err
        return out

    args = ssh_command_args(server, "true")
    err = ""
    try:
        completed = subprocess.run(
            args,
            text=True,
            capture_output=True,
            timeout=timeout_s,
        )
        ok = completed.returncode == 0
    except Exception as e:
        ok = False
        completed = None
        err = str(e)

    out2: Dict[str, Any] = {
        "ok": ok,
        "transport": "openssh",
        "elapsed_ms": int((time.time() - start) * 1000),
    }
    if completed is not None:
        out2["exit_code"] = completed.returncode
        out2["stderr"] = completed.stderr
    else:
        out2["error"] = err
    return out2


def jsonrpc_result(id_value: Any, result: Any) -> Dict[str, Any]:
    return {"jsonrpc": "2.0", "id": id_value, "result": result}


def jsonrpc_error(id_value: Any, code: int, message: str, data: Any = None) -> Dict[str, Any]:
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


def _select_targets(config: MCPConfig, server_name: Optional[str], group_name: Optional[str]) -> List[ServerConfig]:
    if server_name and group_name:
        raise MCPError(-32602, "Provide only one of 'server' or 'group'")

    if group_name:
        if group_name not in config.groups:
            raise MCPError(-32602, f"Unknown group: {group_name}")
        members = config.groups[group_name]
        return [config.servers[m] for m in members]

    if server_name:
        if server_name not in config.servers:
            raise MCPError(-32602, f"Unknown server: {server_name}")
        return [config.servers[server_name]]

    if config.default_server:
        return [config.servers[config.default_server]]

    raise MCPError(-32602, "Missing 'server' or 'group' (and no defaultServer configured)")


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
                                {"type": "array", "items": {"type": "string"}}
                            ]
                        },
                        "passwordKeyring": {
                            "type": "object",
                            "properties": {
                                "service": {"type": "string"},
                                "username": {"type": "string"}
                            },
                            "required": ["service", "username"],
                            "additionalProperties": False
                        },
                        "groups": {"type": "array", "items": {"type": "string"}},
                        "setDefault": {"type": "boolean"}
                    },
                    "required": ["server", "host"],
                    "additionalProperties": False
                }
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
        ]
    }


def _handle_ssh_list(config: MCPConfig) -> Dict[str, Any]:
    return {
        "defaultServer": config.default_server,
        "servers": sorted(config.servers.keys()),
        "groups": {k: list(v) for k, v in sorted(config.groups.items(), key=lambda kv: kv[0])},
        "defaults": {
            "user": config.defaults.user,
            "port": config.defaults.port,
            "identityFile": config.defaults.identity_file,
            "strictHostKeyChecking": config.defaults.strict_host_key_checking,
            "knownHostsFile": config.defaults.known_hosts_file,
            "extraArgs": list(config.defaults.extra_args),
        },
        "policy": {"allow": list(config.policy.allow), "deny": list(config.policy.deny)},
    }


def _handle_ssh_info(config: MCPConfig, arguments: Dict[str, Any]) -> Dict[str, Any]:
    server_name = arguments.get("server")
    if not isinstance(server_name, str) or not server_name.strip():
        raise MCPError(-32602, "'server' must be a non-empty string")
    server = config.servers.get(server_name)
    if server is None:
        raise MCPError(-32602, f"Unknown server: {server_name}")
    return _safe_server_info(server)


def _load_config_json(config_path: str) -> Dict[str, Any]:
    path = Path(config_path)
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception as e:
        raise MCPError(-32700, f"Invalid JSON in config: {e}")


def _atomic_write_json(config_path: str, data: Dict[str, Any]) -> None:
    path = Path(config_path)
    tmp_path = path.with_suffix(path.suffix + ".tmp")
    tmp_path.write_text(json.dumps(data, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    os.replace(str(tmp_path), str(path))


def _atomic_write_and_validate_config(config_path: str, data: Dict[str, Any]) -> None:
    path = Path(config_path)
    tmp_path = path.with_suffix(path.suffix + ".tmp")

    tmp_path.write_text(json.dumps(data, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")

    # Validate BEFORE replacing the real config.
    _ = load_config(str(tmp_path))

    os.replace(str(tmp_path), str(path))


def _handle_ssh_add_server(config_path: str, arguments: Dict[str, Any]) -> Dict[str, Any]:
    name = arguments.get("server")
    host = arguments.get("host")
    if not isinstance(name, str) or not name.strip():
        raise MCPError(-32602, "'server' must be a non-empty string")
    if not isinstance(host, str) or not host.strip():
        raise MCPError(-32602, "'host' must be a non-empty string")

    # Disallow plaintext password by default. Enable only in lab via env.
    if "password" in arguments and os.environ.get("MCP_SSH_ALLOW_PLAINTEXT_PASSWORD") != "1":
        raise MCPError(-32602, "Plaintext 'password' is disabled; use passwordEnv/passwordCommand/passwordKeyring")

    raw = _load_config_json(config_path)
    if raw.get("version", 1) != 1:
        raise MCPError(-32002, "Unsupported config version")

    servers = raw.get("servers")
    if not isinstance(servers, dict):
        raw["servers"] = {}
        servers = raw["servers"]

    server_obj: Dict[str, Any] = dict(servers.get(name, {})) if isinstance(servers.get(name), dict) else {}
    server_obj["host"] = host

    for k in ["port", "user", "identityFile", "strictHostKeyChecking", "knownHostsFile", "extraArgs", "passwordEnv", "passwordCommand", "passwordKeyring"]:
        if k in arguments and arguments[k] is not None:
            server_obj[k] = arguments[k]

    servers[name] = server_obj

    groups = raw.get("groups")
    if groups is None:
        groups = {}
        raw["groups"] = groups
    if not isinstance(groups, dict):
        raise MCPError(-32002, "'groups' must be an object")

    group_list = arguments.get("groups")
    if group_list is not None:
        if not isinstance(group_list, list) or any(not isinstance(g, str) or not g.strip() for g in group_list):
            raise MCPError(-32602, "'groups' must be a list of strings")
        for g in group_list:
            members = groups.get(g, [])
            if members is None:
                members = []
            if not isinstance(members, list):
                raise MCPError(-32002, f"Group '{g}' must be a list")
            if name not in members:
                members.append(name)
            groups[g] = members

    if arguments.get("setDefault") is True:
        raw["defaultServer"] = name

    _atomic_write_and_validate_config(config_path, raw)

    return {
        "ok": True,
        "server": name,
        "written": True,
    }


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

            event: Dict[str, Any] = {
                "ts": _utc_now_iso(),
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
            _audit_log(logging_cfg, event)

        except Exception as e:
            ok = False
            results[server.name] = {"error": _error_to_dict(e)}

            event2: Dict[str, Any] = {
                "ts": _utc_now_iso(),
                "event": tool,
                "request_id": request_id,
                "server": server.name,
                "host": server.host,
                "port": server.port,
                "user": server.user,
                "group": group,
                "ok": False,
                "elapsed_ms": int((time.time() - start) * 1000),
                "error": _error_to_dict(e),
            }
            if logging_cfg.include_command:
                event2["command"] = command
            _audit_log(logging_cfg, event2)

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
    results: Dict[str, Any] = {}
    ok = True

    if max_parallel <= 0:
        raise MCPError(-32602, "'max_parallel' must be a positive integer")

    start_by_name: Dict[str, float] = {s.name: time.time() for s in targets}

    with ThreadPoolExecutor(max_workers=max_parallel) as ex:
        fut_to_server = {ex.submit(run_ssh, s, command, timeout_ms): s for s in targets}
        for fut in as_completed(fut_to_server):
            server = fut_to_server[fut]
            started = start_by_name.get(server.name, time.time())
            try:
                res = fut.result()
                results[server.name] = res
                exit_code = res.get("exit_code")
                if exit_code != 0:
                    ok = False

                event: Dict[str, Any] = {
                    "ts": _utc_now_iso(),
                    "event": tool,
                    "request_id": request_id,
                    "server": server.name,
                    "host": server.host,
                    "port": server.port,
                    "user": server.user,
                    "group": group,
                    "ok": exit_code == 0,
                    "elapsed_ms": int((time.time() - started) * 1000),
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
                _audit_log(logging_cfg, event)

            except Exception as e:
                ok = False
                results[server.name] = {"error": _error_to_dict(e)}

                event2: Dict[str, Any] = {
                    "ts": _utc_now_iso(),
                    "event": tool,
                    "request_id": request_id,
                    "server": server.name,
                    "host": server.host,
                    "port": server.port,
                    "user": server.user,
                    "group": group,
                    "ok": False,
                    "elapsed_ms": int((time.time() - started) * 1000),
                    "error": _error_to_dict(e),
                }
                if logging_cfg.include_command:
                    event2["command"] = command
                _audit_log(logging_cfg, event2)

    return {"ok": ok, "results": results}


def handle_tools_call(config_state: Dict[str, Any], config_path: str, params: Dict[str, Any], *, request_id: Any) -> Dict[str, Any]:
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
        out = {"ok": True, "reloaded": True}
        return {"content": [{"type": "text", "text": json.dumps(out, ensure_ascii=False, indent=2)}]}

    if name == "ssh_add_server":
        out = _handle_ssh_add_server(config_path, arguments)
        # Reload so follow-up calls see the new server.
        config_state["config"] = load_config(config_path)
        try:
            config_state["mtime_ns"] = Path(config_path).stat().st_mtime_ns
        except Exception:
            config_state["mtime_ns"] = 0
        return {"content": [{"type": "text", "text": json.dumps(out, ensure_ascii=False, indent=2)}]}

    if name == "ssh_list":
        out = _handle_ssh_list(config)
        return {"content": [{"type": "text", "text": json.dumps(out, ensure_ascii=False, indent=2)}]}

    if name == "ssh_info":
        out = _handle_ssh_info(config, arguments)
        return {"content": [{"type": "text", "text": json.dumps(out, ensure_ascii=False, indent=2)}]}

    if name == "ssh_test":
        timeout_ms = arguments.get("timeout_ms")
        if timeout_ms is not None and not isinstance(timeout_ms, int):
            raise MCPError(-32602, "'timeout_ms' must be an integer")

        server_name_obj = arguments.get("server")
        server_name = server_name_obj if isinstance(server_name_obj, str) and server_name_obj.strip() else None

        group_name_obj = arguments.get("group")
        group_name = group_name_obj if isinstance(group_name_obj, str) and group_name_obj.strip() else None

        targets = _select_targets(config, server_name, group_name)
        results: Dict[str, Any] = {}
        ok = True
        for s in targets:
            start_s = time.time()
            try:
                r = ssh_test(s, timeout_ms)
                results[s.name] = r
                if not r.get("ok"):
                    ok = False

                if config.logging.log_tests:
                    ev: Dict[str, Any] = {
                        "ts": _utc_now_iso(),
                        "event": "ssh_test",
                        "request_id": request_id,
                        "server": s.name,
                        "host": s.host,
                        "port": s.port,
                        "user": s.user,
                        "group": group_name,
                        "ok": bool(r.get("ok")),
                        "elapsed_ms": int((time.time() - start_s) * 1000),
                        "transport": r.get("transport"),
                    }
                    if config.logging.include_result and "exit_code" in r:
                        ev["exit_code"] = r.get("exit_code")
                    if config.logging.include_stderr and "stderr" in r:
                        ev["stderr"] = r.get("stderr")
                    _audit_log(config.logging, ev)

            except Exception as e:
                ok = False
                results[s.name] = {"error": _error_to_dict(e)}

                if config.logging.log_tests:
                    ev2: Dict[str, Any] = {
                        "ts": _utc_now_iso(),
                        "event": "ssh_test",
                        "request_id": request_id,
                        "server": s.name,
                        "host": s.host,
                        "port": s.port,
                        "user": s.user,
                        "group": group_name,
                        "ok": False,
                        "elapsed_ms": int((time.time() - start_s) * 1000),
                        "error": _error_to_dict(e),
                    }
                    _audit_log(config.logging, ev2)

        out = {"ok": ok, "targets": [t.name for t in targets], "results": results}
        return {"content": [{"type": "text", "text": json.dumps(out, ensure_ascii=False, indent=2)}]}

    if name in {"ssh_exec", "ssh_exec_parallel"}:
        command_obj = arguments.get("command")
        if not isinstance(command_obj, str) or not command_obj.strip():
            raise MCPError(-32602, "'command' must be a non-empty string")
        command = command_obj

        timeout_ms = arguments.get("timeout_ms")
        if timeout_ms is not None and not isinstance(timeout_ms, int):
            raise MCPError(-32602, "'timeout_ms' must be an integer")

        server_name_obj = arguments.get("server")
        server_name = server_name_obj if isinstance(server_name_obj, str) and server_name_obj.strip() else None

        group_name_obj = arguments.get("group")
        group_name = group_name_obj if isinstance(group_name_obj, str) and group_name_obj.strip() else None

        if name == "ssh_exec_parallel":
            if not group_name:
                raise MCPError(-32602, "'group' is required for ssh_exec_parallel")

        targets = _select_targets(config, server_name, group_name)

        logging_cfg = config.logging

        start = time.time()
        if name == "ssh_exec_parallel":
            max_parallel = arguments.get("max_parallel", 8)
            if not isinstance(max_parallel, int):
                raise MCPError(-32602, "'max_parallel' must be an integer")
            exec_out = _exec_targets_parallel(
                targets,
                command,
                timeout_ms,
                max_parallel,
                logging_cfg,
                tool=name,
                request_id=request_id,
                group=group_name,
            )
        else:
            exec_out = _exec_targets_sequential(
                targets,
                command,
                timeout_ms,
                logging_cfg,
                tool=name,
                request_id=request_id,
                group=group_name,
            )

        out = {
            "ok": exec_out["ok"],
            "command": command,
            "targets": [t.name for t in targets],
            "elapsed_ms": int((time.time() - start) * 1000),
            "results": exec_out["results"],
        }
        return {"content": [{"type": "text", "text": json.dumps(out, ensure_ascii=False, indent=2)}]}

    raise MCPError(-32601, f"Unknown tool: {name}")


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
    except MCPError as e:
        sys.stderr.write(f"mcp-ssh: {e.message}\n")
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

        if force or (current_mtime_ns and current_mtime_ns != config_state.get("mtime_ns")):
            config_state["config"] = load_config(config_path)
            config_state["mtime_ns"] = current_mtime_ns

    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue

        try:
            msg = json.loads(line)
        except Exception as e:
            # Claude Desktop's MCP parser doesn't accept id=null.
            sys.stdout.write(json.dumps(jsonrpc_error(0, -32700, f"Parse error: {e}")) + "\n")
            sys.stdout.flush()
            continue

        has_id = "id" in msg
        raw_id = msg.get("id") if has_id else None
        id_value = raw_id if isinstance(raw_id, (str, int)) else 0

        method = msg.get("method")
        params = msg.get("params")

        # If this is a notification (no id), do not respond.
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
                out = handle_tools_call(config_state, config_path, params, request_id=id_value)
                sys.stdout.write(json.dumps(jsonrpc_result(id_value, out)) + "\n")
            else:
                raise MCPError(-32601, f"Method not found: {method}")

        except MCPError as e:
            sys.stdout.write(json.dumps(jsonrpc_error(id_value, e.code, e.message, e.data)) + "\n")

        except Exception as e:
            sys.stdout.write(json.dumps(jsonrpc_error(id_value, -32000, "Internal error", str(e))) + "\n")

        sys.stdout.flush()

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
