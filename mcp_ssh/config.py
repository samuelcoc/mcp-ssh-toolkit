import json
import os
import shlex
from pathlib import Path
from typing import Any, Dict, Optional, Tuple

from mcp_ssh.errors import MCPError
from mcp_ssh.models import (
    Defaults,
    FileOpsLoggingConfig,
    LoggingConfig,
    MCPConfig,
    ServerConfig,
)
from mcp_ssh.policy import as_str_tuple, load_policy, merge_policy


def _expand_path(path_value: Optional[str]) -> Optional[str]:
    if not path_value:
        return None
    return str(Path(os.path.expandvars(os.path.expanduser(path_value))).resolve())


def _parse_password_command(value: Any) -> Optional[Tuple[str, ...]]:
    if value is None:
        return None
    if (
        isinstance(value, list)
        and value
        and all(isinstance(x, str) and x.strip() for x in value)
    ):
        return tuple(value)
    if isinstance(value, str) and value.strip():
        return tuple(shlex.split(value))
    raise MCPError(
        -32002,
        "'passwordCommand' must be a non-empty string or a non-empty string list",
    )


def load_config(config_path: str) -> MCPConfig:
    path = Path(config_path)
    if not path.exists():
        raise MCPError(-32002, f"Config file not found: {config_path}")

    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        raise MCPError(-32700, f"Invalid JSON in config: {exc}")

    version = raw.get("version", 1)
    if version != 1:
        raise MCPError(-32002, f"Unsupported config version: {version}")

    defaults_obj = raw.get("defaults", {}) or {}
    if not isinstance(defaults_obj, dict):
        raise MCPError(-32002, "'defaults' must be an object")

    defaults = Defaults(
        user=defaults_obj.get("user")
        if isinstance(defaults_obj.get("user"), str)
        else None,
        port=defaults_obj.get("port")
        if isinstance(defaults_obj.get("port"), int)
        else None,
        identity_file=_expand_path(defaults_obj.get("identityFile"))
        if isinstance(defaults_obj.get("identityFile"), str)
        else None,
        strict_host_key_checking=defaults_obj.get("strictHostKeyChecking")
        if isinstance(defaults_obj.get("strictHostKeyChecking"), str)
        else None,
        known_hosts_file=_expand_path(defaults_obj.get("knownHostsFile"))
        if isinstance(defaults_obj.get("knownHostsFile"), str)
        else None,
        extra_args=as_str_tuple(defaults_obj.get("extraArgs"), "defaults.extraArgs"),
    )

    global_policy = load_policy(raw.get("policy"), "policy")

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

        user = cfg.get("user", defaults.user)
        if user is not None and (not isinstance(user, str) or not user.strip()):
            raise MCPError(-32002, f"Server '{name}' has invalid 'user'")

        port = cfg.get("port", defaults.port)
        if port is not None and (not isinstance(port, int) or not (1 <= port <= 65535)):
            raise MCPError(-32002, f"Server '{name}' has invalid 'port'")

        identity_file = cfg.get("identityFile", defaults.identity_file)
        if identity_file is not None:
            if not isinstance(identity_file, str):
                raise MCPError(-32002, f"Server '{name}' has invalid 'identityFile'")
            identity_file = _expand_path(identity_file)

        strict = cfg.get("strictHostKeyChecking", defaults.strict_host_key_checking)
        if strict is not None and (not isinstance(strict, str) or not strict.strip()):
            raise MCPError(
                -32002, f"Server '{name}' has invalid 'strictHostKeyChecking'"
            )

        known_hosts = cfg.get("knownHostsFile", defaults.known_hosts_file)
        if known_hosts is not None:
            if not isinstance(known_hosts, str):
                raise MCPError(-32002, f"Server '{name}' has invalid 'knownHostsFile'")
            known_hosts = _expand_path(known_hosts)

        extra = cfg.get("extraArgs")
        if extra is None:
            extra_args = defaults.extra_args
        else:
            if not isinstance(extra, list) or any(
                not isinstance(x, str) for x in extra
            ):
                raise MCPError(
                    -32002,
                    f"Server '{name}' has invalid 'extraArgs' (must be string list)",
                )
            extra_args = tuple(extra)

        password = cfg.get("password")
        if password is not None and not isinstance(password, str):
            raise MCPError(-32002, f"Server '{name}' has invalid 'password'")

        password_env = cfg.get("passwordEnv")
        if password_env is not None and (
            not isinstance(password_env, str) or not password_env.strip()
        ):
            raise MCPError(-32002, f"Server '{name}' has invalid 'passwordEnv'")

        password_command = _parse_password_command(cfg.get("passwordCommand"))
        password_keyring = cfg.get("passwordKeyring")
        if password_keyring is not None and not isinstance(password_keyring, dict):
            raise MCPError(-32002, f"Server '{name}' has invalid 'passwordKeyring'")

        password_fields = [
            x
            for x in [password, password_env, password_command, password_keyring]
            if x is not None
        ]
        if len(password_fields) > 1:
            raise MCPError(
                -32002,
                f"Server '{name}' must set only one of password/passwordEnv/passwordCommand/passwordKeyring",
            )

        server_policy = load_policy(cfg.get("policy"), f"servers.{name}.policy")
        merged_policy = merge_policy(global_policy, server_policy)

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

    groups_obj = raw.get("groups", {}) or {}
    if not isinstance(groups_obj, dict):
        raise MCPError(-32002, "'groups' must be an object")

    groups: Dict[str, Tuple[str, ...]] = {}
    for group_name, members in groups_obj.items():
        if not isinstance(group_name, str) or not group_name.strip():
            raise MCPError(-32002, "Group names must be non-empty strings")
        if not isinstance(members, list) or any(
            not isinstance(x, str) or not x.strip() for x in members
        ):
            raise MCPError(
                -32002, f"Group '{group_name}' must be a list of server name strings"
            )
        if not members:
            raise MCPError(-32002, f"Group '{group_name}' must not be empty")
        unknown = [x for x in members if x not in servers]
        if unknown:
            raise MCPError(
                -32002, f"Group '{group_name}' references unknown servers: {unknown}"
            )
        groups[group_name] = tuple(members)

    default_server = raw.get("defaultServer")
    if default_server is not None:
        if not isinstance(default_server, str) or not default_server.strip():
            raise MCPError(-32002, "'defaultServer' must be a non-empty string")
        if default_server not in servers:
            raise MCPError(
                -32002, f"defaultServer not found in servers: {default_server}"
            )

    logging_obj = raw.get("logging") or {}
    if not isinstance(logging_obj, dict):
        raise MCPError(-32002, "'logging' must be an object")

    logging_enabled = bool(logging_obj.get("enabled", True))
    logging_disabled = os.environ.get("MCP_SSH_AUDIT_LOG_DISABLE") == "1"

    logging_file = logging_obj.get("file")
    if logging_file is not None and (
        not isinstance(logging_file, str) or not logging_file.strip()
    ):
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

    logging_cfg = LoggingConfig(
        enabled=logging_enabled,
        file=_expand_path(logging_file) if isinstance(logging_file, str) else None,
        format=logging_format,
        include_command=True,
        include_result=bool(logging_obj.get("includeResult", True)),
        include_stdout=bool(logging_obj.get("includeStdout", False)),
        include_stderr=bool(logging_obj.get("includeStderr", False)),
        log_tests=bool(logging_obj.get("logTests", False)),
    )

    file_ops_obj = raw.get("fileOpsLogging") or {}
    if not isinstance(file_ops_obj, dict):
        raise MCPError(-32002, "'fileOpsLogging' must be an object")

    file_ops_enabled = bool(file_ops_obj.get("enabled", True))
    file_ops_disabled = os.environ.get("MCP_SSH_FILEOPS_LOG_DISABLE") == "1"

    file_ops_file = file_ops_obj.get("file")
    if file_ops_file is not None and (
        not isinstance(file_ops_file, str) or not file_ops_file.strip()
    ):
        raise MCPError(-32002, "'fileOpsLogging.file' must be a non-empty string")

    env_file_ops_file = os.environ.get("MCP_SSH_FILEOPS_LOG_FILE")
    if env_file_ops_file and not file_ops_disabled:
        file_ops_enabled = True
        file_ops_file = env_file_ops_file

    if file_ops_disabled:
        file_ops_enabled = False

    if file_ops_enabled and not file_ops_file:
        file_ops_file = "~/.mcp-ssh-toolkit/file_ops.jsonl"

    file_ops_format = file_ops_obj.get("format", "jsonl")
    if not isinstance(file_ops_format, str) or not file_ops_format.strip():
        raise MCPError(-32002, "'fileOpsLogging.format' must be a string")
    if file_ops_format != "jsonl":
        raise MCPError(-32002, f"Unsupported fileOpsLogging.format: {file_ops_format}")

    file_ops_logging_cfg = FileOpsLoggingConfig(
        enabled=file_ops_enabled,
        file=_expand_path(file_ops_file) if isinstance(file_ops_file, str) else None,
        format=file_ops_format,
    )

    return MCPConfig(
        servers=servers,
        groups=groups,
        default_server=default_server,
        defaults=defaults,
        policy=global_policy,
        logging=logging_cfg,
        file_ops_logging=file_ops_logging_cfg,
    )
