import re
from dataclasses import dataclass
from typing import Any, Dict, Optional, Tuple

from mcp_ssh.errors import MCPError


@dataclass(frozen=True)
class CommandPolicy:
    allow: Tuple[str, ...] = ()
    deny: Tuple[str, ...] = ()

    def validate(self, command: str) -> None:
        if self.allow and not any(re.search(p, command) for p in self.allow):
            raise MCPError(
                -32602,
                "Command not allowed by allowlist policy",
                {"allow": list(self.allow)},
            )

        for pattern in self.deny:
            if re.search(pattern, command):
                raise MCPError(
                    -32602,
                    "Command blocked by denylist policy",
                    {"deny": list(self.deny), "matched": pattern},
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
    enabled: bool = True
    file: Optional[str] = None
    format: str = "jsonl"
    include_command: bool = True
    include_result: bool = True
    include_stdout: bool = False
    include_stderr: bool = False
    log_tests: bool = False


@dataclass(frozen=True)
class FileOpsLoggingConfig:
    enabled: bool = True
    file: Optional[str] = None
    format: str = "jsonl"


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
    file_ops_logging: FileOpsLoggingConfig
