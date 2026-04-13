import re
from typing import Any, Tuple

from mcp_ssh.errors import MCPError
from mcp_ssh.models import CommandPolicy


def as_str_tuple(value: Any, field_name: str) -> Tuple[str, ...]:
    if value is None:
        return ()
    if isinstance(value, list) and all(isinstance(x, str) for x in value):
        return tuple(value)
    raise MCPError(-32002, f"'{field_name}' must be a list of strings")


def load_policy(obj: Any, field_name: str) -> CommandPolicy:
    if obj is None:
        return CommandPolicy()
    if not isinstance(obj, dict):
        raise MCPError(-32002, f"'{field_name}' must be an object")

    allow = as_str_tuple(obj.get("allow"), f"{field_name}.allow")
    deny = as_str_tuple(obj.get("deny"), f"{field_name}.deny")

    try:
        for pattern in allow + deny:
            re.compile(pattern)
    except re.error as exc:
        raise MCPError(-32002, f"Invalid regex in '{field_name}': {exc}")

    return CommandPolicy(allow=allow, deny=deny)


def merge_policy(
    global_policy: CommandPolicy, server_policy: CommandPolicy
) -> CommandPolicy:
    return CommandPolicy(
        allow=global_policy.allow + server_policy.allow,
        deny=global_policy.deny + server_policy.deny,
    )
