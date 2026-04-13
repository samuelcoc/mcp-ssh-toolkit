import getpass
import os
import posixpath
import shlex
import stat as statmod
import subprocess
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

from mcp_ssh.errors import MCPError
from mcp_ssh.models import ServerConfig


def _resolve_password(server: ServerConfig) -> Optional[str]:
    if server.password is not None:
        return server.password

    if server.password_env:
        val = os.environ.get(server.password_env)
        if val is None:
            raise MCPError(
                -32002,
                f"passwordEnv not set for server '{server.name}': {server.password_env}",
            )
        return val

    if server.password_command:
        try:
            completed = subprocess.run(
                list(server.password_command),
                text=True,
                capture_output=True,
                shell=False,
            )
        except Exception as exc:
            raise MCPError(
                -32000, f"passwordCommand failed for server '{server.name}': {exc}"
            )

        if completed.returncode != 0:
            raise MCPError(
                -32000,
                f"passwordCommand returned non-zero for server '{server.name}'",
                {"exit_code": completed.returncode, "stderr": completed.stderr},
            )

        pwd = (completed.stdout or "").strip()
        if not pwd:
            raise MCPError(
                -32000,
                f"passwordCommand produced empty output for server '{server.name}'",
            )
        return pwd

    if server.password_keyring:
        try:
            import keyring  # type: ignore
        except Exception:
            raise MCPError(
                -32002, "passwordKeyring requires 'keyring' (pip install keyring)"
            )

        service = server.password_keyring.get("service")
        username = server.password_keyring.get("username")
        if not service or not username:
            raise MCPError(
                -32002,
                f"Server '{server.name}' passwordKeyring must include service and username",
            )

        pwd = keyring.get_password(service, username)
        if not pwd:
            raise MCPError(
                -32000, f"No password found in keyring for server '{server.name}'"
            )
        return pwd

    return None


def ssh_command_args(server: ServerConfig, remote_command: str) -> List[str]:
    args: List[str] = ["ssh", "-o", "ConnectTimeout=10"]

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

    target = f"{server.user}@{server.host}" if server.user else server.host
    args += [target, "--", remote_command]
    return args


def _strict_policy_value(value: Optional[str]) -> str:
    return "yes" if not value else value.strip().lower()


def safe_server_info(server: ServerConfig) -> Dict[str, Any]:
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
        "policy": {
            "allow": list(server.policy.allow),
            "deny": list(server.policy.deny),
        },
    }


def _paramiko_exec(
    server: ServerConfig, password: str, command: str, timeout_s: Optional[float]
) -> Dict[str, Any]:
    try:
        import paramiko  # type: ignore
    except Exception:
        raise MCPError(
            -32002,
            "Password auth requires 'paramiko' (pip install paramiko) or switch to key-based auth",
        )

    username = server.user or getpass.getuser()
    port = server.port or 22
    client = paramiko.SSHClient()

    if _strict_policy_value(server.strict_host_key_checking) in {"yes", "true"}:
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
        _, stdout, stderr = client.exec_command(command, timeout=timeout_s)
        out_text = stdout.read().decode("utf-8", errors="replace")
        err_text = stderr.read().decode("utf-8", errors="replace")
        exit_code = stdout.channel.recv_exit_status()
    except Exception as exc:
        raise MCPError(-32000, f"SSH (paramiko) failed: {exc}")
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


def run_ssh(
    server: ServerConfig, command: str, timeout_ms: Optional[int]
) -> Dict[str, Any]:
    server.policy.validate(command)

    timeout_s = None
    if timeout_ms is not None:
        if not isinstance(timeout_ms, int) or timeout_ms <= 0:
            raise MCPError(-32602, "'timeout_ms' must be a positive integer")
        timeout_s = timeout_ms / 1000.0

    password = _resolve_password(server)
    start = time.time()

    if password is not None:
        out = _paramiko_exec(server, password, command, timeout_s)
        out["elapsed_ms"] = int((time.time() - start) * 1000)
        return out

    args = ssh_command_args(server, command)
    try:
        completed = subprocess.run(
            args, text=True, capture_output=True, timeout=timeout_s
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
            raise MCPError(
                -32002, "Password auth requires 'paramiko' (pip install paramiko)"
            )

        username = server.user or getpass.getuser()
        port = server.port or 22
        client = paramiko.SSHClient()

        if _strict_policy_value(server.strict_host_key_checking) in {"yes", "true"}:
            client.set_missing_host_key_policy(paramiko.RejectPolicy())
        else:
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

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
        except Exception as exc:
            ok = False
            err = str(exc)
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
            args, text=True, capture_output=True, timeout=timeout_s
        )
        ok = completed.returncode == 0
    except Exception as exc:
        ok = False
        completed = None
        err = str(exc)

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


def _connect_paramiko_client(server: ServerConfig, timeout_s: Optional[float]):
    try:
        import paramiko  # type: ignore
    except Exception:
        raise MCPError(
            -32002, "File operations require 'paramiko' (pip install paramiko)"
        )

    username = server.user or getpass.getuser()
    port = server.port or 22
    password = _resolve_password(server)

    client = paramiko.SSHClient()
    if _strict_policy_value(server.strict_host_key_checking) in {"yes", "true"}:
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
    except Exception as exc:
        raise MCPError(-32000, f"SFTP connection failed: {exc}")

    return client, username, port


def _sftp_mkdirs(sftp: Any, remote_dir: str) -> None:
    if not remote_dir or remote_dir in {"/", "."}:
        return
    parts = remote_dir.split("/")
    current = "" if remote_dir.startswith("/") else "."
    for part in parts:
        if not part:
            continue
        current = f"/{part}" if current in {"", "/"} else f"{current}/{part}"
        try:
            sftp.stat(current)
        except Exception:
            try:
                sftp.mkdir(current)
            except Exception as exc:
                raise MCPError(
                    -32000, f"Failed creating remote directory '{current}': {exc}"
                )


def upload_file(
    server: ServerConfig,
    local_path: str,
    remote_path: str,
    timeout_ms: Optional[int],
    *,
    make_dirs: bool = True,
    overwrite: bool = True,
) -> Dict[str, Any]:
    local = Path(local_path)
    if not local.exists() or not local.is_file():
        raise MCPError(-32602, f"Local file not found: {local_path}")

    if not isinstance(remote_path, str) or not remote_path.strip():
        raise MCPError(-32602, "'remote_path' must be a non-empty string")

    timeout_s = None
    if timeout_ms is not None:
        if not isinstance(timeout_ms, int) or timeout_ms <= 0:
            raise MCPError(-32602, "'timeout_ms' must be a positive integer")
        timeout_s = timeout_ms / 1000.0

    started = time.time()
    client, username, port = _connect_paramiko_client(server, timeout_s)
    sftp = None
    try:
        sftp = client.open_sftp()

        resolved_remote_path = remote_path
        local_name = local.name

        if resolved_remote_path.endswith("/"):
            resolved_remote_path = posixpath.join(resolved_remote_path, local_name)
        else:
            try:
                st = sftp.stat(resolved_remote_path)
                if statmod.S_ISDIR(st.st_mode):
                    resolved_remote_path = posixpath.join(
                        resolved_remote_path, local_name
                    )
            except Exception:
                pass

        if make_dirs:
            _sftp_mkdirs(sftp, posixpath.dirname(resolved_remote_path))

        if not overwrite:
            try:
                sftp.stat(resolved_remote_path)
                raise MCPError(
                    -32602, f"Remote path already exists: {resolved_remote_path}"
                )
            except MCPError:
                raise
            except Exception:
                pass

        sftp.put(str(local), resolved_remote_path, confirm=True)
        remote_size = int(sftp.stat(resolved_remote_path).st_size)
    except MCPError:
        raise
    except Exception as exc:
        raise MCPError(-32000, f"Upload failed: {exc}")
    finally:
        if sftp is not None:
            try:
                sftp.close()
            except Exception:
                pass
        try:
            client.close()
        except Exception:
            pass

    return {
        "ok": True,
        "transport": "sftp",
        "host": server.host,
        "port": port,
        "user": username,
        "local_path": str(local.resolve()),
        "remote_path": resolved_remote_path,
        "bytes": remote_size,
        "elapsed_ms": int((time.time() - started) * 1000),
    }


def _sftp_delete_recursive(sftp: Any, path: str) -> int:
    removed = 0
    st = sftp.lstat(path)
    if statmod.S_ISDIR(st.st_mode):
        for entry in sftp.listdir_attr(path):
            child = posixpath.join(path, entry.filename)
            removed += _sftp_delete_recursive(sftp, child)
        sftp.rmdir(path)
        return removed + 1

    sftp.remove(path)
    return removed + 1


def delete_remote_path(
    server: ServerConfig,
    remote_path: str,
    timeout_ms: Optional[int],
    *,
    recursive: bool = False,
    missing_ok: bool = False,
) -> Dict[str, Any]:
    if not isinstance(remote_path, str) or not remote_path.strip():
        raise MCPError(-32602, "'remote_path' must be a non-empty string")

    timeout_s = None
    if timeout_ms is not None:
        if not isinstance(timeout_ms, int) or timeout_ms <= 0:
            raise MCPError(-32602, "'timeout_ms' must be a positive integer")
        timeout_s = timeout_ms / 1000.0

    started = time.time()
    client, username, port = _connect_paramiko_client(server, timeout_s)
    sftp = None
    removed_count = 0
    try:
        sftp = client.open_sftp()
        st = None
        try:
            st = sftp.lstat(remote_path)
        except Exception:
            if missing_ok:
                return {
                    "ok": True,
                    "transport": "sftp",
                    "host": server.host,
                    "port": port,
                    "user": username,
                    "remote_path": remote_path,
                    "removed": 0,
                    "missing": True,
                    "elapsed_ms": int((time.time() - started) * 1000),
                }
            raise MCPError(-32000, f"Remote path not found: {remote_path}")

        if st is not None and statmod.S_ISDIR(st.st_mode):
            if not recursive:
                raise MCPError(
                    -32602, "Target is a directory; set 'recursive': true to remove"
                )
            removed_count = _sftp_delete_recursive(sftp, remote_path)
        else:
            sftp.remove(remote_path)
            removed_count = 1
    except MCPError:
        raise
    except Exception as exc:
        raise MCPError(-32000, f"Delete failed: {exc}")
    finally:
        if sftp is not None:
            try:
                sftp.close()
            except Exception:
                pass
        try:
            client.close()
        except Exception:
            pass

    return {
        "ok": True,
        "transport": "sftp",
        "host": server.host,
        "port": port,
        "user": username,
        "remote_path": remote_path,
        "removed": removed_count,
        "elapsed_ms": int((time.time() - started) * 1000),
    }
