import json
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict

from mcp_ssh.models import FileOpsLoggingConfig, LoggingConfig


_AUDIT_LOCK = threading.Lock()
_FILE_OPS_LOCK = threading.Lock()


def utc_now_iso() -> str:
    return (
        datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")
    )


def _write_jsonl(path: str, event: Dict[str, Any], lock: threading.Lock) -> None:
    try:
        log_path = Path(path)
        log_path.parent.mkdir(parents=True, exist_ok=True)
        line = json.dumps(event, ensure_ascii=False)
        with lock:
            with log_path.open("a", encoding="utf-8") as fp:
                fp.write(line + "\n")
    except Exception:
        return


def audit_log(logging_cfg: LoggingConfig, event: Dict[str, Any]) -> None:
    if not logging_cfg.enabled or logging_cfg.format != "jsonl" or not logging_cfg.file:
        return
    _write_jsonl(logging_cfg.file, event, _AUDIT_LOCK)


def file_ops_log(logging_cfg: FileOpsLoggingConfig, event: Dict[str, Any]) -> None:
    if not logging_cfg.enabled or logging_cfg.format != "jsonl" or not logging_cfg.file:
        return
    _write_jsonl(logging_cfg.file, event, _FILE_OPS_LOCK)
