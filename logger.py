"""JSON alert logging for SentinelX."""

from __future__ import annotations

import json
from pathlib import Path
from threading import Lock
from typing import Any


class AlertLogger:
    """Append alerts as JSON Lines for durable, stream-friendly logs."""

    def __init__(self, path: str) -> None:
        self.path = Path(path).expanduser()
        self.path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        self._lock = Lock()
        self._file = self.path.open("a", encoding="utf-8")

    def write(self, alert: dict[str, Any]) -> None:
        try:
            line = json.dumps(alert, sort_keys=True, separators=(",", ":"))
            with self._lock:
                self._file.write(line + "\n")
                self._file.flush()
        except Exception:
            pass

    def close(self) -> None:
        try:
            self._file.close()
        except Exception:
            pass
