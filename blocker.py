"""Linux iptables blocking support for SentinelX."""

from __future__ import annotations

import ipaddress
import platform
import shutil
import subprocess


class IPBlocker:
    """Block malicious IPs using iptables when available."""

    def __init__(self, enabled: bool = True) -> None:
        self.enabled = enabled
        self._blocked: set[str] = set()
        self._iptables_path = shutil.which("iptables")
        self.available = (
            enabled and platform.system().lower() == "linux" and self._iptables_path is not None
        )

    def block(self, ip_address: str) -> bool:
        """Return True when the IP becomes blocked by this call."""
        if not self.enabled or not self.available:
            return False
        if ip_address in self._blocked:
            return False
        if not self._valid_ip(ip_address):
            return False
        if self._rule_exists(ip_address):
            self._blocked.add(ip_address)
            return True

        try:
            subprocess.run(
                [self._iptables_path, "-A", "INPUT", "-s", ip_address, "-j", "DROP"],
                check=True,
                capture_output=True,
                text=True,
            )
        except (OSError, subprocess.CalledProcessError):
            return False

        self._blocked.add(ip_address)
        return True

    def _rule_exists(self, ip_address: str) -> bool:
        try:
            result = subprocess.run(
                [self._iptables_path, "-C", "INPUT", "-s", ip_address, "-j", "DROP"],
                check=False,
                capture_output=True,
                text=True,
            )
        except OSError:
            return False
        return result.returncode == 0

    @staticmethod
    def _valid_ip(ip_address: str) -> bool:
        try:
            ipaddress.ip_address(ip_address)
        except ValueError:
            return False
        return True
