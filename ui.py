"""Rich terminal UI for SentinelX."""

from __future__ import annotations

from typing import Any

BANNER = r"""
   _____            _   _            _ __  __
  / ____|          | | (_)          | |  \/  |
 | (___   ___ _ __ | |_ _ _ __   ___| | \  / |
  \___ \ / _ \ '_ \| __| | '_ \ / _ \ | |\/| |
  ____) |  __/ | | | |_| | | | |  __/ | |  | |
 |_____/ \___|_| |_|\__|_|_| |_|\___|_|_|  |_|
"""


class RichUI:
    """Live Rich dashboard with graceful plain-text fallback."""

    def __init__(self, threshold: int) -> None:
        self.threshold = threshold
        self._live: Any = None
        self._console: Any = None
        self._rich_available = True
        try:
            from rich.console import Console

            self._console = Console()
        except ImportError:
            self._rich_available = False
            self._console = None

    def print_banner(self, banner: str, version: str) -> None:
        if self._rich_available:
            self._console.print(f"[bold cyan]{banner}[/bold cyan]")
            self._console.print(f"[bold]SentinelX v{version}[/bold] IDS/IPS\n")
        else:
            print(banner)
            print(f"SentinelX v{version} IDS/IPS\n")

    def start(self) -> None:
        if not self._rich_available:
            return
        from rich.live import Live

        self._live = Live(
            self._render([], 0, 0, 0),
            console=self._console,
            refresh_per_second=4,
            transient=False,
        )
        self._live.start()

    def stop(self) -> None:
        if self._live is not None:
            self._live.stop()
            self._live = None

    def update(
        self,
        snapshot: list[dict[str, object]],
        total_packets: int,
        active_threats: int,
        blocked_count: int,
    ) -> None:
        if self._live is None:
            return
        self._live.update(
            self._render(snapshot, total_packets, active_threats, blocked_count)
        )

    def alert(self, severity: str, message: str) -> None:
        if self._rich_available:
            style = {
                "high": "bold red",
                "warning": "yellow",
                "normal": "green",
            }.get(severity, "white")
            if self._live is not None:
                self._live.console.print(f"[{style}]{message}[/{style}]")
            else:
                self._console.print(f"[{style}]{message}[/{style}]")
        else:
            print(f"[{severity.upper()}] {message}")

    def _render(
        self,
        snapshot: list[dict[str, object]],
        total_packets: int,
        active_threats: int,
        blocked_count: int,
    ) -> Any:
        from rich import box
        from rich.align import Align
        from rich.console import Group
        from rich.panel import Panel
        from rich.table import Table
        from rich.text import Text

        metrics = Table.grid(expand=True)
        metrics.add_column(justify="center")
        metrics.add_column(justify="center")
        metrics.add_column(justify="center")
        metrics.add_row(
            f"[bold green]Total Packets[/bold green]\n{total_packets}",
            f"[bold yellow]Active Threats[/bold yellow]\n{active_threats}",
            f"[bold red]Blocked IPs[/bold red]\n{blocked_count}",
        )

        table = Table(
            title="Live Threat Scores",
            box=box.SIMPLE_HEAVY,
            expand=True,
            show_lines=False,
        )
        table.add_column("IP", style="cyan", no_wrap=True)
        table.add_column("Score", justify="right")
        table.add_column("Status", justify="center")

        if snapshot:
            for item in snapshot[:20]:
                score = int(item["score"])
                status = str(item["status"])
                score_style = "red" if score >= self.threshold else "yellow"
                status_text = (
                    Text("BLOCKED", style="bold red")
                    if status == "BLOCKED"
                    else Text("MONITOR", style="green")
                )
                table.add_row(str(item["ip"]), f"[{score_style}]{score}[/{score_style}]", status_text)
        else:
            table.add_row("No suspicious IPs", "0", Text("NORMAL", style="green"))

        return Group(
            Panel(metrics, title="SentinelX Metrics", border_style="cyan"),
            Align.left(table),
        )
