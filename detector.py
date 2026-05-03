"""Packet capture and detection logic for SentinelX."""

from __future__ import annotations

import threading
import time
from collections import defaultdict, deque
from dataclasses import dataclass, field
from typing import Any, Deque


@dataclass(frozen=True)
class Detection:
    """A suspicious behavior finding produced by the detector."""

    source_ip: str
    destination_ip: str
    behavior: str
    points: int
    severity: str
    message: str
    metadata: dict[str, Any] = field(default_factory=dict)


class SuspiciousDetector:
    """Stateful traffic heuristics for common IDS signals."""

    def __init__(
        self,
        scan_window_seconds: int = 20,
        scan_unique_ports: int = 8,
        flood_window_seconds: int = 10,
        flood_packet_limit: int = 100,
        repeat_window_seconds: int = 30,
        repeat_connection_limit: int = 20,
        emit_cooldown_seconds: int = 5,
    ) -> None:
        self.scan_window_seconds = scan_window_seconds
        self.scan_unique_ports = scan_unique_ports
        self.flood_window_seconds = flood_window_seconds
        self.flood_packet_limit = flood_packet_limit
        self.repeat_window_seconds = repeat_window_seconds
        self.repeat_connection_limit = repeat_connection_limit
        self.emit_cooldown_seconds = emit_cooldown_seconds

        self._port_activity: dict[str, Deque[tuple[float, int]]] = defaultdict(deque)
        self._packet_activity: dict[str, Deque[float]] = defaultdict(deque)
        self._connection_activity: dict[
            str, dict[tuple[str, int], Deque[float]]
        ] = defaultdict(lambda: defaultdict(deque))
        self._last_emitted: dict[tuple[str, str], float] = {}

    def inspect(self, packet: Any) -> list[Detection]:
        """Inspect a Scapy packet and return suspicious detections."""
        try:
            parsed = self._parse_packet(packet)
            if parsed is None:
                return []

            now = time.time()
            src_ip, dst_ip, dst_port, protocol = parsed

            detections: list[Detection] = []
            self._record_packet(src_ip, now)

            if dst_port is not None:
                self._record_port(src_ip, dst_port, now)
                self._record_connection(src_ip, dst_ip, dst_port, now)

                scan_detection = self._detect_port_scan(src_ip, dst_ip, now)
                if scan_detection:
                    detections.append(scan_detection)

                repeated_detection = self._detect_repeated_connections(
                    src_ip, dst_ip, dst_port, now, protocol
                )
                if repeated_detection:
                    detections.append(repeated_detection)

            flood_detection = self._detect_flood(src_ip, dst_ip, now)
            if flood_detection:
                detections.append(flood_detection)

            return detections
        except Exception:
            return []

    def _parse_packet(self, packet: Any) -> tuple[str, str, int | None, str] | None:
        try:
            from scapy.layers.inet import IP, TCP, UDP
        except ImportError as exc:
            raise RuntimeError("Scapy is required for packet detection.") from exc

        if IP not in packet:
            return None

        ip_layer = packet[IP]
        src_ip = str(ip_layer.src)
        dst_ip = str(ip_layer.dst)

        if TCP in packet:
            return src_ip, dst_ip, int(packet[TCP].dport), "TCP"
        if UDP in packet:
            return src_ip, dst_ip, int(packet[UDP].dport), "UDP"
        return src_ip, dst_ip, None, "IP"

    def _record_packet(self, src_ip: str, now: float) -> None:
        packet_times = self._packet_activity[src_ip]
        packet_times.append(now)
        self._trim_time_deque(packet_times, now - self.flood_window_seconds)

    def _record_port(self, src_ip: str, dst_port: int, now: float) -> None:
        port_times = self._port_activity[src_ip]
        port_times.append((now, dst_port))
        while port_times and port_times[0][0] < now - self.scan_window_seconds:
            port_times.popleft()

    def _record_connection(
        self, src_ip: str, dst_ip: str, dst_port: int, now: float
    ) -> None:
        connection_times = self._connection_activity[src_ip][(dst_ip, dst_port)]
        connection_times.append(now)
        self._trim_time_deque(connection_times, now - self.repeat_window_seconds)

    def _detect_port_scan(
        self, src_ip: str, dst_ip: str, now: float
    ) -> Detection | None:
        ports = {port for _, port in self._port_activity[src_ip]}
        if len(ports) < self.scan_unique_ports or not self._should_emit(src_ip, "scan", now):
            return None
        severity = "high" if len(ports) >= self.scan_unique_ports * 2 else "warning"
        points = 5 if severity == "high" else 4
        return Detection(
            source_ip=src_ip,
            destination_ip=dst_ip,
            behavior="port_scan",
            points=points,
            severity=severity,
            message=f"Possible port scan: {len(ports)} unique destination ports.",
            metadata={
                "unique_ports": len(ports),
                "window_seconds": self.scan_window_seconds,
            },
        )

    def _detect_flood(
        self, src_ip: str, dst_ip: str, now: float
    ) -> Detection | None:
        packet_count = len(self._packet_activity[src_ip])
        if (
            packet_count < self.flood_packet_limit
            or not self._should_emit(src_ip, "flood", now)
        ):
            return None
        severity = "high" if packet_count >= self.flood_packet_limit * 2 else "warning"
        points = 6 if severity == "high" else 5
        return Detection(
            source_ip=src_ip,
            destination_ip=dst_ip,
            behavior="high_rate_traffic",
            points=points,
            severity=severity,
            message=f"High-rate traffic: {packet_count} packets in window.",
            metadata={
                "packet_count": packet_count,
                "window_seconds": self.flood_window_seconds,
            },
        )

    def _detect_repeated_connections(
        self,
        src_ip: str,
        dst_ip: str,
        dst_port: int,
        now: float,
        protocol: str,
    ) -> Detection | None:
        connection_count = len(self._connection_activity[src_ip][(dst_ip, dst_port)])
        emit_key = f"repeat:{dst_ip}:{dst_port}"
        if (
            connection_count < self.repeat_connection_limit
            or not self._should_emit(src_ip, emit_key, now)
        ):
            return None
        severity = (
            "high"
            if connection_count >= self.repeat_connection_limit * 2
            else "warning"
        )
        points = 4 if severity == "high" else 3
        return Detection(
            source_ip=src_ip,
            destination_ip=dst_ip,
            behavior="repeated_connections",
            points=points,
            severity=severity,
            message=(
                f"Repeated {protocol} connections to {dst_ip}:{dst_port}: "
                f"{connection_count} attempts."
            ),
            metadata={
                "destination_port": dst_port,
                "protocol": protocol,
                "connection_count": connection_count,
                "window_seconds": self.repeat_window_seconds,
            },
        )

    def _should_emit(self, src_ip: str, behavior: str, now: float) -> bool:
        key = (src_ip, behavior)
        last_seen = self._last_emitted.get(key, 0)
        if now - last_seen < self.emit_cooldown_seconds:
            return False
        self._last_emitted[key] = now
        return True

    @staticmethod
    def _trim_time_deque(values: Deque[float], minimum_time: float) -> None:
        while values and values[0] < minimum_time:
            values.popleft()


class PacketSniffer:
    """Real-time packet capture loop wired to detection, scoring, IPS, and UI."""

    def __init__(
        self,
        interface: str,
        detector: SuspiciousDetector,
        scorer: Any,
        blocker: Any,
        alert_logger: Any,
        ui: Any,
    ) -> None:
        self.interface = interface
        self.detector = detector
        self.scorer = scorer
        self.blocker = blocker
        self.alert_logger = alert_logger
        self.ui = ui
        self.total_packets = 0
        self._stop_event = threading.Event()

    def start(self) -> None:
        try:
            from scapy.all import conf, sniff
        except ImportError as exc:
            raise RuntimeError(
                "Scapy is not installed. Run: pip install -r requirements.txt"
            ) from exc

        conf.verb = 0
        self.ui.start()
        self.ui.alert("normal", f"Monitoring interface {self.interface}...")

        sniff(
            iface=self.interface,
            prn=self._handle_packet,
            store=False,
            stop_filter=lambda _packet: self._stop_event.is_set(),
        )

    def stop(self) -> None:
        self._stop_event.set()

    def _handle_packet(self, packet: Any) -> None:
        self.total_packets += 1
        try:
            detections = self.detector.inspect(packet)
            for detection in detections:
                score_event = self.scorer.apply_detection(detection)
                blocked_now = False

                if score_event.should_block and self.blocker.block(detection.source_ip):
                    blocked_now = self.scorer.mark_blocked(detection.source_ip)

                alert = {
                    "timestamp": score_event.timestamp,
                    "source_ip": detection.source_ip,
                    "destination_ip": detection.destination_ip,
                    "behavior": detection.behavior,
                    "severity": detection.severity,
                    "points": detection.points,
                    "score": score_event.score,
                    "threshold": self.scorer.threshold,
                    "status": self.scorer.status(detection.source_ip),
                    "blocked_now": blocked_now,
                    "message": detection.message,
                    "metadata": detection.metadata,
                }
                self.alert_logger.write(alert)
                self.ui.alert(detection.severity, self._format_alert(alert))

            self.ui.update(
                snapshot=self.scorer.snapshot(),
                total_packets=self.total_packets,
                active_threats=self.scorer.active_threat_count(),
                blocked_count=self.scorer.blocked_count(),
            )
        except Exception as exc:
            self.ui.alert("warning", f"Packet handling error ignored: {exc}")

    @staticmethod
    def _format_alert(alert: dict[str, Any]) -> str:
        return (
            f"{alert['source_ip']} {alert['behavior']} +{alert['points']} "
            f"(score {alert['score']}/{alert['threshold']}) - {alert['message']}"
        )
