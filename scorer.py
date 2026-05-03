"""Threat scoring for SentinelX."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone


@dataclass(frozen=True)
class ScoreEvent:
    source_ip: str
    score: int
    points_added: int
    threshold: int
    should_block: bool
    timestamp: str


class ThreatScorer:
    """Accumulates threat scores and status per source IP."""

    def __init__(self, threshold: int = 10) -> None:
        self.threshold = threshold
        self._scores: dict[str, int] = {}
        self._blocked: set[str] = set()

    def apply_detection(self, detection: object) -> ScoreEvent:
        source_ip = str(getattr(detection, "source_ip"))
        points = int(getattr(detection, "points"))
        self._scores[source_ip] = self._scores.get(source_ip, 0) + points
        score = self._scores[source_ip]
        return ScoreEvent(
            source_ip=source_ip,
            score=score,
            points_added=points,
            threshold=self.threshold,
            should_block=score >= self.threshold and source_ip not in self._blocked,
            timestamp=datetime.now(timezone.utc).isoformat(),
        )

    def mark_blocked(self, source_ip: str) -> bool:
        if source_ip in self._blocked:
            return False
        self._blocked.add(source_ip)
        return True

    def status(self, source_ip: str) -> str:
        return "BLOCKED" if source_ip in self._blocked else "MONITOR"

    def snapshot(self) -> list[dict[str, object]]:
        return [
            {
                "ip": ip,
                "score": score,
                "status": self.status(ip),
            }
            for ip, score in sorted(
                self._scores.items(),
                key=lambda item: (item[0] not in self._blocked, -item[1], item[0]),
            )
        ]

    def active_threat_count(self) -> int:
        return sum(1 for score in self._scores.values() if score > 0)

    def blocked_count(self) -> int:
        return len(self._blocked)
