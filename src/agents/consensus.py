from dataclasses import dataclass
from enum import Enum
from typing import Optional
from .watcher import AnomalyEvent, AnomalyType
from .osint import OSINTResult, ThreatVerdict


class ActionType(Enum):
    PAUSE_PROTOCOL = "pause_protocol"
    ALERT_ONLY = "alert_only"
    MONITOR = "monitor"
    NO_ACTION = "no_action"


@dataclass
class ConsensusDecision:
    action: ActionType
    threat_score: float  # 0.0 - 100.0
    confidence: float    # 0.0 - 1.0
    reasoning: str
    agent_signals: dict
    should_execute_pause: bool

    def __str__(self):
        action_emoji = {
            ActionType.PAUSE_PROTOCOL: "\U0001f6a8 PAUSE PROTOCOL",
            ActionType.ALERT_ONLY: "\u26a0\ufe0f ALERT ONLY",
            ActionType.MONITOR: "\U0001f441\ufe0f CONTINUE MONITORING",
            ActionType.NO_ACTION: "\u2705 NO ACTION — FALSE ALARM",
        }
        return (
            f"\n{'='*60}"
            f"\n  CONSENSUS DECISION"
            f"\n{'='*60}"
            f"\n  Action      : {action_emoji[self.action]}"
            f"\n  Threat Score: {self.threat_score:.1f}/100"
            f"\n  Confidence  : {self.confidence:.0%}"
            f"\n  Reasoning  : {self.reasoning}"
            f"\n{'='*60}"
        )


class ConsensusEngine:
    """
    SwarmFi-inspired stigmergy consensus.
    
    Scoring formula:
      - Base score from anomaly type (0-40)
      - OSINT verdict multiplier (0-35)
      - OSINT confidence bonus (0-15)
      - Amount severity bonus (0-10)
    
    Thresholds:
      >= 75 : PAUSE_PROTOCOL
      >= 40 : ALERT_ONLY
      >= 20 : MONITOR
      <  20 : NO_ACTION
    """

    ANOMALY_BASE_SCORES = {
        AnomalyType.REENTRANCY_PATTERN: 40,
        AnomalyType.FLASH_LOAN_ATTACK: 38,
        AnomalyType.GOVERNANCE_ATTACK: 35,
        AnomalyType.MASSIVE_OUTFLOW: 25,
        AnomalyType.PRICE_MANIPULATION: 20,
    }

    OSINT_VERDICT_SCORES = {
        ThreatVerdict.CONFIRMED_EXPLOIT: 35,
        ThreatVerdict.SUSPICIOUS: 15,
        ThreatVerdict.FALSE_ALARM: 0,
        ThreatVerdict.INCONCLUSIVE: 10,
    }

    def compute(self, anomaly: AnomalyEvent, osint: OSINTResult) -> ConsensusDecision:
        import math

        # 1. Base score from anomaly type
        base = self.ANOMALY_BASE_SCORES.get(anomaly.anomaly_type, 20)

        # 2. OSINT verdict score
        osint_score = self.OSINT_VERDICT_SCORES.get(osint.verdict, 10)

        # 3. OSINT confidence bonus (only if not a clear false alarm)
        if osint.verdict != ThreatVerdict.FALSE_ALARM:
            confidence_bonus = osint.confidence * 15
        else:
            confidence_bonus = 0

        # 4. Amount severity (logarithmic - suppressed when OSINT says legit)
        if osint.verdict != ThreatVerdict.FALSE_ALARM and anomaly.amount_usd > 0:
            amount_bonus = min(10, math.log10(max(anomaly.amount_usd, 1)) * 2)
        else:
            amount_bonus = 0

        threat_score = min(100, base + osint_score + confidence_bonus + amount_bonus)
        overall_confidence = osint.confidence

        # 5. Determine action based on threat score
        if threat_score >= 75:
            action = ActionType.PAUSE_PROTOCOL
            should_pause = True
            reasoning = (
                f"HIGH THREAT: {anomaly.anomaly_type.value} detected on {anomaly.protocol_name}. "
                f"OSINT confirms {osint.verdict.value} with {osint.confidence:.0%} confidence. "
                f"Immediate pause recommended to prevent further losses."
            )
        elif threat_score >= 40:
            action = ActionType.ALERT_ONLY
            should_pause = False
            reasoning = (
                f"ELEVATED: Anomalous {anomaly.anomaly_type.value} on {anomaly.protocol_name}. "
                f"OSINT signals inconclusive. Alerting responders — auto-pause withheld."
            )
        elif threat_score >= 20:
            action = ActionType.MONITOR
            should_pause = False
            reasoning = (
                f"LOW: Anomaly detected but OSINT suggests legitimate activity. "
                f"Continuing enhanced monitoring on {anomaly.protocol_name}."
            )
        else:
            action = ActionType.NO_ACTION
            should_pause = False
            reasoning = (
                f"FALSE ALARM: {anomaly.amount_usd:,.0f} USDC outflow from {anomaly.protocol_name} "
                f"confirmed as legitimate. No action taken."
            )

        return ConsensusDecision(
            action=action,
            threat_score=threat_score,
            confidence=overall_confidence,
            reasoning=reasoning,
            agent_signals={
                "watcher": {
                    "anomaly_type": anomaly.anomaly_type.value,
                    "amount_usd": anomaly.amount_usd,
                    "base_score": base,
                },
                "osint": {
                    "verdict": osint.verdict.value,
                    "confidence": osint.confidence,
                    "sources_count": len(osint.sources),
                    "keywords": osint.keywords_found,
                    "response_ms": osint.response_time_ms,
                },
                "scoring": {
                    "base": base,
                    "osint_verdict": osint_score,
                    "confidence_bonus": round(confidence_bonus, 1),
                    "amount_bonus": round(amount_bonus, 1),
                    "total": round(threat_score, 1),
                },
            },
            should_execute_pause=should_pause,
        )
