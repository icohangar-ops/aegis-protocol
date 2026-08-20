"""
OSINT Agent - Scrapes Twitter, Telegram, security forums via Tavily.
Uses CritMin Oracle pattern for rapid intelligence synthesis.
"""

import os
import json
import requests
from dataclasses import dataclass, field
from typing import Optional
from enum import Enum


class ThreatVerdict(Enum):
    CONFIRMED_EXPLOIT = "confirmed_exploit"
    SUSPICIOUS = "suspicious"
    FALSE_ALARM = "false_alarm"
    INCONCLUSIVE = "inconclusive"


@dataclass
class OSINTResult:
    verdict: ThreatVerdict
    confidence: float
    ai_summary: str
    sources: list = field(default_factory=list)
    keywords_found: list = field(default_factory=list)
    response_time_ms: int = 0
    raw_tavily_response: dict = field(default_factory=dict)

    def __str__(self):
        verdict_labels = {
            ThreatVerdict.CONFIRMED_EXPLOIT: "CONFIRMED EXPLOIT",
            ThreatVerdict.SUSPICIOUS: "SUSPICIOUS",
            ThreatVerdict.FALSE_ALARM: "FALSE ALARM",
            ThreatVerdict.INCONCLUSIVE: "INCONCLUSIVE",
        }
        return (
            f"\n  Verdict     : {verdict_labels[self.verdict]}"
            f"\n  Confidence  : {self.confidence:.0%}"
            f"\n  Sources     : {len(self.sources)}"
            f"\n  Keywords    : {', '.join(self.keywords_found) if self.keywords_found else 'none'}"
            f"\n  Response    : {self.response_time_ms}ms"
        )


class OSINTAgent:
    """Queries Tavily to verify if an on-chain anomaly is a real exploit."""

    EXPLOIT_KEYWORDS = [
        "exploit", "hacked", "drained", "flash loan attack",
        "reentrancy", "exploited", "rug pull", "attack vector",
        "unauthorized withdrawal", "protocol hacked", "funds stolen",
    ]

    LEGIT_KEYWORDS = [
        "cold wallet", "treasury movement", "binance", "coinbase",
        "legitimate", "routine", "scheduled", "internal transfer",
        "liquidity provision", "market making",
    ]

    def __init__(self, tavily_api_key: Optional[str] = None):
        self.api_key = tavily_api_key or os.getenv("TAVILY_API_KEY")

    def query_tavily(self, protocol_name: str, tx_hash: str, amount_usd: float) -> dict:
        payload = {
            "api_key": self.api_key,
            "query": (
                f"URGENT: Active hack, exploit, or drain occurring right now "
                f"involving {protocol_name} smart contract. TX: {tx_hash[:16]}. "
                f"${amount_usd:,.0f} USDC outflow. "
                f"Include Twitter/X crypto security researcher opinions, "
                f"Telegram alerts, and blockchain security forum discussions."
            ),
            "search_depth": "advanced",
            "include_answer": True,
            "include_raw_content": False,
            "max_results": 5,
        }
        resp = requests.post("https://api.tavily.com/search", json=payload, timeout=15)
        resp.raise_for_status()
        return resp.json()

    def analyze(self, protocol_name: str, tx_hash: str, amount_usd: float, mock: str = "") -> OSINTResult:
        import time

        if mock == "hack":
            return self._mock_hack_result()
        elif mock == "false_alarm":
            return self._mock_false_alarm_result()
        elif mock == "suspicious":
            return self._mock_suspicious_result()

        start = time.time()
        try:
            tavily_resp = self.query_tavily(protocol_name, tx_hash, amount_usd)
        except Exception as e:
            return OSINTResult(
                verdict=ThreatVerdict.INCONCLUSIVE,
                confidence=0.0,
                ai_summary=f"Tavily query failed: {e}",
                response_time_ms=int((time.time() - start) * 1000),
            )

        elapsed_ms = int((time.time() - start) * 1000)
        ai_summary = tavily_resp.get("answer", "").lower()
        sources = tavily_resp.get("results", [])

        exploit_hits = [kw for kw in self.EXPLOIT_KEYWORDS if kw in ai_summary]
        legit_hits = [kw for kw in self.LEGIT_KEYWORDS if kw in ai_summary]

        if exploit_hits and not legit_hits:
            confidence = min(0.95, 0.6 + len(exploit_hits) * 0.1)
            verdict = ThreatVerdict.CONFIRMED_EXPLOIT
        elif legit_hits and not exploit_hits:
            confidence = min(0.95, 0.6 + len(legit_hits) * 0.1)
            verdict = ThreatVerdict.FALSE_ALARM
        elif exploit_hits and legit_hits:
            confidence = 0.5
            verdict = ThreatVerdict.SUSPICIOUS
        else:
            confidence = 0.2
            verdict = ThreatVerdict.INCONCLUSIVE

        return OSINTResult(
            verdict=verdict,
            confidence=confidence,
            ai_summary=tavily_resp.get("answer", "No AI summary available"),
            sources=[{"title": s.get("title", ""), "url": s.get("url", "")} for s in sources],
            keywords_found=exploit_hits + legit_hits,
            response_time_ms=elapsed_ms,
            raw_tavily_response=tavily_resp,
        )

    def _mock_hack_result(self) -> OSINTResult:
        return OSINTResult(
            verdict=ThreatVerdict.CONFIRMED_EXPLOIT,
            confidence=0.94,
            ai_summary=(
                "Multiple security researchers have confirmed an active reentrancy exploit "
                "targeting OmniLend Protocol. @zachxbt posted on X: 'Confirmed reentrancy in OmniLend's "
                "withdrawal handler -- attacker is draining USDC via flash loan loop.' "
                "Crypto security Telegram groups are reporting estimated losses exceeding $8M. "
                "The exploit was first spotted at block 5,892,341 and is still ongoing. "
                "PeckShield has flagged the attacker address as linked to previous DeFi exploits."
            ),
            sources=[
                {"title": "@zachxbt on X: Active reentrancy exploit draining OmniLend", "url": "https://x.com/zachxbt"},
                {"title": "PeckShield Alert: OmniLend Protocol Under Active Exploit", "url": "https://twitter.com/PeckShieldAlert"},
                {"title": "Crypto Security Telegram: Flash Loan Attack Confirmed", "url": "https://t.me/crypto_security"},
            ],
            keywords_found=["exploit", "reentrancy", "draining", "flash loan attack"],
            response_time_ms=1847,
        )

    def _mock_false_alarm_result(self) -> OSINTResult:
        return OSINTResult(
            verdict=ThreatVerdict.FALSE_ALARM,
            confidence=0.91,
            ai_summary=(
                "No exploits detected involving the monitored protocol. Analysts and on-chain "
                "investigators suggest this is a routine Binance cold wallet movement. "
                "@WhaleAlert flagged the transaction as a known Binance consolidation transfer. "
                "No security researchers have reported any anomalies. The receiving address "
                "is a previously identified Binance hot wallet (0xF977...). This is not an exploit."
            ),
            sources=[
                {"title": "@whale_alert: 15,000 USDC transferred from Binance", "url": "https://twitter.com/whale_alert"},
                {"title": "On-chain analysis: Routine Binance wallet consolidation", "url": "https://glassnode.com"},
            ],
            keywords_found=["cold wallet", "binance", "routine", "consolidation"],
            response_time_ms=1523,
        )

    def _mock_suspicious_result(self) -> OSINTResult:
        return OSINTResult(
            verdict=ThreatVerdict.SUSPICIOUS,
            confidence=0.52,
            ai_summary=(
                "Mixed signals detected. One analyst suggests possible unauthorized access, "
                "but others point to a known internal migration. No definitive confirmation of "
                "an exploit. Monitoring recommended. The transaction pattern is atypical but "
                "the receiving address has prior legitimate history with the protocol."
            ),
            sources=[
                {"title": "@onchaindetective: Unusual transfer pattern from DeFi protocol", "url": "https://x.com/onchaindetective"},
            ],
            keywords_found=["unauthorized access", "legitimate", "migration"],
            response_time_ms=2100,
        )
