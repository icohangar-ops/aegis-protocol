"""
Watcher Agent — Monitors on-chain outflows and detects anomalies.
Inspired by icohangar-ops automation patterns.
"""

import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


class AnomalyType(Enum):
    MASSIVE_OUTFLOW = "massive_outflow"
    FLASH_LOAN_ATTACK = "flash_loan_attack"
    REENTRANCY_PATTERN = "reentrancy_pattern"
    GOVERNANCE_ATTACK = "governance_attack"
    PRICE_MANIPULATION = "price_manipulation"


@dataclass
class AnomalyEvent:
    event_id: str
    tx_hash: str
    protocol_name: str
    anomaly_type: AnomalyType
    amount_usd: float
    amount_native: float
    token: str
    from_address: str
    to_address: str
    block_number: int
    timestamp: float
    chain: str = "sepolia"
    details: dict = field(default_factory=dict)

    def __str__(self):
        return (
            f"\n{'='*60}\n"
            f"  ANOMALY DETECTED\n{'='*60}\n"
            f"  Protocol   : {self.protocol_name}\n"
            f"  Type       : {self.anomaly_type.value}\n"
            f"  Amount     : ${self.amount_usd:,.0f} USDC\n"
            f"  TX Hash    : {self.tx_hash[:16]}...\n"
            f"  From       : {self.from_address[:10]}...\n"
            f"  To         : {self.to_address[:10]}...\n"
            f"  Block      : {self.block_number}\n"
            f"  Chain      : {self.chain}\n{'='*60}"
        )


class WatcherAgent:
    """
    Monitors blockchain for anomalous outflows.
    In production: WebSocket subscription to mempool/events.
    In mock mode: generates realistic simulated events.
    """

    def __init__(self, threshold_usd: float = 5_000_000, time_window: int = 60):
        self.threshold_usd = threshold_usd
        self.time_window = time_window
        self.event_count = 0

    def detect_anomaly(self, event: AnomalyEvent) -> bool:
        """Check if an event exceeds the anomaly threshold."""
        self.event_count += 1
        is_anomaly = event.amount_usd >= self.threshold_usd
        return is_anomaly

    def generate_mock_anomaly(self, scenario: str = "hack") -> AnomalyEvent:
        """Generate a realistic mock anomaly for demo purposes."""
        self.event_count += 1
        ts = time.time()

        if scenario == "hack":
            return AnomalyEvent(
                event_id=f"AE-{self.event_count:04d}",
                tx_hash="0x7a3f8c2b1d4e5f6a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1",
                protocol_name="OmniLend Protocol",
                anomaly_type=AnomalyType.REENTRANCY_PATTERN,
                amount_usd=8_200_000,
                amount_native=4200.0,
                token="USDC",
                from_address="0x742d35Cc6634C0532925a3b844Bc9e7595f5bA16",
                to_address="0xdAC17F958D2ee523a2206206994597C13D831ec7",
                block_number=5_892_341,
                timestamp=ts,
                chain="sepolia",
                details={
                    "gas_used": 210000,
                    "gas_price_gwei": 45,
                    "method_sig": "0x2e1a7d4d",
                    "log_count": 12,
                    "internal_txs": 47,
                },
            )
        else:
            return AnomalyEvent(
                event_id=f"AE-{self.event_count:04d}",
                tx_hash="0x1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f2",
                protocol_name="Binance Cold Wallet",
                anomaly_type=AnomalyType.MASSIVE_OUTFLOW,
                amount_usd=15_000_000,
                amount_native=7500.0,
                token="USDC",
                from_address="0x28C6c06298d514Db089934071355E5743bf21d60",
                to_address="0xF977814e90dA44bFA03b6295A0616a897441aceC",
                block_number=5_892_340,
                timestamp=ts,
                chain="sepolia",
                details={
                    "gas_used": 65000,
                    "gas_price_gwei": 30,
                    "method_sig": "0xa9059cbb",
                    "log_count": 1,
                    "internal_txs": 0,
                },
            )
