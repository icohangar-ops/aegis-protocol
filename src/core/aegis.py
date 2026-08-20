from __future__ import annotations
import argparse
import json
import time
import os
import sys

from ..agents.watcher import WatcherAgent, AnomalyEvent, AnomalyType
from ..agents.osint import OSINTAgent, ThreatVerdict
from ..agents.consensus import ConsensusEngine, ActionType
from ..agents.executor import ExecutorAgent, ExecutionStatus


class AegisProtocol:
 """
 Autonomous AI Circuit Breaker.
 Orchestrates the 4-agent swarm: Watcher → OSINT → Consensus → Executor
 """

 BANNER = r"""
 ██████╗ ██████╗ ███████╗ █████╗ ██╗  ████████╗██╗███████╗██╗   ██╗███████╗
██╔════╝ ██╔══██╗██╔════╝██╔══██╗██║  ╚══██╔══╝██║██╔════╝██║   ██║██╔════╝
██║  ███╗██████╔╝█████╗  ███████║██║     ██║   ██║█████╗  ██║   ██║███████╗
██║   ██║██╔══██╗██╔══╝  ██╔══██║██║     ██║   ██║██╔══╝  ╚██╗ ██╔╝██╔════╝
╚██████╔╝██║  ██║███████╗██║  ██║███████╗██║   ██║██║      ╚████╔╝ ███████╗
 ╚═════╝ ╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝╚══════╝╚═╝   ╚═╝╚═╝       ╚═══╝  ╚══════╝
              Autonomous AI Circuit Breaker for DeFi
"""

 def __init__(self, mock: bool = True, chain: str = "sepolia"):
 self.mock = mock
 self.chain = chain
 self.watcher = WatcherAgent()
 self.osint = OSINTAgent() if mock else OSINTAgent(tavily_api_key=os.getenv("TAVILY_API_KEY"))
 self.consensus = ConsensusEngine()
 self.executor = ExecutorAgent(chain=chain)
 self.run_history: list[dict] = []

 def run_scenario(self, scenario: str = "hack") -> dict:
 """
 Execute one full Aegis pipeline scenario.
 scenario: 'hack' | 'false_alarm' | 'suspicious'
 """
 pipeline_start = time.time()
 print(self.BANNER)
 print(f"\n{'═'*60}")
 print(f"  AEGIS PROTOCOL ONLINE — {self.chain.upper()}")
 print(f"  Mode: {'MOCK DEMO' if self.mock else 'LIVE'}")
 print(f"  Scenario: {scenario.upper()}")
 print(f"{'═'*60}")

 # ── STAGE 1: WATCHER ────────────────────────────
 print("\n\U0001f50d [STAGE 1/4] WATCHER AGENT — Scanning mempool...")
 anomaly = self.watcher.generate_mock_anomaly(scenario)
 is_anomaly = self.watcher.detect_anomaly(anomaly)
 print(f"   Anomaly detected: {is_anomaly}")
 print(anomaly)

 # ── STAGE 2: OSINT ──────────────────────────────
 print(f"\n\U0001f50e [STAGE 2/4] OSINT AGENT — Querying Tavily...")
 osint_result = self.osint.analyze(
 protocol_name=anomaly.protocol_name,
 tx_hash=anomaly.tx_hash,
 amount_usd=anomaly.amount_usd,
 mock=scenario,
 )
 print(f"   Query completed in {osint_result.response_time_ms}ms")
 print(osint_result)

 if osint_result.sources:
 print(f"\n   Sources:")
 for s in osint_result.sources:
 print(f"     • {s.get('title', 'Unknown')}")
 print(f"     {s.get('url', '')}")

 # ── STAGE 3: CONSENSUS ──────────────────────────
 print(f"\n\U0001f9ea [STAGE 3/4] CONSENSUS ENGINE — Computing threat score...")
 decision = self.consensus.compute(anomaly, osint_result)
 print(decision)

 print(f"\n   Score Breakdown:")
 scoring = decision.agent_signals["scoring"]
 for k, v in scoring.items():
 print(f"     {k:20s}: {v}")

 # ── STAGE 4: EXECUTOR ───────────────────────────
 print(f"\n\u26a1 [STAGE 4/4] EXECUTOR AGENT — {'Broadcasting pause()' if decision.should_execute_pause else 'Evaluating...'}")
 exec_result = self.executor.execute_pause(
 should_pause=decision.should_execute_pause,
 mock=self.mock,
 )
 print(exec_result)

 # ── SUMMARY ─────────────────────────────────────
 pipeline_time = (time.time() - pipeline_start) * 1000
 result = {
 "run_id": f"aegis-{int(time.time())}",
 "scenario": scenario,
 "pipeline_time_ms": round(pipeline_time),
 "anomaly": {
 "protocol": anomaly.protocol_name,
 "type": anomaly.anomaly_type.value,
 "amount_usd": anomaly.amount_usd,
 "tx_hash": anomaly.tx_hash,
 },
 "osint": {
 "verdict": osint_result.verdict.value,
 "confidence": osint_result.confidence,
 "response_ms": osint_result.response_time_ms,
 "sources": len(osint_result.sources),
 },
 "consensus": {
 "action": decision.action.value,
 "threat_score": decision.threat_score,
 "reasoning": decision.reasoning,
 },
 "execution": {
 "status": exec_result.status.value,
 "tx_hash": exec_result.tx_hash,
 "gas_used": exec_result.gas_used,
 "block": exec_result.block_number,
 },
 }

 self.run_history.append(result)

 # Final verdict
 print(f"\n{'═'*60}")
 if decision.should_execute_pause:
 print(f"  \U0001f6a8 PROTOCOL PAUSED — {anomaly.amount_usd:,.0f} USDC SAVED")
 print(f"  Response time: {pipeline_time:.0f}ms (vs 4+ hours human multisig)")
 else:
 print(f"  \u2705 FALSE ALARM AVOIDED — Protocol remains live")
 print(f"  No unnecessary panic. No bank run.")
 print(f"{'═'*60}")

 return result

def main():
 parser = argparse.ArgumentParser(description="Aegis Protocol — Autonomous AI Circuit Breaker")
 parser.add_argument("--mock", action="store_true", default=True, help="Run in mock mode")
 parser.add_argument("--live", action="store_true", help="Run with live Tavily + Web3")
 parser.add_argument("--scenario", choices=["hack", "false_alarm", "suspicious"], default="hack")
 parser.add_argument("--network", default="sepolia", help="EVM network")
 parser.add_argument("--json", action="store_true", help="Output JSON to stdout")
 args = parser.parse_args()

 mock = not args.live
 aegis = AegisProtocol(mock=mock, chain=args.network)
 result = aegis.run_scenario(scenario=args.scenario)

 if args.json:
 print(json.dumps(result, indent=2))


if __name__ == "__main__":
 main()
