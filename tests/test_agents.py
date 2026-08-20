from src.agents.watcher import WatcherAgent, AnomalyType
from src.agents.osint import OSINTAgent, ThreatVerdict
from src.agents.consensus import ConsensusEngine, ActionType
from src.agents.executor import ExecutorAgent, ExecutionStatus


def test_watcher_detects_anomaly():
 w = WatcherAgent(threshold_usd=5_000_000)
 hack = w.generate_mock_anomaly("hack")
 assert w.detect_anomaly(hack) is True
 assert hack.amount_usd == 8_200_000
 assert hack.anomaly_type == AnomalyType.REENTRANCY_PATTERN


def test_osint_hack_verdict():
 o = OSINTAgent()
 result = o.analyze("OmniLend", "0x1234", 8_000_000, mock="hack")
 assert result.verdict == ThreatVerdict.CONFIRMED_EXPLOIT
 assert result.confidence >= 0.9
 assert len(result.sources) >= 2


def test_osint_false_alarm():
 o = OSINTAgent()
 result = o.analyze("Binance", "0x5678", 15_000_000, mock="false_alarm")
 assert result.verdict == ThreatVerdict.FALSE_ALARM
 assert result.confidence >= 0.9


def test_consensus_pause_on_hack():
 w = WatcherAgent()
 o = OSINTAgent()
 c = ConsensusEngine()

 anomaly = w.generate_mock_anomaly("hack")
 osint = o.analyze("OmniLend", "0x1234", 8_000_000, mock="hack")
 decision = c.compute(anomaly, osint)

 assert decision.action == ActionType.PAUSE_PROTOCOL
 assert decision.should_execute_pause is True
 assert decision.threat_score >= 75


def test_consensus_no_pause_on_false_alarm():
 w = WatcherAgent()
 o = OSINTAgent()
 c = ConsensusEngine()

 anomaly = w.generate_mock_anomaly("false_alarm")
 osint = o.analyze("Binance", "0x5678", 15_000_000, mock="false_alarm")
 decision = c.compute(anomaly, osint)

 assert decision.action in (ActionType.NO_ACTION, ActionType.MONITOR)
 assert decision.should_execute_pause is False


def test_executor_pause():
 e = ExecutorAgent(chain="sepolia")
 result = e.execute_pause(should_pause=True, mock=True)
 assert result.status == ExecutionStatus.SUCCESS
 assert result.tx_hash != "N/A"
 assert result.gas_used > 0


def test_executor_skip():
 e = ExecutorAgent(chain="sepolia")
 result = e.execute_pause(should_pause=False, mock=True)
 assert result.status == ExecutionStatus.SKIPPED


if __name__ == "__main__":
 import pytest, sys
 sys.exit(pytest.main([__file__, "-v"]))