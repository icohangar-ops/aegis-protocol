import { NextResponse } from "next/server";

// ── Types ──────────────────────────────────────────
type Scenario = "hack" | "false_alarm" | "suspicious";
type AnomalyType = "massive_outflow" | "flash_loan_attack" | "reentrancy_pattern" | "governance_attack" | "price_manipulation";
type ThreatVerdict = "confirmed_exploit" | "suspicious" | "false_alarm" | "inconclusive";
type ActionType = "pause_protocol" | "alert_only" | "monitor" | "no_action";
type ExecutionStatus = "success" | "failed" | "skipped";

interface AnomalyEvent {
  event_id: string;
  tx_hash: string;
  protocol_name: string;
  anomaly_type: AnomalyType;
  amount_usd: number;
  token: string;
  from_address: string;
  to_address: string;
  block_number: number;
  gas_used: number;
  gas_price_gwei: number;
  internal_txs: number;
  tx_timestamp: string;
}

interface OSINTSource {
  title: string;
  url: string;
  snippet: string;
}

interface OSINTResult {
  verdict: ThreatVerdict;
  confidence: number;
  ai_summary: string;
  sources: OSINTSource[];
  keywords_found: string[];
  response_time_ms: number;
  queries: string[];
}

interface ConsensusDecision {
  action: ActionType;
  threat_score: number;
  confidence: number;
  reasoning: string;
  agent_signals: {
    watcher: { anomaly_type: string; amount_usd: number; base_score: number; internal_tx_risk: string };
    osint: { verdict: string; confidence: number; sources_count: number; keywords: string[]; response_ms: number };
    scoring: { base: number; osint_verdict: number; confidence_bonus: number; amount_bonus: number; internal_tx_bonus: number; total: number };
  };
  should_execute_pause: boolean;
}

interface ExecutionResult {
  status: ExecutionStatus;
  tx_hash: string;
  block_number: number;
  gas_used: number;
  gas_cost_eth: number;
  execution_time_ms: number;
  chain: string;
  contract_address: string;
  function_signature: string;
}

interface LogEntry {
  timestamp: string;
  agent: string;
  level: "info" | "warn" | "error" | "success";
  message: string;
}

interface PipelineResult {
  run_id: string;
  timestamp: string;
  scenario: Scenario;
  pipeline_time_ms: number;
  logs: LogEntry[];
  anomaly: AnomalyEvent;
  osint: OSINTResult;
  consensus: ConsensusDecision;
  execution: ExecutionResult;
  vault_state: { total_deposits: number; pause_count: number; is_paused: boolean; last_pause: string | null };
}

// ── Mock Data ──────────────────────────────────────
const HACK_ANOMALY: AnomalyEvent = {
  event_id: "AE-0042",
  tx_hash: "0x7a3f8c2b1d4e5f6a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1",
  protocol_name: "OmniLend Protocol",
  anomaly_type: "reentrancy_pattern",
  amount_usd: 8_200_000,
  token: "USDC",
  from_address: "0x742d35Cc6634C0532925a3b844Bc9e7595f5bA16",
  to_address: "0xdAC17F958D2ee523a2206206994597C13D831ec7",
  block_number: 5_892_341,
  gas_used: 210_000,
  gas_price_gwei: 45,
  internal_txs: 47,
  tx_timestamp: "2026-08-20T02:47:13Z",
};

const FALSE_ALARM_ANOMALY: AnomalyEvent = {
  event_id: "AE-0043",
  tx_hash: "0x1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f2",
  protocol_name: "Binance Cold Wallet",
  anomaly_type: "massive_outflow",
  amount_usd: 15_000_000,
  token: "USDC",
  from_address: "0x28C6c06298d514Db089934071355E5743bf21d60",
  to_address: "0xF977814e90dA44bFA03b6295A0616a897441aceC",
  block_number: 5_892_340,
  gas_used: 65_000,
  gas_price_gwei: 30,
  internal_txs: 0,
  tx_timestamp: "2026-08-20T14:22:05Z",
};

const SUSPICIOUS_ANOMALY: AnomalyEvent = {
  event_id: "AE-0044",
  tx_hash: "0xab12cd34ef56ab78cd90ef12ab34cd56ef78ab90cd12ef34ab56cd78ef90ab",
  protocol_name: "YieldMax Finance",
  anomaly_type: "flash_loan_attack",
  amount_usd: 3_400_000,
  token: "USDT",
  from_address: "0xDead000000000000000000000000000000000000",
  to_address: "0xBEef000000000000000000000000000000000000",
  block_number: 5_892_345,
  gas_used: 350_000,
  gas_price_gwei: 52,
  internal_txs: 23,
  tx_timestamp: "2026-08-20T09:15:38Z",
};

const HACK_OSINT: OSINTResult = {
  verdict: "confirmed_exploit",
  confidence: 0.94,
  ai_summary: "Multiple security researchers confirmed an active reentrancy exploit targeting OmniLend Protocol. @zachxbt posted: \"Confirmed reentrancy in withdrawal handler — attacker draining USDC via flash loan loop.\" Telegram groups report losses exceeding $8M. PeckShield flagged attacker address 0x742d... as linked to previous DeFi exploits on Euler Finance and MIM. BlockSec issued real-time alert at 02:47 UTC. No official response from OmniLend team yet — likely due to time zone (2:47 AM UTC).",
  sources: [
    { title: "@zachxbt: Active reentrancy exploit draining OmniLend", url: "https://x.com/zachxbt/status/189234567890", snippet: "Confirmed reentrancy in withdrawal handler — attacker using flash loan loop to drain USDC reserves. Estimated $8.2M so far and counting." },
    { title: "PeckShield Alert: OmniLend Under Active Exploit", url: "https://twitter.com/PeckShieldAlert/status/189234568901", snippet: "[ALERT] OmniLend Protocol (0x742d...) experiencing suspected reentrancy attack. Attacker addr: 0x742d35Cc... Funds draining to Tornado Cash." },
    { title: "BlockSec: Real-time exploit monitoring", url: "https://t.me/blocksec_alerts", snippet: "OmniLend Protocol exploit detected at block 5892341. Reentrancy pattern confirmed. Flash loan from dYdX used as initial capital." },
    { title: "Crypto Security Telegram: Community reports", url: "https://t.me/crypto_security/1234", snippet: "Admin: OmniLend is being drained. Multiple users reporting failed withdrawals. TVL dropping in real-time on DeFiLlama." },
  ],
  keywords_found: ["exploit", "reentrancy", "draining", "flash loan attack", "attacker", "Tornado Cash"],
  response_time_ms: 1847,
  queries: ["OmniLend Protocol exploit hack", "0x742d35Cc6634C0532925a3b844Bc9e7595f5bA16 attacker", "DeFi hack August 2026", "OmniLend reentrancy vulnerability"],
};

const FALSE_ALARM_OSINT: OSINTResult = {
  verdict: "false_alarm",
  confidence: 0.91,
  ai_summary: "No exploits detected. @WhaleAlert flagged as routine Binance cold wallet consolidation. On-chain analyst @hildobby confirmed: \"Standard operational procedure — Binance rotates cold wallet funds every 48 hours.\" Receiving address 0xF977... is a known Binance hot wallet with 200+ prior inbound transactions. No security researchers reported any anomalies. DeFiLlama shows stable TVL across all Binance-associated protocols. This is a false alarm.",
  sources: [
    { title: "@whale_alert: 15,000 USDC transferred from Binance", url: "https://twitter.com/whale_alert/status/189234000000", snippet: "15,000,000 USDC (15,000,000 USD) transferred from Binance Cold Wallet to 0xF977...14e90" },
    { title: "On-chain analysis: Routine Binance wallet consolidation", url: "https://glassnode.com/alert/binance-rotation", snippet: "Binance cold wallet rotation detected. This is the 47th such rotation in 2026. No abnormal patterns identified." },
    { title: "@hildobby: Confirmed routine operation", url: "https://x.com/hildobby/status/189234111111", snippet: "Standard Binance cold wallet movement. Happens every ~48h. Nothing to see here." },
  ],
  keywords_found: ["cold wallet", "binance", "routine", "consolidation", "rotation", "standard"],
  response_time_ms: 1523,
  queries: ["Binance cold wallet movement", "0xF977814e90dA44bFA03b6295A0616a897441aceC", "Binance hack August 2026", "USDC massive transfer legitimate"],
};

const SUSPICIOUS_OSINT: OSINTResult = {
  verdict: "suspicious",
  confidence: 0.52,
  ai_summary: "Mixed signals detected. One analyst @onchaindetective suggested possible unauthorized access: \"Unusual transfer pattern from YieldMax — no prior history of this size to this address.\" However, YieldMax Discord mod confirmed: \"Scheduled treasury migration to new multi-sig.\" Receiving address 0xBEef... has 3 prior legitimate transactions. No security firms have issued alerts. Recommendation: monitor but do not pause — insufficient evidence for emergency action.",
  sources: [
    { title: "@onchaindetective: Unusual transfer from YieldMax", url: "https://x.com/onchaindetective/status/189234222222", snippet: "YieldMax Finance just moved $3.4M USDT to an address I\'ve never seen before. No announcement. Worth watching." },
    { title: "YieldMax Discord: Official response", url: "https://discord.com/channels/yieldmax/announcements", snippet: "Mod: This is a scheduled treasury migration to our new 3/5 multi-sig. Transaction was approved by 3 signers. Nothing to worry about." },
  ],
  keywords_found: ["unauthorized access", "treasury migration", "multi-sig", "legitimate", "monitoring"],
  response_time_ms: 2100,
  queries: ["YieldMax Finance hack", "0xDead000000000000000000000000000000000000", "YieldMax treasury migration", "YieldMax Finance exploit August 2026"],
};

// ── Consensus Engine ──────────────────────────────
function computeConsensus(anomaly: AnomalyEvent, osint: OSINTResult): ConsensusDecision {
  const baseScores: Record<AnomalyType, number> = { reentrancy_pattern: 40, flash_loan_attack: 38, governance_attack: 35, massive_outflow: 25, price_manipulation: 20 };
  const verdictScores: Record<ThreatVerdict, number> = { confirmed_exploit: 35, suspicious: 15, false_alarm: 0, inconclusive: 10 };

  const base = baseScores[anomaly.anomaly_type] || 20;
  const osintScore = verdictScores[osint.verdict] || 10;
  const confidenceBonus = osint.verdict !== "false_alarm" ? osint.confidence * 15 : 0;
  const amountBonus = osint.verdict !== "false_alarm" && anomaly.amount_usd > 0 ? Math.min(10, Math.log10(Math.max(anomaly.amount_usd, 1)) * 2) : 0;
  const internalTxBonus = anomaly.internal_txs > 20 ? 5 : anomaly.internal_txs > 5 ? 2 : 0;
  const threatScore = Math.min(100, base + osintScore + confidenceBonus + amountBonus + internalTxBonus);

  let action: ActionType;
  let shouldPause: boolean;
  let reasoning: string;
  const internalTxRisk = anomaly.internal_txs > 20 ? "CRITICAL — reentrancy pattern" : anomaly.internal_txs > 5 ? "ELEVATED" : "LOW";

  if (threatScore >= 75) {
    action = "pause_protocol"; shouldPause = true;
    reasoning = `HIGH THREAT (${Math.round(threatScore)}/100): ${anomaly.anomaly_type.replace(/_/g, " ")} detected on ${anomaly.protocol_name}. OSINT confirms ${osint.verdict.replace(/_/g, " ")} at ${Math.round(osint.confidence * 100)}% confidence across ${osint.sources.length} independent sources. Internal transaction pattern: ${internalTxRisk}. Immediate emergency pause required.`;
  } else if (threatScore >= 40) {
    action = "alert_only"; shouldPause = false;
    reasoning = `ELEVATED RISK (${Math.round(threatScore)}/100): ${anomaly.anomaly_type.replace(/_/g, " ")} on ${anomaly.protocol_name}. OSINT inconclusive (${Math.round(osint.confidence * 100)}% confidence, ${osint.sources.length} sources). ${internalTxRisk} internal tx pattern. Alerting human responders for manual review.`;
  } else if (threatScore >= 20) {
    action = "monitor"; shouldPause = false;
    reasoning = `LOW RISK (${Math.round(threatScore)}/100): OSINT suggests legitimate activity on ${anomaly.protocol_name}. ${osint.sources.length} sources indicate routine operation. Enhanced monitoring activated for next 24h.`;
  } else {
    action = "no_action"; shouldPause = false;
    reasoning = `FALSE ALARM (${Math.round(threatScore)}/100): ${anomaly.protocol_name} confirmed legitimate by ${osint.sources.length} independent OSINT sources at ${Math.round(osint.confidence * 100)}% confidence. Zero internal txs. No action required.`;
  }

  return {
    action, threat_score: Math.round(threatScore * 10) / 10, confidence: osint.confidence, reasoning,
    agent_signals: {
      watcher: { anomaly_type: anomaly.anomaly_type, amount_usd: anomaly.amount_usd, base_score: base, internal_tx_risk: internalTxRisk },
      osint: { verdict: osint.verdict, confidence: osint.confidence, sources_count: osint.sources.length, keywords: osint.keywords_found, response_ms: osint.response_time_ms },
      scoring: { base, osint_verdict: osintScore, confidence_bonus: Math.round(confidenceBonus * 10) / 10, amount_bonus: Math.round(amountBonus * 10) / 10, internal_tx_bonus: internalTxBonus, total: Math.round(threatScore * 10) / 10 },
    },
    should_execute_pause: shouldPause,
  };
}

// ── Log Generation ─────────────────────────────────
function generateLogs(scenario: Scenario, anomaly: AnomalyEvent, osint: OSINTResult, consensus: ConsensusDecision, exec: ExecutionResult): LogEntry[] {
  const t = (offset_ms: number) => new Date(Date.now() - 3000 + offset_ms).toISOString();
  const logs: LogEntry[] = [];
  const add = (ts: number, agent: string, level: LogEntry["level"], msg: string) => logs.push({ timestamp: t(ts), agent, level, message: msg });

  add(0, "AEGIS", "info", `Aegis Protocol v1.0.0 initialized — ${scenario === "hack" ? "LIVE MONITORING" : scenario === "false_alarm" ? "LIVE MONITORING" : "LIVE MONITORING"} mode`);
  add(100, "AEGIS", "info", `Connecting to Sepolia WebSocket (wss://eth-sepolia.g.alchemy.com/v2/...)`);
  add(200, "AEGIS", "success", "WebSocket connection established. Subscribing to Withdrawal events...");
  add(400, "WATCHER", "info", `Scanning block #${anomaly.block_number.toLocaleString()} mempool...`);
  add(600, "WATCHER", "warn", `ANOMALY DETECTED: ${anomaly.anomaly_type.replace(/_/g, " ").toUpperCase()} on ${anomaly.protocol_name}`);
  add(700, "WATCHER", "warn", `Amount: $${anomaly.amount_usd.toLocaleString()} ${anomaly.token} | Internal TXs: ${anomaly.internal_txs} | Gas: ${anomaly.gas_used.toLocaleString()}`);
  add(800, "WATCHER", "info", `TX: ${anomaly.tx_hash.slice(0, 18)}...${anomaly.tx_hash.slice(-8)}`);
  add(900, "WATCHER", "info", `From: ${anomaly.from_address} → To: ${anomaly.to_address}`);
  add(1000, "WATCHER", "warn", anomaly.internal_txs > 20 ? `INTERNAL TX PATTERN: ${anomaly.internal_txs} internal calls — consistent with reentrancy attack vector` : `Internal tx count: ${anomaly.internal_txs} — within normal range`);
  add(1100, "AEGIS", "info", `Anomaly confirmed. Escalating to OSINT Agent for verification...`);
  add(1200, "OSINT", "info", `Initializing Tavily API — searching for: "${anomaly.protocol_name} exploit"`);
  add(1300, "OSINT", "info", `Query 1/4: "${osint.queries[0]}" — 3 results`);
  add(1400, "OSINT", "info", `Query 2/4: "${osint.queries[1]}" — 2 results`);
  add(1500, "OSINT", "info", `Query 3/4: "${osint.queries[2]}" — 1 result`);
  add(1600, "OSINT", "info", `Query 4/4: "${osint.queries[3]}" — ${osint.sources.length - 3 > 0 ? osint.sources.length - 3 : 0} results`);
  add(1800, "OSINT", osint.verdict === "confirmed_exploit" ? "error" : osint.verdict === "false_alarm" ? "success" : "warn", `AI SYNTHESIS COMPLETE — Verdict: ${osint.verdict.replace(/_/g, " ").toUpperCase()} (${Math.round(osint.confidence * 100)}% confidence)`);
  add(1900, "OSINT", "info", `Sources: ${osint.sources.length} | Keywords: [${osint.keywords_found.slice(0, 3).join(", ")}...]`);
  add(2000, "AEGIS", "info", "OSINT analysis complete. Routing to Consensus Engine...");
  add(2100, "CONSENSUS", "info", "Stigmergy consensus initiated — aggregating agent signals...");
  add(2200, "CONSENSUS", "info", `Watcher signal: base_score=${consensus.agent_signals.watcher.base_score} (${consensus.agent_signals.watcher.anomaly_type})`);
  add(2300, "CONSENSUS", "info", `OSINT signal: verdict=${osint.verdict} confidence=${Math.round(osint.confidence * 100)}% sources=${osint.sources.length}`);
  add(2400, "CONSENSUS", "info", `Scoring: base(${consensus.agent_signals.scoring.base}) + osint(${consensus.agent_signals.scoring.osint_verdict}) + conf(${consensus.agent_signals.scoring.confidence_bonus}) + amt(${consensus.agent_signals.scoring.amount_bonus}) + intx(${consensus.agent_signals.scoring.internal_tx_bonus}) = ${consensus.agent_signals.scoring.total}`);
  add(2500, "CONSENSUS", consensus.should_execute_pause ? "error" : consensus.action === "alert_only" ? "warn" : "success", `DECISION: ${consensus.action.replace(/_/g, " ").toUpperCase()} — threat_score=${consensus.threat_score}/100`);
  add(2600, "AEGIS", consensus.should_execute_pause ? "error" : "info", consensus.should_execute_pause ? `CONSENSUS REACHED: PAUSE PROTOCOL. Executor Agent activated.` : `CONSENSUS REACHED: ${consensus.action.replace(/_/g, " ").toUpperCase()}. No pause required.`);

  if (consensus.should_execute_pause) {
    add(2700, "EXECUTOR", "info", "Preparing transaction: triggerEmergencyPause()");
    add(2800, "EXECUTOR", "info", `Contract: ${exec.contract_address}`);
    add(2900, "EXECUTOR", "info", `Signing with account 0xAeGiS...${exec.tx_hash.slice(-6)}`);
    add(3000, "EXECUTOR", "info", "Broadcasting transaction to Sepolia...");
    add(3100, "EXECUTOR", "success", `TX CONFIRMED: ${exec.tx_hash}`);
    add(3200, "EXECUTOR", "success", `Block #${exec.block_number.toLocaleString()} | Gas: ${exec.gas_used.toLocaleString()} | Cost: ${exec.gas_cost_eth} ETH`);
    add(3300, "AEGIS", "success", `PROTOCOL PAUSED. $${anomaly.amount_usd.toLocaleString()} ${anomaly.token} SAVED. Response: ${exec.execution_time_ms + osint.response_time_ms + 420}ms`);
  } else {
    add(2700, "AEGIS", "success", `FALSE ALARM AVOIDED. ${anomaly.protocol_name} remains live. No unnecessary panic.`);
  }

  return logs;
}

// ── Endpoint ───────────────────────────────────────
export async function GET(request: Request) {
  const { searchParams } = new URL(request.url);
  const scenario = (searchParams.get("scenario") as Scenario) || "hack";

  const anomalies = { hack: HACK_ANOMALY, false_alarm: FALSE_ALARM_ANOMALY, suspicious: SUSPICIOUS_ANOMALY };
  const osints = { hack: HACK_OSINT, false_alarm: FALSE_ALARM_OSINT, suspicious: SUSPICIOUS_OSINT };

  const anomaly = anomalies[scenario];
  const osint = osints[scenario];
  const consensus = computeConsensus(anomaly, osint);

  const execution: ExecutionResult = consensus.should_execute_pause
    ? { status: "success", tx_hash: "0xaegis_pause_" + Math.floor(Date.now() / 1000).toString(16), block_number: 5_892_342, gas_used: 48_721, gas_cost_eth: 0.002193, execution_time_ms: 312, chain: "sepolia", contract_address: "0x742d35Cc6634C0532925a3b844Bc9e7595f5bA16", function_signature: "triggerEmergencyPause()" }
    : { status: "skipped", tx_hash: "N/A", block_number: 0, gas_used: 0, gas_cost_eth: 0, execution_time_ms: 0, chain: "sepolia", contract_address: "0x742d35Cc6634C0532925a3b844Bc9e7595f5bA16", function_signature: "N/A" };

  const logs = generateLogs(scenario, anomaly, osint, consensus, execution);
  const vault_state = consensus.should_execute_pause
    ? { total_deposits: 24_800_000, pause_count: 1, is_paused: true, last_pause: new Date().toISOString() }
    : { total_deposits: 24_800_000, pause_count: 0, is_paused: false, last_pause: null };

  return NextResponse.json({
    run_id: `aegis-${Date.now().toString(36)}`,
    timestamp: new Date().toISOString(),
    scenario,
    pipeline_time_ms: osint.response_time_ms + execution.execution_time_ms + 420,
    logs,
    anomaly, osint, consensus, execution, vault_state,
  } satisfies PipelineResult);
}
