"use client";

import { useState, useEffect, useCallback, useRef } from "react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Progress } from "@/components/ui/progress";
import { Skeleton } from "@/components/ui/skeleton";
import { Separator } from "@/components/ui/separator";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import {
  Shield, ShieldAlert, ShieldCheck, Eye, Search, Brain, Zap,
  AlertTriangle, CheckCircle2, XCircle, Clock, Activity, ArrowRight,
  Radio, Terminal, Lock, ExternalLink, Play, Skull, FileText, Server,
  Ban, Hexagon, Wifi, FileCode2, Gavel, Globe2,
} from "lucide-react";

// ── Types ──────────────────────────────────────────
type Scenario = "hack" | "false_alarm" | "suspicious";
type ActionType = "pause_protocol" | "alert_only" | "monitor" | "no_action";
type ThreatVerdict = "confirmed_exploit" | "suspicious" | "false_alarm" | "inconclusive";

interface LogEntry {
  timestamp: string; agent: string;
  level: "info" | "warn" | "error" | "success"; message: string;
}

interface PipelineResult {
  run_id: string; timestamp: string; scenario: Scenario;
  pipeline_time_ms: number; logs: LogEntry[];
  anomaly: {
    event_id: string; tx_hash: string; protocol_name: string; anomaly_type: string;
    amount_usd: number; token: string; from_address: string; to_address: string;
    block_number: number; gas_used: number; gas_price_gwei: number; internal_txs: number;
    tx_timestamp: string;
  };
  osint: {
    verdict: ThreatVerdict; confidence: number; ai_summary: string;
    sources: { title: string; url: string; snippet: string }[];
    keywords_found: string[]; response_time_ms: number; queries: string[];
  };
  consensus: {
    action: ActionType; threat_score: number; confidence: number; reasoning: string;
    agent_signals: {
      watcher: { anomaly_type: string; amount_usd: number; base_score: number; internal_tx_risk: string };
      osint: { verdict: string; confidence: number; sources_count: number; keywords: string[]; response_ms: number };
      scoring: { base: number; osint_verdict: number; confidence_bonus: number; amount_bonus: number; internal_tx_bonus: number; total: number };
    };
    should_execute_pause: boolean;
  };
  execution: {
    status: string; tx_hash: string; block_number: number; gas_used: number;
    gas_cost_eth: number; execution_time_ms: number; chain: string;
    contract_address: string; function_signature: string;
  };
  vault_state: { total_deposits: number; pause_count: number; is_paused: boolean; last_pause: string | null };
}

// ── Pipeline Stages ───────────────────────────────
const STAGES = [
  { label: "Watcher Agent", icon: Eye, desc: "Mempool anomaly scan", color: "text-blue-400" },
  { label: "OSINT Agent", icon: Search, desc: "Tavily exploit verification", color: "text-purple-400" },
  { label: "Consensus Engine", icon: Brain, desc: "SwarmFi threat scoring", color: "text-amber-400" },
  { label: "Executor Agent", icon: Zap, desc: "On-chain pause() broadcast", color: "text-red-400" },
];

// ── Configs ───────────────────────────────────────
const verdictConfig: Record<ThreatVerdict, { label: string; color: string; icon: React.ElementType }> = {
  confirmed_exploit: { label: "CONFIRMED EXPLOIT", color: "bg-red-500/20 text-red-400 border-red-500/40", icon: Skull },
  suspicious: { label: "SUSPICIOUS", color: "bg-amber-500/20 text-amber-400 border-amber-500/40", icon: AlertTriangle },
  false_alarm: { label: "FALSE ALARM", color: "bg-emerald-500/20 text-emerald-400 border-emerald-500/40", icon: CheckCircle2 },
  inconclusive: { label: "INCONCLUSIVE", color: "bg-slate-500/20 text-slate-400 border-slate-500/40", icon: XCircle },
};

const actionConfig: Record<ActionType, { label: string; color: string; desc: string }> = {
  pause_protocol: { label: "PAUSE PROTOCOL", color: "bg-red-500/20 text-red-400 border border-red-500/40 shadow-red-500/20 shadow-lg", desc: "Emergency pause() broadcast" },
  alert_only: { label: "ALERT ONLY", color: "bg-amber-500/20 text-amber-400 border border-amber-500/40", desc: "Humans alerted, no auto-action" },
  monitor: { label: "MONITOR", color: "bg-blue-500/20 text-blue-400 border border-blue-500/40", desc: "Enhanced monitoring active" },
  no_action: { label: "NO ACTION", color: "bg-emerald-500/20 text-emerald-400 border border-emerald-500/40", desc: "False alarm confirmed" },
};

const agentColors: Record<string, string> = {
  AEGIS: "text-slate-400", WATCHER: "text-blue-400", OSINT: "text-purple-400", CONSENSUS: "text-amber-400", EXECUTOR: "text-red-400",
};
const levelColors: Record<string, string> = {
  info: "text-slate-500", warn: "text-amber-400", error: "text-red-400", success: "text-emerald-400",
};

// ── Components ─────────────────────────────────────

function StatCard({ icon: Icon, label, value, sub, accent }: { icon: React.ElementType; label: string; value: string | number; sub?: string; accent?: string }) {
  return (
    <Card className="bg-slate-900/60 border-slate-700/50 backdrop-blur-sm">
      <CardContent className="p-4 flex items-center gap-3">
        <div className={`p-2.5 rounded-lg ${accent || "bg-slate-800"}`}>
          <Icon className={`h-5 w-5 ${accent ? "text-white" : "text-slate-400"}`} />
        </div>
        <div>
          <p className="text-[10px] text-slate-500 uppercase tracking-wider">{label}</p>
          <p className="text-2xl font-bold text-white tabular-nums">{value}</p>
          {sub && <p className="text-[10px] text-slate-500">{sub}</p>}
        </div>
      </CardContent>
    </Card>
  );
}

function PipelineProgress({ stage }: { stage: number }) {
  return (
    <div className="space-y-2.5">
      {STAGES.map((s, i) => {
        const done = i < stage;
        const active = i === stage;
        const Icon = s.icon;
        return (
          <div key={s.label} className="flex items-center gap-3">
            <div className={`w-9 h-9 rounded-full flex items-center justify-center shrink-0 transition-all duration-500 ${
              done ? "bg-emerald-500/20 text-emerald-400" : active ? `bg-slate-800 ${s.color} animate-pulse` : "bg-slate-800/50 text-slate-700"
            }`}>
              {done ? <CheckCircle2 className="h-4 w-4" /> : <Icon className="h-4 w-4" />}
            </div>
            <div className="flex-1 min-w-0">
              <p className={`text-xs font-semibold ${done ? "text-emerald-400" : active ? s.color : "text-slate-700"}`}>{s.label}</p>
              <p className={`text-[10px] truncate ${done ? "text-slate-600" : active ? "text-slate-500" : "text-slate-800"}`}>{s.desc}</p>
            </div>
            {done && <ArrowRight className="h-3.5 w-3.5 text-emerald-700" />}
          </div>
        );
      })}
    </div>
  );
}

function LogTerminal({ logs, isRunning }: { logs: LogEntry[]; isRunning: boolean }) {
  const scrollRef = useRef<HTMLDivElement>(null);
  useEffect(() => {
    if (scrollRef.current) scrollRef.current.scrollTop = scrollRef.current.scrollHeight;
  }, [logs]);
  return (
    <div className="bg-[#0c0c14] border border-slate-800/80 rounded-xl overflow-hidden">
      <div className="flex items-center gap-2 px-4 py-2.5 border-b border-slate-800/80 bg-slate-900/50">
        <div className="flex gap-1.5">
          <div className="w-2.5 h-2.5 rounded-full bg-red-500/70" />
          <div className="w-2.5 h-2.5 rounded-full bg-amber-500/70" />
          <div className="w-2.5 h-2.5 rounded-full bg-emerald-500/70" />
        </div>
        <Terminal className="h-3.5 w-3.5 text-slate-600 ml-1" />
        <span className="text-[10px] text-slate-600 font-mono">aegis-protocol — agent swarm logs</span>
        <div className="flex-1" />
        {isRunning && <div className="flex items-center gap-1.5"><div className="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-pulse" /><span className="text-[9px] text-emerald-500 font-mono">STREAMING</span></div>}
      </div>
      <div ref={scrollRef} className="p-3 h-[460px] overflow-y-auto font-mono text-[11px] leading-relaxed space-y-0.5">
        {logs.length === 0 && !isRunning && <p className="text-slate-700">Waiting for pipeline run...</p>}
        {logs.map((log, i) => (
          <div key={i} className="flex gap-2">
            <span className="text-slate-700 shrink-0">{log?.timestamp?.slice?.(11, 23) ?? "--:--:--"}</span>
            <span className={`shrink-0 font-bold w-[72px] ${agentColors[log?.agent || ""] || "text-slate-500"}`}>{(log?.agent || "?").padEnd(9)}</span>
            <span className={`shrink-0 w-[28px] ${levelColors[log?.level || "info"]}`}>{log?.level === "error" ? "ERR" : log?.level === "warn" ? "WRN" : log?.level === "success" ? "OK " : "INF"}</span>
            <span className={`${levelColors[log?.level || "info"]}`}>{log?.message ?? ""}</span>
          </div>
        ))}
      </div>
    </div>
  );
}

// ── Main Page ──────────────────────────────────────
export default function AegisDashboard() {
  const [data, setData] = useState<PipelineResult | null>(null);
  const [loading, setLoading] = useState(false);
  const [pipelineStage, setPipelineStage] = useState(-1);
  const [selectedScenario, setSelectedScenario] = useState<Scenario>("hack");

  const runPipeline = useCallback(async (scenario: Scenario) => {
    setLoading(true);
    setPipelineStage(0);
    setData(null);
    for (let i = 0; i < STAGES.length; i++) {
      setPipelineStage(i);
      await new Promise((r) => setTimeout(r, 500 + Math.random() * 400));
    }
    try {
      const res = await fetch(`/api/aegis-protocol?scenario=${scenario}`);
      const json = await res.json();
      setData(json);
      setPipelineStage(STAGES.length);
    } catch { console.error("Pipeline failed"); }
    finally { setLoading(false); }
  }, []);

  useEffect(() => {
    const t = setTimeout(() => runPipeline("hack"), 100);
    return () => clearTimeout(t);
  }, [runPipeline]);

  const scenarioCards: { key: Scenario; label: string; desc: string; accent: string; emoji: string }[] = [
    { key: "hack", label: "Active Exploit", desc: "Reentrancy drain on OmniLend — $8.2M at risk", accent: "border-red-500/30 hover:border-red-500/50", emoji: "🚨" },
    { key: "false_alarm", label: "False Alarm", desc: "Binance cold wallet consolidation — $15M moved", accent: "border-emerald-500/30 hover:border-emerald-500/50", emoji: "✅" },
    { key: "suspicious", label: "Suspicious", desc: "Unknown YieldMax Finance transfer — $3.4M", accent: "border-amber-500/30 hover:border-amber-500/50", emoji: "⚠️" },
  ];

  return (
    <div className="min-h-screen bg-[#0a0a0f] text-white">
      {/* Header */}
      <header className="border-b border-slate-800 bg-[#0a0a0f]/80 backdrop-blur-md sticky top-0 z-50">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 py-3 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="p-2 rounded-lg bg-red-500/10 border border-red-500/20">
              <Hexagon className="h-5 w-5 text-red-400" />
            </div>
            <div>
              <h1 className="text-sm sm:text-base font-bold tracking-tight">Aegis Protocol</h1>
              <p className="text-[10px] text-slate-500">Autonomous AI Circuit Breaker for DeFi</p>
            </div>
          </div>
          <div className="flex items-center gap-3">
            {data && (
              <div className="hidden sm:flex items-center gap-2 text-xs text-slate-500">
                <Wifi className="h-3 w-3 text-emerald-500" />
                <span className="font-mono">Sepolia</span>
                <Separator orientation="vertical" className="h-3 bg-slate-800" />
                <Clock className="h-3 w-3" />
                <span className="font-mono">{new Date(data.timestamp).toLocaleTimeString()}</span>
              </div>
            )}
            <Button size="sm" onClick={() => runPipeline(selectedScenario)} disabled={loading}
              className="bg-red-500/10 hover:bg-red-500/20 text-red-400 border border-red-500/30 text-xs gap-1.5">
              <Play className="h-3 w-3" /> Run Agent
            </Button>
          </div>
        </div>
      </header>

      <main className="max-w-7xl mx-auto px-4 sm:px-6 py-6 space-y-6">
        {/* Scenario Selector */}
        <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
          {scenarioCards.map((s) => (
            <button key={s.key} onClick={() => { setSelectedScenario(s.key); runPipeline(s.key); }} disabled={loading}
              className={`text-left p-4 rounded-xl border bg-slate-900/60 backdrop-blur-sm transition-all ${data?.scenario === s.key ? s.accent + " ring-1 ring-slate-600" : "border-slate-700/50 hover:border-slate-600/50"} disabled:opacity-50`}>
              <p className="text-lg mb-1">{s.emoji}</p>
              <p className="text-sm font-semibold text-white">{s.label}</p>
              <p className="text-[11px] text-slate-500 mt-0.5">{s.desc}</p>
            </button>
          ))}
        </div>

        {/* Stats Row */}
        {data ? (
          <div className="grid grid-cols-2 sm:grid-cols-5 gap-3">
            <StatCard icon={Activity} label="Amount" value={`$${(data.anomaly.amount_usd / 1e6).toFixed(1)}M`} accent="bg-red-500/20" sub={data.anomaly.token} />
            <StatCard icon={Search} label="OSINT Sources" value={data.osint.sources.length} sub={`${data.osint.response_time_ms}ms`} accent="bg-purple-500/20" />
            <StatCard icon={Brain} label="Threat Score" value={`${data.consensus.threat_score}`} sub={actionConfig[data.consensus.action]?.label} accent={data.consensus.threat_score >= 75 ? "bg-red-500/20" : data.consensus.threat_score >= 40 ? "bg-amber-500/20" : "bg-emerald-500/20"} />
            <StatCard icon={Zap} label="Response" value={`${data.pipeline_time_ms}ms`} sub={data.execution.status === "success" ? "pause() sent" : "no action"} accent="bg-blue-500/20" />
            <StatCard icon={Server} label="Vault" value={data.vault_state.is_paused ? "PAUSED" : "ACTIVE"} sub={`TVL $${(data.vault_state.total_deposits / 1e6).toFixed(1)}M`} accent={data.vault_state.is_paused ? "bg-red-500/20" : "bg-emerald-500/20"} />
          </div>
        ) : (
          <div className="grid grid-cols-2 sm:grid-cols-5 gap-3">
            {Array.from({ length: 5 }).map((_, i) => <Skeleton key={i} className="h-20 bg-slate-900 rounded-lg" />)}
          </div>
        )}

        {/* Pipeline + Vault + Contract */}
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
          <Card className="bg-slate-900/60 border-slate-700/50 backdrop-blur-sm">
            <CardHeader className="pb-3">
              <CardTitle className="text-sm font-medium text-slate-400 flex items-center gap-2"><Radio className="h-4 w-4" /> Agent Swarm Pipeline</CardTitle>
            </CardHeader>
            <CardContent className="p-4 pt-0">
              <PipelineProgress stage={pipelineStage} />
              {pipelineStage >= STAGES.length && data && (
                <div className={`mt-4 p-3 rounded-lg border ${data.consensus.should_execute_pause ? "bg-red-500/10 border-red-500/20 text-red-400" : "bg-emerald-500/10 border-emerald-500/20 text-emerald-400"}`}>
                  <p className="text-xs font-medium text-center">
                    {data.consensus.should_execute_pause ? `PROTOCOL PAUSED in ${data.pipeline_time_ms}ms — $${data.anomaly.amount_usd.toLocaleString()} SAVED` : `FALSE ALARM AVOIDED — Protocol stays live`}
                  </p>
                </div>
              )}
            </CardContent>
          </Card>

          {data ? (
            <Card className="bg-slate-900/60 border-slate-700/50 backdrop-blur-sm">
              <CardHeader className="pb-3"><CardTitle className="text-sm font-medium text-slate-400 flex items-center gap-2"><Server className="h-4 w-4" /> VulnerableVault — On-Chain State</CardTitle></CardHeader>
              <CardContent className="p-4 pt-0 space-y-3">
                <div className={`p-3 rounded-lg border flex items-center gap-2 ${data.vault_state.is_paused ? "bg-red-950/30 border-red-500/20" : "bg-emerald-950/20 border-emerald-500/20"}`}>
                  {data.vault_state.is_paused ? <Ban className="h-5 w-5 text-red-400" /> : <ShieldCheck className="h-5 w-5 text-emerald-400" />}
                  <span className={`text-sm font-bold ${data.vault_state.is_paused ? "text-red-400" : "text-emerald-400"}`}>{data.vault_state.is_paused ? "VAULT PAUSED" : "VAULT ACTIVE"}</span>
                </div>
                <div className="grid grid-cols-3 gap-2">
                  {[{l:"TVL",v:`$${(data.vault_state.total_deposits/1e6).toFixed(1)}M`,c:"text-white"},{l:"Pauses",v:`${data.vault_state.pause_count}`,c:data.vault_state.pause_count>0?"text-red-400":"text-white"},{l:"Chain",v:"Sepolia",c:"text-white"}].map(x=>(
                    <div key={x.l} className="bg-slate-950/50 rounded-lg p-2.5 border border-slate-800/50 text-center">
                      <p className="text-[10px] text-slate-500">{x.l}</p>
                      <p className={`text-sm font-bold font-mono ${x.c}`}>{x.v}</p>
                    </div>
                  ))}
                </div>
                {data.vault_state.is_paused && data.vault_state.last_pause && (
                  <div className="bg-slate-950/50 rounded-lg p-2.5 border border-slate-800/50">
                    <p className="text-[10px] text-slate-500">LAST PAUSE</p>
                    <p className="text-xs text-white font-mono">{new Date(data.vault_state.last_pause).toLocaleString()}</p>
                  </div>
                )}
                <div className="bg-slate-950/50 rounded-lg p-2.5 border border-slate-800/50">
                  <p className="text-[10px] text-slate-500 mb-1">CONTRACT</p>
                  <p className="text-[11px] text-slate-400 font-mono truncate">{data.execution.contract_address}</p>
                </div>
              </CardContent>
            </Card>
          ) : <Skeleton className="h-[280px] bg-slate-900 rounded-lg" />}

          {data ? (
            <Card className="bg-slate-900/60 border-slate-700/50 backdrop-blur-sm">
              <CardHeader className="pb-3"><CardTitle className="text-sm font-medium text-slate-400 flex items-center gap-2"><FileCode2 className="h-4 w-4" /> VulnerableVault.sol</CardTitle></CardHeader>
              <CardContent className="p-4 pt-0 space-y-2.5">
                <div className="bg-slate-950/50 rounded-lg p-3 border border-slate-800/50 font-mono text-[10px] space-y-0.5">
                  <p className="text-slate-600">// SPDX-License-Identifier: MIT</p>
                  <p className="text-purple-400">contract <span className="text-emerald-400">VulnerableVault</span></p>
                  <p className="text-slate-600">  is Pausable, Ownable {"{"}</p>
                  <p className="text-amber-400">  function <span className="text-white">triggerEmergencyPause</span>()</p>
                  <p className="text-amber-400">    external onlyOwner {"{"}</p>
                  <p className={data.vault_state.is_paused ? "text-red-400" : "text-slate-500"}>      <span className={data.vault_state.is_paused ? "" : ""}>_pause();</span></p>
                  <p className="text-slate-600">    {"}"}</p>
                  <p className="text-slate-600">{"}"}</p>
                </div>
                <div className="bg-slate-950/50 rounded-lg p-3 border border-slate-800/50">
                  <p className="text-[10px] text-slate-500 mb-1">FUNCTION CALLED</p>
                  <p className="text-xs text-white font-mono">{data.execution.function_signature}</p>
                </div>
                <div className="grid grid-cols-2 gap-2">
                  <div className="bg-slate-950/50 rounded-lg p-2.5 border border-slate-800/50">
                    <p className="text-[10px] text-slate-500">Gas Used</p>
                    <p className="text-xs text-white font-mono">{data.execution.gas_used > 0 ? data.execution.gas_used.toLocaleString() : "N/A"}</p>
                  </div>
                  <div className="bg-slate-950/50 rounded-lg p-2.5 border border-slate-800/50">
                    <p className="text-[10px] text-slate-500">Gas Cost</p>
                    <p className="text-xs text-white font-mono">{data.execution.gas_cost_eth > 0 ? `${data.execution.gas_cost_eth} ETH` : "N/A"}</p>
                  </div>
                </div>
              </CardContent>
            </Card>
          ) : <Skeleton className="h-[280px] bg-slate-900 rounded-lg" />}
        </div>

        {/* Tabbed Detail Panels */}
        {data && (
          <Tabs defaultValue="logs" className="w-full">
            <TabsList className="bg-slate-900/60 border border-slate-700/50">
              <TabsTrigger value="logs" className="text-xs gap-1.5 data-[state=active]:bg-slate-800"><Terminal className="h-3.5 w-3.5" /> Agent Logs</TabsTrigger>
              <TabsTrigger value="anomaly" className="text-xs gap-1.5 data-[state=active]:bg-slate-800"><Eye className="h-3.5 w-3.5" /> Anomaly</TabsTrigger>
              <TabsTrigger value="osint" className="text-xs gap-1.5 data-[state=active]:bg-slate-800"><Globe2 className="h-3.5 w-3.5" /> OSINT</TabsTrigger>
              <TabsTrigger value="consensus" className="text-xs gap-1.5 data-[state=active]:bg-slate-800"><Gavel className="h-3.5 w-3.5" /> Consensus</TabsTrigger>
              <TabsTrigger value="execution" className="text-xs gap-1.5 data-[state=active]:bg-slate-800"><Zap className="h-3.5 w-3.5" /> Execution</TabsTrigger>
            </TabsList>
            <TabsContent value="logs" className="mt-4"><LogTerminal logs={data.logs} isRunning={loading} /></TabsContent>
            <TabsContent value="anomaly" className="mt-4">
              <Card className="bg-slate-900/60 border-slate-700/50 backdrop-blur-sm">
                <CardHeader className="pb-3"><CardTitle className="text-sm font-medium text-slate-400 flex items-center gap-2"><Eye className="h-4 w-4" /> Watcher Agent — Anomaly</CardTitle></CardHeader>
                <CardContent className="p-4 pt-0 space-y-3">
                  <div className="flex items-center justify-between">
                    <p className="text-sm font-semibold text-white">{data.anomaly.protocol_name}</p>
                    <Badge className="bg-red-500/20 text-red-400 border border-red-500/30 text-[10px]">{data.anomaly.anomaly_type.replace(/_/g, " ").toUpperCase()}</Badge>
                  </div>
                  <div className="grid grid-cols-2 sm:grid-cols-4 gap-2">
                    {[{l:"Amount",v:`$${data.anomaly.amount_usd.toLocaleString()} ${data.anomaly.token}`},{l:"Block",v:`#${data.anomaly.block_number.toLocaleString()}`},{l:"Gas",v:`${data.anomaly.gas_used.toLocaleString()}`},{l:"Internal TXs",v:`${data.anomaly.internal_txs}`,c:data.anomaly.internal_txs>10?"text-red-400":"text-white"}].map(x=>(
                      <div key={x.l} className="bg-slate-950/50 rounded-lg p-2.5 border border-slate-800/50">
                        <p className="text-[10px] text-slate-500">{x.l}</p>
                        <p className={`text-white font-mono font-bold ${"c" in x ? x.c : ""}`}>{x.v}</p>
                      </div>
                    ))}
                  </div>
                  <div className="bg-slate-950/50 rounded-lg p-2.5 border border-slate-800/50"><p className="text-[10px] text-slate-500 mb-1">TX HASH</p><p className="text-xs text-slate-400 font-mono break-all">{data.anomaly.tx_hash}</p></div>
                  <div className="grid grid-cols-2 gap-2">
                    <div><p className="text-[10px] text-slate-500 mb-0.5">FROM</p><p className="text-[11px] text-slate-400 font-mono truncate">{data.anomaly.from_address}</p></div>
                    <div><p className="text-[10px] text-slate-500 mb-0.5">TO</p><p className="text-[11px] text-slate-400 font-mono truncate">{data.anomaly.to_address}</p></div>
                  </div>
                </CardContent>
              </Card>
            </TabsContent>
            <TabsContent value="osint" className="mt-4">
              <Card className="bg-slate-900/60 border-slate-700/50 backdrop-blur-sm">
                <CardHeader className="pb-3"><CardTitle className="text-sm font-medium text-slate-400 flex items-center gap-2"><Globe2 className="h-4 w-4" /> OSINT Agent — Tavily</CardTitle></CardHeader>
                <CardContent className="p-4 pt-0 space-y-3">
                  <div className="flex items-center gap-3">
                    <Badge className={`text-[10px] border ${verdictConfig[data.osint.verdict].color}`}>{verdictConfig[data.osint.verdict].label}</Badge>
                    <div className="flex-1"><div className="flex items-center gap-2"><p className="text-xs text-slate-500">Confidence</p><p className="text-sm font-bold text-white">{Math.round(data.osint.confidence * 100)}%</p></div><Progress value={data.osint.confidence * 100} className="h-1.5 mt-1" /></div>
                  </div>
                  <div className="bg-slate-950/50 rounded-lg p-3 border border-slate-800/50"><p className="text-[10px] text-slate-500 mb-1.5">TAVILY AI SYNTHESIS</p><p className="text-xs text-slate-300 leading-relaxed">{data.osint.ai_summary}</p></div>
                  <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                    <div>
                      <p className="text-[10px] text-slate-500 mb-1.5">SOURCES ({data.osint.sources.length})</p>
                      {data.osint.sources.map((s, i) => (
                        <div key={i} className="mb-2 p-2 rounded-lg bg-slate-950/30 border border-slate-800/30">
                          <div className="flex items-center gap-1.5 mb-1"><ExternalLink className="h-3 w-3 text-blue-400 shrink-0" /><span className="text-xs text-white font-medium truncate">{s.title}</span></div>
                          <p className="text-[10px] text-slate-500 leading-relaxed line-clamp-2">{s.snippet}</p>
                        </div>
                      ))}
                    </div>
                    <div>
                      <p className="text-[10px] text-slate-500 mb-1.5">TAVILY QUERIES</p>
                      {data.osint.queries.map((q, i) => (<div key={i} className="flex items-center gap-2 text-xs mb-1.5"><Search className="h-3 w-3 text-purple-400 shrink-0" /><span className="text-slate-400 font-mono text-[11px]">{q}</span></div>))}
                      <p className="text-[10px] text-slate-500 mb-1.5 mt-3">KEYWORDS</p>
                      <div className="flex flex-wrap gap-1">{data.osint.keywords_found.map((kw) => (<Badge key={kw} variant="outline" className="text-[9px] border-slate-700 text-slate-400 bg-slate-800/50">{kw}</Badge>))}</div>
                    </div>
                  </div>
                </CardContent>
              </Card>
            </TabsContent>
            <TabsContent value="consensus" className="mt-4">
              <Card className="bg-slate-900/60 border-slate-700/50 backdrop-blur-sm">
                <CardHeader className="pb-3"><CardTitle className="text-sm font-medium text-slate-400 flex items-center gap-2"><Gavel className="h-4 w-4" /> Consensus — SwarmFi</CardTitle></CardHeader>
                <CardContent className="p-4 pt-0 space-y-4">
                  <div className={`p-4 rounded-xl border ${actionConfig[data.consensus.action].color}`}>
                    <div className="flex items-center gap-3">{data.consensus.should_execute_pause ? <ShieldAlert className="h-6 w-6 text-red-400" /> : <ShieldCheck className="h-6 w-6 text-emerald-400" />}<div><p className="text-sm font-bold">{actionConfig[data.consensus.action].label}</p><p className="text-[11px] opacity-70">{actionConfig[data.consensus.action].desc}</p></div></div>
                  </div>
                  <div>
                    <div className="flex justify-between items-center mb-1.5"><p className="text-xs text-slate-500">Threat Score</p><p className={`text-lg font-bold font-mono ${data.consensus.threat_score >= 75 ? "text-red-400" : data.consensus.threat_score >= 40 ? "text-amber-400" : "text-emerald-400"}`}>{data.consensus.threat_score}</p></div>
                    <div className="w-full h-3 bg-slate-800 rounded-full overflow-hidden"><div className={`h-full rounded-full transition-all duration-1000 ${data.consensus.threat_score >= 75 ? "bg-red-500" : data.consensus.threat_score >= 40 ? "bg-amber-500" : "bg-emerald-500"}`} style={{ width: `${data.consensus.threat_score}%` }} /></div>
                    <div className="flex justify-between mt-1 text-[9px] text-slate-600"><span>0 SAFE</span><span className="text-amber-500">40 ALERT</span><span className="text-red-500">75 PAUSE</span></div>
                  </div>
                  <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                    <div className="space-y-2">
                      <p className="text-[10px] text-slate-500">SCORE BREAKDOWN</p>
                      {Object.entries(data.consensus.agent_signals.scoring).filter(([k]) => k !== "total").map(([key, val]) => (<div key={key} className="flex items-center justify-between text-xs"><span className="text-slate-400 capitalize">{key.replace(/_/g, " ")}</span><span className="text-white font-mono">+{val as number}</span></div>))}
                      <Separator className="bg-slate-800" />
                      <div className="flex items-center justify-between text-xs"><span className="text-slate-300 font-medium">Total</span><span className="text-white font-bold font-mono">{data.consensus.agent_signals.scoring.total}</span></div>
                    </div>
                    <div className="space-y-2">
                      <p className="text-[10px] text-slate-500">AGENT SIGNALS</p>
                      <div className="bg-slate-950/50 rounded-lg p-2.5 border border-slate-800/50"><p className="text-[10px] text-blue-400 font-bold mb-1">WATCHER</p><p className="text-[11px] text-slate-400">Type: {data.consensus.agent_signals.watcher.anomaly_type.replace(/_/g, " ")}</p><p className="text-[11px] text-slate-400">Base: {data.consensus.agent_signals.watcher.base_score} | Risk: <span className={data.consensus.agent_signals.watcher.internal_tx_risk.includes("CRITICAL") ? "text-red-400" : "text-white"}>{data.consensus.agent_signals.watcher.internal_tx_risk}</span></p></div>
                      <div className="bg-slate-950/50 rounded-lg p-2.5 border border-slate-800/50"><p className="text-[10px] text-purple-400 font-bold mb-1">OSINT</p><p className="text-[11px] text-slate-400">Verdict: {data.consensus.agent_signals.osint.verdict.replace(/_/g, " ")} | Conf: {Math.round(data.consensus.agent_signals.osint.confidence * 100)}%</p></div>
                    </div>
                  </div>
                  <p className="text-xs text-slate-400 leading-relaxed">{data.consensus.reasoning}</p>
                </CardContent>
              </Card>
            </TabsContent>
            <TabsContent value="execution" className="mt-4">
              <Card className={`bg-slate-900/60 border backdrop-blur-sm ${data.execution.status === "success" ? "border-red-500/30" : "border-slate-700/50"}`}>
                <CardHeader className="pb-3"><CardTitle className="text-sm font-medium text-slate-400 flex items-center gap-2"><Zap className="h-4 w-4" /> Executor — On-Chain</CardTitle></CardHeader>
                <CardContent className="p-4 pt-0 space-y-3">
                  {data.execution.status === "success" ? (
                    <>
                      <div className="p-3 rounded-lg bg-red-950/30 border border-red-500/20"><p className="text-xs font-bold text-red-400 mb-1">EMERGENCY PAUSE BROADCAST</p><p className="text-xs text-slate-400">triggerEmergencyPause() executed on Sepolia</p></div>
                      <div className="grid grid-cols-2 gap-2">
                        {["TX Hash",data.execution.tx_hash,"Block",`#${data.execution.block_number.toLocaleString()}`,"Gas Used",`${data.execution.gas_used.toLocaleString()}`,"Gas Cost",`${data.execution.gas_cost_eth} ETH`].reduce<React.ReactNode[]>((acc,v,i,a)=>{if(i%2===0)acc.push(<div key={i} className="bg-slate-950/50 rounded-lg p-2.5 border border-slate-800/50"><p className="text-[10px] text-slate-500">{v as string}</p><p className="text-xs text-white font-mono truncate">{a[i+1] as string}</p></div>);return acc;},[])}
                      </div>
                    </>
                  ) : (
                    <div className="p-8 rounded-lg bg-emerald-950/20 border border-emerald-500/20 text-center"><CheckCircle2 className="h-8 w-8 text-emerald-400 mx-auto mb-2" /><p className="text-sm font-medium text-emerald-400">No Pause Required</p><p className="text-xs text-slate-500 mt-1">Protocol remains live. No unnecessary panic.</p></div>
                  )}
                </CardContent>
              </Card>
            </TabsContent>
          </Tabs>
        )}
        <footer className="border-t border-slate-800 pt-6 mt-8">
          <div className="flex flex-col sm:flex-row items-center justify-between gap-3 text-xs text-slate-600">
            <p>Aegis Protocol — DoraHacks Web3 Hackathon 2026</p>
            <div className="flex items-center gap-3">
              {["Tavily AI","Web3.py","Solidity","SwarmFi"].map(t=><Badge key={t} variant="outline" className="text-[9px] border-slate-800 text-slate-500">{t}</Badge>)}
            </div>
          </div>
        </footer>
      </main>
    </div>
  );
}