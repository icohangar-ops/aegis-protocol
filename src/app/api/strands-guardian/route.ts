import { NextResponse } from "next/server";

// ── Types ──────────────────────────────────────────────
type Priority = "P1" | "P2" | "P3";
type Severity = "critical" | "high" | "medium" | "low";

export interface ICSAsset {
  id: string;
  host: string;
  ip: string;
  port: number;
  protocol: string;
  city: string;
  state: string;
  lat: number;
  lon: number;
  org: string;
}

export interface ThreatIntel {
  asset_id: string;
  title: string;
  source: string;
  severity: Severity;
  summary: string;
  date: string;
}

export interface MitreTechnique {
  id: string;
  name: string;
  tactic: string;
  matrix: "ICS" | "Enterprise";
  confidence: number;
}

export interface CisaKevEntry {
  cve: string;
  product: string;
  description: string;
  ransomware_used: boolean;
}

export interface GeoEvent {
  id: string;
  type: string;
  title: string;
  severity: Severity;
  lat: number;
  lon: number;
  distance_km: number;
  bearing: string;
}

export interface Dossier {
  asset: ICSAsset;
  priority: Priority;
  score: number;
  threats: ThreatIntel[];
  mitre_techniques: MitreTechnique[];
  cisa_kev: CisaKevEntry[];
  geo_events: GeoEvent[];
  summary: string;
}

export interface PipelineRun {
  run_id: string;
  timestamp: string;
  status: string;
  mode: string;
  total_assets: number;
  total_threats: number;
  total_kev: number;
  total_mitre: number;
  total_geo_events: number;
  p1_count: number;
  p2_count: number;
  p3_count: number;
  assets: ICSAsset[];
  dossiers: Dossier[];
}

// ── Mock Data ──────────────────────────────────────────
const ASSETS: ICSAsset[] = [
  { id: "ast-001", host: "plc-houston-01", ip: "198.51.100.22", port: 502, protocol: "Modbus TCP", city: "Houston", state: "TX", lat: 29.76, lon: -95.37, org: "Gulf Coast Energy Corp" },
  { id: "ast-002", host: "scada-atlanta-01", ip: "203.0.113.45", port: 102, protocol: "Siemens S7", city: "Atlanta", state: "GA", lat: 33.75, lon: -84.39, org: "Piedmont Power Grid" },
  { id: "ast-003", host: "rtu-chatt-01", ip: "192.0.2.78", port: 20000, protocol: "DNP3", city: "Chattanooga", state: "TN", lat: 35.05, lon: -85.31, org: "Tennessee Valley Utilities" },
  { id: "ast-004", host: "enip-charlotte-01", ip: "198.51.100.130", port: 44818, protocol: "EtherNet/IP", city: "Charlotte", state: "NC", lat: 35.23, lon: -80.84, org: "Carolina Manufacturing Co." },
  { id: "ast-005", host: "bacnet-nash-01", ip: "203.0.113.200", port: 47808, protocol: "BACnet", city: "Nashville", state: "TN", lat: 36.16, lon: -86.78, org: "Metro Hospital Network" },
];

const THREATS: ThreatIntel[] = [
  { asset_id: "ast-001", title: "Volt Typhoon APT targets US critical infrastructure", source: "CISA Advisory", severity: "critical", summary: "Chinese state-sponsored APT group observed targeting US energy sector ICS assets with living-off-the-land techniques. Modbus TCP devices are primary reconnaissance targets.", date: "2025-08-15" },
  { asset_id: "ast-001", title: "Ransomware group exploiting Modbus weak authentication", source: "Dark Reading", severity: "high", summary: "New ransomware variant specifically targeting SCADA systems with Modbus TCP, exploiting lack of authentication in protocol specification.", date: "2025-08-12" },
  { asset_id: "ast-002", title: "Siemens S7 PLC firmware vulnerability CVE-2025-41877", source: "NIST NVD", severity: "critical", summary: "Remote code execution vulnerability in Siemens S7-1500 series PLCs allows unauthenticated attackers to execute arbitrary code via crafted S7comm packets.", date: "2025-08-10" },
  { asset_id: "ast-002", title: "APT33 targeting energy sector with S7-specific implants", source: "Mandiant", severity: "high", summary: "Iranian threat group deploying custom S7 protocol implants in Middle Eastern and US energy infrastructure, enabling persistent unauthorized access.", date: "2025-08-08" },
  { asset_id: "ast-003", title: "DNP3 outstation spoofing attacks on water utilities", source: "ICS-CERT", severity: "high", summary: "Multiple water utilities report DNP3 outstation spoofing attacks attempting to manipulate sensor readings and control relay states.", date: "2025-08-05" },
  { asset_id: "ast-004", title: "EtherNet/IP device enumeration tool released", source: "Exploit-DB", severity: "medium", summary: "Open-source tool for mass-enumerating EtherNet/IP devices on the public internet. Targets Rockwell Automation and Allen-Bradley controllers.", date: "2025-07-30" },
  { asset_id: "ast-005", title: "BACnet protocol used as C2 channel in hospital attack", source: "Recorded Future", severity: "medium", summary: "Threat actors used BACnet protocol as covert command-and-control channel during ransomware attack on healthcare network.", date: "2025-07-28" },
];

const MITRE_TECHNIQUES: MitreTechnique[] = [
  { id: "T0881", name: "Modbus Function Code Inhibition", tactic: "Inhibit Response Function", matrix: "ICS", confidence: 0.95 },
  { id: "T0882", name: "Modbus Read Device Identification", tactic: "Discovery", matrix: "ICS", confidence: 0.90 },
  { id: "T0885", name: "Manipulation of Control Logic", tactic: "Manipulation of Control", matrix: "ICS", confidence: 0.88 },
  { id: "T0886", name: "Modbus Bus Traffic Manipulation", tactic: "Manipulation of Control", matrix: "ICS", confidence: 0.85 },
  { id: "T0881", name: "Edge Peripheral Device Discovery", tactic: "Discovery", matrix: "Enterprise", confidence: 0.80 },
  { id: "T1046", name: "Network Service Discovery", tactic: "Discovery", matrix: "Enterprise", confidence: 0.92 },
  { id: "T1078", name: "Valid Accounts", tactic: "Initial Access", matrix: "Enterprise", confidence: 0.87 },
  { id: "T1059", name: "Command and Scripting Interpreter", tactic: "Execution", matrix: "Enterprise", confidence: 0.85 },
  { id: "T1055", name: "Process Injection", tactic: "Defense Evasion", matrix: "Enterprise", confidence: 0.78 },
  { id: "T1490", name: "Inhibit System Recovery", tactic: "Impact", matrix: "Enterprise", confidence: 0.82 },
  { id: "T1486", name: "Data Encrypted for Impact", tactic: "Impact", matrix: "Enterprise", confidence: 0.91 },
  { id: "T0831", name: "Loss of Protection", tactic: "Impair Process Control", matrix: "ICS", confidence: 0.86 },
];

const CISA_KEV: CisaKevEntry[] = [
  { cve: "CVE-2025-41877", product: "Siemens S7-1500 CPU Firmware", description: "Remote code execution via crafted S7comm packets in Siemens S7-1500 PLC firmware versions prior to 2.9.", ransomware_used: true },
  { cve: "CVE-2024-47176", product: "CUPS IPP Service", description: "Remote code execution in CUPS printing service commonly found in OT network management workstations.", ransomware_used: false },
  { cve: "CVE-2024-3400", product: "Palo Alto Networks PAN-OS", description: "OS command injection in GlobalProtect gateway, enabling unauthenticated RCE on perimeter firewalls protecting ICS networks.", ransomware_used: true },
];

const GEO_EVENTS: GeoEvent[] = [
  { id: "geo-001", type: "NOAA CAP Alert", title: "Severe Thunderstorm Warning — Southeast US", severity: "high", lat: 34.0, lon: -85.0, distance_km: 142, bearing: "SE" },
  { id: "geo-002", type: "NASA FIRMS VIIRS", title: "Wildfire Detection FRP=187 MW near Chattanooga", severity: "critical", lat: 35.2, lon: -85.5, distance_km: 17, bearing: "W" },
  { id: "geo-003", type: "USGS Earthquake", title: "M4.7 Earthquake — Eastern Tennessee", severity: "high", lat: 35.4, lon: -84.8, distance_km: 45, bearing: "NE" },
  { id: "geo-004", type: "GDACS Alert", title: "Tropical Storm Warning — Gulf of Mexico", severity: "medium", lat: 28.5, lon: -92.0, distance_km: 135, bearing: "S" },
];

function haversineKm(lat1: number, lon1: number, lat2: number, lon2: number): number {
  const R = 6371;
  const dLat = ((lat2 - lat1) * Math.PI) / 180;
  const dLon = ((lon2 - lon1) * Math.PI) / 180;
  const a = Math.sin(dLat / 2) ** 2 + Math.cos((lat1 * Math.PI) / 180) * Math.cos((lat2 * Math.PI) / 180) * Math.sin(dLon / 2) ** 2;
  return R * 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1 - a));
}

function bearingDeg(lat1: number, lon1: number, lat2: number, lon2: number): number {
  const dLon = ((lon2 - lon1) * Math.PI) / 180;
  const y = Math.sin(dLon) * Math.cos((lat2 * Math.PI) / 180);
  const x = Math.cos((lat1 * Math.PI) / 180) * Math.sin((lat2 * Math.PI) / 180) - Math.sin((lat1 * Math.PI) / 180) * Math.cos((lat2 * Math.PI) / 180) * Math.cos(dLon);
  return ((Math.atan2(y, x) * 180) / Math.PI + 360) % 360;
}

function bearingLabel(deg: number): string {
  const dirs = ["N", "NE", "E", "SE", "S", "SW", "W", "NW"];
  return dirs[Math.round(deg / 45) % 8];
}

// ── Score + Build Dossiers ─────────────────────────────
function computePriority(threatCount: number, kevCount: number, mitreCount: number, geoSevere: number, hasRansomware: boolean): { priority: Priority; score: number } {
  let score = threatCount * 8 + kevCount * 25 + mitreCount * 10 + geoSevere * 15;
  if (hasRansomware) score += 30;
  let priority: Priority = "P3";
  if (score >= 100 || hasRansomware) priority = "P1";
  else if (score >= 40) priority = "P2";
  return { priority, score };
}

function buildDossiers(): Dossier[] {
  const mitreByProtocol: Record<string, MitreTechnique[]> = {
    "Modbus TCP": [MITRE_TECHNIQUES[0], MITRE_TECHNIQUES[1], MITRE_TECHNIQUES[3], MITRE_TECHNIQUES[5], MITRE_TECHNIQUES[7]],
    "Siemens S7": [MITRE_TECHNIQUES[2], MITRE_TECHNIQUES[0], MITRE_TECHNIQUES[4], MITRE_TECHNIQUES[5], MITRE_TECHNIQUES[8], MITRE_TECHNIQUES[9]],
    "DNP3": [MITRE_TECHNIQUES[2], MITRE_TECHNIQUES[11], MITRE_TECHNIQUES[5], MITRE_TECHNIQUES[6]],
    "EtherNet/IP": [MITRE_TECHNIQUES[4], MITRE_TECHNIQUES[5], MITRE_TECHNIQUES[7]],
    "BACnet": [MITRE_TECHNIQUES[4], MITRE_TECHNIQUES[5], MITRE_TECHNIQUES[10]],
  };

  return ASSETS.map((asset) => {
    const assetThreats = THREATS.filter((t) => t.asset_id === asset.id);
    const mitre = mitreByProtocol[asset.protocol] || [];
    // KEV: match Siemens CVE to Siemens assets; PAN-OS to perimeter-relevant; CUPS to workstation-relevant
    const kev = CISA_KEV.filter((k) => {
      if (asset.protocol.includes("Siemens") && k.cve === "CVE-2025-41877") return true;
      if (asset.protocol === "EtherNet/IP" && k.cve === "CVE-2024-3400") return true;
      return false;
    });
    const nearbyGeo = GEO_EVENTS.map((g) => {
      const dist = Math.round(haversineKm(asset.lat, asset.lon, g.lat, g.lon));
      const bear = bearingLabel(bearingDeg(asset.lat, asset.lon, g.lat, g.lon));
      return { ...g, distance_km: dist, bearing: bear };
    }).filter((g) => g.distance_km < 150);
    const geoSevere = nearbyGeo.filter(
      (g) => g.severity === "critical" || g.severity === "high"
    ).length;
    const hasRansomware = kev.some((k) => k.ransomware_used) || assetThreats.some((t) => t.title.toLowerCase().includes("ransomware"));

    const { priority, score } = computePriority(assetThreats.length, kev.length, mitre.length, geoSevere, hasRansomware);

    const summaries: Record<Priority, string> = {
      P1: `CRITICAL — Active exploitation confirmed. ${asset.org} ${asset.protocol} asset at ${asset.city}, ${asset.state} has ${kev.length} CISA KEV entries, ${assetThreats.length} active threats, and ${mitre.length} MITRE ATT&CK technique mappings. Ransomware activity ${hasRansomware ? "detected" : "not detected"}. ${nearbyGeo.length} severe geo-events within 100km. Immediate SOC response recommended.`,
      P2: `ELEVATED — ${asset.org} ${asset.protocol} asset at ${asset.city}, ${asset.state} shows ${assetThreats.length} threat intelligence hits with ${mitre.length} MITRE ATT&CK mappings. ${kev.length} KEV entries found. ${nearbyGeo.length} nearby geo-events warrant monitoring.`,
      P3: `MONITOR — ${asset.org} ${asset.protocol} asset at ${asset.city}, ${asset.state} has ${assetThreats.length} low-severity intelligence items and ${mitre.length} technique mappings. No immediate action required; continue routine monitoring.`,
    };

    return {
      asset,
      priority,
      score,
      threats: assetThreats,
      mitre_techniques: mitre,
      cisa_kev: kev,
      geo_events: nearbyGeo,
      summary: summaries[priority],
    };
  }).sort((a, b) => b.score - a.score);
}

// ── Endpoint ───────────────────────────────────────────
export async function GET() {
  const dossiers = buildDossiers();

  const pipelineRun: PipelineRun = {
    run_id: `run-${Date.now().toString(36)}`,
    timestamp: new Date().toISOString(),
    status: "completed",
    mode: "mock-demo",
    total_assets: ASSETS.length,
    total_threats: THREATS.length,
    total_kev: CISA_KEV.length,
    total_mitre: [...new Map(MITRE_TECHNIQUES.map((t) => [t.id, t])).values()].length,
    total_geo_events: GEO_EVENTS.length,
    p1_count: dossiers.filter((d) => d.priority === "P1").length,
    p2_count: dossiers.filter((d) => d.priority === "P2").length,
    p3_count: dossiers.filter((d) => d.priority === "P3").length,
    assets: ASSETS,
    dossiers,
  };

  return NextResponse.json(pipelineRun);
}
