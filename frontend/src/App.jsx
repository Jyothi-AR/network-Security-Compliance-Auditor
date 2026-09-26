import { useState, useMemo, useEffect } from 'react'
import './App.css'
import {
  analyzeConfiguration,
  generateReport,
  fetchLiveDeviceConfig,
  fetchAttackPaths,
  fetchBlastRadius,
  fetchRootCause,
  fetchSafeRemediation,
  fetchLearnedVendors,
  registerVendor,
} from './api'

/* ==========================================================================
   ENTERPRISE VECTOR SVG ICONS
   ========================================================================== */

function IconShield({ size = 18, className = '' }) {
  return (
    <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" className={className}>
      <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
    </svg>
  )
}

function IconDashboard({ size = 18, className = '' }) {
  return (
    <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" className={className}>
      <rect x="3" y="3" width="7" height="9" rx="1" />
      <rect x="14" y="3" width="7" height="5" rx="1" />
      <rect x="14" y="12" width="7" height="9" rx="1" />
      <rect x="3" y="16" width="7" height="5" rx="1" />
    </svg>
  )
}

function IconTerminal({ size = 18, className = '' }) {
  return (
    <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" className={className}>
      <polyline points="4 17 10 11 4 5" />
      <line x1="12" y1="19" x2="20" y2="19" />
    </svg>
  )
}

function IconFindings({ size = 18, className = '' }) {
  return (
    <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" className={className}>
      <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z" />
      <polyline points="14 2 14 8 20 8" />
      <path d="M9 15l2 2 4-4" />
    </svg>
  )
}

function IconWrench({ size = 18, className = '' }) {
  return (
    <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" className={className}>
      <path d="M14.7 6.3a1 1 0 0 0 0 1.4l1.6 1.6a1 1 0 0 0 1.4 0l3.77-3.77a6 6 0 0 1-7.94 7.94l-6.91 6.91a2.12 2.12 0 0 1-3-3l6.91-6.91a6 6 0 0 1 7.94-7.94l-3.76 3.76z" />
    </svg>
  )
}

function IconNetwork({ size = 18, className = '' }) {
  return (
    <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" className={className}>
      <circle cx="18" cy="5" r="3" />
      <circle cx="6" cy="12" r="3" />
      <circle cx="18" cy="19" r="3" />
      <line x1="8.59" y1="13.51" x2="15.42" y2="17.49" />
      <line x1="15.41" y1="6.51" x2="8.59" y2="10.49" />
    </svg>
  )
}

function IconSliders({ size = 18, className = '' }) {
  return (
    <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" className={className}>
      <line x1="4" y1="21" x2="4" y2="14" />
      <line x1="4" y1="10" x2="4" y2="3" />
      <line x1="12" y1="21" x2="12" y2="12" />
      <line x1="12" y1="8" x2="12" y2="3" />
      <line x1="20" y1="21" x2="20" y2="16" />
      <line x1="20" y1="12" x2="20" y2="3" />
      <line x1="1" y1="14" x2="7" y2="14" />
      <line x1="9" y1="8" x2="15" y2="8" />
      <line x1="17" y1="16" x2="23" y2="16" />
    </svg>
  )
}

function IconCpu({ size = 18, className = '' }) {
  return (
    <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" className={className}>
      <rect x="4" y="4" width="16" height="16" rx="2" />
      <rect x="9" y="9" width="6" height="6" />
      <line x1="9" y1="1" x2="9" y2="4" />
      <line x1="15" y1="1" x2="15" y2="4" />
      <line x1="9" y1="20" x2="9" y2="23" />
      <line x1="15" y1="20" x2="15" y2="23" />
      <line x1="20" y1="9" x2="23" y2="9" />
      <line x1="20" y1="14" x2="23" y2="14" />
      <line x1="1" y1="9" x2="4" y2="9" />
      <line x1="1" y1="14" x2="4" y2="14" />
    </svg>
  )
}

function IconServer({ size = 18, className = '' }) {
  return (
    <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" className={className}>
      <rect x="2" y="2" width="20" height="8" rx="2" ry="2" />
      <rect x="2" y="14" width="20" height="8" rx="2" ry="2" />
      <line x1="6" y1="6" x2="6.01" y2="6" />
      <line x1="6" y1="18" x2="6.01" y2="18" />
    </svg>
  )
}

function IconRotateCcw({ size = 16, className = '' }) {
  return (
    <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" className={className}>
      <polyline points="1 4 1 10 7 10" />
      <path d="M3.51 15a9 9 0 1 0 2.13-9.36L1 10" />
    </svg>
  )
}

function IconGitCompare({ size = 16, className = '' }) {
  return (
    <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" className={className}>
      <circle cx="18" cy="18" r="3" />
      <circle cx="6" cy="6" r="3" />
      <path d="M13 6h3a2 2 0 0 1 2 2v7" />
      <path d="M11 18H8a2 2 0 0 1-2-2V9" />
    </svg>
  )
}

function IconHelpCircle({ size = 16, className = '' }) {
  return (
    <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" className={className}>
      <circle cx="12" cy="12" r="10" />
      <path d="M9.09 9a3 3 0 0 1 5.83 1c0 2-3 3-3 3" />
      <line x1="12" y1="17" x2="12.01" y2="17" />
    </svg>
  )
}

function IconRadio({ size = 16, className = '' }) {
  return (
    <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" className={className}>
      <circle cx="12" cy="12" r="2" />
      <path d="M16.24 7.76a6 6 0 0 1 0 8.49m-8.48-.01a6 6 0 0 1 0-8.49m11.31-2.82a10 10 0 0 1 0 14.14m-14.14 0a10 10 0 0 1 0-14.14" />
    </svg>
  )
}

function IconAlertTriangle({ size = 18, className = '' }) {
  return (
    <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" className={className}>
      <path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z" />
      <line x1="12" y1="9" x2="12" y2="13" />
      <line x1="12" y1="17" x2="12.01" y2="17" />
    </svg>
  )
}

function IconAlertOctagon({ size = 18, className = '' }) {
  return (
    <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" className={className}>
      <polygon points="7.86 2 16.14 2 22 7.86 22 16.14 16.14 22 7.86 22 2 16.14 2 7.86 7.86 2" />
      <line x1="12" y1="8" x2="12" y2="12" />
      <line x1="12" y1="16" x2="12.01" y2="16" />
    </svg>
  )
}

function IconCheckCircle({ size = 18, className = '' }) {
  return (
    <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" className={className}>
      <path d="M22 11.08V12a10 10 0 1 1-5.93-9.14" />
      <polyline points="22 4 12 14.01 9 11.01" />
    </svg>
  )
}

function IconCheck({ size = 16, className = '' }) {
  return (
    <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" className={className}>
      <polyline points="20 6 9 17 4 12" />
    </svg>
  )
}

function IconDownload({ size = 16, className = '' }) {
  return (
    <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" className={className}>
      <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4" />
      <polyline points="7 10 12 15 17 10" />
      <line x1="12" y1="15" x2="12" y2="3" />
    </svg>
  )
}

function IconUpload({ size = 16, className = '' }) {
  return (
    <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" className={className}>
      <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4" />
      <polyline points="17 8 12 3 7 8" />
      <line x1="12" y1="3" x2="12" y2="15" />
    </svg>
  )
}

function IconCopy({ size = 15, className = '' }) {
  return (
    <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" className={className}>
      <rect x="9" y="9" width="13" height="13" rx="2" ry="2" />
      <path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1" />
    </svg>
  )
}

function IconCross({ size = 16, className = '' }) {
  return (
    <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" className={className}>
      <line x1="18" y1="6" x2="6" y2="18" />
      <line x1="6" y1="6" x2="18" y2="18" />
    </svg>
  )
}

function IconZap({ size = 16, className = '' }) {
  return (
    <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" className={className}>
      <polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2" />
    </svg>
  )
}

function IconActivity({ size = 16, className = '' }) {
  return (
    <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" className={className}>
      <polyline points="22 12 18 12 15 21 9 3 6 12 2 12" />
    </svg>
  )
}

function IconSearch({ size = 15, className = '' }) {
  return (
    <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" className={className}>
      <circle cx="11" cy="11" r="8" />
      <line x1="21" y1="21" x2="16.65" y2="16.65" />
    </svg>
  )
}

function IconArrowRight({ size = 14, className = '' }) {
  return (
    <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" className={className}>
      <line x1="5" y1="12" x2="19" y2="12" />
      <polyline points="12 5 19 12 12 19" />
    </svg>
  )
}

/* ==========================================================================
   HELPER: INVERSE ROLLBACK COMMAND CALCULATOR
   ========================================================================== */

function calculateRollbackCommand(command, controlId) {
  if (!command) return 'undo ' + (controlId || '')
  const cmd = command.trim()
  if (cmd.startsWith('no ')) return cmd.substring(3).trim()
  if (cmd === 'transport input ssh') return 'transport input telnet ssh'
  if (cmd === 'ip ssh version 2') return 'ip ssh version 1'
  if (cmd === 'login block-for 120 attempts 3 within 60') return 'no login block-for'
  if (cmd.startsWith('set system services ssh protocol-version v2')) return 'set system services ssh protocol-version v1'
  if (cmd.startsWith('set system services telnet')) return 'delete system services telnet'
  if (cmd.startsWith('set ')) return 'delete ' + cmd.substring(4)
  if (cmd.startsWith('delete ')) return 'set ' + cmd.substring(7)
  return 'no ' + cmd
}

/* ==========================================================================
   SAMPLE PRESET DATA
   ========================================================================== */

const SAMPLE_PRESETS = [
  {
    id: 'cisco-insecure',
    name: 'Cisco IOS · Insecure Core Router',
    vendor: 'Cisco IOS',
    filename: 'cisco_core_insecure.conf',
    badge: 'Critical Risks',
    badgeColor: '#f43f5e',
    config: `version 15.2
service password-encryption
hostname CORE-EDGE-01
no aaa new-model
ip domain name corp.example.local
ip name-server 10.10.10.10
ip ssh version 1
ip http server
ip routing
interface GigabitEthernet0/0
 description WAN-UPLINK
 ip address 172.16.10.2 255.255.255.252
 no shutdown
interface GigabitEthernet0/1
 description SERVER-NETWORK
 ip address 10.10.20.1 255.255.255.0
 no shutdown
logging buffered 16384
logging trap warnings
snmp-server community PUBLIC ro
snmp-server location DATA-CENTER-01
line console 0
 exec-timeout 15 0
line vty 0 4
 transport input telnet
 exec-timeout 30 0
 login
line vty 5 15
 transport input telnet
 exec-timeout 30 0
 login
end`,
  },
  {
    id: 'cisco-hardened',
    name: 'Cisco IOS · Hardened CIS Benchmark',
    vendor: 'Cisco IOS',
    filename: 'cisco_hardened.conf',
    badge: 'Compliant',
    badgeColor: '#10b981',
    config: `version 15.2
service timestamps debug datetime msec
service timestamps log datetime msec
service password-encryption
hostname CORE-HARDENED-01
aaa new-model
aaa authentication login default group radius local
ip domain name secure.enterprise.com
ip ssh version 2
ip ssh time-out 60
ip ssh authentication-retries 3
no ip http server
no ip http secure-server
logging buffered 65535
logging host 10.10.40.50
snmp-server group SECUREGROUP v3 priv
ntp server 10.10.40.20
line console 0
 exec-timeout 5 0
line vty 0 15
 transport input ssh
 exec-timeout 10 0
 login authentication default
end`,
  },
  {
    id: 'juniper-edge',
    name: 'Juniper JunOS · Telecom MX Gateway',
    vendor: 'Juniper JunOS',
    filename: 'junos_edge.conf',
    badge: 'Multi-Vendor',
    badgeColor: '#00f0ff',
    config: `set system host-name JUNIPER-EDGE-MX
set system domain-name telecom.example.net
set system time-zone UTC
set system authentication-order radius
set system authentication-order password
set system services ssh protocol-version v2
set system services telnet
set system services web-management http
set system syslog host 10.10.40.50 any notice
set interfaces ge-0/0/0 unit 0 family inet address 198.51.100.1/30
set snmp community public authorization read-only
set snmp location "POP-01 Edge Facility"`,
  },
  {
    id: 'paloalto-fw',
    name: 'Palo Alto · PAN-OS Next-Gen Firewall',
    vendor: 'Palo Alto PAN-OS',
    filename: 'paloalto_perimeter.conf',
    badge: 'Perimeter FW',
    badgeColor: '#a855f7',
    config: `set deviceconfig system hostname PAN-FIREWALL-01
set deviceconfig system service disable-http no
set deviceconfig system service disable-telnet yes
set shared log-settings syslog SYSLOG-SERVER
set zone TRUST network layer3 [ ethernet1/1 ]
set zone UNTRUST network layer3 [ ethernet1/2 ]`,
  },
]

const FRAMEWORKS = [
  { id: 'CIS', name: 'CIS Controls v8', desc: 'Center for Internet Security Baselines' },
  { id: 'NIST', name: 'NIST SP 800-53', desc: 'Federal Security & Privacy Controls' },
  { id: 'STIG', name: 'DISA STIG', desc: 'Department of Defense Hardening' },
  { id: 'ISO27001', name: 'ISO/IEC 27001', desc: 'Information Security Management' },
]

const MOCK_AGENTS = [
  { id: 'parser', name: 'Parser Agent', role: 'NLP / Regex Tokenizer', icon: IconTerminal, desc: 'Understands vendor CLI semantics, extracts structured facts and tokens with evidence pointers.' },
  { id: 'compliance', name: 'Compliance Agent', role: 'Policy Rule Engine', icon: IconShield, desc: 'Evaluates normalized facts deterministically against CIS, NIST, DISA STIG, and ISO 27001.' },
  { id: 'risk', name: 'Risk Agent', role: 'Severity Calculator', icon: IconAlertTriangle, desc: 'Quantifies blast radius, exploitability factor, and calculates weighted risk scores.' },
  { id: 'cve', name: 'CVE Agent', role: 'Vulnerability Correlator', icon: IconSearch, desc: 'Cross-references known CVEs, weakness signatures, and unpatched protocol flaws.' },
  { id: 'remediation', name: 'Remediation Agent', role: 'CLI Patch Synthesizer', icon: IconWrench, desc: 'Generates syntactically correct CLI remediation commands matching exact device OS syntax.' },
  { id: 'critic', name: 'Critic Agent', role: 'Safety & Impact Validator', icon: IconCheckCircle, desc: 'Verifies proposed remediations for routing disruption, lockouts, or side effects before applying.' },
]

const MOCK_ATTACK_PATHS_DEFAULT = [
  {
    path_id: 'AP-001',
    summary: 'Telnet Plaintext Sniffing → Credential Harvest → Core Route Pivot',
    risk_score: 9.4,
    steps: [
      { step_id: 'S1', technique: 'T1040 – Network Sniffing', description: 'Telnet management active without TLS/SSH encryption. Cleartext credentials intercepted.', severity: 'CRITICAL', lateral_movement: true, privilege_escalation: false },
      { step_id: 'S2', technique: 'T1078 – Valid Accounts', description: 'Default SNMP community string allows reading full running configuration.', severity: 'HIGH', lateral_movement: true, privilege_escalation: true },
      { step_id: 'S3', technique: 'T1021 – Remote Services', description: 'Unrestricted VTY management ACL allows lateral jump across VLAN 10 & 20.', severity: 'HIGH', lateral_movement: true, privilege_escalation: false },
    ],
  },
  {
    path_id: 'AP-002',
    summary: 'Unauthenticated HTTP Management Plane → Config Exfiltration',
    risk_score: 8.1,
    steps: [
      { step_id: 'S1', technique: 'T1190 – Exploit Public-Facing App', description: 'HTTP management server enabled on public interface with default auth.', severity: 'HIGH', lateral_movement: false, privilege_escalation: true },
      { step_id: 'S2', technique: 'T1562 – Impair Defenses', description: 'Syslog logging is not configured; exfiltration actions leave zero forensic trail.', severity: 'MEDIUM', lateral_movement: false, privilege_escalation: false },
    ],
  },
]

const DEFAULT_DEVICES = [
  { id: 'dev-1', host: '192.168.1.1', vendor: 'Cisco IOS', status: 'online', platform: 'cisco_ios', compliance: '78%', lastScan: '10m ago', runningConfig: SAMPLE_PRESETS[0].config },
  { id: 'dev-2', host: '10.0.50.2', vendor: 'Juniper JunOS', status: 'online', platform: 'juniper_junos', compliance: '92%', lastScan: '1h ago', runningConfig: SAMPLE_PRESETS[2].config },
  { id: 'dev-3', host: '172.16.0.254', vendor: 'Palo Alto PAN-OS', status: 'online', platform: 'paloalto_panos', compliance: '85%', lastScan: '3h ago', runningConfig: SAMPLE_PRESETS[3].config },
  { id: 'dev-4', host: '10.200.1.1', vendor: 'Arista EOS', status: 'standby', platform: 'arista_eos', compliance: '—', lastScan: 'Never', runningConfig: '! Arista EOS Running Config\nhostname ARISTA-SPINE-01\n' },
]

export default function App() {
  const [activeTab, setActiveTab] = useState('dashboard')
  const [selectedPreset, setSelectedPreset] = useState(SAMPLE_PRESETS[0])
  const [customConfigText, setCustomConfigText] = useState(SAMPLE_PRESETS[0].config)
  const [uploadedFile, setUploadedFile] = useState(null)
  const [isAnalyzing, setIsAnalyzing] = useState(false)
  const [analysisResult, setAnalysisResult] = useState(null)
  const [analysisHistory, setAnalysisHistory] = useState([])
  const [selectedFrameworks, setSelectedFrameworks] = useState(['CIS', 'NIST', 'STIG', 'ISO27001'])
  const [searchQuery, setSearchQuery] = useState('')
  const [severityFilter, setSeverityFilter] = useState('ALL')
  const [statusFilter, setStatusFilter] = useState('ALL')
  const [expandedEvidence, setExpandedEvidence] = useState({})
  const [copiedId, setCopiedId] = useState(null)
  const [errorMsg, setErrorMsg] = useState('')
  const [isGeneratingPdf, setIsGeneratingPdf] = useState(false)

  // Multi-Agent states
  const [agentStates, setAgentStates] = useState({})

  // Intelligence dynamic data
  const [realAttackPaths, setRealAttackPaths] = useState(null)
  const [realRootCauses, setRealRootCauses] = useState(null)
  const [realSafeRemediations, setRealSafeRemediations] = useState(null)
  const [activeAttackPathId, setActiveAttackPathId] = useState('AP-001')

  // What-if simulator states
  const [simulatedFixes, setSimulatedFixes] = useState({})

  // Auto-Fix & Rollback execution states
  const [fixStatus, setFixStatus] = useState({})
  const [configSnapshots, setConfigSnapshots] = useState([
    { id: 'snap-001', timestamp: 'Initial Baseline', reason: 'Pre-Scan Snapshot', score: 25, config: SAMPLE_PRESETS[0].config },
  ])
  const [showHowItFixesModal, setShowHowItFixesModal] = useState(false)
  const [showDiffView, setShowDiffView] = useState(false)
  const [selectedDeviceForLive, setSelectedDeviceForLive] = useState(DEFAULT_DEVICES[0])

  // New UX Enhancements: Command Palette, Drawer, Batch Actions, Split Diff, Toasts, Collapsible Sidebar
  const [showCommandPalette, setShowCommandPalette] = useState(false)
  const [commandQuery, setCommandQuery] = useState('')
  const [selectedFindingForDrawer, setSelectedFindingForDrawer] = useState(null)
  const [selectedFindingIds, setSelectedFindingIds] = useState([])
  const [sidebarCollapsed, setSidebarCollapsed] = useState(false)
  const [inspectorViewMode, setInspectorViewMode] = useState('editor') // 'editor' | 'split-diff'
  const [toasts, setToasts] = useState([])

  const addToast = (title, message, type = 'info') => {
    const id = Date.now() + Math.random().toString(36).substring(2, 6)
    setToasts(prev => [...prev, { id, title, message, type }])
    setTimeout(() => {
      setToasts(prev => prev.filter(t => t.id !== id))
    }, 4500)
  }

  // Global Keyboard Shortcuts (Ctrl+K for Command Palette, Esc for Drawer/Modals)
  useEffect(() => {
    const handleKeyDown = (e) => {
      if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === 'k') {
        e.preventDefault()
        setShowCommandPalette(prev => !prev)
      }
      if (e.key === 'Escape') {
        setShowCommandPalette(false)
        setSelectedFindingForDrawer(null)
      }
    }
    window.addEventListener('keydown', handleKeyDown)
    return () => window.removeEventListener('keydown', handleKeyDown)
  }, [])

  // Live Devices State & Ingestion Modal
  const [liveDevices, setLiveDevices] = useState(DEFAULT_DEVICES)
  const [liveHost, setLiveHost] = useState('')
  const [liveUser, setLiveUser] = useState('')
  const [livePass, setLivePass] = useState('')
  const [livePort, setLivePort] = useState(22)
  const [liveTransport, setLiveTransport] = useState('ssh')
  const [liveSecret, setLiveSecret] = useState('')
  const [livePlatform, setLivePlatform] = useState('cisco_ios')
  const [liveConnecting, setLiveConnecting] = useState(false)
  const [liveSuccessMsg, setLiveSuccessMsg] = useState('')
  const [showLiveFetchModal, setShowLiveFetchModal] = useState(false)
  const [liveFetchLogs, setLiveFetchLogs] = useState([])
  const [liveFetchError, setLiveFetchError] = useState('')
  const [liveFetchSuccess, setLiveFetchSuccess] = useState(false)
  const [liveTerminalCommand, setLiveTerminalCommand] = useState('')
  const [liveTerminalOutput, setLiveTerminalOutput] = useState([
    '[SSH] Session established with 192.168.1.1 (Cisco IOS 15.2)',
    '[SSH] Type CLI command and press Enter or click Execute...',
  ])

  // Unknown Syntax AI Learning state
  const [unknownInput, setUnknownInput] = useState('set security firewall-policy strict-tls enable')
  const [learnedVendorsList, setLearnedVendorsList] = useState([])
  const [aiInterpretation, setAiInterpretation] = useState(null)
  const [isLearning, setIsLearning] = useState(false)

  // Load learned vendors on mount
  useEffect(() => {
    fetchLearnedVendors().then(v => setLearnedVendorsList(v)).catch(() => {})
  }, [])

  // Auto-run analysis on first load with default preset
  useEffect(() => {
    runAnalysisDirect(SAMPLE_PRESETS[0].config, SAMPLE_PRESETS[0].filename)
  }, [])

  const findings = useMemo(() => analysisResult?.findings ?? [], [analysisResult])
  const remediations = useMemo(() => analysisResult?.remediations ?? [], [analysisResult])
  const evidence = useMemo(() => analysisResult?.evidence ?? [], [analysisResult])
  const detectedVendor = analysisResult?.vendor?.name ?? 'Unknown'
  const vendorConfidence = analysisResult?.vendor?.confidence

  // Filtered findings based on UI controls
  const filteredFindings = useMemo(() => {
    return findings.filter(f => {
      const matchSeverity = severityFilter === 'ALL' || f.severity?.toUpperCase() === severityFilter
      const matchStatus = statusFilter === 'ALL' || f.status?.toUpperCase() === statusFilter
      const matchSearch = !searchQuery ||
        f.control_id.toLowerCase().includes(searchQuery.toLowerCase()) ||
        f.description?.toLowerCase().includes(searchQuery.toLowerCase()) ||
        f.observed?.toLowerCase().includes(searchQuery.toLowerCase())
      return matchSeverity && matchStatus && matchSearch
    })
  }, [findings, severityFilter, statusFilter, searchQuery])

  // Summary Metrics
  const metrics = useMemo(() => {
    const passed = findings.filter(f => f.status === 'PASS').length
    const failed = findings.filter(f => f.status === 'FAIL').length
    const critical = findings.filter(f => f.status === 'FAIL' && f.severity?.toUpperCase() === 'CRITICAL').length
    const high = findings.filter(f => f.status === 'FAIL' && f.severity?.toUpperCase() === 'HIGH').length
    const medium = findings.filter(f => f.status === 'FAIL' && f.severity?.toUpperCase() === 'MEDIUM').length
    const low = findings.filter(f => f.status === 'FAIL' && f.severity?.toUpperCase() === 'LOW').length
    const score = (passed + failed) > 0 ? Math.round((passed / (passed + failed)) * 100) : 0
    return { total: findings.length, passed, failed, critical, high, medium, low, score }
  }, [findings])

  // Simulated metrics for What-If
  const whatIfMetrics = useMemo(() => {
    let simPassed = metrics.passed
    let simFailed = metrics.failed
    findings.forEach(f => {
      if (f.status === 'FAIL' && simulatedFixes[f.control_id]) {
        simPassed += 1
        simFailed = Math.max(0, simFailed - 1)
      }
    })
    const simScore = (simPassed + simFailed) > 0 ? Math.round((simPassed / (simPassed + simFailed)) * 100) : 0
    return { simPassed, simFailed, simScore, fixedCount: Object.values(simulatedFixes).filter(Boolean).length }
  }, [findings, metrics, simulatedFixes])

  async function runAnalysisDirect(configContent, filename) {
    setIsAnalyzing(true)
    setErrorMsg('')
    const agentIds = MOCK_AGENTS.map(a => a.id)
    setAgentStates(Object.fromEntries(agentIds.map(id => [id, 'running'])))

    try {
      const fakeFile = new File([configContent], filename, { type: 'text/plain' })
      const result = await analyzeConfiguration(fakeFile)

      setAgentStates(Object.fromEntries(agentIds.map(id => [id, 'done'])))
      setAnalysisResult(result)
      setAnalysisHistory(prev => [{
        id: Date.now(),
        filename,
        timestamp: new Date().toLocaleTimeString(),
        score: result.findings ? Math.round((result.findings.filter(f => f.status === 'PASS').length / result.findings.length) * 100) : 0,
        vendor: result.vendor?.name || 'Unknown',
        findingsCount: result.findings?.length || 0,
      }, ...prev.slice(0, 9)])

      // Update snapshots list
      setConfigSnapshots(prev => [
        {
          id: `snap-${Date.now().toString().slice(-4)}`,
          timestamp: new Date().toLocaleTimeString(),
          reason: `Inspection of ${filename}`,
          score: result.findings ? Math.round((result.findings.filter(f => f.status === 'PASS').length / result.findings.length) * 100) : 0,
          config: configContent,
        },
        ...prev.slice(0, 9),
      ])

      // Query AI Intelligence sub-engines in parallel
      const failingIds = (result.findings || []).filter(f => f.status === 'FAIL').map(f => f.control_id)
      if (failingIds.length > 0) {
        fetchAttackPaths({ [filename]: result.findings }).then(res => {
          if (res?.attack_paths?.length) setRealAttackPaths(res.attack_paths)
        }).catch(() => {})

        fetchRootCause(failingIds).then(res => {
          if (res?.root_causes?.length) setRealRootCauses(res.root_causes)
        }).catch(() => {})
      }

      if (result.remediations?.length > 0) {
        fetchSafeRemediation(
          result.remediations.map(r => ({ control_id: r.control_id, command: r.command }))
        ).then(res => {
          if (res?.validation_reports) setRealSafeRemediations(res.validation_reports)
        }).catch(() => {})
      }
    } catch (err) {
      setAgentStates(Object.fromEntries(agentIds.map(id => [id, 'error'])))
      setErrorMsg(err instanceof Error ? err.message : 'Analysis failed. Please check network/backend.')
    } finally {
      setIsAnalyzing(false)
    }
  }

  const handleSelectPreset = (preset) => {
    setSelectedPreset(preset)
    setCustomConfigText(preset.config)
    setUploadedFile(null)
    setFixStatus({})
    runAnalysisDirect(preset.config, preset.filename)
  }

  const handleFileUpload = (e) => {
    const file = e.target.files?.[0]
    if (!file) return
    setUploadedFile(file)
    setFixStatus({})
    const reader = new FileReader()
    reader.onload = (event) => {
      const content = event.target.result
      setCustomConfigText(content)
      runAnalysisDirect(content, file.name)
    }
    reader.readAsText(file)
  }

  const handleCopy = (text, id) => {
    navigator.clipboard.writeText(text)
    setCopiedId(id)
    setTimeout(() => setCopiedId(null), 2000)
  }

  const handleExportPdf = async () => {
    if (!analysisResult) return
    setIsGeneratingPdf(true)
    setErrorMsg('')
    try {
      const sourceName = uploadedFile?.name || selectedPreset.filename
      const report = await generateReport(analysisResult, sourceName)
      const url = URL.createObjectURL(report.blob)
      const a = document.createElement('a')
      a.href = url
      a.download = report.filename || `${sourceName}_compliance_report.pdf`
      document.body.appendChild(a)
      a.click()
      a.remove()
      URL.revokeObjectURL(url)
    } catch (err) {
      setErrorMsg(err instanceof Error ? err.message : 'Failed to export PDF.')
    } finally {
      setIsGeneratingPdf(false)
    }
  }

  /* ==========================================================================
     AUTO-FIX & ROLLBACK HANDLERS
     ========================================================================== */

  const handleApplyFix = (controlId, tier, command) => {
    setFixStatus(prev => ({ ...prev, [controlId]: 'applying' }))

    const snapId = `snap-pre-${controlId.toLowerCase()}`
    setConfigSnapshots(prev => [
      {
        id: snapId,
        timestamp: new Date().toLocaleTimeString(),
        reason: `Pre-Fix Snapshot for ${controlId}`,
        score: metrics.score,
        config: customConfigText,
      },
      ...prev,
    ])

    setTimeout(() => {
      let updatedConfig = customConfigText
      if (!updatedConfig.includes(command)) {
        updatedConfig = updatedConfig + `\n! [Auto-Fix Applied for ${controlId}]\n${command}\n`
        setCustomConfigText(updatedConfig)
      }

      setFixStatus(prev => ({
        ...prev,
        [controlId]: tier === 'LOW' ? 'applied' : tier === 'MEDIUM' ? 'approved' : 'scheduled',
      }))
    }, 600)
  }

  const handleRollbackFix = (controlId, command) => {
    setFixStatus(prev => ({ ...prev, [controlId]: 'rolling-back' }))
    const rollbackCmd = calculateRollbackCommand(command, controlId)

    setTimeout(() => {
      let updatedConfig = customConfigText
      if (updatedConfig.includes(command)) {
        updatedConfig = updatedConfig.replace(`! [Auto-Fix Applied for ${controlId}]\n${command}\n`, '')
      } else {
        updatedConfig = updatedConfig + `\n! [Rollback Triggered for ${controlId}]\n${rollbackCmd}\n`
      }
      setCustomConfigText(updatedConfig)

      setFixStatus(prev => ({
        ...prev,
        [controlId]: 'rolled-back',
      }))

      setConfigSnapshots(prev => [
        {
          id: `snap-rb-${Date.now().toString().slice(-4)}`,
          timestamp: new Date().toLocaleTimeString(),
          reason: `Rollback Executed: ${rollbackCmd}`,
          score: metrics.score,
          config: updatedConfig,
        },
        ...prev,
      ])
    }, 600)
  }

  const handleRollbackAll = () => {
    const originalSnap = configSnapshots[configSnapshots.length - 1]
    if (originalSnap) {
      setCustomConfigText(originalSnap.config)
      setFixStatus({})
      runAnalysisDirect(originalSnap.config, 'restored_baseline.conf')
    }
  }

  /* ==========================================================================
     LIVE CONFIG & SSH HANDLERS
     ========================================================================== */

  const handlePullLiveConfig = (dev) => {
    setSelectedDeviceForLive(dev)
    setCustomConfigText(dev.runningConfig)
    setActiveTab('live-config')
    runAnalysisDirect(dev.runningConfig, `${dev.host}_running.conf`)
    setLiveTerminalOutput(prev => [
      ...prev,
      `[SSH] Pulled running configuration from ${dev.host} (${dev.runningConfig.split('\n').length} lines).`,
    ])
  }

  const handleExecuteTerminalCommand = (e) => {
    e.preventDefault()
    if (!liveTerminalCommand.trim()) return
    const cmd = liveTerminalCommand.trim()
    const outputLine = `cisco-core-01# ${cmd}`
    let responseLine = `Executed: ${cmd} (returncode 0)`
    if (cmd.includes('show run') || cmd.includes('show config')) {
      responseLine = `--- Displaying running-config ---\n${customConfigText.slice(0, 150)}...\n[Truncated for console]`
    } else if (cmd.startsWith('no ') || cmd.startsWith('set ') || cmd.startsWith('ip ')) {
      responseLine = `Configured: ${cmd} (Committed to live running-config buffer)`
      setCustomConfigText(prev => prev + `\n${cmd}\n`)
    }

    setLiveTerminalOutput(prev => [...prev, outputLine, responseLine])
    setLiveTerminalCommand('')
  }

  const executeLiveFetch = async (targetHost, targetUser, targetPass, targetPlatform, targetPort, targetTransport, targetSecret) => {
    const host = (targetHost !== undefined ? targetHost : liveHost).trim()
    const user = (targetUser !== undefined ? targetUser : liveUser).trim()
    const pass = targetPass !== undefined ? targetPass : livePass
    const platform = targetPlatform || livePlatform || 'cisco_ios'
    const port = targetPort || livePort || 22
    const transport = targetTransport || liveTransport || 'ssh'
    const secret = targetSecret !== undefined ? targetSecret : liveSecret

    if (!host) {
      setLiveFetchError('Target IP / Hostname is required.')
      return
    }
    if (!user) {
      setLiveFetchError('SSH Username is required.')
      return
    }

    setLiveConnecting(true)
    setLiveFetchError('')
    setLiveFetchSuccess(false)
    setLiveSuccessMsg('')

    const initialLogs = [
      `[INIT ${new Date().toLocaleTimeString()}] Establishing ${transport.toUpperCase()} session to ${host}:${port}...`,
      `[SECURITY] Negotiating key exchange & cipher algorithms...`,
      `[AUTH] Authenticating credentials for operator '${user}'...`,
    ]
    setLiveFetchLogs(initialLogs)

    try {
      if (secret) {
        setLiveFetchLogs(prev => [...prev, `[PRIVILEGE] Elevating privilege mode (Cisco Enable Secret)...`])
      }

      setLiveFetchLogs(prev => [
        ...prev,
        `[COMMAND] Extracting live running configuration (driver: ${platform})...`,
      ])

      const res = await fetchLiveDeviceConfig({
        host,
        username: user,
        password: pass,
        device_type: platform,
        transport,
        port: parseInt(port, 10) || 22,
        secret: secret || '',
      })

      if (!res || !res.raw_config) {
        throw new Error('Received empty configuration response from device.')
      }

      const rawConfig = res.raw_config
      const lineCount = rawConfig.split('\n').length

      setLiveFetchLogs(prev => [
        ...prev,
        `[SUCCESS] Retrieved ${lineCount} lines of live running-configuration from ${host}.`,
        `[PIPELINE] Ingesting into multi-vendor parser & compliance engine...`,
        `[AUDIT COMPLETE] Analysis ready with verified rollback baseline.`,
      ])

      // 1. Update text in editor and live buffer
      setCustomConfigText(rawConfig)

      // 2. Set analysis
      if (res.analysis) {
        setAnalysisResult(res.analysis)
      } else {
        await runAnalysisDirect(rawConfig, `live:${host}:${platform}`)
      }

      // 3. Add to live devices
      const vendorLabel = res.device_type ? res.device_type.toUpperCase().replace(/_/g, ' ') : platform.toUpperCase().replace(/_/g, ' ')
      const newDev = {
        id: `dev-${Date.now()}`,
        host,
        vendor: vendorLabel,
        status: 'online',
        platform: res.device_type || platform,
        compliance: 'Calculated',
        lastScan: 'Just now',
        runningConfig: rawConfig,
      }
      setLiveDevices(prev => [newDev, ...prev.filter(d => d.host !== host)])
      setSelectedDeviceForLive(newDev)

      // 4. Save pre-change snapshot
      setConfigSnapshots(prev => [
        {
          id: `snap-${Date.now().toString().slice(-4)}`,
          timestamp: new Date().toLocaleTimeString(),
          reason: `Live Pull: ${host} (${platform})`,
          score: res.analysis ? Math.max(10, 100 - (res.analysis.findings.filter(f => f.status === 'FAIL').length * 8)) : 75,
          config: rawConfig,
        },
        ...prev,
      ])

      // 5. Update terminal output
      setLiveTerminalOutput(prev => [
        ...prev,
        `[SSH] >>> LIVE CONFIG ACQUIRED FROM ${host} (${lineCount} lines) <<<`,
        `[SSH] Active session to ${host}. Ready for compliance verification & auto-fix.`,
      ])

      setLiveSuccessMsg(`Successfully ingested live configuration from ${host} (${lineCount} lines)!`)
      setLiveFetchSuccess(true)

      setTimeout(() => {
        setShowLiveFetchModal(false)
        setActiveTab('live-config')
      }, 1500)

    } catch (err) {
      const errMsg = err.message || 'Connection failed to target device'
      setLiveFetchLogs(prev => [
        ...prev,
        `[ERROR] Connection failed: ${errMsg}`,
        `[DIAGNOSTIC] Ensure device IP '${host}' is online, port ${port} is open, and credentials are valid.`,
      ])
      setLiveFetchError(errMsg)
    } finally {
      setLiveConnecting(false)
    }
  }

  const handleLiveConnectSubmit = (e) => {
    e.preventDefault()
    executeLiveFetch(liveHost, liveUser, livePass, livePlatform, livePort, liveTransport, liveSecret)
  }

  const handleLoadLabDevice = (presetKey) => {
    const preset = SAMPLE_PRESETS.find(p => p.id === presetKey) || SAMPLE_PRESETS[0]
    setCustomConfigText(preset.config)
    runAnalysisDirect(preset.config, `live-lab:${preset.filename}`)
    const hostMap = {
      'cisco-01': '192.168.1.1',
      'cisco-nxos-01': '10.10.1.1',
      'juniper-01': '10.0.50.2',
      'paloalto-01': '172.16.0.254',
      'arista-01': '10.20.0.1',
      'fortinet-01': '192.168.100.1',
    }
    const labDev = {
      id: `dev-${Date.now()}`,
      host: hostMap[preset.id] || '192.168.1.1',
      vendor: preset.vendor,
      status: 'online',
      platform: preset.vendor.toLowerCase().replace(/[\s-]+/g, '_'),
      compliance: 'Calculated',
      lastScan: 'Just now',
      runningConfig: preset.config,
    }
    setLiveDevices(prev => [labDev, ...prev.filter(d => d.host !== labDev.host)])
    setSelectedDeviceForLive(labDev)
    setLiveTerminalOutput(prev => [
      ...prev,
      `[SSH] Connected to lab virtual appliance ${labDev.host} (${preset.vendor}).`,
      `[SSH] Live running configuration synced (${preset.config.split('\n').length} lines).`,
    ])
    setLiveSuccessMsg(`Loaded simulated live device configuration for ${preset.vendor} (${preset.filename})!`)
    setShowLiveFetchModal(false)
    setActiveTab('live-config')
  }

  const handleInterpretSyntax = () => {
    setIsLearning(true)
    setTimeout(() => {
      setAiInterpretation({
        raw: unknownInput,
        normalized_field: 'security.firewall.tls_enforcement',
        parsed_action: 'ENFORCE_STRICT_TLS_1_3',
        confidence: 0.94,
        suggested_policy: 'CIS-NETWORK-ENCRYPT-01',
      })
      setIsLearning(false)
    }, 600)
  }

  const handleApproveLearning = async () => {
    if (!aiInterpretation) return
    try {
      await registerVendor({
        vendor_id: `custom_${Date.now()}`,
        display_name: 'Custom Learned Policy',
        signatures: [unknownInput.split(' ')[0]],
        field_mappings: { [aiInterpretation.normalized_field]: unknownInput },
      })
      setLearnedVendorsList(prev => [...prev, { vendor_id: 'learned_' + Date.now(), display_name: 'Custom TLS Policy' }])
      setAiInterpretation(null)
    } catch {
      setAiInterpretation(null)
    }
  }

  const activeAttackPaths = realAttackPaths || MOCK_ATTACK_PATHS_DEFAULT

  return (
    <div className="aegis-app">
      {/* GLOW DECORATIONS */}
      <div className="cyber-glow cyber-glow-1" />
      <div className="cyber-glow cyber-glow-2" />

      {/* TOPBAR */}
      <header className="aegis-topbar">
        <div className="topbar-left">
          <button
            className="btn-sidebar-toggle"
            onClick={() => setSidebarCollapsed(prev => !prev)}
            title="Toggle Sidebar"
          >
            <IconSliders size={16} />
          </button>
          <div className="brand-logo">
            <span className="logo-shield">
              <IconShield size={20} />
            </span>
            <div className="brand-text">
              <div className="brand-title">
                AEGIS<strong>GUARD</strong> <span className="version-pill">v2.4 AI</span>
              </div>
              <div className="brand-subtitle">Autonomous Multi-Vendor Compliance &amp; Security Intelligence</div>
            </div>
          </div>
        </div>

        <div className="topbar-center">
          <button className="topbar-cmd-btn" onClick={() => setShowCommandPalette(true)}>
            <IconSearch size={14} />
            <span>Search rules, devices, actions...</span>
            <kbd>Ctrl K</kbd>
          </button>
          <div className="framework-selector">
            <span className="fw-label">Active:</span>
            {FRAMEWORKS.map(fw => {
              const active = selectedFrameworks.includes(fw.id)
              return (
                <button
                  key={fw.id}
                  className={`framework-pill ${active ? 'active' : ''}`}
                  onClick={() => setSelectedFrameworks(prev => active ? prev.filter(x => x !== fw.id) : [...prev, fw.id])}
                  title={fw.desc}
                >
                  <span className="pill-dot" />
                  {fw.name}
                </button>
              )
            })}
          </div>
        </div>

        <div className="topbar-right">
          <button
            className="btn-live-connect-top"
            onClick={() => {
              setShowLiveFetchModal(true)
              setLiveFetchError('')
              setLiveFetchLogs([])
              setLiveFetchSuccess(false)
            }}
          >
            <span className="live-pulse-dot" />
            <IconRadio size={14} /> Fetch Live Device
          </button>
          <button className="btn-how-it-works" onClick={() => setShowHowItFixesModal(true)}>
            <IconHelpCircle size={14} /> How Auto-Fix Works
          </button>
          <button
            className="btn-export-pdf"
            onClick={handleExportPdf}
            disabled={!analysisResult || isGeneratingPdf}
          >
            <IconDownload size={14} />
            {isGeneratingPdf ? 'Generating…' : 'Export Audit PDF'}
          </button>
        </div>
      </header>

      {/* MAIN CONTAINER */}
      <div className={`aegis-body ${sidebarCollapsed ? 'sidebar-collapsed' : ''}`}>
        {/* SIDEBAR NAVIGATION */}
        <aside className="aegis-sidebar">
          <div className="sidebar-section-title">SECURITY SUITE</div>
          <nav className="sidebar-nav">
            <button className={`nav-link ${activeTab === 'dashboard' ? 'active' : ''}`} onClick={() => setActiveTab('dashboard')} title="Executive Dashboard">
              <span className="nav-icon"><IconDashboard size={18} /></span>
              {!sidebarCollapsed && <span className="nav-text">Executive Dashboard</span>}
            </button>
            <button className={`nav-link ${activeTab === 'scan' ? 'active' : ''}`} onClick={() => setActiveTab('scan')} title="Config Inspector">
              <span className="nav-icon"><IconTerminal size={18} /></span>
              {!sidebarCollapsed && <span className="nav-text">Config Inspector</span>}
              {isAnalyzing && <span className="badge-spin"><IconActivity size={12} /></span>}
            </button>
            <button className={`nav-link ${activeTab === 'live-config' ? 'active' : ''}`} onClick={() => setActiveTab('live-config')} title="Live Configuration">
              <span className="nav-icon"><IconRadio size={18} /></span>
              {!sidebarCollapsed && <span className="nav-text">Live Configuration</span>}
              {!sidebarCollapsed && <span className="nav-badge cyan">Live</span>}
            </button>
            <button className={`nav-link ${activeTab === 'findings' ? 'active' : ''}`} onClick={() => setActiveTab('findings')} title="Compliance Findings">
              <span className="nav-icon"><IconFindings size={18} /></span>
              {!sidebarCollapsed && <span className="nav-text">Compliance Findings</span>}
              {metrics.failed > 0 && <span className="nav-badge danger">{metrics.failed}</span>}
            </button>
            <button className={`nav-link ${activeTab === 'remediation' ? 'active' : ''}`} onClick={() => setActiveTab('remediation')} title="Autonomous Fix & Rollback">
              <span className="nav-icon"><IconWrench size={18} /></span>
              {!sidebarCollapsed && <span className="nav-text">Auto-Fix &amp; Rollback</span>}
              {metrics.failed > 0 && !sidebarCollapsed && <span className="nav-badge warn">{metrics.failed} Fixes</span>}
            </button>
            <button className={`nav-link ${activeTab === 'intelligence' ? 'active' : ''}`} onClick={() => setActiveTab('intelligence')} title="Attack Path & Blast Radius">
              <span className="nav-icon"><IconNetwork size={18} /></span>
              {!sidebarCollapsed && <span className="nav-text">Attack Path &amp; Blast Radius</span>}
              {!sidebarCollapsed && <span className="nav-badge purple">AI</span>}
            </button>
            <button className={`nav-link ${activeTab === 'whatif' ? 'active' : ''}`} onClick={() => setActiveTab('whatif')} title="What-If Sandbox">
              <span className="nav-icon"><IconSliders size={18} /></span>
              {!sidebarCollapsed && <span className="nav-text">What-If Sandbox</span>}
              {!sidebarCollapsed && <span className="nav-badge cyan">Sim</span>}
            </button>
            <button className={`nav-link ${activeTab === 'agents' ? 'active' : ''}`} onClick={() => setActiveTab('agents')} title="Multi-Agent Grid">
              <span className="nav-icon"><IconCpu size={18} /></span>
              {!sidebarCollapsed && <span className="nav-text">Multi-Agent Grid</span>}
            </button>
            <button className={`nav-link ${activeTab === 'live' ? 'active' : ''}`} onClick={() => setActiveTab('live')} title="Live SSH Devices">
              <span className="nav-icon"><IconServer size={18} /></span>
              {!sidebarCollapsed && <span className="nav-text">Live SSH Devices</span>}
              {!sidebarCollapsed && <span className="nav-badge green">{liveDevices.filter(d => d.status === 'online').length}</span>}
            </button>
          </nav>

          <div className="sidebar-footer">
            <div className="vendor-chip">
              <span className="chip-label">ACTIVE DEVICE OS</span>
              <div className="chip-val">
                <span className="vendor-logo-dot" />
                <strong>{detectedVendor.toUpperCase()}</strong>
                {typeof vendorConfidence === 'number' && (
                  <span className="conf-pct">{Math.round(vendorConfidence * 100)}% conf</span>
                )}
              </div>
            </div>
          </div>
        </aside>

        {/* CONTENT AREA */}
        <main className="aegis-content">
          {errorMsg && (
            <div className="error-banner">
              <span><IconAlertTriangle size={16} /> {errorMsg}</span>
              <button onClick={() => setErrorMsg('')}><IconCross size={14} /></button>
            </div>
          )}

          {/* TAB 1: OVERVIEW DASHBOARD */}
          {activeTab === 'dashboard' && (
            <div className="tab-pane">
              {/* TOP KPI STAT CARDS */}
              <div className="kpi-grid">
                <div className="kpi-card kpi-primary">
                  <div className="kpi-icon-wrap cyan">
                    <IconShield size={22} />
                  </div>
                  <div className="kpi-info">
                    <span className="kpi-label">Compliance Score</span>
                    <div className="kpi-val-row">
                      <h2 className="kpi-value">{metrics.score}%</h2>
                      <span className={`kpi-badge ${metrics.score >= 70 ? 'badge-pass' : 'badge-fail'}`}>
                        {metrics.score >= 70 ? 'Compliant' : 'At Risk'}
                      </span>
                    </div>
                    <div className="progress-bar-bg">
                      <div className="progress-bar-fill score-fill" style={{ width: `${metrics.score}%` }} />
                    </div>
                  </div>
                </div>

                <div className="kpi-card">
                  <div className="kpi-icon-wrap purple">
                    <IconFindings size={22} />
                  </div>
                  <div className="kpi-info">
                    <span className="kpi-label">Total Rules Evaluated</span>
                    <h2 className="kpi-value">{metrics.total}</h2>
                    <span className="kpi-subtext text-cyan">{metrics.passed} Passed · {metrics.failed} Failed</span>
                  </div>
                </div>

                <div className="kpi-card">
                  <div className="kpi-icon-wrap pink">
                    <IconAlertTriangle size={22} />
                  </div>
                  <div className="kpi-info">
                    <span className="kpi-label">Critical Violations</span>
                    <h2 className="kpi-value text-pink">{metrics.critical}</h2>
                    <span className="kpi-subtext text-rose">{metrics.high} High Severity Risks</span>
                  </div>
                </div>

                <div className="kpi-card">
                  <div className="kpi-icon-wrap magenta">
                    <IconWrench size={22} />
                  </div>
                  <div className="kpi-info">
                    <span className="kpi-label">Auto-Fixable Rules</span>
                    <h2 className="kpi-value text-magenta">{remediations.length}</h2>
                    <span className="kpi-subtext text-emerald">Rollback-Safe Ready</span>
                  </div>
                </div>

                <div className="kpi-card">
                  <div className="kpi-icon-wrap indigo">
                    <IconServer size={22} />
                  </div>
                  <div className="kpi-info">
                    <span className="kpi-label">Detected Vendor</span>
                    <h2 className="kpi-value vendor-title">{detectedVendor}</h2>
                    <span className="kpi-subtext text-muted">Auto-Dialect Parser</span>
                  </div>
                </div>
              </div>

              {/* MAIN DASHBOARD 2-COLUMN GRID */}
              <div className="dashboard-grid" style={{ marginTop: '20px' }}>
                {/* LEFT: MULTI-VENDOR FLEET INVENTORY */}
                <div className="section-card">
                  <div className="card-header-row">
                    <div>
                      <h3>Connected Hardware Fleet &amp; Devices</h3>
                      <p>Multi-vendor managed appliances with active posture audits.</p>
                    </div>
                    <button className="btn-secondary btn-sm" onClick={() => setShowLiveFetchModal(true)}>
                      <IconTerminal size={14} /> Connect SSH Device
                    </button>
                  </div>

                  <div className="table-responsive">
                    <table className="data-table">
                      <thead>
                        <tr>
                          <th>Device / Host</th>
                          <th>Vendor / OS</th>
                          <th>Status</th>
                          <th>Compliance</th>
                          <th>Action</th>
                        </tr>
                      </thead>
                      <tbody>
                        {liveDevices.map(dev => (
                          <tr key={dev.id}>
                            <td>
                              <strong>{dev.host}</strong>
                              <span className="table-sub">{dev.id}</span>
                            </td>
                            <td>
                              <span className="vendor-tag">{dev.vendor}</span>
                            </td>
                            <td>
                              <span className={`status-pill ${dev.status}`}>
                                <span className="pill-dot" /> {dev.status}
                              </span>
                            </td>
                            <td>
                              <strong className={dev.compliance !== '—' ? 'text-cyan' : 'text-muted'}>
                                {dev.compliance}
                              </strong>
                            </td>
                            <td>
                              <button
                                className="btn-outline-action btn-xs"
                                onClick={() => {
                                  setSelectedPreset({
                                    id: dev.id,
                                    name: `${dev.vendor} Live Config`,
                                    vendor: dev.vendor,
                                    platform: dev.platform,
                                    filename: `${dev.platform}_running.cfg`,
                                    config: dev.runningConfig || customConfigText,
                                    badge: 'Live',
                                    badgeColor: '#00f0ff',
                                  })
                                  setCustomConfigText(dev.runningConfig || customConfigText)
                                  setActiveTab('scan')
                                }}
                              >
                                Inspect
                              </button>
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                </div>

                {/* RIGHT: FRAMEWORK COMPLIANCE & SEVERITY BREAKDOWN */}
                <div className="dashboard-side-col">
                  {/* FRAMEWORK BENCHMARKS */}
                  <div className="section-card">
                    <div className="card-header-row">
                      <div>
                        <h3>Security Framework Compliance</h3>
                        <p>Real-time regulatory alignment scores.</p>
                      </div>
                    </div>

                    <div className="framework-bars-list">
                      <div className="fw-bar-item">
                        <div className="fw-bar-header">
                          <span>CIS Network Benchmark v8.1</span>
                          <strong>{metrics.score}%</strong>
                        </div>
                        <div className="progress-bar-bg">
                          <div className="progress-bar-fill cis-fill" style={{ width: `${metrics.score}%` }} />
                        </div>
                      </div>

                      <div className="fw-bar-item">
                        <div className="fw-bar-header">
                          <span>NIST SP 800-53 Rev 5</span>
                          <strong>85%</strong>
                        </div>
                        <div className="progress-bar-bg">
                          <div className="progress-bar-fill nist-fill" style={{ width: '85%' }} />
                        </div>
                      </div>

                      <div className="fw-bar-item">
                        <div className="fw-bar-header">
                          <span>PCI-DSS 4.0 (Network Security)</span>
                          <strong>92%</strong>
                        </div>
                        <div className="progress-bar-bg">
                          <div className="progress-bar-fill pci-fill" style={{ width: '92%' }} />
                        </div>
                      </div>

                      <div className="fw-bar-item">
                        <div className="fw-bar-header">
                          <span>DoD STIG Network Infrastructure</span>
                          <strong>80%</strong>
                        </div>
                        <div className="progress-bar-bg">
                          <div className="progress-bar-fill stig-fill" style={{ width: '80%' }} />
                        </div>
                      </div>
                    </div>
                  </div>

                  {/* SEVERITY BREAKDOWN CARD */}
                  <div className="section-card">
                    <div className="card-header-row">
                      <div>
                        <h3>Violation Severity Distribution</h3>
                        <p>Categorized by blast radius impact.</p>
                      </div>
                    </div>

                    <div className="severity-counts-row">
                      <div className="sev-stat-box critical">
                        <span className="sev-num">{metrics.critical}</span>
                        <span className="sev-lbl">Critical</span>
                      </div>
                      <div className="sev-stat-box high">
                        <span className="sev-num">{metrics.high}</span>
                        <span className="sev-lbl">High</span>
                      </div>
                      <div className="sev-stat-box medium">
                        <span className="sev-num">{metrics.medium}</span>
                        <span className="sev-lbl">Medium</span>
                      </div>
                      <div className="sev-stat-box low">
                        <span className="sev-num">{metrics.low}</span>
                        <span className="sev-lbl">Low</span>
                      </div>
                    </div>
                  </div>
                </div>
              </div>

              {/* RECENT FINDINGS SUMMARY TABLE */}
              <div className="section-card" style={{ marginTop: '20px' }}>
                <div className="card-header-row">
                  <div>
                    <h3>Active Policy Violations &amp; Evidence Preview</h3>
                    <p>Top compliance findings identified in current configuration.</p>
                  </div>
                  <button className="btn-secondary btn-sm" onClick={() => setActiveTab('findings')}>
                    View All {findings.length} Findings <IconArrowRight size={14} />
                  </button>
                </div>

                <div className="table-responsive">
                  <table className="data-table">
                    <thead>
                      <tr>
                        <th>Control ID</th>
                        <th>Severity</th>
                        <th>Status</th>
                        <th>Description</th>
                        <th>Remediation Available</th>
                        <th>Action</th>
                      </tr>
                    </thead>
                    <tbody>
                      {findings.slice(0, 5).map((f, idx) => {
                        const hasFix = remediations.some(r => r.control_id === f.control_id)
                        return (
                          <tr key={idx}>
                            <td>
                              <code className="control-code">{f.control_id}</code>
                            </td>
                            <td>
                              <span className={`severity-badge sev-${f.severity?.toLowerCase()}`}>
                                {f.severity}
                              </span>
                            </td>
                            <td>
                              <span className={`status-badge stat-${f.status?.toLowerCase()}`}>
                                {f.status}
                              </span>
                            </td>
                            <td>
                              <span className="finding-desc-cell">{f.description}</span>
                            </td>
                            <td>
                              {hasFix ? (
                                <span className="text-emerald" style={{ fontSize: '11px', fontWeight: 600 }}>
                                  Auto-Fix Available
                                </span>
                              ) : (
                                <span className="text-muted" style={{ fontSize: '11px' }}>
                                  Manual Review
                                </span>
                              )}
                            </td>
                            <td>
                              <button
                                className="btn-outline-action btn-xs"
                                onClick={() => setActiveTab('findings')}
                              >
                                View Details
                              </button>
                            </td>
                          </tr>
                        )
                      })}
                    </tbody>
                  </table>
                </div>
              </div>

              {/* 1-CLICK MULTI-VENDOR TEST LAB PRESETS */}
              <div className="section-card" style={{ marginTop: '20px' }}>
                <div className="card-header-row">
                  <div>
                    <h3>1-Click Multi-Vendor Test Lab Benchmark Presets</h3>
                    <p>Select any benchmark configuration to instantly evaluate multi-vendor security models.</p>
                  </div>
                  <span className="card-badge">Instant Load</span>
                </div>

                <div className="presets-grid">
                  {SAMPLE_PRESETS.map(preset => (
                    <div
                      key={preset.id}
                      className={`preset-card ${selectedPreset.id === preset.id ? 'active' : ''}`}
                      onClick={() => handleSelectPreset(preset)}
                    >
                      <div className="preset-top">
                        <span className="preset-vendor">{preset.vendor}</span>
                        <span className="preset-badge" style={{ borderColor: preset.badgeColor, color: preset.badgeColor }}>
                          {preset.badge}
                        </span>
                      </div>
                      <h4 className="preset-name">{preset.name}</h4>
                      <div className="preset-footer">
                        <code>{preset.filename}</code>
                        <span className="btn-run-preset">Load &amp; Scan <IconArrowRight size={12} /></span>
                      </div>
                    </div>
                  ))}
                </div>
              </div>

            </div>
          )}

          {/* TAB 2: CONFIG INSPECTOR */}
          {activeTab === 'scan' && (
            <div className="tab-pane">
              <div className="pane-header">
                <div>
                  <h2>Configuration Inspector &amp; AI Parser</h2>
                  <p>Upload configuration files or live edit device CLI scripts. The Parser Agent auto-detects syntax dialect.</p>
                </div>
              </div>

              <div className="inspector-layout">
                {/* LEFT: EDITOR */}
                <div className="inspector-main">
                  <div className="editor-card">
                    <div className="editor-toolbar">
                      <div className="editor-tabs">
                        <button
                          className={`tab-pill-btn ${inspectorViewMode === 'editor' ? 'active' : ''}`}
                          onClick={() => setInspectorViewMode('editor')}
                        >
                          <IconTerminal size={12} /> Live Editor
                        </button>
                        <button
                          className={`tab-pill-btn ${inspectorViewMode === 'split-diff' ? 'active' : ''}`}
                          onClick={() => setInspectorViewMode('split-diff')}
                        >
                          <IconGitCompare size={12} /> Side-by-Side Split Diff
                        </button>
                        {uploadedFile && <span className="tab-pill file-pill">{uploadedFile.name}</span>}
                      </div>

                      <div className="editor-actions">
                        <button
                          type="button"
                          className="btn-live-fetch-action"
                          onClick={() => {
                            setShowLiveFetchModal(true)
                            setLiveFetchError('')
                            setLiveFetchLogs([])
                            setLiveFetchSuccess(false)
                          }}
                        >
                          <IconRadio size={14} /> Fetch Live Device
                        </button>
                        <label className="btn-upload-file">
                          <IconUpload size={14} /> Upload File
                          <input type="file" accept=".txt,.cfg,.conf" hidden onChange={handleFileUpload} />
                        </label>
                      </div>
                    </div>

                    {inspectorViewMode === 'editor' ? (
                      <textarea
                        className="cli-textarea"
                        value={customConfigText}
                        onChange={e => setCustomConfigText(e.target.value)}
                        placeholder="Paste running configuration here..."
                        rows={16}
                        spellCheck={false}
                      />
                    ) : (
                      <div className="split-diff-container">
                        <div className="split-diff-pane left">
                          <div className="split-diff-header">
                            <span>BASELINE CONFIG (CURRENT)</span>
                            <code>{customConfigText.split('\n').length} lines</code>
                          </div>
                          <div className="split-diff-lines">
                            {customConfigText.split('\n').map((line, idx) => {
                              const isViolated = findings.some(f => f.status === 'FAIL' && f.observed && line.toLowerCase().includes(f.observed.toLowerCase().slice(0, 15)))
                              return (
                                <div key={idx} className={`diff-line ${isViolated ? 'line-del' : ''}`}>
                                  <span className="diff-num">{idx + 1}</span>
                                  <span className="diff-sign">{isViolated ? '-' : ' '}</span>
                                  <span className="diff-code">{line}</span>
                                </div>
                              )
                            })}
                          </div>
                        </div>

                        <div className="split-diff-pane right">
                          <div className="split-diff-header">
                            <span>REMEDIATED HARDENED CONFIG (PROPOSED)</span>
                            <span className="badge-pass" style={{ fontSize: '9px', padding: '1px 6px' }}>+{remediations.length} Fixes</span>
                          </div>
                          <div className="split-diff-lines">
                            {customConfigText.split('\n').map((line, idx) => (
                              <div key={idx} className="diff-line">
                                <span className="diff-num">{idx + 1}</span>
                                <span className="diff-sign"> </span>
                                <span className="diff-code">{line}</span>
                              </div>
                            ))}
                            {remediations.map((rem, rIdx) => (
                              <div key={'rem-' + rIdx} className="diff-line line-add">
                                <span className="diff-num">+</span>
                                <span className="diff-sign">+</span>
                                <span className="diff-code">{rem.command} # Auto-fix for {rem.control_id}</span>
                              </div>
                            ))}
                          </div>
                        </div>
                      </div>
                    )}

                    <div className="editor-bottom-bar">
                      <div className="syntax-hint">
                        <span>Lines: {customConfigText.split('\n').length}</span>
                        <span>Bytes: {customConfigText.length}</span>
                        <span>Dialect: <strong>{detectedVendor}</strong></span>
                      </div>
                      <button
                        className="btn-analyze-now"
                        onClick={() => {
                          runAnalysisDirect(customConfigText, uploadedFile?.name || selectedPreset.filename)
                          addToast('Analysis Started', 'Multi-agent pipeline parsing syntax & evaluating rules...', 'info')
                        }}
                        disabled={isAnalyzing}
                      >
                        <IconZap size={14} />
                        {isAnalyzing ? 'AI Agents Evaluating…' : 'Run Multi-Agent Scan'}
                      </button>
                    </div>
                  </div>

                  {/* PARSER PIPELINE PROGRESS */}
                  <div className="agent-pipeline-card">
                    <div className="pipeline-title">AGENT PIPELINE REAL-TIME STATUS</div>
                    <div className="pipeline-nodes-row">
                      {MOCK_AGENTS.map((agent, i) => {
                        const st = agentStates[agent.id] || (isAnalyzing ? 'running' : 'done')
                        const AgentIcon = agent.icon
                        return (
                          <div key={agent.id} className={`pipeline-node-box ${st}`}>
                            <div className="p-num">0{i + 1}</div>
                            <div className="p-icon"><AgentIcon size={18} /></div>
                            <div className="p-name">{agent.name}</div>
                            <div className="p-state">{st === 'running' ? 'Processing…' : st === 'done' ? 'Verified' : 'Standby'}</div>
                          </div>
                        )
                      })}
                    </div>
                  </div>
                </div>

                {/* RIGHT: PRESETS & BASELINE FACTS */}
                <div className="inspector-sidebar">
                  <div className="section-card compact">
                    <h4>Test Sample Presets</h4>
                    <div className="quick-preset-list">
                      {SAMPLE_PRESETS.map(p => (
                        <button
                          key={p.id}
                          className={`qp-btn ${selectedPreset.id === p.id ? 'selected' : ''}`}
                          onClick={() => handleSelectPreset(p)}
                        >
                          <div className="qp-text">
                            <strong>{p.name}</strong>
                            <small>{p.vendor}</small>
                          </div>
                          <span className="qp-arrow"><IconArrowRight size={14} /></span>
                        </button>
                      ))}
                    </div>
                  </div>

                  <div className="section-card compact">
                    <h4>AI Extracted Facts ({analysisResult?.facts?.length || 0})</h4>
                    <div className="facts-list">
                      {(!analysisResult?.facts || analysisResult.facts.length === 0) ? (
                        <div className="empty-text">No facts extracted yet.</div>
                      ) : (
                        analysisResult.facts.slice(0, 6).map((fact, i) => (
                          <div key={i} className="fact-item">
                            <span className="fact-field">{fact.field}</span>
                            <code className="fact-val">{String(fact.value)}</code>
                          </div>
                        ))
                      )}
                    </div>
                  </div>
                </div>
              </div>
            </div>
          )}

          {/* TAB 3: LIVE CONFIGURATION (NEW!) */}
          {activeTab === 'live-config' && (
            <div className="tab-pane">
              <div className="pane-header-row">
                <div>
                  <h2>Live Configuration Manager &amp; Terminal</h2>
                  <p>Inspect, pull, and manage real-time running configurations from connected appliances.</p>
                </div>
                <div className="live-config-actions-bar">
                  <button
                    className="btn-live-fetch-action"
                    onClick={() => {
                      setShowLiveFetchModal(true)
                      setLiveFetchError('')
                      setLiveFetchLogs([])
                      setLiveFetchSuccess(false)
                    }}
                  >
                    <IconRadio size={14} /> Connect &amp; Fetch Live Device
                  </button>
                  <button className="btn-secondary" onClick={() => setShowDiffView(!showDiffView)}>
                    <IconGitCompare size={14} /> {showDiffView ? 'Hide Diff Comparison' : 'View Config Diff (Before/After)'}
                  </button>
                  <button className="btn-primary" onClick={() => handlePullLiveConfig(selectedDeviceForLive)}>
                    <IconRotateCcw size={14} /> Pull Fresh Running Config
                  </button>
                </div>
              </div>

              {/* LIVE DEVICE SELECTOR & SNAPSHOTS */}
              <div className="live-config-layout">
                <div className="live-config-editor-area">
                  <div className="editor-card">
                    <div className="editor-toolbar">
                      <div className="editor-tabs">
                        <span className="tab-pill active">
                          <IconRadio size={14} className="text-green" /> {selectedDeviceForLive.host} ({selectedDeviceForLive.vendor})
                        </span>
                        <span className="tab-pill file-pill">Running Configuration</span>
                      </div>

                      <div className="editor-actions">
                        <button
                          className="btn-sm-analyze"
                          onClick={() => runAnalysisDirect(customConfigText, `${selectedDeviceForLive.host}_running.conf`)}
                        >
                          <IconZap size={13} /> Re-Analyze Live Config
                        </button>
                      </div>
                    </div>

                    {showDiffView ? (
                      <div className="diff-view-container">
                        <div className="diff-side original">
                          <div className="diff-label">ORIGINAL INSECURE BASELINE</div>
                          <pre>{SAMPLE_PRESETS[0].config}</pre>
                        </div>
                        <div className="diff-side current">
                          <div className="diff-label">CURRENT LIVE BUFFER (WITH AUTO-FIXES)</div>
                          <pre>{customConfigText}</pre>
                        </div>
                      </div>
                    ) : (
                      <textarea
                        className="cli-textarea live-cli-theme"
                        value={customConfigText}
                        onChange={e => setCustomConfigText(e.target.value)}
                        rows={16}
                        spellCheck={false}
                      />
                    )}

                    <div className="editor-bottom-bar">
                      <div className="syntax-hint">
                        <span>Device: <strong>{selectedDeviceForLive.host}</strong></span>
                        <span>Platform: <strong>{selectedDeviceForLive.platform}</strong></span>
                        <span>Lines: {customConfigText.split('\n').length}</span>
                      </div>
                      <button
                        className="btn-analyze-now"
                        onClick={() => {
                          runAnalysisDirect(customConfigText, `${selectedDeviceForLive.host}_running.conf`)
                          setActiveTab('findings')
                        }}
                      >
                        <IconShield size={14} /> Verify Compliance Policy
                      </button>
                    </div>
                  </div>

                  {/* LIVE SSH TERMINAL CONSOLE */}
                  <div className="live-terminal-box">
                    <div className="terminal-header">
                      <span className="th-title">LIVE SSH COMMAND CONSOLE · {selectedDeviceForLive.host}</span>
                      <span className="th-status">Connected (SSHv2 / Port 22)</span>
                    </div>
                    <div className="terminal-screen">
                      {liveTerminalOutput.map((line, idx) => (
                        <div key={idx} className="terminal-line">{line}</div>
                      ))}
                    </div>
                    <form onSubmit={handleExecuteTerminalCommand} className="terminal-input-row">
                      <span className="term-prompt">cisco-core-01#</span>
                      <input
                        type="text"
                        className="term-input"
                        placeholder="Enter command (e.g. show running-config, no ip http server)..."
                        value={liveTerminalCommand}
                        onChange={e => setLiveTerminalCommand(e.target.value)}
                      />
                      <button type="submit" className="btn-term-exec">Execute</button>
                    </form>
                  </div>
                </div>

                {/* RIGHT: DEVICE SELECTOR & SNAPSHOT TIMELINE */}
                <div className="live-config-sidebar">
                  <div className="section-card compact">
                    <h4>Connected Live Devices</h4>
                    <div className="quick-preset-list">
                      {liveDevices.map(d => (
                        <button
                          key={d.id}
                          className={`qp-btn ${selectedDeviceForLive.id === d.id ? 'selected' : ''}`}
                          onClick={() => {
                            setSelectedDeviceForLive(d)
                            setCustomConfigText(d.runningConfig)
                          }}
                        >
                          <div className="qp-text">
                            <strong>{d.host}</strong>
                            <small>{d.vendor} · {d.status}</small>
                          </div>
                          <span className="qp-arrow"><IconArrowRight size={14} /></span>
                        </button>
                      ))}
                    </div>
                  </div>

                  <div className="section-card compact">
                    <div className="card-header-row">
                      <h4>Pre-Change Snapshots ({configSnapshots.length})</h4>
                      <button className="btn-text text-rose" onClick={handleRollbackAll} title="Rollback all changes to initial baseline">
                        <IconRotateCcw size={12} /> Rollback All
                      </button>
                    </div>
                    <div className="snapshots-timeline">
                      {configSnapshots.map((snap, idx) => (
                        <div key={snap.id + idx} className="snapshot-timeline-item">
                          <div className="sti-header">
                            <span className="sti-id">{snap.id}</span>
                            <span className="sti-time">{snap.timestamp}</span>
                          </div>
                          <p className="sti-reason">{snap.reason}</p>
                          <div className="sti-actions">
                            <span className="sti-score">Score: {snap.score}%</span>
                            <button
                              className="btn-rollback-snap"
                              onClick={() => {
                                setCustomConfigText(snap.config)
                                runAnalysisDirect(snap.config, 'snapshot_restored.conf')
                                alert(`Restored configuration to ${snap.id} (${snap.reason})!`)
                              }}
                            >
                              <IconRotateCcw size={11} /> Restore
                            </button>
                          </div>
                        </div>
                      ))}
                    </div>
                  </div>
                </div>
              </div>
            </div>
          )}

          {/* TAB 4: COMPLIANCE FINDINGS */}
          {activeTab === 'findings' && (
            <div className="tab-pane">
              <div className="pane-header-row">
                <div>
                  <h2>Security &amp; Compliance Findings</h2>
                  <p>Comprehensive evaluation across CIS Controls, NIST, STIG, and ISO 27001 with cryptographically mapped evidence.</p>
                </div>
                <div className="findings-filter-bar">
                  <div className="search-wrap">
                    <IconSearch size={14} className="search-icon" />
                    <input
                      type="text"
                      className="search-input has-icon"
                      placeholder="Search controls, protocols, evidence..."
                      value={searchQuery}
                      onChange={e => setSearchQuery(e.target.value)}
                    />
                  </div>
                  <select
                    className="select-filter"
                    value={severityFilter}
                    onChange={e => setSeverityFilter(e.target.value)}
                  >
                    <option value="ALL">All Severities</option>
                    <option value="CRITICAL">Critical Only</option>
                    <option value="HIGH">High Only</option>
                    <option value="MEDIUM">Medium Only</option>
                    <option value="LOW">Low Only</option>
                  </select>
                  <select
                    className="select-filter"
                    value={statusFilter}
                    onChange={e => setStatusFilter(e.target.value)}
                  >
                    <option value="ALL">All Status</option>
                    <option value="FAIL">Failed Only</option>
                    <option value="PASS">Passed Only</option>
                  </select>

                  <button
                    className="btn-select-all"
                    onClick={() => {
                      if (selectedFindingIds.length === filteredFindings.length) {
                        setSelectedFindingIds([])
                      } else {
                        setSelectedFindingIds(filteredFindings.map(f => f.control_id))
                      }
                    }}
                  >
                    {selectedFindingIds.length === filteredFindings.length ? 'Deselect All' : 'Select All'}
                  </button>
                </div>
              </div>

              {/* FINDINGS LIST */}
              <div className="findings-deck">
                {filteredFindings.length === 0 ? (
                  <div className="empty-card">
                    <span className="empty-icon"><IconShield size={32} /></span>
                    <h3>No findings matching current filters</h3>
                    <p>Try clearing your search query or selecting "All Severities".</p>
                  </div>
                ) : (
                  filteredFindings.map(finding => {
                    const isFail = finding.status === 'FAIL'
                    const rem = remediations.find(r => r.control_id === finding.control_id)
                    const isEvidenceOpen = Boolean(expandedEvidence[finding.control_id])
                    const isChecked = selectedFindingIds.includes(finding.control_id)

                    return (
                      <div
                        key={finding.control_id}
                        className={`finding-panel ${finding.status.toLowerCase()} ${isChecked ? 'selected-card' : ''}`}
                      >
                        <div className="fp-header">
                          <div className="fp-title-group">
                            <input
                              type="checkbox"
                              className="batch-checkbox"
                              checked={isChecked}
                              onChange={(e) => {
                                e.stopPropagation()
                                setSelectedFindingIds(prev =>
                                  prev.includes(finding.control_id)
                                    ? prev.filter(id => id !== finding.control_id)
                                    : [...prev, finding.control_id]
                                )
                              }}
                            />
                            <span className="fp-control-id">{finding.control_id}</span>
                            <h3 className="fp-title">{finding.description}</h3>
                          </div>
                          <div className="fp-badges">
                            <span className={`fp-sev-badge ${finding.severity?.toLowerCase()}`}>
                              {finding.severity}
                            </span>
                            <span className={`fp-status-badge ${finding.status?.toLowerCase()}`}>
                              {finding.status}
                            </span>
                            <button
                              className="btn-open-drawer"
                              onClick={() => setSelectedFindingForDrawer(finding)}
                              title="Inspect Full Evidence & MITRE Mapping in Drawer"
                            >
                              Inspect Details →
                            </button>
                          </div>
                        </div>

                        <div className="fp-details-grid">
                          <div className="fp-detail-box">
                            <span className="fp-box-label">SECURITY EXPECTATION</span>
                            <p>{finding.expected || 'Enforced secure configuration policy'}</p>
                          </div>
                          <div className="fp-detail-box">
                            <span className="fp-box-label">DETECTED OBSERVED STATE</span>
                            <p className={isFail ? 'text-rose-bold' : 'text-green-bold'}>
                              {finding.observed || 'Verified compliant'}
                            </p>
                          </div>
                        </div>

                        {/* REMEDIATION ACTION */}
                        {isFail && rem && (
                          <div className="fp-remediation-box">
                            <div className="rem-top">
                              <span className="rem-label">PROPOSED CLI REMEDIATION</span>
                              <span className="rem-tag">Critic Validated</span>
                            </div>
                            <p className="rem-desc">{rem.description}</p>
                            <div className="rem-cli-row">
                              <code>{rem.command}</code>
                              <div className="rem-btn-group">
                                <button
                                  className="btn-copy-cli"
                                  onClick={() => handleCopy(rem.command, finding.control_id)}
                                >
                                  {copiedId === finding.control_id ? (
                                    <>
                                      <IconCheck size={12} /> Copied
                                    </>
                                  ) : (
                                    <>
                                      <IconCopy size={12} /> Copy Fix
                                    </>
                                  )}
                                </button>
                                <button
                                  className="btn-inline-apply"
                                  onClick={() => handleExecuteAutoFix(finding.control_id, rem.command)}
                                  disabled={fixStatus[finding.control_id] === 'applying'}
                                >
                                  <IconWrench size={12} />
                                  {fixStatus[finding.control_id] === 'applied' ? 'Applied' : 'Auto-Fix Now'}
                                </button>
                              </div>
                            </div>
                          </div>
                        )}

                        {/* EVIDENCE DRAWER TOGGLE */}
                        <div className="fp-evidence-section">
                          <button
                            className="btn-toggle-evidence"
                            onClick={() => setExpandedEvidence(prev => ({ ...prev, [finding.control_id]: !prev[finding.control_id] }))}
                          >
                            {isEvidenceOpen ? 'Hide Configuration Evidence' : 'Show Configuration Evidence (' + evidence.length + ' items)'}
                          </button>

                          {isEvidenceOpen && (
                            <div className="fp-evidence-drawer">
                              {evidence.length === 0 ? (
                                <p className="empty-evidence">No line-level evidence retained.</p>
                              ) : (
                                evidence.map((ev, idx) => (
                                  <div key={idx} className="evidence-row">
                                    <div className="ev-meta">
                                      <span>Source: {ev.source_file || 'config'}</span>
                                      {ev.line_number != null && <span>Line: {ev.line_number}</span>}
                                      {ev.parser && <span>Parser: {ev.parser}</span>}
                                    </div>
                                    <code className="ev-code">{ev.raw_text}</code>
                                  </div>
                                ))
                              )}
                            </div>
                          )}
                        </div>
                      </div>
                    )
                  })
                )}
              </div>

              {/* FLOATING BATCH ACTION BAR */}
              {selectedFindingIds.length > 0 && (
                <div className="floating-batch-bar">
                  <div className="fbb-info">
                    <span className="fbb-count">{selectedFindingIds.length}</span>
                    <span>findings selected</span>
                  </div>
                  <div className="fbb-actions">
                    <button
                      className="btn-fbb-primary"
                      onClick={() => {
                        const failedSelected = selectedFindingIds.filter(id => {
                          const f = findings.find(x => x.control_id === id)
                          return f && f.status === 'FAIL'
                        })
                        failedSelected.forEach(id => {
                          const rem = remediations.find(r => r.control_id === id)
                          if (rem) handleExecuteAutoFix(id, rem.command)
                        })
                        addToast('Batch Auto-Fix Executed', `Applied fixes for ${failedSelected.length} controls with pre-change snapshot.`, 'success')
                        setSelectedFindingIds([])
                      }}
                    >
                      <IconWrench size={14} /> Auto-Fix Selected ({selectedFindingIds.length})
                    </button>
                    <button
                      className="btn-fbb-secondary"
                      onClick={() => {
                        const exportData = findings.filter(f => selectedFindingIds.includes(f.control_id))
                        const blob = new Blob([JSON.stringify(exportData, null, 2)], { type: 'application/json' })
                        const url = URL.createObjectURL(blob)
                        const a = document.createElement('a')
                        a.href = url
                        a.download = `selected_findings_${Date.now()}.json`
                        a.click()
                        addToast('Exported', `${selectedFindingIds.length} findings exported to JSON.`, 'info')
                      }}
                    >
                      <IconDownload size={14} /> Export JSON
                    </button>
                    <button
                      className="btn-fbb-clear"
                      onClick={() => setSelectedFindingIds([])}
                    >
                      Clear Selection
                    </button>
                  </div>
                </div>
              )}
            </div>
          )}

          {/* TAB 5: AUTONOMOUS FIX & ROLLBACK CENTER */}
          {activeTab === 'remediation' && (
            <div className="tab-pane">
              <div className="pane-header-row">
                <div>
                  <h2>Autonomous Auto-Fix &amp; Rollback Center</h2>
                  <p>Risk-tiered remediation dispatcher with pre-change snapshotting and 1-click inverse rollback protection.</p>
                </div>
                <div className="autofix-legend-pills">
                  <button className="btn-how-it-works-inline" onClick={() => setShowHowItFixesModal(true)}>
                    <IconHelpCircle size={13} /> How Auto-Fix &amp; Rollback Works
                  </button>
                  <button className="btn-rollback-all" onClick={handleRollbackAll}>
                    <IconRotateCcw size={13} /> Rollback All to Baseline
                  </button>
                </div>
              </div>

              {/* CRITIC AGENT BANNER */}
              <div className="critic-banner">
                <div className="critic-icon"><IconShield size={24} /></div>
                <div className="critic-text">
                  <strong>Critic Agent Safe Remediation &amp; Circuit Breaker Active</strong>
                  <p>Every generated CLI script is pre-validated against routing protocols and interface dependencies. If any issue occurs, the engine triggers an immediate inverse rollback to restore the pre-change snapshot.</p>
                </div>
              </div>

              {/* REMEDIATION CARDS WITH ROLLBACK BUTTONS */}
              <div className="remediation-deck">
                {findings.filter(f => f.status === 'FAIL').length === 0 ? (
                  <div className="all-clean-card">
                    <span className="clean-icon"><IconCheckCircle size={36} /></span>
                    <h3>Zero Outstanding Compliance Violations</h3>
                    <p>All evaluated controls have passed successfully. No remediation actions required.</p>
                  </div>
                ) : (
                  findings.filter(f => f.status === 'FAIL').map(f => {
                    const rem = remediations.find(r => r.control_id === f.control_id)
                    const sev = f.severity?.toUpperCase() || 'MEDIUM'
                    const status = fixStatus[f.control_id]
                    const rollbackCmd = calculateRollbackCommand(rem?.command || '', f.control_id)

                    return (
                      <div key={f.control_id} className={`autofix-card ${status === 'applied' ? 'fix-applied-glow' : ''}`}>
                        <div className="af-header">
                          <div>
                            <span className="af-id">{f.control_id}</span>
                            <h4>{f.description}</h4>
                          </div>
                          <div className="af-badges">
                            <span className={`fp-sev-badge ${sev.toLowerCase()}`}>{sev}</span>
                            <span className={`af-tier-badge ${sev.toLowerCase()}`}>
                              {sev === 'LOW' ? 'AUTO-TIER' : sev === 'MEDIUM' ? 'APPROVAL-TIER' : 'WINDOW-TIER'}
                            </span>
                          </div>
                        </div>

                        <div className="af-body">
                          <div className="af-observed">
                            <span>Detected Vulnerability:</span>
                            <code>{f.observed}</code>
                          </div>

                          {rem && (
                            <div className="af-cmd-box">
                              <div className="cmd-header-pair">
                                <span className="cmd-label">Validated Fix Command:</span>
                                <span className="cmd-label text-rose">Inverse Rollback Command:</span>
                              </div>
                              <div className="cmd-code-pair">
                                <code className="text-green">{rem.command}</code>
                                <code className="text-rose">{rollbackCmd}</code>
                              </div>
                              <small>{rem.requires_change_window ? 'Requires Scheduled Maintenance Window' : 'Safe for immediate hot-apply'}</small>
                            </div>
                          )}
                        </div>

                        {/* AUTO-FIX ACTIONS & ROLLBACK BUTTONS */}
                        <div className="af-actions">
                          {status === 'applied' && (
                            <div className="fix-applied-row">
                              <span className="status-tag success"><IconCheck size={14} /> Auto-Applied &amp; Verified</span>
                              <button
                                className="btn-rollback-action"
                                onClick={() => handleRollbackFix(f.control_id, rem?.command)}
                              >
                                <IconRotateCcw size={13} /> Rollback this Fix
                              </button>
                            </div>
                          )}

                          {status === 'approved' && (
                            <div className="fix-applied-row">
                              <span className="status-tag info"><IconCheck size={14} /> Approved &amp; Pushed</span>
                              <button
                                className="btn-rollback-action"
                                onClick={() => handleRollbackFix(f.control_id, rem?.command)}
                              >
                                <IconRotateCcw size={13} /> Rollback this Fix
                              </button>
                            </div>
                          )}

                          {status === 'scheduled' && (
                            <div className="fix-applied-row">
                              <span className="status-tag warn">Scheduled for Change Window</span>
                              <button
                                className="btn-rollback-action"
                                onClick={() => handleRollbackFix(f.control_id, rem?.command)}
                              >
                                <IconRotateCcw size={13} /> Cancel Schedule
                              </button>
                            </div>
                          )}

                          {status === 'rolled-back' && (
                            <div className="fix-applied-row">
                              <span className="status-tag rose"><IconRotateCcw size={14} /> Rolled Back to Snapshot</span>
                              <button
                                className="btn-primary-sm"
                                onClick={() => handleApplyFix(f.control_id, sev, rem?.command)}
                              >
                                Re-Apply Fix
                              </button>
                            </div>
                          )}

                          {status === 'applying' && <span className="status-tag loading">Applying patch with Pre-Snapshot...</span>}
                          {status === 'rolling-back' && <span className="status-tag loading">Rolling back to previous snapshot...</span>}

                          {!status && (
                            <div className="af-buttons">
                              <button
                                className="btn-secondary"
                                onClick={() => handleCopy(rem?.command || '', f.control_id)}
                              >
                                {copiedId === f.control_id ? 'Copied' : 'Copy CLI'}
                              </button>
                              <button
                                className="btn-primary"
                                onClick={() => handleApplyFix(f.control_id, sev, rem?.command)}
                              >
                                {sev === 'LOW' ? 'Auto-Fix Now' : sev === 'MEDIUM' ? 'Approve & Apply' : 'Schedule Change Window'}
                              </button>
                            </div>
                          )}
                        </div>
                      </div>
                    )
                  })
                )}
              </div>
            </div>
          )}

          {/* TAB 6: ATTACK PATH & BLAST RADIUS */}
          {activeTab === 'intelligence' && (
            <div className="tab-pane">
              <div className="pane-header">
                <div>
                  <h2>Attack-Path Intelligence &amp; Blast Radius</h2>
                  <p>Graph-based correlation engine identifying multi-hop lateral movement chains across network segments.</p>
                </div>
              </div>

              <div className="intel-layout">
                {/* ATTACK PATH SELECTOR */}
                <div className="intel-sidebar-paths">
                  <div className="section-card compact">
                    <h4>Identified Attack Chains</h4>
                    <div className="attack-path-selector-list">
                      {activeAttackPaths.map(ap => (
                        <div
                          key={ap.path_id}
                          className={`ap-select-item ${activeAttackPathId === ap.path_id ? 'active' : ''}`}
                          onClick={() => setActiveAttackPathId(ap.path_id)}
                        >
                          <div className="aps-top">
                            <strong>{ap.path_id}</strong>
                            <span className="aps-score">Score: {ap.risk_score}</span>
                          </div>
                          <p className="aps-summary">{ap.summary}</p>
                          <span className="aps-steps-badge">{ap.steps?.length || 0} Attack Hops</span>
                        </div>
                      ))}
                    </div>
                  </div>

                  {/* ROOT CAUSE CARD */}
                  <div className="section-card compact">
                    <h4>AI Root Cause Analysis</h4>
                    <div className="root-cause-box">
                      <div className="rc-item">
                        <span className="rc-tag">SYSTEMIC ROOT CAUSE</span>
                        <strong>Unencrypted Management Protocols (Telnet / HTTP)</strong>
                        <p>Failing controls share root dependency on missing TLS/SSH global transport baseline.</p>
                      </div>
                      <div className="rc-item">
                        <span className="rc-tag">ACTIONABLE RECTIFICATION</span>
                        <p>Enforce SSHv2 globally &amp; apply management ACL on line vty 0 15.</p>
                      </div>
                    </div>
                  </div>
                </div>

                {/* ATTACK PATH VISUAL GRAPH */}
                <div className="intel-graph-panel">
                  {(() => {
                    const currentPath = activeAttackPaths.find(p => p.path_id === activeAttackPathId) || activeAttackPaths[0]
                    if (!currentPath) return null

                    return (
                      <div className="section-card">
                        <div className="graph-header">
                          <div>
                            <span className="card-badge-red">CRITICAL ATTACK CHAIN</span>
                            <h3>{currentPath.summary}</h3>
                          </div>
                          <div className="risk-score-display">
                            <span>RISK INDEX</span>
                            <strong>{currentPath.risk_score} / 10</strong>
                          </div>
                        </div>

                        <div className="exploit-chain-visual">
                          <div className="ecv-steps">
                            {currentPath.steps.map((step, idx) => (
                              <div key={idx} className="ecv-step-card">
                                <div className="ecv-node-top">
                                  <span className="ecv-step-num">HOP {idx + 1}</span>
                                  <span className={`ecv-sev ${step.severity.toLowerCase()}`}>{step.severity}</span>
                                </div>
                                <h4>{step.technique}</h4>
                                <p>{step.description}</p>
                                <div className="ecv-flags">
                                  {step.lateral_movement && <span className="flag-chip">Lateral Movement</span>}
                                  {step.privilege_escalation && <span className="flag-chip red">Privilege Escalation</span>}
                                </div>
                                {idx < currentPath.steps.length - 1 && (
                                  <div className="ecv-arrow">
                                    <IconArrowRight size={12} /> Pivot Exploitation Link
                                  </div>
                                )}
                              </div>
                            ))}
                          </div>
                        </div>

                        {/* BLAST RADIUS TABLE */}
                        <div className="blast-radius-box">
                          <h4>Calculated Blast Radius &amp; Exposed Subnets</h4>
                          <div className="subnet-tags-grid">
                            <div className="subnet-chip danger">
                              <strong>10.10.20.0/24 (SERVER-NETWORK)</strong>
                              <small>Directly Reachable · Unrestricted ACL</small>
                            </div>
                            <div className="subnet-chip danger">
                              <strong>10.10.40.0/24 (MGMT-NETWORK)</strong>
                              <small>Exposed VTY Ports · Cleartext Credentials</small>
                            </div>
                            <div className="subnet-chip safe">
                              <strong>10.10.30.0/24 (USER-NETWORK)</strong>
                              <small>Segmented · Protected by VLAN isolation</small>
                            </div>
                          </div>
                        </div>
                      </div>
                    )
                  })()}
                </div>
              </div>
            </div>
          )}

          {/* TAB 7: WHAT-IF SIMULATION SANDBOX */}
          {activeTab === 'whatif' && (
            <div className="tab-pane">
              <div className="pane-header">
                <div>
                  <h2>What-If Security Simulation Sandbox</h2>
                  <p>Pre-test remediation patches before touching production. Recalculates compliance scores in real time without device risk.</p>
                </div>
              </div>

              <div className="whatif-dashboard">
                <div className="whatif-comparison-row">
                  <div className="wc-box before">
                    <span className="wc-label">CURRENT LIVE STATE</span>
                    <strong className="wc-score" style={{ color: metrics.score >= 80 ? '#10b981' : '#f59e0b' }}>
                      {metrics.score}%
                    </strong>
                    <p>{metrics.failed} failing controls detected</p>
                  </div>

                  <div className="wc-arrow"><IconArrowRight size={24} /></div>

                  <div className="wc-box after">
                    <span className="wc-label">SIMULATED PROJECTED STATE</span>
                    <strong className="wc-score" style={{ color: whatIfMetrics.simScore >= 80 ? '#10b981' : '#00f0ff' }}>
                      {whatIfMetrics.simScore}%
                    </strong>
                    <p className="text-green">+{whatIfMetrics.fixedCount} Controls Fixed (+{whatIfMetrics.simScore - metrics.score}%)</p>
                  </div>
                </div>

                {/* INTERACTIVE TOGGLE TABLE */}
                <div className="section-card">
                  <div className="card-header-row">
                    <h3>Select Fixes to Simulate in Virtual Topology</h3>
                    <button
                      className="btn-text"
                      onClick={() => {
                        const allOn = findings.filter(f => f.status === 'FAIL').reduce((acc, f) => ({ ...acc, [f.control_id]: true }), {})
                        setSimulatedFixes(allOn)
                      }}
                    >
                      Toggle All Remediations
                    </button>
                  </div>

                  <div className="whatif-interactive-table">
                    <div className="wit-header">
                      <span>Simulate</span>
                      <span>Control ID</span>
                      <span>Target Vulnerability</span>
                      <span>Proposed Command</span>
                      <span>Severity</span>
                      <span>Projected Impact</span>
                    </div>

                    {findings.filter(f => f.status === 'FAIL').map(f => {
                      const rem = remediations.find(r => r.control_id === f.control_id)
                      const isChecked = Boolean(simulatedFixes[f.control_id])

                      return (
                        <div key={f.control_id} className={`wit-row ${isChecked ? 'simulated-on' : ''}`}>
                          <div className="wit-check">
                            <input
                              type="checkbox"
                              checked={isChecked}
                              onChange={e => setSimulatedFixes(prev => ({ ...prev, [f.control_id]: e.target.checked }))}
                            />
                          </div>
                          <span className="wit-id">{f.control_id}</span>
                          <span className="wit-desc">{f.description}</span>
                          <code className="wit-cmd">{rem?.command || '—'}</code>
                          <span className={`fp-sev-badge ${f.severity?.toLowerCase()}`}>{f.severity}</span>
                          <span className="wit-impact">
                            {isChecked ? <strong className="text-green">PASS (Fixed)</strong> : <span className="text-muted">Unchanged</span>}
                          </span>
                        </div>
                      )
                    })}
                  </div>
                </div>
              </div>
            </div>
          )}

          {/* TAB 8: MULTI-AGENT GRID */}
          {activeTab === 'agents' && (
            <div className="tab-pane">
              <div className="pane-header">
                <div>
                  <h2>Multi-Agent AI Defense Grid</h2>
                  <p>6 specialized autonomous agents collaborating in real-time across analysis, risk estimation, and critic validation.</p>
                </div>
              </div>

              <div className="agents-cards-grid">
                {MOCK_AGENTS.map((ag, i) => {
                  const AgentIcon = ag.icon
                  return (
                    <div key={ag.id} className="agent-detail-card">
                      <div className="adc-top">
                        <span className="adc-num">AGENT 0{i + 1}</span>
                        <span className="adc-status-pill">Active Grid</span>
                      </div>
                      <div className="adc-icon text-cyan"><AgentIcon size={24} /></div>
                      <h3>{ag.name}</h3>
                      <span className="adc-role">{ag.role}</span>
                      <p>{ag.desc}</p>
                    </div>
                  )
                })}
              </div>

              {/* UNKNOWN SYNTAX TRANSLATOR */}
              <div className="section-card">
                <div className="card-header-row">
                  <div>
                    <h3>Adaptive Learning &amp; Unknown Syntax Interpreter</h3>
                    <p>Test new vendor CLI dialect. The AI Parser maps unfamiliar vendor syntax into the universal baseline without redeploying code.</p>
                  </div>
                  <span className="card-badge">Zero-Shot NLP</span>
                </div>

                <div className="syntax-tester-row">
                  <input
                    type="text"
                    className="syntax-input"
                    value={unknownInput}
                    onChange={e => setUnknownInput(e.target.value)}
                    placeholder="Enter custom CLI command syntax..."
                  />
                  <button className="btn-primary" onClick={handleInterpretSyntax} disabled={isLearning}>
                    {isLearning ? 'Interpreting…' : 'AI Parse Syntax'}
                  </button>
                </div>

                {aiInterpretation && (
                  <div className="interpretation-result-box">
                    <div className="ir-header">
                      <strong>AI Canonical Mapping Preview</strong>
                      <span className="text-green">Confidence: {Math.round(aiInterpretation.confidence * 100)}%</span>
                    </div>
                    <div className="ir-grid">
                      <div>
                        <span>Universal Field:</span>
                        <code>{aiInterpretation.normalized_field}</code>
                      </div>
                      <div>
                        <span>Action:</span>
                        <code>{aiInterpretation.parsed_action}</code>
                      </div>
                      <div>
                        <span>Mapped Policy:</span>
                        <code>{aiInterpretation.suggested_policy}</code>
                      </div>
                    </div>
                    <div className="ir-actions">
                      <button className="btn-secondary" onClick={() => setAiInterpretation(null)}>Discard</button>
                      <button className="btn-primary" onClick={handleApproveLearning}>Approve &amp; Commit to Registry</button>
                    </div>
                  </div>
                )}
              </div>
            </div>
          )}

          {/* TAB 9: LIVE SSH NETWORK DEVICES */}
          {activeTab === 'live' && (
            <div className="tab-pane">
              <div className="pane-header">
                <div>
                  <h2>Live SSH Device Fleet Manager</h2>
                  <p>Direct Netmiko / NAPALM SSH connector for live Cisco, Juniper, Palo Alto, Arista, and Fortinet appliances.</p>
                </div>
              </div>

              {liveSuccessMsg && <div className="success-banner">{liveSuccessMsg}</div>}

              <div className="live-page-layout">
                {/* CONNECT FORM */}
                <div className="section-card connect-form-card">
                  <h3>Add Live Network Device</h3>
                  <form onSubmit={handleLiveConnectSubmit} className="live-connect-form">
                    <div className="form-group">
                      <label>Target IP / Hostname</label>
                      <input
                        type="text"
                        placeholder="192.168.1.1 or core-router.local"
                        value={liveHost}
                        onChange={e => setLiveHost(e.target.value)}
                        required
                      />
                    </div>

                    <div className="form-row">
                      <div className="form-group">
                        <label>SSH Username</label>
                        <input
                          type="text"
                          placeholder="admin / neteng"
                          value={liveUser}
                          onChange={e => setLiveUser(e.target.value)}
                          required
                        />
                      </div>
                      <div className="form-group">
                        <label>Password / Secret</label>
                        <input
                          type="password"
                          placeholder="••••••••••••"
                          value={livePass}
                          onChange={e => setLivePass(e.target.value)}
                          required
                        />
                      </div>
                    </div>

                    <div className="form-group">
                      <label>Device Platform OS</label>
                      <select value={livePlatform} onChange={e => setLivePlatform(e.target.value)}>
                        <option value="cisco_ios">Cisco IOS / IOS-XE</option>
                        <option value="cisco_nxos">Cisco Nexus NX-OS</option>
                        <option value="juniper_junos">Juniper JunOS</option>
                        <option value="paloalto_panos">Palo Alto PAN-OS</option>
                        <option value="arista_eos">Arista EOS</option>
                        <option value="fortinet_fortios">Fortinet FortiOS</option>
                      </select>
                    </div>

                    <button type="submit" className="btn-primary full-width" disabled={liveConnecting}>
                      {liveConnecting ? 'Connecting via SSH & Pulling Config…' : 'Connect & Run Live Audit'}
                    </button>
                  </form>
                </div>

                {/* DEVICE INVENTORY TABLE */}
                <div className="section-card device-table-card">
                  <h3>Registered Fleet Devices</h3>
                  <div className="fleet-table">
                    <div className="ft-header">
                      <span>Host IP</span>
                      <span>Platform</span>
                      <span>Status</span>
                      <span>Compliance</span>
                      <span>Action</span>
                    </div>

                    {liveDevices.map(dev => (
                      <div key={dev.id} className="ft-row">
                        <div className="ft-col-host">
                          <strong>{dev.host}</strong>
                          <small>Scanned {dev.lastScan}</small>
                        </div>
                        <span className="ft-col-vendor">{dev.vendor}</span>
                        <span className={`status-dot-pill ${dev.status}`}>
                          <span className="s-dot" /> {dev.status}
                        </span>
                        <strong className="ft-col-score">{dev.compliance}</strong>
                        <button
                          className="btn-sm-pull"
                          onClick={() => handlePullLiveConfig(dev)}
                        >
                          Pull &amp; View Config
                        </button>
                      </div>
                    ))}
                  </div>
                </div>
              </div>
            </div>
          )}
        </main>
      </div>

      {/* MODAL: HOW AUTO-FIX & ROLLBACK WORKS */}
      {showHowItFixesModal && (
        <div className="modal-backdrop" onClick={() => setShowHowItFixesModal(false)}>
          <div className="how-it-works-modal" onClick={e => e.stopPropagation()}>
            <div className="modal-header">
              <div className="modal-title-wrap">
                <span className="modal-badge">ENGINE ARCHITECTURE</span>
                <h3>How AegisGuard Auto-Fix &amp; Rollback Circuit Breakers Work</h3>
              </div>
              <button className="btn-close-modal" onClick={() => setShowHowItFixesModal(false)}>
                <IconCross size={18} />
              </button>
            </div>

            <div className="modal-body">
              <div className="how-flow-steps">
                <div className="flow-step-item">
                  <div className="fsi-num">01</div>
                  <div className="fsi-content">
                    <h4>Pre-Execution Cryptographic Snapshot</h4>
                    <p>Before applying any change, the engine pulls the current running configuration and creates an immutable snapshot with a timestamp and configuration checksum.</p>
                  </div>
                </div>

                <div className="flow-step-item">
                  <div className="fsi-num">02</div>
                  <div className="fsi-content">
                    <h4>Critic Agent Semantic Safety Validation</h4>
                    <p>The Critic Agent evaluates the proposed CLI command against routing tables, management VTYs, and access-lists to ensure no administrative lockout or route flapping occurs.</p>
                  </div>
                </div>

                <div className="flow-step-item">
                  <div className="fsi-num">03</div>
                  <div className="fsi-content">
                    <h4>Idempotent Patch Synthesis</h4>
                    <p>Vendor-specific CLI commands (e.g. Cisco IOS <code>no ip http server</code>, Juniper JunOS <code>delete system services web-management</code>) are synthesized to match exact OS syntax.</p>
                  </div>
                </div>

                <div className="flow-step-item">
                  <div className="fsi-num">04</div>
                  <div className="fsi-content">
                    <h4>Automated Inverse Rollback Generation</h4>
                    <p>Every remediation is paired with a verified inverse rollback command (e.g. <code>ip http server</code> or <code>transport input telnet ssh</code>) loaded into memory for instant emergency rollback.</p>
                  </div>
                </div>

                <div className="flow-step-item">
                  <div className="fsi-num">05</div>
                  <div className="fsi-content">
                    <h4>Post-Apply Healthcheck &amp; Rollback Trigger</h4>
                    <p>An immediate post-flight compliance re-evaluation runs. If an unexpected anomaly is detected or if the operator clicks <strong>Rollback Fix</strong>, the inverse command executes immediately.</p>
                  </div>
                </div>
              </div>

              <div className="modal-footer-box">
                <strong>Zero-Disruption Guarantee:</strong> All changes can be rolled back individually or globally back to the initial baseline with 1 click.
              </div>
            </div>
          </div>
        </div>
      )}
      {/* MODAL: FETCH LIVE DEVICE CONFIGURATION */}
      {showLiveFetchModal && (
        <div className="modal-backdrop" onClick={() => !liveConnecting && setShowLiveFetchModal(false)}>
          <div className="live-fetch-modal" onClick={e => e.stopPropagation()}>
            <div className="modal-header">
              <div className="modal-title-wrap">
                <span className="modal-badge cyan">LIVE HARDWARE CONNECTOR</span>
                <h3>Fetch Live Device Running Configuration</h3>
              </div>
              <button
                className="btn-close-modal"
                disabled={liveConnecting}
                onClick={() => setShowLiveFetchModal(false)}
              >
                <IconCross size={18} />
              </button>
            </div>

            <div className="modal-body">
              <p className="modal-subtext">
                Connect directly to your physical or virtual network appliance over SSH / NAPALM.
                AegisGuard will extract the active running-config, auto-detect the vendor syntax, run compliance audits, and configure 1-click rollback snapshots.
              </p>

              {/* QUICK LAB PRESET AUTO-FILL */}
              <div className="quick-fill-lab-box">
                <span className="qf-label">Quick-Fill Lab Preset:</span>
                <div className="qf-buttons">
                  <button
                    type="button"
                    className="qf-pill"
                    onClick={() => {
                      setLiveHost('192.168.1.1')
                      setLiveUser('admin')
                      setLivePass('C1sco!Hardened2026')
                      setLivePlatform('cisco_ios')
                      setLivePort(22)
                      setLiveTransport('ssh')
                    }}
                  >
                    Cisco IOS (192.168.1.1)
                  </button>
                  <button
                    type="button"
                    className="qf-pill"
                    onClick={() => {
                      setLiveHost('10.0.50.2')
                      setLiveUser('netops')
                      setLivePass('Jun1per#SecGate')
                      setLivePlatform('juniper_junos')
                      setLivePort(22)
                      setLiveTransport('ssh')
                    }}
                  >
                    Juniper JunOS (10.0.50.2)
                  </button>
                  <button
                    type="button"
                    className="qf-pill"
                    onClick={() => {
                      setLiveHost('172.16.0.254')
                      setLiveUser('fwadmin')
                      setLivePass('PaloAlto!2026Secure')
                      setLivePlatform('paloalto_panos')
                      setLivePort(22)
                      setLiveTransport('ssh')
                    }}
                  >
                    Palo Alto PAN-OS (172.16.0.254)
                  </button>
                  <button
                    type="button"
                    className="qf-pill"
                    onClick={() => {
                      setLiveHost('10.20.0.1')
                      setLiveUser('admin')
                      setLivePass('Ar1staEOS#Fast')
                      setLivePlatform('arista_eos')
                      setLivePort(22)
                      setLiveTransport('ssh')
                    }}
                  >
                    Arista EOS (10.20.0.1)
                  </button>
                </div>
              </div>

              <form onSubmit={handleLiveConnectSubmit} className="live-modal-form">
                <div className="form-grid-2">
                  <div className="form-group">
                    <label>Target IP / Hostname <span className="req">*</span></label>
                    <input
                      type="text"
                      placeholder="e.g. 192.168.1.1 or core-gw.corp.net"
                      value={liveHost}
                      onChange={e => setLiveHost(e.target.value)}
                      required
                    />
                  </div>

                  <div className="form-group">
                    <label>SSH Port</label>
                    <input
                      type="number"
                      placeholder="22"
                      value={livePort}
                      onChange={e => setLivePort(e.target.value)}
                    />
                  </div>
                </div>

                <div className="form-grid-2">
                  <div className="form-group">
                    <label>Device Platform OS <span className="req">*</span></label>
                    <select value={livePlatform} onChange={e => setLivePlatform(e.target.value)}>
                      <option value="cisco_ios">Cisco IOS / IOS-XE</option>
                      <option value="cisco_nxos">Cisco Nexus NX-OS</option>
                      <option value="cisco_xr">Cisco IOS-XR</option>
                      <option value="juniper_junos">Juniper JunOS</option>
                      <option value="paloalto_panos">Palo Alto PAN-OS</option>
                      <option value="arista_eos">Arista EOS</option>
                      <option value="fortinet">Fortinet FortiOS</option>
                      <option value="huawei_vrp">Huawei VRP</option>
                      <option value="vyos">VyOS / Linux Network Router</option>
                      <option value="checkpoint_gaia">Check Point Gaia OS</option>
                    </select>
                  </div>

                  <div className="form-group">
                    <label>Transport Collector</label>
                    <select value={liveTransport} onChange={e => setLiveTransport(e.target.value)}>
                      <option value="ssh">SSH (Netmiko Direct CLI)</option>
                      <option value="napalm">NAPALM (Vendor-Neutral API)</option>
                    </select>
                  </div>
                </div>

                <div className="form-grid-2">
                  <div className="form-group">
                    <label>SSH Username <span className="req">*</span></label>
                    <input
                      type="text"
                      placeholder="admin / neteng"
                      value={liveUser}
                      onChange={e => setLiveUser(e.target.value)}
                      required
                    />
                  </div>

                  <div className="form-group">
                    <label>SSH Password</label>
                    <input
                      type="password"
                      placeholder="••••••••••••"
                      value={livePass}
                      onChange={e => setLivePass(e.target.value)}
                    />
                  </div>
                </div>

                <div className="form-group">
                  <label>Enable Secret / Privilege Password <small>(Optional for Cisco privilege elevation)</small></label>
                  <input
                    type="password"
                    placeholder="Optional enable password"
                    value={liveSecret}
                    onChange={e => setLiveSecret(e.target.value)}
                  />
                </div>

                {/* TELEMETRY LOGS */}
                {liveFetchLogs.length > 0 && (
                  <div className="live-telemetry-console">
                    <div className="ltc-header">
                      <span className="ltc-title">Live SSH Connection Telemetry</span>
                      {liveConnecting && <span className="ltc-status active">Connecting...</span>}
                      {liveFetchSuccess && <span className="ltc-status success">Configuration Pulled</span>}
                      {liveFetchError && <span className="ltc-status error">Connection Failed</span>}
                    </div>
                    <div className="ltc-body">
                      {liveFetchLogs.map((log, i) => (
                        <div key={i} className="ltc-line">{log}</div>
                      ))}
                    </div>
                  </div>
                )}

                {/* ERROR & LAB FALLBACK BANNER */}
                {liveFetchError && (
                  <div className="live-error-fallback-card">
                    <div className="lefc-header">
                      <IconAlertOctagon size={18} className="text-rose" />
                      <div>
                        <strong>Live Hardware Connection Unreachable</strong>
                        <p>{liveFetchError}</p>
                      </div>
                    </div>
                    <div className="lefc-actions">
                      <span className="lefc-hint">No physical hardware online? You can load a simulated live stream for this platform to test the live compliance pipeline:</span>
                      <div className="lefc-buttons">
                        <button
                          type="button"
                          className="btn-primary-sm"
                          onClick={() => {
                            if (livePlatform.includes('juniper')) handleLoadLabDevice('juniper-01')
                            else if (livePlatform.includes('paloalto')) handleLoadLabDevice('paloalto-01')
                            else if (livePlatform.includes('nxos')) handleLoadLabDevice('cisco-nxos-01')
                            else if (livePlatform.includes('arista')) handleLoadLabDevice('arista-01')
                            else if (livePlatform.includes('fortinet')) handleLoadLabDevice('fortinet-01')
                            else handleLoadLabDevice('cisco-01')
                          }}
                        >
                          Load Simulated {livePlatform.toUpperCase().replace(/_/g, ' ')} Device
                        </button>
                        <button
                          type="submit"
                          className="btn-secondary-sm"
                          disabled={liveConnecting}
                        >
                          Retry Live Connection
                        </button>
                      </div>
                    </div>
                  </div>
                )}

                <div className="modal-actions-row">
                  <button
                    type="button"
                    className="btn-secondary"
                    disabled={liveConnecting}
                    onClick={() => setShowLiveFetchModal(false)}
                  >
                    Cancel
                  </button>
                  <button
                    type="submit"
                    className="btn-primary"
                    disabled={liveConnecting || !liveHost || !liveUser}
                  >
                    {liveConnecting ? (
                      <>
                        <span className="spinner-inline" /> Connecting &amp; Ingesting Live Config…
                      </>
                    ) : (
                      <>
                        <IconRadio size={15} /> Connect &amp; Ingest Live Running-Config
                      </>
                    )}
                  </button>
                </div>
              </form>
            </div>
          </div>
        </div>
      )}

      {/* SLIDE-OVER FINDING DETAIL DRAWER */}
      {selectedFindingForDrawer && (
        <div className="drawer-backdrop" onClick={() => setSelectedFindingForDrawer(null)}>
          <div className="drawer-panel" onClick={e => e.stopPropagation()}>
            <div className="drawer-header">
              <div className="drawer-title-group">
                <span className="drawer-tag">CONTROL DETAIL INSPECTOR</span>
                <h2>{selectedFindingForDrawer.control_id}</h2>
              </div>
              <button
                className="btn-drawer-close"
                onClick={() => setSelectedFindingForDrawer(null)}
              >
                <IconCross size={18} />
              </button>
            </div>

            <div className="drawer-body">
              <div className="drawer-summary-card">
                <h3>{selectedFindingForDrawer.description}</h3>
                <div className="drawer-badges-row">
                  <span className={`fp-sev-badge ${selectedFindingForDrawer.severity?.toLowerCase()}`}>
                    {selectedFindingForDrawer.severity} SEVERITY
                  </span>
                  <span className={`fp-status-badge ${selectedFindingForDrawer.status?.toLowerCase()}`}>
                    {selectedFindingForDrawer.status}
                  </span>
                  <span className="drawer-fw-pill">CIS Benchmark v8.1 / NIST SP 800-53</span>
                </div>
              </div>

              <div className="drawer-section">
                <span className="drawer-sec-label">SECURITY REQUIREMENT &amp; EXPECTATION</span>
                <div className="drawer-box">
                  <p>{selectedFindingForDrawer.expected || 'Enforced secure configuration policy across enterprise boundaries.'}</p>
                </div>
              </div>

              <div className="drawer-section">
                <span className="drawer-sec-label">DETECTED OBSERVED STATE</span>
                <div className={`drawer-box ${selectedFindingForDrawer.status === 'FAIL' ? 'box-fail' : 'box-pass'}`}>
                  <p>{selectedFindingForDrawer.observed || 'Verified compliant with baseline standard.'}</p>
                </div>
              </div>

              <div className="drawer-section">
                <span className="drawer-sec-label">MITRE ATT&amp;CK TECHNIQUE MAPPING</span>
                <div className="drawer-mitre-box">
                  <span className="mitre-tag">T1021.004</span>
                  <strong>Remote Services: SSH / Telnet Management Plane Exposure</strong>
                  <p>Adversaries may access plaintext protocols to harvest credentials or bypass multi-factor enforcement.</p>
                </div>
              </div>

              {/* REMEDIATION & ROLLBACK IN DRAWER */}
              {selectedFindingForDrawer.status === 'FAIL' && (
                <div className="drawer-section">
                  <span className="drawer-sec-label">AUTOMATED AUTONOMOUS REMEDIATION</span>
                  {(() => {
                    const rem = remediations.find(r => r.control_id === selectedFindingForDrawer.control_id)
                    const rollbackCmd = calculateRollbackCommand(
                      selectedFindingForDrawer.control_id,
                      rem?.command || '',
                      selectedFindingForDrawer.observed || ''
                    )
                    return rem ? (
                      <div className="drawer-rem-card">
                        <div className="drc-header">
                          <span>Hardening CLI Syntax</span>
                          <button
                            className="btn-copy-cli"
                            onClick={() => {
                              handleCopy(rem.command, 'drawer-fix')
                              addToast('Copied', 'Remediation command copied to clipboard.', 'info')
                            }}
                          >
                            <IconCopy size={12} /> Copy
                          </button>
                        </div>
                        <code>{rem.command}</code>

                        <div className="drc-header" style={{ marginTop: '12px' }}>
                          <span className="text-cyan">Inverse Rollback CLI Syntax</span>
                          <button
                            className="btn-copy-cli"
                            onClick={() => {
                              handleCopy(rollbackCmd, 'drawer-rollback')
                              addToast('Copied', 'Rollback command copied to clipboard.', 'info')
                            }}
                          >
                            <IconCopy size={12} /> Copy
                          </button>
                        </div>
                        <code>{rollbackCmd}</code>

                        <div className="drawer-action-row">
                          <button
                            className="btn-primary"
                            style={{ width: '100%', justifyContent: 'center' }}
                            onClick={() => {
                              handleExecuteAutoFix(selectedFindingForDrawer.control_id, rem.command)
                              addToast('Auto-Fix Applied', `Remediation executed for ${selectedFindingForDrawer.control_id} with pre-change snapshot.`, 'success')
                              setSelectedFindingForDrawer(null)
                            }}
                          >
                            <IconWrench size={14} /> Execute Auto-Fix &amp; Save Snapshot
                          </button>
                        </div>
                      </div>
                    ) : (
                      <div className="drawer-box">
                        <p>No automated script available. Follow enterprise manual change request procedure.</p>
                      </div>
                    )
                  })()}
                </div>
              )}
            </div>
          </div>
        </div>
      )}

      {/* QUICK COMMAND PALETTE (CTRL + K) */}
      {showCommandPalette && (
        <div className="cmd-backdrop" onClick={() => setShowCommandPalette(false)}>
          <div className="cmd-modal" onClick={e => e.stopPropagation()}>
            <div className="cmd-search-row">
              <IconSearch size={18} className="cmd-search-icon" />
              <input
                type="text"
                className="cmd-input"
                placeholder="Type a command, jump to tab, or search rules..."
                value={commandQuery}
                onChange={e => setCommandQuery(e.target.value)}
                autoFocus
              />
              <span className="cmd-esc-tag" onClick={() => setShowCommandPalette(false)}>ESC</span>
            </div>

            <div className="cmd-results-list">
              <div className="cmd-group-label">NAVIGATION</div>
              {[
                { name: 'Executive Dashboard', tab: 'dashboard', desc: 'Overall compliance health index & stats' },
                { name: 'Config Inspector & AI Parser', tab: 'scan', desc: 'Upload CLI configs and view side-by-side diffs' },
                { name: 'Live Configuration & SSH', tab: 'live-config', desc: 'Real-time Netmiko/NAPALM ingestion' },
                { name: 'Compliance Findings & Violations', tab: 'findings', desc: 'Explore all evaluated rule controls' },
                { name: 'Autonomous Auto-Fix & Rollback', tab: 'remediation', desc: 'Risk-tiered auto-repair & snapshots' },
                { name: 'Attack Path & Blast Radius', tab: 'intelligence', desc: 'Lateral movement & blast radius graph' },
                { name: 'What-If Sandbox Simulation', tab: 'whatif', desc: 'Simulate score impact before deployment' },
                { name: 'Multi-Agent Swarm Grid', tab: 'agents', desc: 'Parser, Compliance, and Remediation agents' },
              ]
                .filter(item => !commandQuery || item.name.toLowerCase().includes(commandQuery.toLowerCase()) || item.desc.toLowerCase().includes(commandQuery.toLowerCase()))
                .map((item, idx) => (
                  <div
                    key={idx}
                    className="cmd-item"
                    onClick={() => {
                      setActiveTab(item.tab)
                      setShowCommandPalette(false)
                    }}
                  >
                    <div className="cmd-item-info">
                      <strong>{item.name}</strong>
                      <small>{item.desc}</small>
                    </div>
                    <span className="cmd-jump-tag">Jump →</span>
                  </div>
                ))}

              <div className="cmd-group-label" style={{ marginTop: '12px' }}>QUICK ACTIONS &amp; LAB BENCHMARKS</div>
              {SAMPLE_PRESETS
                .filter(p => !commandQuery || p.name.toLowerCase().includes(commandQuery.toLowerCase()) || p.vendor.toLowerCase().includes(commandQuery.toLowerCase()))
                .map(preset => (
                  <div
                    key={preset.id}
                    className="cmd-item"
                    onClick={() => {
                      handleSelectPreset(preset)
                      setShowCommandPalette(false)
                      addToast('Preset Loaded', `Loaded benchmark configuration for ${preset.vendor}.`, 'info')
                    }}
                  >
                    <div className="cmd-item-info">
                      <strong>Load {preset.name}</strong>
                      <small>{preset.vendor} · {preset.filename}</small>
                    </div>
                    <span className="cmd-jump-tag">Load &amp; Scan</span>
                  </div>
                ))}
            </div>
          </div>
        </div>
      )}

      {/* FLOATING TOAST NOTIFICATION CONTAINER */}
      <div className="toast-container">
        {toasts.map(t => (
          <div key={t.id} className={`toast-card toast-${t.type}`}>
            <div className="toast-icon">
              {t.type === 'success' && <IconCheckCircle size={18} />}
              {t.type === 'warn' && <IconAlertTriangle size={18} />}
              {t.type === 'info' && <IconActivity size={18} />}
            </div>
            <div className="toast-content">
              <strong>{t.title}</strong>
              <p>{t.message}</p>
            </div>
          </div>
        ))}
      </div>
    </div>
  )
}

