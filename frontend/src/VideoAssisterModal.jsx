import React, { useState, useEffect, useRef } from 'react'

/* ==========================================================================
   VECTOR SVG ICONS FOR VIDEO ASSISTER
   ========================================================================== */

function IconPlay({ size = 16, className = '' }) {
  return (
    <svg width={size} height={size} viewBox="0 0 24 24" fill="currentColor" className={className}>
      <polygon points="5 3 19 12 5 21 5 3" />
    </svg>
  )
}

function IconPause({ size = 16, className = '' }) {
  return (
    <svg width={size} height={size} viewBox="0 0 24 24" fill="currentColor" className={className}>
      <rect x="6" y="4" width="4" height="16" rx="1" />
      <rect x="14" y="4" width="4" height="16" rx="1" />
    </svg>
  )
}

function IconRotateCcw({ size = 16, className = '' }) {
  return (
    <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" className={className}>
      <polyline points="1 4 1 10 7 10" />
      <path d="M3.51 15a9 9 0 1 0 2.13-9.36L1 10" />
    </svg>
  )
}

function IconVolume2({ size = 16, className = '' }) {
  return (
    <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" className={className}>
      <polygon points="11 5 6 9 2 9 2 15 6 15 11 19 11 5" />
      <path d="M19.07 4.93a10 10 0 0 1 0 14.14M15.54 8.46a5 5 0 0 1 0 7.07" />
    </svg>
  )
}

function IconVolumeX({ size = 16, className = '' }) {
  return (
    <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" className={className}>
      <polygon points="11 5 6 9 2 9 2 15 6 15 11 19 11 5" />
      <line x1="23" y1="9" x2="17" y2="15" />
      <line x1="17" y1="9" x2="23" y2="15" />
    </svg>
  )
}

function IconVideo({ size = 16, className = '' }) {
  return (
    <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" className={className}>
      <polygon points="23 7 16 12 23 17 23 7" />
      <rect x="1" y="5" width="15" height="14" rx="2" ry="2" />
    </svg>
  )
}

function IconExternalLink({ size = 14, className = '' }) {
  return (
    <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" className={className}>
      <path d="M18 13v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h6" />
      <polyline points="15 3 21 3 21 9" />
      <line x1="10" y1="14" x2="21" y2="3" />
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

function IconSearch({ size = 14, className = '' }) {
  return (
    <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" className={className}>
      <circle cx="11" cy="11" r="8" />
      <line x1="21" y1="21" x2="16.65" y2="16.65" />
    </svg>
  )
}

function IconCheckCircle({ size = 16, className = '' }) {
  return (
    <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" className={className}>
      <path d="M22 11.08V12a10 10 0 1 1-5.93-9.14" />
      <polyline points="22 4 12 14.01 9 11.01" />
    </svg>
  )
}

/* ==========================================================================
   FEATURE VIDEO MODULE CATALOG
   ========================================================================== */

export const VIDEO_CATALOG = [
  {
    id: 'live-network-audit',
    tab: 'network-audit',
    title: 'Live Subnet Discovery & Fleet Audit',
    category: 'Network Operations',
    duration: '1:15',
    badge: 'Core Feature',
    badgeColor: '#00f0ff',
    desc: 'Automated non-destructive subnet discovery, deterministic vendor classification, read-only credential verification, and cross-device attack path modeling.',
    keyTakeaways: [
      'Probes safe management ports (22, 80, 443, 830, 8728) with <=350ms timeouts.',
      'Progressive 4-stage lifecycle: DISCOVERED -> IDENTIFIED -> AUTHENTICATED -> AUDITED.',
      'Hardcoded read-only allowlists block destructive CLI tokens (config t, reboot, set, rm).',
      'Cross-device topology engine maps multi-hop attack paths and systemic perimeter exposure.',
    ],
    scenes: [
      {
        timestamp: 0,
        title: 'Target Subnet Configuration',
        caption: 'The operator designates an authorized subnet CIDR like 192.168.1.0/24 and toggles between Live Scan or simulated Multi-Vendor Lab.',
        visualType: 'cidr-setup',
        narration: 'Welcome to the Live Network Audit. You can configure target IP subnets with strict rate limits, and choose between live probing or demo lab mode.',
      },
      {
        timestamp: 25,
        title: 'Non-Destructive ARP & Port Inspection',
        caption: 'The scanner captures local ARP caches and probes management ports without sending exploit payloads or disrupting device traffic.',
        visualType: 'scanner-radar',
        narration: 'The discovery engine inspects local ARP tables and performs safe, non-destructive TCP connect checks on management ports 22, 80, and 443.',
      },
      {
        timestamp: 50,
        title: 'Deterministic Vendor AST Classification',
        caption: 'Service banners, SNMP sysDescr, and MAC OUIs deterministically classify appliances as Cisco, Fortinet, Palo Alto, MikroTik, or Linux.',
        visualType: 'vendor-classify',
        narration: 'Devices advance from Discovered to Identified. Our engine matches banners and MAC OUIs to recognize Cisco, Fortinet, Palo Alto, and MikroTik.',
      },
      {
        timestamp: 75,
        title: 'Cross-Device Exposure & Multi-Hop Risk Graph',
        caption: 'AegisGuard synthesizes the 4-layer topology (Perimeter -> Core -> Access -> Workload) to uncover compound lateral movement vulnerabilities.',
        visualType: 'topology-graph',
        narration: 'Finally, the cross-device intelligence engine models traffic flows across the network topology to expose compound multi-hop attack risks.',
      },
    ],
  },
  {
    id: 'executive-dashboard',
    tab: 'dashboard',
    title: 'Executive Security Dashboard & Framework Scoring',
    category: 'Governance & Risk',
    duration: '1:00',
    badge: 'Executive',
    badgeColor: '#a855f7',
    desc: 'Real-time compliance score computation across CIS Benchmarks v8.1, NIST SP 800-53, DoD DISA STIG, and ISO 27001 with active KPI dials.',
    keyTakeaways: [
      'Universal compliance score based on passing vs failing control ratios.',
      'Multi-framework simultaneous cross-mapping (CIS, NIST, STIG, ISO 27001).',
      'Real-time fleet inventory status and one-click PDF audit report generator.',
    ],
    scenes: [
      {
        timestamp: 0,
        title: 'Real-Time Posture Scoring',
        caption: 'AegisGuard evaluates configuration parameters to calculate an aggregated percentage score with compliant vs at-risk health badges.',
        visualType: 'dashboard-gauge',
        narration: 'The Executive Dashboard aggregates compliance health into a unified security score, highlighting pass versus fail ratios across all active baselines.',
      },
      {
        timestamp: 30,
        title: 'Multi-Framework Selector',
        caption: 'Select or combine CIS Benchmarks, NIST SP 800-53, DoD STIG, and ISO 27001 to assess federal and international regulatory readiness.',
        visualType: 'framework-pills',
        narration: 'Toggle regulatory frameworks like CIS, NIST, DISA STIG, and ISO 27001. Findings instantly adjust to match the selected governance profiles.',
      },
      {
        timestamp: 65,
        title: 'Audit PDF Generation',
        caption: 'Generate cryptographic-ready PDF audit reports formatted for CISOs, compliance auditors, and regulatory submission.',
        visualType: 'pdf-export',
        narration: 'Click Export Audit PDF to generate an executive-ready compliance summary with finding breakdowns, evidence lines, and signed remediation logs.',
      },
    ],
  },
  {
    id: 'compliance-findings',
    tab: 'findings',
    title: 'Compliance Findings Deep-Dive & Evidence Drawer',
    category: 'Compliance Analysis',
    duration: '1:05',
    badge: 'Audit Intelligence',
    badgeColor: '#f59e0b',
    desc: 'Per-control findings with line-level CLI evidence citations, severity filtering, inline auto-fix buttons, and bulk action export capabilities.',
    keyTakeaways: [
      'Every FAIL finding includes exact configuration line numbers as audit evidence.',
      'Filter by severity (CRITICAL, HIGH, MEDIUM, LOW) and status (PASS / FAIL / UNKNOWN).',
      'Inline "Auto-Fix Now" button directly applies deterministic remediation from the findings view.',
      'Bulk select findings for JSON export or batch scheduling.',
    ],
    scenes: [
      {
        timestamp: 0,
        title: 'Per-Control Finding Cards',
        caption: 'Each finding card shows the control ID, severity badge, observed misconfiguration vs expected baseline, and framework mapping (CIS/NIST/STIG).',
        visualType: 'findings-cards',
        narration: 'The Findings tab lists every evaluated control with a clear pass or fail verdict, showing observed values versus expected security baseline requirements.',
      },
      {
        timestamp: 40,
        title: 'Line-Level CLI Evidence Citations',
        caption: 'Expand any finding to see the exact raw configuration lines that triggered the violation, with source file and parser context.',
        visualType: 'evidence-drawer',
        narration: 'Expand the Evidence Drawer on any finding to see the exact raw CLI lines flagged, complete with line numbers and parser context for audit submissions.',
      },
      {
        timestamp: 75,
        title: 'Inline Auto-Fix & Severity Filtering',
        caption: 'Apply vendor-validated fixes inline or filter findings by severity to focus remediation on the highest-risk controls first.',
        visualType: 'findings-filter',
        narration: 'Use severity filters to prioritize CRITICAL and HIGH findings. Click Auto-Fix Now to immediately apply a deterministic fix without leaving the findings view.',
      },
    ],
  },
  {
    id: 'live-config-ssh',
    tab: 'live-config',
    title: 'Live SSH Config Collector & Terminal Console',
    category: 'Live Device Operations',
    duration: '1:10',
    badge: 'SSH Operations',
    badgeColor: '#34d399',
    desc: 'Pull live running configurations from authorized network devices over SSH, inspect them in a split-pane viewer, and run compliance audits directly on the live running state.',
    keyTakeaways: [
      'Connects to real network devices via SSH — Cisco IOS, Juniper, Palo Alto, Fortinet supported.',
      'Running config is pulled read-only and immediately fed into the full compliance pipeline.',
      'Built-in SSH terminal console for safe interactive show commands.',
      'Side-by-side raw vs normalized config inspector with line-diff overlay.',
    ],
    scenes: [
      {
        timestamp: 0,
        title: 'Vendor Fleet Device Selector',
        caption: 'Select from discovered devices or enter SSH credentials manually. The connector negotiates SSH transport and validates authentication before any config pull.',
        visualType: 'live-device-select',
        narration: 'The Live Config tab lets you connect to any authorized device. Select a device from the inventory or enter SSH credentials directly to begin.',
      },
      {
        timestamp: 40,
        title: 'Read-Only Running Config Pull',
        caption: 'AegisGuard issues show running-config over SSH. The raw text is immediately parsed through the AST compliance pipeline without write access.',
        visualType: 'config-pull',
        narration: 'Running configurations are pulled in read-only mode using show running-config. The engine never issues write or configuration mode commands.',
      },
      {
        timestamp: 75,
        title: 'SSH Terminal & Compliance Re-Audit',
        caption: 'Use the built-in terminal console to run safe show commands, then click Audit Live Config to score the device against all active frameworks.',
        visualType: 'ssh-terminal',
        narration: 'The SSH console lets you run read-only show commands interactively. Click Audit Live Config to instantly evaluate the pulled configuration against all frameworks.',
      },
    ],
  },
  {
    id: 'autonomous-remediation',
    tab: 'remediation',
    title: 'AI Auto-Fix Center: 5-Stage Live Pipeline & Rollback',
    category: 'SecOps Remediation',
    duration: '1:30',
    badge: 'Live AutoFix',
    badgeColor: '#10b981',
    desc: 'Risk-tiered auto-fix with precondition lockout checks, pre-change DB backup snapshot, verified command push, compliance re-audit, and 1-click inverse rollback.',
    keyTakeaways: [
      'Stage 1: Lockout prevention — aborts if fix would break SSH/admin access.',
      'Stage 2: Pre-change config snapshot saved to DB before any command is pushed.',
      'Stage 3: Only deterministic vendor-specific commands execute — never raw AI text.',
      'Stage 4: Compliance engine re-audits the device after fix to verify resolution.',
      'Stage 5: If verification fails, 1-click rollback restores Stage 2 snapshot.',
    ],
    scenes: [
      {
        timestamp: 0,
        title: 'Uploaded Config Mode — Offline Fix & Download',
        caption: 'In Uploaded Config mode, AegisGuard generates a fully corrected configuration file with disclaimers. The physical device is NEVER touched.',
        visualType: 'remediation-tiers',
        narration: 'In Uploaded Config mode, fixes are applied offline. A corrected configuration file is generated with clear disclaimers that no physical device was modified.',
      },
      {
        timestamp: 28,
        title: 'Live Device Mode — Precondition Safety Gate',
        caption: 'Before any live command is executed, the engine checks: Is SSH reachable? Will this command lock out the admin? All checks must pass or the pipeline aborts.',
        visualType: 'precondition-gate',
        narration: 'Switching to Live Device mode activates the 5-stage safety pipeline. Stage 1 runs precondition checks including lockout prevention before any change is made.',
      },
      {
        timestamp: 55,
        title: 'Backup Snapshot & Verified Command Push',
        caption: 'Stage 2 saves the full pre-change config to the database. Stage 3 pushes only deterministic vendor commands — never raw AI-generated text.',
        visualType: 'snapshot-save',
        narration: 'Stage 2 creates an immutable config backup. Stage 3 then pushes the validated command set. No raw AI output ever executes on the device.',
      },
      {
        timestamp: 80,
        title: 'Re-Audit Verification & 1-Click Rollback',
        caption: 'Stage 4 re-audits the device running config. Stage 5 marks RESOLVED if the control now passes — or shows a Rollback button to instantly restore the backup.',
        visualType: 'live-pipeline-verify',
        narration: 'Stage 4 re-audits the live running config. If the finding passes, it is marked RESOLVED. If verification fails, one click executes the full backup restoration.',
      },
    ],
  },
  {
    id: 'cyber-intelligence',
    tab: 'intelligence',
    title: 'Attack Path Graph & Transitive Blast Radius',
    category: 'Threat Modeling',
    duration: '1:10',
    badge: 'AI Cyber Graph',
    badgeColor: '#ec4899',
    desc: 'Uncovers lateral movement pathways and calculates the transitive blast radius an adversary could traverse if misconfigured management planes are breached.',
    keyTakeaways: [
      'Correlates plaintext Telnet, default SNMP, and weak SSH into compound attack graphs.',
      'Calculates blast radius scores across Edge, Core, Distribution, and Server layers.',
      'Identifies root-cause misconfigurations that eliminate multiple downstream attack paths.',
    ],
    scenes: [
      {
        timestamp: 0,
        title: 'Lateral Movement Path Visualization',
        caption: 'The attack graph visualizes how an attacker moving from untrusted internet can pivot through edge firewalls to core routers.',
        visualType: 'attack-path-flow',
        narration: 'Attack Path Intelligence models lateral movement across network zones, showing how unencrypted services allow adversaries to pivot deep into internal clusters.',
      },
      {
        timestamp: 40,
        title: 'Transitive Blast Radius Calculation',
        caption: 'The engine evaluates which downstream VLANs, routers, and management consoles are exposed if an appliance is compromised.',
        visualType: 'blast-radius-map',
        narration: 'Blast radius scoring quantifies transitive damage, determining how many critical assets and downstream subnets are threatened by a single weak device.',
      },
      {
        timestamp: 70,
        title: 'Single-Remediation Root Cause Elimination',
        caption: 'Highlights the single root-cause fix that dissolves the entire multi-hop attack chain with minimal administrative overhead.',
        visualType: 'root-cause-fix',
        narration: 'Root cause analysis pinpoints the exact foundational policy fix that collapses the entire attack vector at the earliest possible hop.',
      },
    ],
  },
  {
    id: 'config-inspector',
    tab: 'scan',
    title: 'Config Inspector & Side-by-Side Split Diff',
    category: 'AST Parsing',
    duration: '0:55',
    badge: 'Deep Inspection',
    badgeColor: '#38bdf8',
    desc: 'Multi-vendor raw configuration parser, AST block extraction, Security Baseline Model normalization, and side-by-side split diff comparison.',
    keyTakeaways: [
      'Contextual grammar parsers for Cisco IOS, Juniper JunOS, Palo Alto, and Fortinet.',
      'Split diff view highlights additions and deletions with zero syntax loss.',
      'Instant drag-and-drop or copy-paste configuration upload.',
    ],
    scenes: [
      {
        timestamp: 0,
        title: 'Multi-Vendor Grammar Parsing',
        caption: 'Upload any router or firewall configuration. Contextual parsers identify block structures, interface hierarchies, and ACL stanzas.',
        visualType: 'parser-ast',
        narration: 'The Config Inspector parses hierarchical stanzas and flat CLI files, translating complex vendor dialects into canonical security representations.',
      },
      {
        timestamp: 45,
        title: 'Side-by-Side Split Diff Viewer',
        caption: 'Compare the current running-config directly against proposed hardening scripts with colored line additions and deletions.',
        visualType: 'split-diff-view',
        narration: 'Use the side-by-side split diff viewer to preview exact proposed script alterations with clear visual line additions and removals.',
      },
    ],
  },
  {
    id: 'what-if-sandbox',
    tab: 'whatif',
    title: 'What-If Sandbox Simulation',
    category: 'Predictive Modeling',
    duration: '0:50',
    badge: 'Simulation',
    badgeColor: '#00f0ff',
    desc: 'Non-production simulation sandbox enabling operators to toggle proposed hardening fixes and preview projected score improvements.',
    keyTakeaways: [
      'Interactive toggles simulate rule remediation without touching live network hardware.',
      'Real-time recalculation of passing controls, critical risks, and score projections.',
      'Enables Change Advisory Boards to forecast security uplift prior to deployment.',
    ],
    scenes: [
      {
        timestamp: 0,
        title: 'Interactive Policy Impact Toggles',
        caption: 'Toggle individual remediation controls on or off to simulate what happens to your security posture before executing scripts.',
        visualType: 'whatif-toggle',
        narration: 'In the What-If Sandbox, operators can toggle remediation controls on and off to simulate compliance score improvements before touching production systems.',
      },
      {
        timestamp: 50,
        title: 'Predictive Score Impact Forecast',
        caption: 'Watch the compliance dial and critical risk meters update in real-time as each simulated fix is toggled.',
        visualType: 'whatif-score-jump',
        narration: 'The dashboard projects your future compliance score in real time, giving Change Advisory Boards complete visibility into planned maintenance impact.',
      },
    ],
  },
  {
    id: 'multi-agent-grid',
    tab: 'agents',
    title: 'Multi-Agent Defense Grid & AI Syntax Learning',
    category: 'Autonomous AI',
    duration: '1:05',
    badge: 'AI Swarm',
    badgeColor: '#8b5cf6',
    desc: 'Swarm of 6 specialized autonomous agents collaborating on ingestion, compliance, blast radius, and zero-shot NLP adaptive syntax translation.',
    keyTakeaways: [
      '6 collaborative autonomous agents: Ingestion, Parser, Compliance, Intelligence, Remediation, and Critic.',
      'Adaptive learning engine interprets unfamiliar proprietary syntax without code changes.',
      'Human-in-the-loop approval persists learned policies into the universal registry.',
    ],
    scenes: [
      {
        timestamp: 0,
        title: '6 Autonomous Specialized Security Agents',
        caption: 'Ingestion, Parser, Policy, Intelligence, Remediation, and Critic agents execute concurrently with cross-validation.',
        visualType: 'agents-swarm',
        narration: 'The Multi-Agent Grid coordinates six autonomous AI agents, each specializing in ingestion, AST parsing, compliance evaluation, or remediation.',
      },
      {
        timestamp: 45,
        title: 'Zero-Shot NLP Proprietary Syntax Learning',
        caption: 'Encounter custom or rare vendor syntax? The NLP interpreter normalizes unknown commands into standard policies on the fly.',
        visualType: 'nlp-learning',
        narration: 'Encounter unfamiliar vendor syntax? The adaptive NLP interpreter analyzes the command structure and maps it to universal baseline controls.',
      },
    ],
  },
  {
    id: 'live-ssh-devices',
    tab: 'live',
    title: 'Live SSH Device Fleet & Preset Vendor Labs',
    category: 'Device Management',
    duration: '0:55',
    badge: 'Device Fleet',
    badgeColor: '#fb923c',
    desc: 'Pre-loaded multi-vendor device library (Cisco, Juniper, Palo Alto, Fortinet, MikroTik, Linux) with real SSH credential management and terminal access.',
    keyTakeaways: [
      'Pre-loaded with 6 vendor device presets covering all major platforms.',
      'Pull live running configs and immediately audit them in the compliance engine.',
      'SSH credential store with read-only verification before config collection.',
      'Quick-switch between devices keeps context and snapshot history per device.',
    ],
    scenes: [
      {
        timestamp: 0,
        title: 'Multi-Vendor Device Presets',
        caption: 'The fleet view shows all discovered and pre-configured devices with their vendor, IP, last scan time, and compliance score badge.',
        visualType: 'device-fleet',
        narration: 'The Live SSH Devices tab maintains a full fleet inventory. Select any pre-loaded vendor preset or add your own SSH device credentials.',
      },
      {
        timestamp: 45,
        title: 'Credential Verification & Config Audit',
        caption: 'SSH credentials are validated read-only. After successful authentication, the running config is pulled and immediately scored.',
        visualType: 'ssh-auth-flow',
        narration: 'Enter SSH credentials for any device. The engine validates access in read-only mode, then pulls and audits the running configuration automatically.',
      },
    ],
  },
]
{
    title: 'Live Subnet Discovery & Fleet Audit',
    category: 'Network Operations',
    duration: '1:15',
    badge: 'Core Feature',
    badgeColor: '#00f0ff',
    desc: 'Automated non-destructive subnet discovery, deterministic vendor classification, read-only credential verification, and cross-device attack path modeling.',
    keyTakeaways: [
      'Probes safe management ports (22, 80, 443, 830, 8728) with <=350ms timeouts.',
      'Progressive 4-stage lifecycle: DISCOVERED -> IDENTIFIED -> AUTHENTICATED -> AUDITED.',
      'Hardcoded read-only allowlists block destructive CLI tokens (config t, reboot, set, rm).',
      'Cross-device topology engine maps multi-hop attack paths and systemic perimeter exposure.',
    ],
    scenes: [
      {
        timestamp: 0,
        title: 'Target Subnet Configuration',
        caption: 'The operator designates an authorized subnet CIDR like 192.168.1.0/24 and toggles between Live Scan or simulated Multi-Vendor Lab.',
        visualType: 'cidr-setup',
        narration: 'Welcome to the Live Network Audit. You can configure target IP subnets with strict rate limits, and choose between live probing or demo lab mode.',
      },
      {
        timestamp: 25,
        title: 'Non-Destructive ARP & Port Inspection',
        caption: 'The scanner captures local ARP caches and probes management ports without sending exploit payloads or disrupting device traffic.',
        visualType: 'scanner-radar',
        narration: 'The discovery engine inspects local ARP tables and performs safe, non-destructive TCP connect checks on management ports 22, 80, and 443.',
      },
      {
        timestamp: 50,
        title: 'Deterministic Vendor AST Classification',
        caption: 'Service banners, SNMP sysDescr, and MAC OUIs deterministically classify appliances as Cisco, Fortinet, Palo Alto, MikroTik, or Linux.',
        visualType: 'vendor-classify',
        narration: 'Devices advance from Discovered to Identified. Our engine matches banners and MAC OUIs to recognize Cisco, Fortinet, Palo Alto, and MikroTik.',
      },
      {
        timestamp: 75,
        title: 'Cross-Device Exposure & Multi-Hop Risk Graph',
        caption: 'AegisGuard synthesizes the 4-layer topology (Perimeter -> Core -> Access -> Workload) to uncover compound lateral movement vulnerabilities.',
        visualType: 'topology-graph',
        narration: 'Finally, the cross-device intelligence engine models traffic flows across the network topology to expose compound multi-hop attack risks.',
      },
    ],
  },
  {
    id: 'executive-dashboard',
    tab: 'dashboard',
    title: 'Executive Security Dashboard & Framework Scoring',
    category: 'Governance & Risk',
    duration: '1:00',
    badge: 'Executive',
    badgeColor: '#a855f7',
    desc: 'Real-time compliance score computation across CIS Benchmarks v8.1, NIST SP 800-53, DoD DISA STIG, and ISO 27001 with active KPI dials.',
    keyTakeaways: [
      'Universal compliance score based on passing vs failing control ratios.',
      'Multi-framework simultaneous cross-mapping (CIS, NIST, STIG, ISO 27001).',
      'Real-time fleet inventory status and one-click PDF audit report generator.',
    ],
    scenes: [
      {
        timestamp: 0,
        title: 'Real-Time Posture Scoring',
        caption: 'AegisGuard evaluates configuration parameters to calculate an aggregated percentage score with compliant vs at-risk health badges.',
        visualType: 'dashboard-gauge',
        narration: 'The Executive Dashboard aggregates compliance health into a unified security score, highlighting pass versus fail ratios across all active baselines.',
      },
      {
        timestamp: 30,
        title: 'Multi-Framework Selector',
        caption: 'Select or combine CIS Benchmarks, NIST SP 800-53, DoD STIG, and ISO 27001 to assess federal and international regulatory readiness.',
        visualType: 'framework-pills',
        narration: 'Toggle regulatory frameworks like CIS, NIST, DISA STIG, and ISO 27001. Findings instantly adjust to match the selected governance profiles.',
      },
      {
        timestamp: 65,
        title: 'Audit PDF Generation',
        caption: 'Generate cryptographic-ready PDF audit reports formatted for CISOs, compliance auditors, and regulatory submission.',
        visualType: 'pdf-export',
        narration: 'Click Export Audit PDF to generate an executive-ready compliance summary with finding breakdowns, evidence lines, and signed remediation logs.',
      },
    ],
  },
  {
    id: 'autonomous-remediation',
    tab: 'remediation',
    title: 'Autonomous Fix & 1-Click Rollback Engine',
    category: 'SecOps Remediation',
    duration: '1:20',
    badge: 'Automated Hardening',
    badgeColor: '#10b981',
    desc: 'Risk-tiered auto-fix generation with pre-change snapshot isolation and mathematically exact inverse rollback synthesizer.',
    keyTakeaways: [
      'Risk Tiers: Low (Automated Instant), Medium (Scheduled), High (Change Advisory Approval).',
      'Automatic configuration snapshot captured before executing any CLI fix.',
      '1-Click Rollback reverses fixes using computed inverse commands (no, undo, delete).',
    ],
    scenes: [
      {
        timestamp: 0,
        title: 'Risk-Tiered Remediation Categorization',
        caption: 'Fixes are categorized into Low, Medium, and High risk tiers to prevent accidental outages on mission-critical trunk links or AAA daemons.',
        visualType: 'remediation-tiers',
        narration: 'The Remediation engine categorizes fixes into Low, Medium, and High risk tiers, guaranteeing that dangerous changes are not pushed without review.',
      },
      {
        timestamp: 35,
        title: 'Pre-Change Snapshot Isolation',
        caption: 'Before applying a hardening command, a full running-config snapshot is safely captured in the local database with timestamped baseline metrics.',
        visualType: 'snapshot-save',
        narration: 'Every auto-fix action triggers a cryptographic pre-change configuration snapshot, ensuring a reliable fallback checkpoint is always available.',
      },
      {
        timestamp: 70,
        title: 'Mathematically Exact Inverse Rollback',
        caption: 'AegisGuard calculates the exact inverse CLI syntax to revert changes cleanly without restarting hardware appliances.',
        visualType: 'rollback-diff',
        narration: 'If an anomaly occurs, one click executes the exact inverse rollback command, restoring the previous working configuration state in seconds.',
      },
    ],
  },
  {
    id: 'cyber-intelligence',
    tab: 'intelligence',
    title: 'Attack Path Graph & Transitive Blast Radius',
    category: 'Threat Modeling',
    duration: '1:10',
    badge: 'AI Cyber Graph',
    badgeColor: '#ec4899',
    desc: 'Uncovers lateral movement pathways and calculates the transitive blast radius an adversary could traverse if misconfigured management planes are breached.',
    keyTakeaways: [
      'Correlates plaintext Telnet, default SNMP, and weak SSH into compound attack graphs.',
      'Calculates blast radius scores across Edge, Core, Distribution, and Server layers.',
      'Identifies root-cause misconfigurations that eliminate multiple downstream attack paths.',
    ],
    scenes: [
      {
        timestamp: 0,
        title: 'Lateral Movement Path Visualization',
        caption: 'The attack graph visualizes how an attacker moving from untrusted internet can pivot through edge firewalls to core routers.',
        visualType: 'attack-path-flow',
        narration: 'Attack Path Intelligence models lateral movement across network zones, showing how unencrypted services allow adversaries to pivot deep into internal clusters.',
      },
      {
        timestamp: 40,
        title: 'Transitive Blast Radius Calculation',
        caption: 'The engine evaluates which downstream VLANs, routers, and management consoles are exposed if an appliance is compromised.',
        visualType: 'blast-radius-map',
        narration: 'Blast radius scoring quantifies transitive damage, determining how many critical assets and downstream subnets are threatened by a single weak device.',
      },
      {
        timestamp: 70,
        title: 'Single-Remediation Root Cause Elimination',
        caption: 'Highlights the single root-cause fix that dissolves the entire multi-hop attack chain with minimal administrative overhead.',
        visualType: 'root-cause-fix',
        narration: 'Root cause analysis pinpoints the exact foundational policy fix that collapses the entire attack vector at the earliest possible hop.',
      },
    ],
  },
  {
    id: 'config-inspector',
    tab: 'scan',
    title: 'Config Inspector & Side-by-Side Split Diff',
    category: 'AST Parsing',
    duration: '0:55',
    badge: 'Deep Inspection',
    badgeColor: '#38bdf8',
    desc: 'Multi-vendor raw configuration parser, AST block extraction, Security Baseline Model normalization, and side-by-side split diff comparison.',
    keyTakeaways: [
      'Contextual grammar parsers for Cisco IOS, Juniper JunOS, Palo Alto, and Fortinet.',
      'Split diff view highlights additions and deletions with zero syntax loss.',
      'Instant drag-and-drop or copy-paste configuration upload.',
    ],
    scenes: [
      {
        timestamp: 0,
        title: 'Multi-Vendor Grammar Parsing',
        caption: 'Upload any router or firewall configuration. Contextual parsers identify block structures, interface hierarchies, and ACL stanzas.',
        visualType: 'parser-ast',
        narration: 'The Config Inspector parses hierarchical stanzas and flat CLI files, translating complex vendor dialects into canonical security representations.',
      },
      {
        timestamp: 45,
        title: 'Side-by-Side Split Diff Viewer',
        caption: 'Compare the current running-config directly against proposed hardening scripts with colored line additions and deletions.',
        visualType: 'split-diff-view',
        narration: 'Use the side-by-side split diff viewer to preview exact proposed script alterations with clear visual line additions and removals.',
      },
    ],
  },
  {
    id: 'what-if-sandbox',
    tab: 'whatif',
    title: 'What-If Sandbox Simulation',
    category: 'Predictive Modeling',
    duration: '0:50',
    badge: 'Simulation',
    badgeColor: '#00f0ff',
    desc: 'Non-production simulation sandbox enabling operators to toggle proposed hardening fixes and preview projected score improvements.',
    keyTakeaways: [
      'Interactive toggles simulate rule remediation without touching live network hardware.',
      'Real-time recalculation of passing controls, critical risks, and score projections.',
      'Enables Change Advisory Boards to forecast security uplift prior to deployment.',
    ],
    scenes: [
      {
        timestamp: 0,
        title: 'Interactive Policy Impact Toggles',
        caption: 'Toggle individual remediation controls on or off to simulate what happens to your security posture before executing scripts.',
        visualType: 'whatif-toggle',
        narration: 'In the What-If Sandbox, operators can toggle remediation controls on and off to simulate compliance score improvements before touching production systems.',
      },
      {
        timestamp: 50,
        title: 'Predictive Score Impact Forecast',
        caption: 'Watch the compliance dial and critical risk meters update in real-time as each simulated fix is toggled.',
        visualType: 'whatif-score-jump',
        narration: 'The dashboard projects your future compliance score in real time, giving Change Advisory Boards complete visibility into planned maintenance impact.',
      },
    ],
  },
  {
    id: 'multi-agent-grid',
    tab: 'agents',
    title: 'Multi-Agent Defense Grid & AI Syntax Learning',
    category: 'Autonomous AI',
    duration: '1:05',
    badge: 'AI Swarm',
    badgeColor: '#8b5cf6',
    desc: 'Swarm of 6 specialized autonomous agents collaborating on ingestion, compliance, blast radius, and zero-shot NLP adaptive syntax translation.',
    keyTakeaways: [
      '6 collaborative autonomous agents: Ingestion, Parser, Compliance, Intelligence, Remediation, and Critic.',
      'Adaptive learning engine interprets unfamiliar proprietary syntax without code changes.',
      'Human-in-the-loop approval persists learned policies into the universal registry.',
    ],
    scenes: [
      {
        timestamp: 0,
        title: '6 Autonomous Specialized Security Agents',
        caption: 'Ingestion, Parser, Policy, Intelligence, Remediation, and Critic agents execute concurrently with cross-validation.',
        visualType: 'agents-swarm',
        narration: 'The Multi-Agent Grid coordinates six autonomous AI agents, each specializing in ingestion, AST parsing, compliance evaluation, or remediation.',
      },
      {
        timestamp: 45,
        title: 'Zero-Shot NLP Proprietary Syntax Learning',
        caption: 'Encounter custom or rare vendor syntax? The NLP interpreter normalizes unknown commands into standard policies on the fly.',
        visualType: 'nlp-learning',
        narration: 'Encounter unfamiliar vendor syntax? The adaptive NLP interpreter analyzes the command structure and maps it to universal baseline controls.',
      },
    ],
  },
]

/* ==========================================================================
   VIDEO ASSISTER MODAL COMPONENT
   ========================================================================== */

export default function VideoAssisterModal({ isOpen, onClose, onNavigateToTab }) {
  const [selectedVideo, setSelectedVideo] = useState(VIDEO_CATALOG[0])
  const [isPlaying, setIsPlaying] = useState(false)
  const [currentTime, setCurrentTime] = useState(0)
  const [playbackSpeed, setPlaybackSpeed] = useState(1)
  const [isVoiceEnabled, setIsVoiceEnabled] = useState(true)
  const [searchFilter, setSearchFilter] = useState('')
  const timerRef = useRef(null)

  // Speech Synthesis Narration instance
  const stopSpeech = () => {
    if (typeof window !== 'undefined' && 'speechSynthesis' in window) {
      window.speechSynthesis.cancel()
    }
  }

  const speakText = (text) => {
    if (!isVoiceEnabled || typeof window === 'undefined' || !('speechSynthesis' in window)) return
    window.speechSynthesis.cancel()
    const utterance = new SpeechSynthesisUtterance(text)
    utterance.rate = playbackSpeed
    utterance.pitch = 1.05
    window.speechSynthesis.speak(utterance)
  }

  // Current active scene based on currentTime
  const currentSceneIndex = selectedVideo.scenes.reduce((acc, scene, idx) => {
    return currentTime >= scene.timestamp ? idx : acc
  }, 0)

  const currentScene = selectedVideo.scenes[currentSceneIndex] || selectedVideo.scenes[0]

  // Playback timer loop
  useEffect(() => {
    if (isPlaying) {
      timerRef.current = setInterval(() => {
        setCurrentTime((prev) => {
          if (prev >= 100) {
            setIsPlaying(false)
            stopSpeech()
            return 100
          }
          return prev + 1.2 * playbackSpeed
        })
      }, 300)
    } else {
      clearInterval(timerRef.current)
      stopSpeech()
    }

    return () => clearInterval(timerRef.current)
  }, [isPlaying, playbackSpeed])

  // Narrate on scene change while playing
  useEffect(() => {
    if (isPlaying && isVoiceEnabled && currentScene?.narration) {
      speakText(currentScene.narration)
    }
  }, [currentSceneIndex, isPlaying, isVoiceEnabled])

  // Reset when modal closes or video changes
  useEffect(() => {
    if (!isOpen) {
      setIsPlaying(false)
      stopSpeech()
    }
  }, [isOpen])

  const handleSelectVideo = (video) => {
    stopSpeech()
    setSelectedVideo(video)
    setCurrentTime(0)
    setIsPlaying(false)
  }

  const handleTogglePlay = () => {
    if (currentTime >= 100) {
      setCurrentTime(0)
    }
    const nextState = !isPlaying
    setIsPlaying(nextState)
    if (!nextState) {
      stopSpeech()
    } else if (currentScene?.narration) {
      speakText(currentScene.narration)
    }
  }

  const handleRestart = () => {
    stopSpeech()
    setCurrentTime(0)
    setIsPlaying(true)
    if (selectedVideo.scenes[0]?.narration) {
      speakText(selectedVideo.scenes[0].narration)
    }
  }

  const handleScrub = (e) => {
    const val = Number(e.target.value)
    setCurrentTime(val)
  }

  const filteredVideos = VIDEO_CATALOG.filter(v =>
    !searchFilter ||
    v.title.toLowerCase().includes(searchFilter.toLowerCase()) ||
    v.category.toLowerCase().includes(searchFilter.toLowerCase()) ||
    v.desc.toLowerCase().includes(searchFilter.toLowerCase())
  )

  if (!isOpen) return null

  return (
    <div className="aegis-modal-backdrop video-assister-backdrop" onClick={onClose}>
      <div className="aegis-modal video-assister-modal" onClick={e => e.stopPropagation()}>
        {/* MODAL TOPBAR */}
        <div className="modal-header va-modal-header">
          <div className="va-header-title-wrap">
            <div className="va-live-rec-badge">
              <span className="rec-pulse-dot" />
              <span>AI VIDEO ASSISTER &amp; FEATURE TOUR</span>
            </div>
            <h3>Interactive Feature Walkthroughs &amp; Architecture Simulator</h3>
          </div>
          <button className="btn-close-modal" onClick={onClose}>
            <IconCross size={18} />
          </button>
        </div>

        {/* MODAL MAIN CONTENT */}
        <div className="va-modal-body">
          {/* LEFT: VIDEO PLAYER & SIMULATION CANVAS */}
          <div className="va-player-container">
            {/* SIMULATION SCREEN */}
            <div className="va-screen-wrapper">
              <div className="va-screen-scanline" />
              <div className="va-screen-vignette" />

              {/* OVERLAY HEADER */}
              <div className="va-screen-top-bar">
                <div className="va-stb-left">
                  <span className="va-module-chip">{selectedVideo.category}</span>
                  <strong className="va-module-title">{selectedVideo.title}</strong>
                </div>
                <div className="va-stb-right">
                  <span className="va-time-counter">
                    {Math.floor(currentTime)}% · Step {currentSceneIndex + 1}/{selectedVideo.scenes.length}
                  </span>
                </div>
              </div>

              {/* DYNAMIC SCENE SIMULATOR */}
              <div className="va-canvas-simulation">
                {currentScene.visualType === 'cidr-setup' && (
                  <div className="sim-scene sim-cidr-setup">
                    <div className="sim-mock-window">
                      <div className="sim-win-bar">
                        <span className="dot red" /><span className="dot yellow" /><span className="dot green" />
                        <span className="win-title">AegisGuard · Subnet Discovery Controller</span>
                      </div>
                      <div className="sim-win-body">
                        <div className="sim-input-row">
                          <span className="sim-lbl">Subnet CIDR:</span>
                          <span className="sim-fake-input active-glow">192.168.1.0/24</span>
                          <span className="sim-btn pulse-glow">Discover Subnet</span>
                        </div>
                        <div className="sim-status-steps">
                          <span className="step-pill active">1. DISCOVERED</span>
                          <span className="step-pill">2. IDENTIFIED</span>
                          <span className="step-pill">3. AUTHENTICATED</span>
                          <span className="step-pill">4. AUDITED</span>
                        </div>
                      </div>
                    </div>
                  </div>
                )}

                {currentScene.visualType === 'scanner-radar' && (
                  <div className="sim-scene sim-radar-scan">
                    <div className="radar-circle">
                      <div className="radar-sweep" />
                      <div className="radar-blip blip-1" style={{ top: '35%', left: '42%' }}>
                        <span className="blip-label">192.168.1.1 (SSH 22)</span>
                      </div>
                      <div className="radar-blip blip-2" style={{ top: '65%', left: '70%' }}>
                        <span className="blip-label">192.168.1.20 (HTTPS 443)</span>
                      </div>
                      <div className="radar-blip blip-3" style={{ top: '25%', left: '78%' }}>
                        <span className="blip-label">192.168.1.50 (API 8728)</span>
                      </div>
                    </div>
                    <div className="radar-telemetry">
                      <span>Probing safe management ports: 22, 80, 443, 830, 8728...</span>
                      <span className="text-cyan">Safe Timeout: 350ms per probe · Zero write execution</span>
                    </div>
                  </div>
                )}

                {currentScene.visualType === 'vendor-classify' && (
                  <div className="sim-scene sim-vendor-classify">
                    <div className="sim-device-cards">
                      <div className="sim-dev-card cisco animate-in">
                        <span className="sd-icon">RTR-01</span>
                        <strong>CORE-RTR-01</strong>
                        <code>192.168.1.1</code>
                        <span className="sd-vendor cisco">Cisco IOS (Switch/Router)</span>
                        <span className="sd-conf">95% Confidence</span>
                      </div>
                      <div className="sim-dev-card fortinet animate-in">
                        <span className="sd-icon">FW-01</span>
                        <strong>EDGE-FW-01</strong>
                        <code>192.168.1.20</code>
                        <span className="sd-vendor fortinet">Fortinet FortiOS (Firewall)</span>
                        <span className="sd-conf">92% Confidence</span>
                      </div>
                      <div className="sim-dev-card mikrotik animate-in">
                        <span className="sd-icon">GW-01</span>
                        <strong>BRANCH-GW-01</strong>
                        <code>192.168.1.50</code>
                        <span className="sd-vendor mikrotik">MikroTik RouterOS</span>
                        <span className="sd-conf">94% Confidence</span>
                      </div>
                    </div>
                  </div>
                )}

                {currentScene.visualType === 'topology-graph' && (
                  <div className="sim-scene sim-topology-graph">
                    <div className="sim-topo-layers">
                      <div className="sim-layer">
                        <span className="sl-title">Perimeter</span>
                        <div className="sl-node fw">EDGE-FW-01</div>
                      </div>
                      <div className="sl-arrow">&rarr;</div>
                      <div className="sim-layer">
                        <span className="sl-title">Core</span>
                        <div className="sl-node rtr">CORE-RTR-01</div>
                      </div>
                      <div className="sl-arrow">&rarr;</div>
                      <div className="sim-layer">
                        <span className="sl-title">Access</span>
                        <div className="sl-node sw">DIST-SW-01</div>
                      </div>
                      <div className="sl-arrow">&rarr;</div>
                      <div className="sim-layer">
                        <span className="sl-title">Workloads</span>
                        <div className="sl-node srv">MGMT-SRV-01</div>
                      </div>
                    </div>
                    <div className="sim-exposure-callout">
                      <span className="badge-warn">Compound Exposure Detected</span>
                      <span>Edge FW allows transit to internal switch with unencrypted HTTP management (CIS 4.1 violation).</span>
                    </div>
                  </div>
                )}

                {currentScene.visualType === 'dashboard-gauge' && (
                  <div className="sim-scene sim-gauge-view">
                    <div className="sim-kpi-ring">
                      <div className="skr-inner">
                        <span className="skr-num">78%</span>
                        <span className="skr-sub">CIS Score</span>
                      </div>
                    </div>
                    <div className="sim-kpi-stats">
                      <div className="sks-item"><span className="text-cyan">91</span> Evaluated</div>
                      <div className="sks-item"><span className="text-green">71</span> Passed</div>
                      <div className="sks-item"><span className="text-pink">20</span> Failed</div>
                    </div>
                  </div>
                )}

                {currentScene.visualType === 'framework-pills' && (
                  <div className="sim-scene sim-framework-view">
                    <div className="sim-fw-pills">
                      <span className="fw-chip active">CIS Benchmarks v8.1</span>
                      <span className="fw-chip active">NIST SP 800-53</span>
                      <span className="fw-chip active">DoD DISA STIG</span>
                      <span className="fw-chip active">ISO/IEC 27001</span>
                    </div>
                    <div className="sim-fw-detail">
                      Simultaneously evaluated across 4 regulatory frameworks with exact CLI line citations.
                    </div>
                  </div>
                )}

                {currentScene.visualType === 'pdf-export' && (
                  <div className="sim-scene sim-pdf-view">
                    <div className="sim-pdf-page">
                      <div className="spp-header">
                        <strong>AEGISGUARD SECURITY AUDIT REPORT</strong>
                        <span className="badge-pass">PASS / CERTIFIED</span>
                      </div>
                      <div className="spp-lines">
                        <div className="line l1" />
                        <div className="line l2" />
                        <div className="line l3" />
                      </div>
                    </div>
                  </div>
                )}

                {currentScene.visualType === 'remediation-tiers' && (
                  <div className="sim-scene sim-rem-tiers">
                    <div className="tier-card low">
                      <span className="t-badge">LOW RISK</span>
                      <strong>Autonomous Safe Fix</strong>
                      <code>transport input ssh</code>
                    </div>
                    <div className="tier-card medium">
                      <span className="t-badge">MEDIUM RISK</span>
                      <strong>Scheduled Maintenance</strong>
                      <code>service password-encryption</code>
                    </div>
                    <div className="tier-card high">
                      <span className="t-badge">HIGH RISK</span>
                      <strong>Requires CAB Approval</strong>
                      <code>no ip http server</code>
                    </div>
                  </div>
                )}

                {currentScene.visualType === 'snapshot-save' && (
                  <div className="sim-scene sim-snapshot-view">
                    <div className="snapshot-box">
                      <IconCheckCircle size={24} className="text-green" />
                      <strong>Pre-Change Running Config Isolated</strong>
                      <span className="snap-time">Snapshot #snap-0492 · Stored with SHA-256 Checksum</span>
                    </div>
                  </div>
                )}

                {currentScene.visualType === 'rollback-diff' && (
                  <div className="sim-scene sim-rollback-view">
                    <div className="rollback-box">
                      <div className="rb-title">1-Click Inverse Rollback Synthesizer</div>
                      <div className="rb-code diff">
                        <span className="del">- ip http server</span>
                        <span className="add">+ no ip http server</span>
                        <span className="rb-cmd">Computed Rollback: &quot;ip http server&quot;</span>
                      </div>
                    </div>
                  </div>
                )}

                {currentScene.visualType === 'attack-path-flow' && (
                  <div className="sim-scene sim-attack-flow">
                    <div className="attack-path-steps">
                      <div className="ap-step">1. Internet Exploitation</div>
                      <div className="ap-arrow">&rarr;</div>
                      <div className="ap-step">2. Edge Firewall Weak ACL</div>
                      <div className="ap-arrow">&rarr;</div>
                      <div className="ap-step">3. Switch Telnet Sniffing</div>
                      <div className="ap-arrow">&rarr;</div>
                      <div className="ap-step alert">4. Domain Controller Lateral Hop</div>
                    </div>
                  </div>
                )}

                {currentScene.visualType === 'blast-radius-map' && (
                  <div className="sim-scene sim-blast-view">
                    <div className="blast-core">
                      <span className="blast-ring r1" />
                      <span className="blast-ring r2" />
                      <span className="blast-center">Compromised Core</span>
                    </div>
                    <span className="blast-stat">Impact Radius: 14 Downstream Subnets &middot; 85 Hosts</span>
                  </div>
                )}

                {currentScene.visualType === 'root-cause-fix' && (
                  <div className="sim-scene sim-rc-view">
                    <div className="rc-solution-card">
                      <span className="rc-tag">Root Cause Fix</span>
                      <h4>Disable Unencrypted Management at Ingress</h4>
                      <p>Resolves 3 attack vectors and reduces systemic fleet risk by 48% with a single CLI commit.</p>
                    </div>
                  </div>
                )}

                {/* FALLBACK SIMULATION */}
                {!['cidr-setup', 'scanner-radar', 'vendor-classify', 'topology-graph', 'dashboard-gauge', 'framework-pills', 'pdf-export', 'remediation-tiers', 'snapshot-save', 'rollback-diff', 'attack-path-flow', 'blast-radius-map', 'root-cause-fix'].includes(currentScene.visualType) && (
                  <div className="sim-scene sim-generic-view">
                    <div className="generic-feature-box">
                      <IconVideo size={36} className="text-cyan pulse-slow" />
                      <h4>{currentScene.title}</h4>
                      <p>{currentScene.caption}</p>
                    </div>
                  </div>
                )}
              </div>

              {/* LIVE CLOSED CAPTION / SUBTITLE BANNER */}
              <div className="va-subtitle-ticker">
                <div className="st-voice-indicator">
                  <span className={`audio-bar b1 ${isPlaying && isVoiceEnabled ? 'animating' : ''}`} />
                  <span className={`audio-bar b2 ${isPlaying && isVoiceEnabled ? 'animating' : ''}`} />
                  <span className={`audio-bar b3 ${isPlaying && isVoiceEnabled ? 'animating' : ''}`} />
                </div>
                <div className="st-text-wrap">
                  <span className="st-step-badge">{currentScene.title}:</span>
                  <span className="st-caption-text">{currentScene.caption}</span>
                </div>
              </div>
            </div>

            {/* VIDEO PLAYER CONTROLS BAR */}
            <div className="va-controls-bar">
              {/* PLAY / PAUSE / RESTART */}
              <div className="va-ctrl-group">
                <button
                  className={`btn-play-pause ${isPlaying ? 'playing' : ''}`}
                  onClick={handleTogglePlay}
                  title={isPlaying ? 'Pause' : 'Play Walkthrough'}
                >
                  {isPlaying ? <IconPause size={16} /> : <IconPlay size={16} />}
                </button>

                <button
                  className="btn-ctrl-icon"
                  onClick={handleRestart}
                  title="Restart Walkthrough"
                >
                  <IconRotateCcw size={15} />
                </button>

                <button
                  className={`btn-ctrl-icon ${isVoiceEnabled ? 'active-voice' : ''}`}
                  onClick={() => setIsVoiceEnabled(prev => !prev)}
                  title={isVoiceEnabled ? 'Voice Narration Enabled (Click to Mute)' : 'Voice Muted (Click to Unmute)'}
                >
                  {isVoiceEnabled ? <IconVolume2 size={16} /> : <IconVolumeX size={16} />}
                </button>

                <div className="va-speed-selector">
                  <button
                    className={`btn-speed ${playbackSpeed === 1 ? 'active' : ''}`}
                    onClick={() => setPlaybackSpeed(1)}
                  >
                    1x
                  </button>
                  <button
                    className={`btn-speed ${playbackSpeed === 1.5 ? 'active' : ''}`}
                    onClick={() => setPlaybackSpeed(1.5)}
                  >
                    1.5x
                  </button>
                  <button
                    className={`btn-speed ${playbackSpeed === 2 ? 'active' : ''}`}
                    onClick={() => setPlaybackSpeed(2)}
                  >
                    2x
                  </button>
                </div>
              </div>

              {/* TIMELINE PROGRESS SCRUBBER */}
              <div className="va-scrubber-container">
                <input
                  type="range"
                  min="0"
                  max="100"
                  value={currentTime}
                  onChange={handleScrub}
                  className="va-scrubber-slider"
                />
              </div>

              {/* JUMP TO FEATURE IN APP ACTION */}
              <div className="va-jump-action">
                <button
                  className="btn-launch-feature"
                  onClick={() => {
                    onNavigateToTab(selectedVideo.tab)
                    onClose()
                  }}
                  title={`Navigate directly to the ${selectedVideo.title} feature in AegisGuard`}
                >
                  <span>Launch in App</span>
                  <IconExternalLink size={13} />
                </button>
              </div>
            </div>

            {/* KEY TAKEAWAYS & OPERATOR GUIDANCE CARD */}
            <div className="va-takeaways-card">
              <div className="va-tc-header">
                <strong>Architectural Best Practices &amp; Security Guarantees:</strong>
                <span className="va-duration-badge">{selectedVideo.duration} Explainer</span>
              </div>
              <ul className="va-takeaway-list">
                {selectedVideo.keyTakeaways.map((point, idx) => (
                  <li key={idx}>
                    <IconCheckCircle size={14} className="text-cyan flex-shrink-0" />
                    <span>{point}</span>
                  </li>
                ))}
              </ul>
            </div>
          </div>

          {/* RIGHT: FEATURE VIDEO LIBRARY CATALOG */}
          <div className="va-catalog-sidebar">
            <div className="va-catalog-header">
              <h4>Feature Video Library</h4>
              <span className="va-count-badge">{VIDEO_CATALOG.length} Explanations</span>
            </div>

            {/* SEARCH FILTER */}
            <div className="va-search-box">
              <IconSearch size={13} className="va-search-icon" />
              <input
                type="text"
                placeholder="Search tutorials &amp; features..."
                value={searchFilter}
                onChange={e => setSearchFilter(e.target.value)}
                className="va-search-input"
              />
            </div>

            {/* VIDEO LIST */}
            <div className="va-video-items-list">
              {filteredVideos.map((video) => {
                const isSelected = selectedVideo.id === video.id
                return (
                  <div
                    key={video.id}
                    className={`va-video-item ${isSelected ? 'selected' : ''}`}
                    onClick={() => handleSelectVideo(video)}
                  >
                    <div className="va-vi-thumb">
                      <IconVideo size={18} />
                      <span className="va-vi-play-hover"><IconPlay size={12} /></span>
                    </div>

                    <div className="va-vi-content">
                      <div className="va-vi-top">
                        <span className="va-vi-cat">{video.category}</span>
                        <span className="va-vi-duration">{video.duration}</span>
                      </div>
                      <strong className="va-vi-title">{video.title}</strong>
                      <p className="va-vi-desc">{video.desc}</p>
                    </div>
                  </div>
                )
              })}
            </div>
          </div>
        </div>
      </div>
    </div>
  )
}
