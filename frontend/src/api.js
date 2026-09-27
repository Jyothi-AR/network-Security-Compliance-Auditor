const API_BASE_URL = 'http://127.0.0.1:8000'

export async function analyzeConfiguration(file) {
  const config = await file.text()

  const response = await fetch(`${API_BASE_URL}/api/analysis`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({
      config,
      source_file: file.name,
    }),
  })

  if (!response.ok) {
    let message = `Analysis failed (${response.status})`

    try {
      const errorBody = await response.json()
      if (errorBody.detail) {
        message = errorBody.detail
      }
    } catch {
      // Keep the generic error message.
    }

    throw new Error(message)
  }

  return response.json()
}

export async function generateReport(analysis, sourceFile) {
  const response = await fetch(`${API_BASE_URL}/api/reports`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({
      source_file: sourceFile,
      analysis,
    }),
  })

  if (!response.ok) {
    let message = `Report generation failed (${response.status})`

    try {
      const errorBody = await response.json()
      if (errorBody.detail) {
        message = errorBody.detail
      }
    } catch {
      // Keep the generic error message.
    }

    throw new Error(message)
  }

  const disposition = response.headers.get('content-disposition')
  const filename = disposition?.match(/filename="?([^";]+)"?/)?.[1]

  return {
    blob: await response.blob(),
    filename: filename || 'compliance-report.pdf',
  }
}

export async function fetchLiveDeviceConfig({ host, username, password, device_type, transport = 'ssh', port = 22 }) {
  const response = await fetch(`${API_BASE_URL}/api/live-fetch`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ host, username, password, device_type, transport, port }),
  })

  if (!response.ok) {
    let message = `Live fetch failed (${response.status})`
    try {
      const err = await response.json()
      if (err.detail) message = err.detail
    } catch {}
    throw new Error(message)
  }

  return response.json()
}

export async function fetchLocalDevice() {
  const response = await fetch(`${API_BASE_URL}/api/live-device/local`)
  if (!response.ok) {
    throw new Error(`Failed to inspect local device (${response.status})`)
  }
  return response.json()
}

export async function auditLocalDevice() {
  const response = await fetch(`${API_BASE_URL}/api/live-device/local-audit`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
  })
  if (!response.ok) {
    let message = `Local host audit failed (${response.status})`
    try {
      const err = await response.json()
      if (err.detail) message = err.detail
    } catch {}
    throw new Error(message)
  }
  return response.json()
}

export async function fetchAttackPaths(deviceFindings) {
  const response = await fetch(`${API_BASE_URL}/api/intelligence/attack-paths`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ device_findings: deviceFindings }),
  })
  if (!response.ok) return null
  return response.json()
}

export async function fetchBlastRadius(sourceDevices, deviceSegments = {}, deviceAclStatus = {}) {
  const response = await fetch(`${API_BASE_URL}/api/intelligence/blast-radius`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      source_devices: sourceDevices,
      device_segments: deviceSegments,
      device_acl_status: deviceAclStatus,
    }),
  })
  if (!response.ok) return null
  return response.json()
}

export async function fetchRootCause(failingControlIds) {
  const response = await fetch(`${API_BASE_URL}/api/intelligence/root-cause`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ failing_control_ids: failingControlIds }),
  })
  if (!response.ok) return null
  return response.json()
}

export async function fetchSafeRemediation(remediations, currentBaseline = {}) {
  const response = await fetch(`${API_BASE_URL}/api/intelligence/safe-remediation`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ remediations, current_baseline: currentBaseline }),
  })
  if (!response.ok) return null
  return response.json()
}

export async function fetchLearnedVendors() {
  const response = await fetch(`${API_BASE_URL}/api/learning/vendors`)
  if (!response.ok) return []
  const data = await response.json()
  return data.vendors || []
}

export async function registerVendor(vendorData) {
  const response = await fetch(`${API_BASE_URL}/api/learning/vendors`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(vendorData),
  })
  if (!response.ok) {
    let message = 'Registration failed'
    try {
      const err = await response.json()
      if (err.detail) message = err.detail
    } catch {}
    throw new Error(message)
  }
  return response.json()
}

// ---------------------------------------------------------------------------
// Live Network Discovery & Cross-Device Audit APIs
// ---------------------------------------------------------------------------

export async function discoverNetwork({ cidr = '192.168.1.0/24', is_demo = false, max_hosts = 64 }) {
  const response = await fetch(`${API_BASE_URL}/api/network/discover`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ cidr, is_demo, max_hosts }),
  })
  if (!response.ok) {
    let msg = `Discovery failed (${response.status})`
    try {
      const err = await response.json()
      if (err.detail) msg = err.detail
    } catch {}
    throw new Error(msg)
  }
  return response.json()
}

export async function fetchDiscoveredDevices(demoFilter = null) {
  let url = `${API_BASE_URL}/api/network/devices`
  if (demoFilter !== null) {
    url += `?demo=${demoFilter}`
  }
  const response = await fetch(url)
  if (!response.ok) {
    throw new Error(`Failed to fetch devices (${response.status})`)
  }
  return response.json()
}

export async function authenticateDevice({ device_id, username, password = '', port = 22, is_demo = false }) {
  const response = await fetch(`${API_BASE_URL}/api/network/authenticate`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ device_id, username, password, port, is_demo }),
  })
  if (!response.ok) {
    let msg = `Authentication request failed (${response.status})`
    try {
      const err = await response.json()
      if (err.detail) msg = err.detail
    } catch {}
    throw new Error(msg)
  }
  return response.json()
}

export async function collectDeviceConfig({ device_id, username = 'admin', password = '', port = 22, is_demo = false }) {
  const response = await fetch(`${API_BASE_URL}/api/network/collect`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ device_id, username, password, port, is_demo }),
  })
  if (!response.ok) {
    let msg = `Configuration collection failed (${response.status})`
    try {
      const err = await response.json()
      if (err.detail) msg = err.detail
    } catch {}
    throw new Error(msg)
  }
  return response.json()
}

export async function auditDevice({ device_id, username = 'admin', password = '', port = 22, is_demo = false }) {
  const response = await fetch(`${API_BASE_URL}/api/network/audit-device`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ device_id, username, password, port, is_demo }),
  })
  if (!response.ok) {
    let msg = `Device audit failed (${response.status})`
    try {
      const err = await response.json()
      if (err.detail) msg = err.detail
    } catch {}
    throw new Error(msg)
  }
  return response.json()
}

export async function auditAllDevices() {
  const response = await fetch(`${API_BASE_URL}/api/network/audit-all`, {
    method: 'POST',
  })
  if (!response.ok) {
    let msg = `Batch audit failed (${response.status})`
    try {
      const err = await response.json()
      if (err.detail) msg = err.detail
    } catch {}
    throw new Error(msg)
  }
  return response.json()
}

export async function fetchNetworkTopology() {
  const response = await fetch(`${API_BASE_URL}/api/network/topology`)
  if (!response.ok) {
    throw new Error(`Topology retrieval failed (${response.status})`)
  }
  return response.json()
}

export async function clearDemoDevices() {
  const response = await fetch(`${API_BASE_URL}/api/network/devices/clear-demo`, {
    method: 'POST',
  })
  if (!response.ok) return { cleared_count: 0 }
  return response.json()
}

// ---------------------------------------------------------------------------
// AI-Assisted Auto-Fix & Remediation APIs
// ---------------------------------------------------------------------------

export async function fetchRemediationProposals({ vendor, raw_config, findings, baseline = null, target_type = 'upload', target_id = 'config.conf' }) {
  const response = await fetch(`${API_BASE_URL}/api/remediation/proposals`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ vendor, raw_config, findings, baseline, target_type, target_id }),
  })
  if (!response.ok) {
    let msg = `Proposal generation failed (${response.status})`
    try {
      const err = await response.json()
      if (err.detail) msg = err.detail
    } catch {}
    throw new Error(msg)
  }
  return response.json()
}

export async function downloadRemediatedConfig({ vendor, raw_config, selected_control_ids = [], findings = [], source_name = 'config.conf' }) {
  const response = await fetch(`${API_BASE_URL}/api/remediation/download-config`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ vendor, raw_config, selected_control_ids, findings, source_name }),
  })
  if (!response.ok) {
    let msg = `Download generation failed (${response.status})`
    try {
      const err = await response.json()
      if (err.detail) msg = err.detail
    } catch {}
    throw new Error(msg)
  }
  return response.json()
}

export async function applyLiveRemediation({ device_id, control_id, approved = true, approved_by = 'Security Administrator', is_demo = false, raw_config = null, vendor = null, hostname = null }) {
  const response = await fetch(`${API_BASE_URL}/api/remediation/live/apply`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ device_id, control_id, approved, approved_by, is_demo, raw_config, vendor, hostname }),
  })
  if (!response.ok) {
    let msg = `Live remediation application failed (${response.status})`
    try {
      const err = await response.json()
      if (err.detail) msg = err.detail
    } catch {}
    throw new Error(msg)
  }
  return response.json()
}

export async function rollbackLiveDevice({ audit_record_id = null, device_id, approved_by = 'Security Administrator' }) {
  const response = await fetch(`${API_BASE_URL}/api/remediation/live/rollback`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ audit_record_id, device_id, approved_by }),
  })
  if (!response.ok) {
    let msg = `Live rollback failed (${response.status})`
    try {
      const err = await response.json()
      if (err.detail) msg = err.detail
    } catch {}
    throw new Error(msg)
  }
  return response.json()
}

export async function fetchRemediationAuditTrail(limit = 50) {
  const response = await fetch(`${API_BASE_URL}/api/remediation/audit-trail?limit=${limit}`)
  if (!response.ok) return { total: 0, records: [] }
  return response.json()
}



