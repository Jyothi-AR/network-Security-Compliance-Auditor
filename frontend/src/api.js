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

