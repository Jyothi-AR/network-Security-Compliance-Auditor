from pathlib import Path

from sih26155.core.pipeline.analyze import analyze_config


def test_full_juniper_analysis_pipeline():
    config_path = Path("data/configs/juniper/junos_edge.conf")
    config = config_path.read_text(encoding="utf-8")

    result = analyze_config(
        config=config,
        source_file=str(config_path),
    )

    assert result.vendor.vendor.value == "juniper"
    assert result.baseline.device.hostname == "JUNIPER-EDGE-MX"
    assert result.baseline.management.ssh.enabled is True
    assert result.baseline.management.telnet.enabled is True
    assert result.baseline.management.http.enabled is True

    findings = {finding.control_id: finding for finding in result.findings}

    assert findings["MGMT-SSH-001"].status == "PASS"
    assert findings["MGMT-TELNET-001"].status == "FAIL"
    assert findings["MGMT-HTTP-001"].status == "FAIL"
    assert findings["LOG-001"].status == "PASS"

    remediation_controls = [r.control_id for r in result.remediations]
    assert "MGMT-TELNET-001" in remediation_controls
    assert "MGMT-HTTP-001" in remediation_controls
