from pathlib import Path

from sih26155.core.pipeline.analyze import analyze_config


def test_full_paloalto_analysis_pipeline():
    config_path = Path("data/configs/paloalto/panos_fw.conf")
    config = config_path.read_text(encoding="utf-8")

    result = analyze_config(
        config=config,
        source_file=str(config_path),
    )

    assert result.vendor.vendor.value == "paloalto"
    assert result.baseline.device.hostname == "PA-NGFW-PERIMETER"
    assert result.baseline.management.ssh.enabled is True
    assert result.baseline.management.telnet.enabled is False
    assert result.baseline.management.http.enabled is False
    assert result.baseline.logging.enabled is True

    findings = {finding.control_id: finding for finding in result.findings}

    assert findings["MGMT-SSH-001"].status == "PASS"
    assert findings["MGMT-TELNET-001"].status == "PASS"
    assert findings["MGMT-HTTP-001"].status == "PASS"
    assert findings["LOG-001"].status == "PASS"
