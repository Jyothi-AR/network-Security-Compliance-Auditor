from sih26155.parsers.paloalto.panos import PaloAltoPANOSParser


PANOS_CONFIG = """\
set deviceconfig system hostname PA-PERIMETER-01
set deviceconfig system service disable-http yes
set deviceconfig system service disable-telnet yes
set deviceconfig system service disable-ssh no
set shared log-settings syslog SYSLOG-SERVER server 10.10.40.50
"""


def test_paloalto_panos_parser_extracts_facts():
    parser = PaloAltoPANOSParser()
    result = parser.parse(config=PANOS_CONFIG, source_file="panos.conf")

    fields = {fact.field: fact.value for fact in result.facts}

    assert fields["device.hostname"] == "PA-PERIMETER-01"
    assert fields["management.ssh.enabled"] is True
    assert fields["management.ssh.version"] == 2
    assert fields["management.telnet.enabled"] is False
    assert fields["management.http.enabled"] is False
    assert fields["logging.enabled"] is True
    assert fields["authentication.login_protection.enabled"] is True


def test_paloalto_panos_parser_insecure_services():
    parser = PaloAltoPANOSParser()
    insecure_config = """\
set deviceconfig system hostname PA-INSECURE
set deviceconfig system service disable-http no
set deviceconfig system service disable-telnet no
"""
    result = parser.parse(config=insecure_config, source_file="insecure.conf")

    fields = {fact.field: fact.value for fact in result.facts}
    assert fields["device.hostname"] == "PA-INSECURE"
    assert fields["management.telnet.enabled"] is True
    assert fields["management.http.enabled"] is True
