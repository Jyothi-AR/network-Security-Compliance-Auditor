from sih26155.parsers.juniper.junos import JuniperJunosParser


JUNOS_CONFIG = """\
set system host-name JUNIPER-EDGE-01
set system services ssh protocol-version v2
set system services telnet
set system services web-management http
set system syslog host 10.10.40.50 any notice
set system login retry-options tries-before-lockout 3
"""


def test_juniper_junos_parser_extracts_facts():
    parser = JuniperJunosParser()
    result = parser.parse(config=JUNOS_CONFIG, source_file="junos.conf")

    fields = {fact.field: fact.value for fact in result.facts}

    assert fields["device.hostname"] == "JUNIPER-EDGE-01"
    assert fields["management.ssh.enabled"] is True
    assert fields["management.ssh.version"] == 2
    assert fields["management.telnet.enabled"] is True
    assert fields["management.http.enabled"] is True
    assert fields["logging.enabled"] is True
    assert fields["authentication.login_protection.enabled"] is True


def test_juniper_junos_parser_defaults():
    parser = JuniperJunosParser()
    minimal_config = "set system host-name MINIMAL-JUNIPER"
    result = parser.parse(config=minimal_config, source_file="minimal.conf")

    fields = {fact.field: fact.value for fact in result.facts}
    assert fields["device.hostname"] == "MINIMAL-JUNIPER"
    assert fields["management.telnet.enabled"] is False
    assert fields["management.http.enabled"] is False
    assert fields["authentication.login_protection.enabled"] is False
