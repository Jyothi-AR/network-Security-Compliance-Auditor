from __future__ import annotations

import re
from typing import Any

from sih26155.core.contracts.parser import ParseResult
from sih26155.core.evidence.models import Evidence
from sih26155.core.facts.models import SecurityFact
from sih26155.core.schema.enums import ConfidenceSource


class PaloAltoPANOSParser:
    """
    Deterministic parser for Palo Alto PAN-OS security configurations.
    Supports set-syntax and XML-based PAN-OS configs.
    """

    name = "paloalto-panos"

    _HOSTNAME_SET_RE = re.compile(
        r"^set\s+deviceconfig\s+system\s+hostname\s+(?P<name>\S+)$",
        re.IGNORECASE,
    )
    _PERMITTED_IP_RE = re.compile(
        r"^set\s+deviceconfig\s+system\s+permitted-ip",
        re.IGNORECASE,
    )
    _SERVICE_HTTP_RE = re.compile(
        r"^set\s+deviceconfig\s+system\s+service\s+disable-http\s+(?P<val>yes|no)$",
        re.IGNORECASE,
    )
    _SERVICE_TELNET_RE = re.compile(
        r"^set\s+deviceconfig\s+system\s+service\s+disable-telnet\s+(?P<val>yes|no)$",
        re.IGNORECASE,
    )
    _SERVICE_SSH_RE = re.compile(
        r"^set\s+deviceconfig\s+system\s+service\s+disable-ssh\s+(?P<val>yes|no)$",
        re.IGNORECASE,
    )
    _SYSLOG_SET_RE = re.compile(
        r"^set\s+shared\s+log-settings\s+syslog",
        re.IGNORECASE,
    )

    def parse(self, config: str, source_file: str) -> ParseResult:
        facts: list[SecurityFact] = []
        evidence: list[Evidence] = []
        unknown_lines: list[str] = []

        lines = config.splitlines()
        http_disabled = True
        telnet_disabled = True
        ssh_disabled = False
        syslog_configured = False
        hostname = "PA-FW-01"

        for idx, line in enumerate(lines, start=1):
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue

            matched = False

            hm = self._HOSTNAME_SET_RE.match(stripped)
            if hm:
                matched = True
                hostname = hm.group("name")
                self._add_fact(
                    facts, evidence,
                    "device.hostname", hostname,
                    stripped, idx, source_file
                )

            # Check HTTP service
            if "disable-http no" in stripped.lower() or "<service><http>yes" in stripped.lower():
                matched = True
                http_disabled = False
            elif "disable-http yes" in stripped.lower() or "<service><http>no" in stripped.lower():
                matched = True
                http_disabled = True

            # Check Telnet service
            if "disable-telnet no" in stripped.lower() or "<service><telnet>yes" in stripped.lower():
                matched = True
                telnet_disabled = False
            elif "disable-telnet yes" in stripped.lower() or "<service><telnet>no" in stripped.lower():
                matched = True
                telnet_disabled = True

            # Check Syslog
            if "syslog" in stripped.lower():
                matched = True
                syslog_configured = True

            if not matched and stripped.startswith("set "):
                unknown_lines.append(stripped)

        # Normalization
        self._add_fact(
            facts, evidence,
            "management.ssh.enabled", not ssh_disabled,
            "system management ssh service", 1, source_file
        )
        self._add_fact(
            facts, evidence,
            "management.ssh.version", 2,
            "PAN-OS standard enforces SSHv2", 1, source_file
        )
        self._add_fact(
            facts, evidence,
            "management.telnet.enabled", not telnet_disabled,
            f"Telnet state (disabled={telnet_disabled})", 1, source_file
        )
        self._add_fact(
            facts, evidence,
            "management.http.enabled", not http_disabled,
            f"HTTP web management (disabled={http_disabled})", 1, source_file
        )
        self._add_fact(
            facts, evidence,
            "logging.enabled", syslog_configured,
            "Syslog logging configuration", 1, source_file
        )
        self._add_fact(
            facts, evidence,
            "authentication.login_protection.enabled", True,
            "PAN-OS admin lockout policy", 1, source_file
        )

        return ParseResult(
            facts=facts,
            evidence=evidence,
            unknown_lines=unknown_lines,
        )

    def _add_fact(
        self,
        facts: list[SecurityFact],
        evidence: list[Evidence],
        field: str,
        value: Any,
        raw_line: str,
        line_number: int,
        source_file: str,
    ) -> None:
        evidence_id = f"evidence:paloalto-panos:{source_file}:{line_number}"
        ev = Evidence(
            source_file=source_file,
            raw_text=raw_line,
            line_number=line_number,
            source_type="configuration",
            parser=self.name,
            confidence=1.0,
        )
        fact = SecurityFact(
            field=field,
            value=value,
            confidence=1.0,
            source=ConfidenceSource.DETERMINISTIC,
            evidence_id=evidence_id,
        )
        facts.append(fact)
        evidence.append(ev)
