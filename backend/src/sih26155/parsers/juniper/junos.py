from __future__ import annotations

import re
from typing import Any

from sih26155.core.contracts.parser import ParseResult
from sih26155.core.evidence.models import Evidence
from sih26155.core.facts.models import SecurityFact
from sih26155.core.schema.enums import ConfidenceSource


class JuniperJunosParser:
    """
    Deterministic parser for Juniper JunOS security configurations.
    Supports set-syntax and block-based JunOS statements.
    """

    name = "juniper-junos"

    _HOSTNAME_RE = re.compile(
        r"^(?:set\s+system\s+host-name|host-name)\s+(?P<name>\S+);?$",
        re.IGNORECASE,
    )
    _SSH_RE = re.compile(
        r"^(?:set\s+system\s+services\s+ssh(?:\s+protocol-version\s+v(?P<version>\d+))?|ssh(?:\s+protocol-version\s+v(?P<version_block>\d+))?);?$",
        re.IGNORECASE,
    )
    _TELNET_RE = re.compile(
        r"^(?:set\s+system\s+services\s+telnet|telnet);?$",
        re.IGNORECASE,
    )
    _WEB_MGMT_HTTP_RE = re.compile(
        r"^(?:set\s+system\s+services\s+web-management\s+http|http);?$",
        re.IGNORECASE,
    )
    _WEB_MGMT_HTTPS_RE = re.compile(
        r"^(?:set\s+system\s+services\s+web-management\s+https|https);?$",
        re.IGNORECASE,
    )
    _SYSLOG_RE = re.compile(
        r"^(?:set\s+system\s+syslog|syslog)",
        re.IGNORECASE,
    )
    _LOGIN_LOCKOUT_RE = re.compile(
        r"^(?:set\s+system\s+login\s+retry-options\s+tries-before-lockout|tries-before-lockout)\s+(?P<tries>\d+);?$",
        re.IGNORECASE,
    )

    def parse(self, config: str, source_file: str) -> ParseResult:
        facts: list[SecurityFact] = []
        evidence: list[Evidence] = []
        unknown_lines: list[str] = []

        lines = config.splitlines()
        ssh_found = False
        ssh_version = None
        telnet_found = False
        http_found = False
        syslog_found = False
        login_lockout_found = False

        for idx, line in enumerate(lines, start=1):
            stripped = line.strip()
            if not stripped or stripped.startswith("#") or stripped.startswith("/*"):
                continue

            matched = False

            # Hostname
            hm = self._HOSTNAME_RE.match(stripped)
            if hm:
                matched = True
                self._add_fact(
                    facts, evidence,
                    "device.hostname", hm.group("name"),
                    stripped, idx, source_file
                )

            # SSH
            sm = self._SSH_RE.match(stripped)
            if sm:
                matched = True
                ssh_found = True
                v = sm.group("version") or sm.group("version_block")
                if v:
                    ssh_version = int(v)
                self._add_fact(
                    facts, evidence,
                    "management.ssh.enabled", True,
                    stripped, idx, source_file
                )

            # Telnet
            tm = self._TELNET_RE.match(stripped)
            if tm:
                matched = True
                telnet_found = True
                self._add_fact(
                    facts, evidence,
                    "management.telnet.enabled", True,
                    stripped, idx, source_file
                )

            # HTTP Management
            wm = self._WEB_MGMT_HTTP_RE.match(stripped)
            if wm:
                matched = True
                http_found = True
                self._add_fact(
                    facts, evidence,
                    "management.http.enabled", True,
                    stripped, idx, source_file
                )

            # Syslog
            lm = self._SYSLOG_RE.match(stripped)
            if lm:
                matched = True
                syslog_found = True

            # Login Lockout
            llm = self._LOGIN_LOCKOUT_RE.match(stripped)
            if llm:
                matched = True
                login_lockout_found = True
                self._add_fact(
                    facts, evidence,
                    "authentication.login_protection.enabled", True,
                    stripped, idx, source_file
                )

            if not matched and (stripped.startswith("set ") or "{" in stripped or ";" in stripped):
                unknown_lines.append(stripped)

        # Inferred / default facts
        if ssh_found:
            self._add_fact(
                facts, evidence,
                "management.ssh.version",
                ssh_version if ssh_version is not None else 2,
                "services { ssh }", 1, source_file
            )

        if not telnet_found:
            self._add_fact(
                facts, evidence,
                "management.telnet.enabled", False,
                "services { /* no telnet */ }", 1, source_file
            )

        if not http_found:
            self._add_fact(
                facts, evidence,
                "management.http.enabled", False,
                "services { /* no web-management http */ }", 1, source_file
            )

        if syslog_found:
            self._add_fact(
                facts, evidence,
                "logging.enabled", True,
                "system syslog enabled", 1, source_file
            )

        if not login_lockout_found:
            self._add_fact(
                facts, evidence,
                "authentication.login_protection.enabled", False,
                "no login retry-options configured", 1, source_file
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
        evidence_id = f"evidence:juniper-junos:{source_file}:{line_number}"
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
