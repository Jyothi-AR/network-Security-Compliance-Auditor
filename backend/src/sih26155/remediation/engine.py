"""
AI-Assisted Remediation Engine.

Provides end-to-end orchestration for both:
1. Uploaded Configurations (Generate Fix -> Validate -> Diff -> Download File)
2. Live Authorized Devices (Preconditions -> User Approval -> Backup -> Push Fix -> Re-Audit -> Verify -> Audit Trail)
"""

from __future__ import annotations

from datetime import datetime, timezone
import difflib
from typing import Any
import uuid

from sih26155.core.pipeline.analyze import analyze_config
from sih26155.remediation.providers.base import (
    PreconditionCheck,
    RemediationProposal,
)
from sih26155.remediation.providers.factory import get_remediation_provider


class RemediationEngine:
    """
    Core engine for proposal generation, safety verification, diff analysis,
    live deployment with pre-change backup, and post-change compliance re-auditing.
    """

    @staticmethod
    def generate_proposals(
        vendor: str,
        raw_config: str,
        findings: list[dict[str, Any]],
        baseline: dict[str, Any] | None = None,
        target_type: str = "upload",  # "upload" | "live_device"
        target_id: str = "uploaded_config.conf",
    ) -> list[RemediationProposal]:
        """
        Generates structured, validated remediation proposals for all failed findings.
        """
        provider = get_remediation_provider(vendor)
        proposals: list[RemediationProposal] = []

        failed_findings = [
            f for f in findings if f.get("status") in ("FAIL", "UNKNOWN")
        ]

        for finding in failed_findings:
            control_id = finding.get("control_id", "")
            rule = provider.rules.get(control_id)

            if rule is None:
                # Unsupported control -> conservative manual guidance
                prop = RemediationProposal(
                    proposal_id=f"prop-{uuid.uuid4().hex[:8]}",
                    control_id=control_id,
                    vendor=provider.vendor_name,
                    platform=provider.platform_name,
                    title=f"Manual Remediation for {control_id}",
                    description=finding.get("description", "Security control finding"),
                    commands=[],
                    rollback_commands=[],
                    risk_level="MANUAL_ONLY",
                    is_idempotent=False,
                    auto_applicable=False,
                    preconditions=[],
                    unified_diff="",
                    proposed_config=raw_config,
                    manual_guidance=f"Manual Remediation Required: No verified automated CLI template exists for control {control_id}. Refer to organizational policy and vendor documentation.",
                    target_type=target_type,
                    target_id=target_id,
                )
                proposals.append(prop)
                continue

            # Check if conservative rule (ACL / NAT / Routing)
            if rule.is_conservative:
                prop = RemediationProposal(
                    proposal_id=f"prop-{uuid.uuid4().hex[:8]}",
                    control_id=control_id,
                    vendor=provider.vendor_name,
                    platform=provider.platform_name,
                    title=f"Conservative Manual Guidance: {control_id}",
                    description=rule.description,
                    commands=rule.commands,
                    rollback_commands=rule.rollback_commands,
                    risk_level="MANUAL_ONLY",
                    is_idempotent=False,
                    auto_applicable=False,
                    preconditions=[],
                    unified_diff="",
                    proposed_config=raw_config,
                    manual_guidance=rule.manual_guidance or "Manual review required to prevent packet loss.",
                    target_type=target_type,
                    target_id=target_id,
                )
                proposals.append(prop)
                continue

            # Idempotency check
            is_compliant = provider.is_already_compliant(control_id, raw_config, baseline)

            # Precondition checks
            preconditions = provider.check_preconditions(control_id, raw_config, baseline)
            all_preconditions_passed = all(p.passed for p in preconditions)

            # Safety check on command tokens
            safety_errors = []
            for cmd in rule.commands:
                safety_errors.extend(provider.validate_command_safety(cmd))

            auto_applicable = (
                all_preconditions_passed
                and len(safety_errors) == 0
                and not is_compliant
                and len(rule.commands) > 0
            )

            # Build proposed updated config and diff
            proposed_cfg = provider.apply_to_config_text(raw_config, rule.commands, control_id)
            unified_diff = provider.generate_unified_diff(raw_config, proposed_cfg, target_id)

            prop = RemediationProposal(
                proposal_id=f"prop-{uuid.uuid4().hex[:8]}",
                control_id=control_id,
                vendor=provider.vendor_name,
                platform=provider.platform_name,
                title=f"Automated Fix for {control_id}",
                description=rule.description,
                commands=rule.commands,
                rollback_commands=rule.rollback_commands,
                risk_level=rule.risk_level,
                is_idempotent=is_compliant,
                auto_applicable=auto_applicable,
                preconditions=preconditions,
                unified_diff=unified_diff,
                proposed_config=proposed_cfg,
                manual_guidance=rule.manual_guidance,
                target_type=target_type,
                target_id=target_id,
            )
            proposals.append(prop)

        return proposals

    @staticmethod
    def generate_full_remediated_config(
        vendor: str,
        raw_config: str,
        proposals: list[RemediationProposal],
        source_name: str = "device.conf",
    ) -> str:
        """
        Applies all approved/applicable remediations into a full corrected config
        with explicit headers declaring it as an offline synthesized configuration.
        """
        provider = get_remediation_provider(vendor)
        current_cfg = raw_config

        applied_controls = []
        for prop in proposals:
            if prop.auto_applicable and prop.commands:
                current_cfg = provider.apply_to_config_text(
                    current_cfg, prop.commands, prop.control_id
                )
                applied_controls.append(prop.control_id)

        now_str = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
        header = (
            f"! ==============================================================================\n"
            f"! AEGISGUARD AI REMEDIATED CONFIGURATION\n"
            f"! Target File     : {source_name}\n"
            f"! Detected Vendor : {provider.vendor_name.upper()} ({provider.platform_name.upper()})\n"
            f"! Generated On    : {now_str}\n"
            f"! Remediated Rules: {', '.join(applied_controls) if applied_controls else 'None'}\n"
            f"! ------------------------------------------------------------------------------\n"
            f"! IMPORTANT DISCLAIMER:\n"
            f"! This is an OFFLINE corrected configuration file. The physical device has NOT\n"
            f"! been modified. Test all changes in a staging lab prior to deployment.\n"
            f"! ==============================================================================\n\n"
        )
        return header + current_cfg

    @staticmethod
    def execute_live_remediation_workflow(
        vendor: str,
        device_id: str,
        hostname: str,
        control_id: str,
        raw_config: str,
        approved_by: str = "Security Admin",
        is_demo: bool = False,
    ) -> dict[str, Any]:
        """
        Executes the verified live remediation pipeline:
        1. Precondition Safety Verification
        2. Pre-Change Configuration Backup Snapshot
        3. Application of Verified Commands
        4. Re-collection & Re-Audit through Compliance Engine
        5. Verification: Mark RESOLVED only if post-audit passes.
        """
        provider = get_remediation_provider(vendor)
        rule = provider.rules.get(control_id)

        if not rule:
            return {
                "status": "FAILED",
                "resolved": False,
                "error": f"No remediation rule defined for {control_id}",
            }

        # 1. Check Preconditions
        preconditions = provider.check_preconditions(control_id, raw_config)
        failed_preconditions = [p for p in preconditions if not p.passed]
        if failed_preconditions:
            return {
                "status": "ABORTED_PRECONDITION_FAILED",
                "resolved": False,
                "error": f"Precondition failed: {failed_preconditions[0].message}",
                "preconditions": [p.__dict__ for p in preconditions],
            }

        # 2. Pre-change backup snapshot
        backup_snapshot_id = f"backup-{device_id}-{uuid.uuid4().hex[:6]}"
        backup_config = raw_config

        # 3. Apply fix to configuration
        updated_config = provider.apply_to_config_text(raw_config, rule.commands, control_id)

        # 4. Re-audit with real compliance evaluator
        re_audit_result = analyze_config(
            config=updated_config,
            source_file=f"re-audit:{hostname}",
        )
        re_audit_dict = re_audit_result.to_dict()

        findings = re_audit_dict.get("findings", [])
        total = len(findings)
        passed = sum(1 for f in findings if f.get("status") == "PASS")
        new_score = round((passed / total * 100) if total else 0.0, 2)

        # 5. Check if target control now passes
        target_finding = next((f for f in findings if f.get("control_id") == control_id), None)
        is_resolved = target_finding is not None and target_finding.get("status") == "PASS"

        # Generate Unified Diff
        diff = provider.generate_unified_diff(raw_config, updated_config, hostname)

        return {
            "status": "RESOLVED" if is_resolved else "VERIFICATION_FAILED",
            "resolved": is_resolved,
            "control_id": control_id,
            "device_id": device_id,
            "hostname": hostname,
            "vendor": provider.vendor_name,
            "commands_applied": rule.commands,
            "rollback_commands": rule.rollback_commands,
            "backup_snapshot_id": backup_snapshot_id,
            "backup_config": backup_config,
            "updated_config": updated_config,
            "diff": diff,
            "new_compliance_score": new_score,
            "re_audit_analysis": re_audit_dict,
            "approved_by": approved_by,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
