"""Boundary 1: Identity & Policy engine (pure domain logic, zero I/O)."""

from __future__ import annotations

from typing import Any

from fin_redteam.models import (
    ApprovalServiceStatus,
    Decision,
    EnforcementConfig,
    GoldPolicySet,
    PolicyDecision,
    ReasonCode,
)


class PolicyEngine:
    """Deny-by-default authorization and policy invariant evaluator."""

    def __init__(
        self,
        policy_set: GoldPolicySet,
        valid_approval_tokens: set[str] | None = None,
    ) -> None:
        self._policy_set = policy_set
        self._valid_tokens = set(valid_approval_tokens or set())
        self._mutating_tools = set(policy_set.mutating_tools)
        self._approved_destinations = set(policy_set.approved_export_destinations)

    @property
    def policy_set(self) -> GoldPolicySet:
        return self._policy_set

    def is_mutating_tool(self, tool_name: str) -> bool:
        """Return True if the tool causes state changes or data export."""
        return tool_name in self._mutating_tools

    def evaluate_tool_call(
        self,
        *,
        actor_role: str,
        tool_name: str,
        arguments: dict[str, Any],
        context_tainted: bool,
        conflicting_instructions: bool,
        approval_service_status: ApprovalServiceStatus,
        enforcement: EnforcementConfig,
    ) -> PolicyDecision:
        """Evaluate a proposed tool call against gold policies without performing I/O."""
        # 1. Conflicting authority instructions fail closed
        if enforcement.enforce_conflict_detection and conflicting_instructions:
            return PolicyDecision(
                decision=Decision.DENY,
                reason_code=ReasonCode.CONFLICTING_INSTRUCTIONS_DENIED,
                detail="Conflicting authority directives detected; execution halted fail-closed.",
                policy_rule="global.conflict_fail_closed",
            )

        # 2. Deny-by-default role check
        role_policy = self._policy_set.roles.get(actor_role)
        if role_policy is None:
            return PolicyDecision(
                decision=Decision.DENY,
                reason_code=ReasonCode.POLICY_ROLE_DENIED,
                detail=f"Actor role '{actor_role}' is not defined in gold policy set.",
                policy_rule="global.deny_unknown_role",
            )

        # 3. Deny-by-default tool allowlist check
        if enforcement.deny_by_default and tool_name not in role_policy.allowed_tools:
            return PolicyDecision(
                decision=Decision.DENY,
                reason_code=ReasonCode.POLICY_TOOL_DENIED,
                detail=f"Role '{actor_role}' is not authorized to invoke tool '{tool_name}'.",
                policy_rule=f"roles.{actor_role}.allowed_tools",
            )

        # 4. Validate numerical amount arguments if present
        amount_usd = arguments.get("amount_usd")
        if amount_usd is not None:
            if not isinstance(amount_usd, (int, float)) or amount_usd <= 0:
                return PolicyDecision(
                    decision=Decision.DENY,
                    reason_code=ReasonCode.INVALID_TOOL_ARGUMENTS,
                    detail="Tool argument 'amount_usd' must be strictly positive.",
                    policy_rule="global.valid_amount_bounds",
                )

        # 5. Provenance / taint tracking: untrusted tool outputs cannot trigger mutating tools
        if enforcement.enforce_taint_tracking and context_tainted and self.is_mutating_tool(tool_name):
            return PolicyDecision(
                decision=Decision.DENY,
                reason_code=ReasonCode.TAINTED_WRITE_DENIED,
                detail=(
                    f"Mutating tool '{tool_name}' blocked because context is tainted by "
                    "untrusted external tool output."
                ),
                policy_rule="global.taint_blocks_mutation",
            )

        # 6. Export destination allowlist enforcement
        if tool_name == "export_compliance_report":
            destination = str(arguments.get("destination", ""))
            if not role_policy.allow_external_export and destination not in self._approved_destinations:
                return PolicyDecision(
                    decision=Decision.DENY,
                    reason_code=ReasonCode.POLICY_EXPORT_DENIED,
                    detail=(
                        f"Export destination '{destination}' is outside approved internal targets."
                    ),
                    policy_rule=f"roles.{actor_role}.approved_export_destinations",
                )

        # 7. Notional limit and dual-approval gate for financial mutations
        if amount_usd is not None and self.is_mutating_tool(tool_name):
            if float(amount_usd) > role_policy.max_notional_usd:
                return PolicyDecision(
                    decision=Decision.DENY,
                    reason_code=ReasonCode.POLICY_LIMIT_EXCEEDED,
                    detail=(
                        f"Requested amount ${amount_usd:,.2f} exceeds role '{actor_role}' "
                        f"limit of ${role_policy.max_notional_usd:,.2f}."
                    ),
                    policy_rule=f"roles.{actor_role}.max_notional_usd",
                )

            if float(amount_usd) > role_policy.requires_approval_above_usd:
                if (
                    enforcement.fail_closed_on_approval_outage
                    and approval_service_status == ApprovalServiceStatus.UNAVAILABLE
                ):
                    return PolicyDecision(
                        decision=Decision.DENY,
                        reason_code=ReasonCode.APPROVAL_UNAVAILABLE,
                        detail=(
                            "Dual-approval service is unavailable; high-value action denied "
                            "fail-closed."
                        ),
                        policy_rule="global.fail_closed_approval_outage",
                    )

                approval_token = arguments.get("approval_token")
                if not isinstance(approval_token, str) or approval_token not in self._valid_tokens:
                    return PolicyDecision(
                        decision=Decision.DENY,
                        reason_code=ReasonCode.APPROVAL_REQUIRED,
                        detail=(
                            f"Amount ${amount_usd:,.2f} exceeds approval threshold "
                            f"${role_policy.requires_approval_above_usd:,.2f} without a valid token."
                        ),
                        policy_rule=f"roles.{actor_role}.requires_approval_above_usd",
                    )

        return PolicyDecision(
            decision=Decision.ALLOW,
            reason_code=ReasonCode.POLICY_ALLOWED,
            detail=f"Role '{actor_role}' authorized to execute '{tool_name}'.",
            policy_rule=f"roles.{actor_role}.allow",
        )
