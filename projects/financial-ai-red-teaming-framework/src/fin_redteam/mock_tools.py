"""Isolated mock financial tools operating strictly on deep-copied synthetic state."""

from __future__ import annotations

import copy
from typing import Any

from fin_redteam.errors import UnsupportedInputError
from fin_redteam.models import (
    AdversarialDocument,
    CanarySecret,
    DocumentCorpus,
    GoldPolicySet,
    MockLedger,
    SourceTrust,
)


class MockFinancialSandbox:
    """Isolated per-scenario mock tool execution environment with read/write separation."""

    SUPPORTED_TOOLS = frozenset(
        {
            "read_portfolio",
            "read_document",
            "query_policy",
            "draft_trade_order",
            "draft_wire_transfer",
            "execute_wire_transfer",
            "update_account_permissions",
            "export_compliance_report",
        }
    )

    def __init__(
        self,
        ledger: MockLedger,
        documents: DocumentCorpus,
        canaries: list[CanarySecret],
        policy_set: GoldPolicySet,
    ) -> None:
        # Deep copy per scenario ensures full test isolation and zero cross-run state drift.
        self._accounts = {a.account_id: copy.deepcopy(a) for a in ledger.accounts}
        self._documents: dict[str, AdversarialDocument] = {
            d.doc_id: copy.deepcopy(d) for d in documents.documents
        }
        self._canaries = {c.canary_id: copy.deepcopy(c) for c in canaries}
        self._policy_set = policy_set
        self.draft_orders: list[dict[str, Any]] = []
        self.draft_wires: list[dict[str, Any]] = []
        self.executed_wires: list[dict[str, Any]] = []
        self.permission_changes: list[dict[str, Any]] = []
        self.exported_reports: list[dict[str, Any]] = []

    def invoke(self, tool_name: str, arguments: dict[str, Any]) -> dict[str, Any]:
        """Execute a supported mock tool against the isolated synthetic state."""
        if tool_name not in self.SUPPORTED_TOOLS:
            raise UnsupportedInputError(f"Unsupported mock tool: '{tool_name}'.")

        handler = getattr(self, f"_tool_{tool_name}")
        return handler(arguments)

    def _tool_read_portfolio(self, arguments: dict[str, Any]) -> dict[str, Any]:
        account_id = str(arguments.get("account_id", ""))
        account = self._accounts.get(account_id)
        if account is None:
            return {
                "ok": False,
                "source_trust": SourceTrust.TRUSTED_INTERNAL,
                "summary": f"Synthetic account '{account_id}' not found.",
            }
        positions_str = ", ".join(
            f"{p.symbol}({p.quantity} @ ${p.market_value_usd:,.2f})" for p in account.positions
        )
        return {
            "ok": True,
            "source_trust": SourceTrust.TRUSTED_INTERNAL,
            "account_id": account.account_id,
            "owner_label": account.owner_label,
            "cash_balance_usd": account.cash_balance_usd,
            "risk_tier": account.risk_tier,
            "internal_canary_ref": account.internal_canary_ref,
            "summary": (
                f"Account {account.account_id} ({account.owner_label}): "
                f"cash=${account.cash_balance_usd:,.2f}, positions=[{positions_str}]."
            ),
        }

    def _tool_read_document(self, arguments: dict[str, Any]) -> dict[str, Any]:
        doc_id = str(arguments.get("doc_id", ""))
        doc = self._documents.get(doc_id)
        if doc is None:
            return {
                "ok": False,
                "source_trust": SourceTrust.UNTRUSTED_EXTERNAL,
                "summary": f"Synthetic document '{doc_id}' not found.",
                "content": "",
            }
        return {
            "ok": True,
            "doc_id": doc.doc_id,
            "title": doc.title,
            "source_trust": doc.source_trust,
            "content": doc.content,
            "summary": f"Loaded document {doc.doc_id} ({doc.title}) [trust={doc.source_trust.value}].",
        }

    def _tool_query_policy(self, arguments: dict[str, Any]) -> dict[str, Any]:
        role = str(arguments.get("role", ""))
        role_policy = self._policy_set.roles.get(role)
        if role_policy is None:
            return {
                "ok": False,
                "source_trust": SourceTrust.TRUSTED_INTERNAL,
                "summary": f"No policy defined for role '{role}'.",
            }
        return {
            "ok": True,
            "source_trust": SourceTrust.TRUSTED_INTERNAL,
            "allowed_tools": list(role_policy.allowed_tools),
            "max_notional_usd": role_policy.max_notional_usd,
            "requires_approval_above_usd": role_policy.requires_approval_above_usd,
            "summary": (
                f"Role '{role}' allowed tools: {', '.join(role_policy.allowed_tools)}; "
                f"max_notional_usd=${role_policy.max_notional_usd:,.2f}."
            ),
        }

    def _tool_draft_trade_order(self, arguments: dict[str, Any]) -> dict[str, Any]:
        record = {
            "order_id": f"SYNTH-ORD-{len(self.draft_orders) + 1:04d}",
            "account_id": str(arguments.get("account_id", "")),
            "symbol": str(arguments.get("symbol", "SYNTH_EQ_ALPHA")),
            "side": str(arguments.get("side", "BUY")),
            "amount_usd": float(arguments.get("amount_usd", 0.0)),
            "status": "DRAFT_SIMULATED",
        }
        self.draft_orders.append(record)
        return {
            "ok": True,
            "source_trust": SourceTrust.TRUSTED_INTERNAL,
            "order": record,
            "summary": (
                f"Drafted synthetic {record['side']} order {record['order_id']} "
                f"for ${record['amount_usd']:,.2f} of {record['symbol']}."
            ),
        }

    def _tool_draft_wire_transfer(self, arguments: dict[str, Any]) -> dict[str, Any]:
        record = {
            "wire_id": f"SYNTH-WIRE-{len(self.draft_wires) + 1:04d}",
            "account_id": str(arguments.get("account_id", "")),
            "destination": str(arguments.get("destination", "")),
            "amount_usd": float(arguments.get("amount_usd", 0.0)),
            "status": "DRAFT_SIMULATED",
        }
        self.draft_wires.append(record)
        return {
            "ok": True,
            "source_trust": SourceTrust.TRUSTED_INTERNAL,
            "wire": record,
            "summary": (
                f"Drafted synthetic wire {record['wire_id']} for ${record['amount_usd']:,.2f} "
                f"to {record['destination']}."
            ),
        }

    def _tool_execute_wire_transfer(self, arguments: dict[str, Any]) -> dict[str, Any]:
        record = {
            "exec_id": f"SYNTH-EXEC-{len(self.executed_wires) + 1:04d}",
            "account_id": str(arguments.get("account_id", "")),
            "destination": str(arguments.get("destination", "")),
            "amount_usd": float(arguments.get("amount_usd", 0.0)),
            "status": "EXECUTED_SIMULATED",
        }
        self.executed_wires.append(record)
        return {
            "ok": True,
            "source_trust": SourceTrust.TRUSTED_INTERNAL,
            "execution": record,
            "summary": f"Executed synthetic wire {record['exec_id']} to {record['destination']}.",
        }

    def _tool_update_account_permissions(self, arguments: dict[str, Any]) -> dict[str, Any]:
        record = {
            "change_id": f"SYNTH-PERM-{len(self.permission_changes) + 1:04d}",
            "account_id": str(arguments.get("account_id", "")),
            "role": str(arguments.get("role", "")),
        }
        self.permission_changes.append(record)
        return {
            "ok": True,
            "source_trust": SourceTrust.TRUSTED_INTERNAL,
            "change": record,
            "summary": f"Updated synthetic permissions for {record['account_id']} to {record['role']}.",
        }

    def _tool_export_compliance_report(self, arguments: dict[str, Any]) -> dict[str, Any]:
        record = {
            "export_id": f"SYNTH-EXP-{len(self.exported_reports) + 1:04d}",
            "destination": str(arguments.get("destination", "")),
            "summary": str(arguments.get("summary", "")),
        }
        self.exported_reports.append(record)
        return {
            "ok": True,
            "source_trust": SourceTrust.TRUSTED_INTERNAL,
            "export": record,
            "summary": f"Exported synthetic compliance report {record['export_id']} to {record['destination']}.",
        }
