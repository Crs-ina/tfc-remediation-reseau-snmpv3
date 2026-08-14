from __future__ import annotations

import json
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path

from .calendar_policy import ScheduleDecision


@dataclass(frozen=True)
class PlaybookDefinition:
    playbook_id: str
    incident_type: str | None
    action: str
    disruptive: bool
    allow_automatic_outside_business_hours: bool
    file_name: str


@dataclass(frozen=True)
class RuleContext:
    incident_type: str | None
    target_confirmed: bool
    identification_attempts: int
    target_whitelisted: bool
    schedule: ScheduleDecision
    automatic_allowed_actions: frozenset[str]
    quarantine_vlan_exists: bool = False
    quarantine_vlan_isolated: bool = False


@dataclass(frozen=True)
class RuleDecision:
    playbook_id: str
    action: str
    state: str
    execution_mode: str
    reason: str


class PlaybookRepository:
    def __init__(self, directory: Path) -> None:
        self.directory = Path(directory)

    @lru_cache(maxsize=8)
    def _load_json(self, file_name: str) -> dict:
        path = self.directory / file_name
        return json.loads(path.read_text(encoding="utf-8"))

    def get(self, incident_type: str | None) -> PlaybookDefinition:
        index = self._load_json("playbook_index.json")
        route = index["known_incident_types"].get(incident_type)
        if route is None:
            route = index["fallback"]

        playbook = self._load_json(route["file"])
        metadata = playbook["metadata"]
        decision = playbook["decision"]
        automation = playbook.get("automation", {})
        if metadata["playbook_id"] != route["playbook_id"]:
            raise RuntimeError(f"Playbook incoherent: {route['file']}")

        return PlaybookDefinition(
            playbook_id=metadata["playbook_id"],
            incident_type=playbook.get("incident_type"),
            action=decision["proposed_action"],
            disruptive=bool(decision.get("disruptive", False)),
            allow_automatic_outside_business_hours=bool(
                automation.get("allowed_outside_business_hours", False)
            ),
            file_name=route["file"],
        )


class RuleEngine:
    def __init__(self, repository: PlaybookRepository) -> None:
        self.repository = repository

    def evaluate(self, context: RuleContext) -> RuleDecision:
        playbook = self.repository.get(context.incident_type)

        if playbook.action == "NO_ACTION":
            return RuleDecision(
                playbook_id=playbook.playbook_id,
                action=playbook.action,
                state="ESCALATED_NO_REMEDIATION",
                execution_mode="NONE",
                reason="playbook_forbids_network_change",
            )

        if not context.target_confirmed:
            state = (
                "ESCALATED"
                if context.identification_attempts >= 2
                else "IDENTIFYING_TARGET"
            )
            return RuleDecision(
                playbook_id=playbook.playbook_id,
                action=playbook.action,
                state=state,
                execution_mode="NONE",
                reason="target_not_confirmed",
            )

        if context.target_whitelisted:
            return RuleDecision(
                playbook_id=playbook.playbook_id,
                action=playbook.action,
                state="ESCALATED",
                execution_mode="NONE",
                reason="target_is_whitelisted",
            )

        if playbook.action == "QUARANTINE_VLAN" and not (
            context.quarantine_vlan_exists and context.quarantine_vlan_isolated
        ):
            return RuleDecision(
                playbook_id=playbook.playbook_id,
                action=playbook.action,
                state="ESCALATED",
                execution_mode="NONE",
                reason="quarantine_vlan_precondition_failed",
            )

        # Les actions disruptives restent toujours supervisees. Le calendrier
        # ne vaut jamais approbation humaine pour une ecriture SNMP.
        if playbook.disruptive:
            return RuleDecision(
                playbook_id=playbook.playbook_id,
                action=playbook.action,
                state="WAITING_ADMIN_APPROVAL",
                execution_mode="HUMAN_APPROVAL",
                reason="explicit_admin_approval_required",
            )

        automatic_allowed = (
            context.schedule.mode == "AUTOMATIC"
            and playbook.allow_automatic_outside_business_hours
            and playbook.action in context.automatic_allowed_actions
        )
        if automatic_allowed:
            return RuleDecision(
                playbook_id=playbook.playbook_id,
                action=playbook.action,
                state="AUTOMATICALLY_AUTHORIZED",
                execution_mode="AUTOMATIC",
                reason=context.schedule.reason,
            )

        return RuleDecision(
            playbook_id=playbook.playbook_id,
            action=playbook.action,
            state="WAITING_ADMIN_APPROVAL",
            execution_mode="HUMAN_APPROVAL",
            reason="explicit_admin_approval_required",
        )
