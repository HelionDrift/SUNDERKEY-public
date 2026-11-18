"""Shared enums for profiles, missions, evidence, and events."""

from __future__ import annotations

from enum import StrEnum


class ProfileKind(StrEnum):
    SPECIALIST = "specialist"
    DOMAIN_COMMANDER = "domain_commander"
    SHARED = "shared"


class ActionTier(StrEnum):
    R0 = "R0"
    R1 = "R1"
    R2 = "R2"
    R3 = "R3"
    R4 = "R4"
    R5 = "R5"

    @property
    def rank(self) -> int:
        return int(self.value[1:])

    def allows(self, requested: ActionTier) -> bool:
        return requested.rank <= self.rank


class EvidenceLevel(StrEnum):
    E0 = "E0"
    E1 = "E1"
    E2 = "E2"
    E3 = "E3"
    E4 = "E4"

    @property
    def rank(self) -> int:
        return int(self.value[1:])

    def satisfies(self, required: EvidenceLevel) -> bool:
        return self.rank >= required.rank


class EventType(StrEnum):
    OBSERVATION = "observation"
    HYPOTHESIS = "hypothesis"
    PROPOSAL = "proposal"
    AUTHORIZATION = "authorization"
    RESULT = "result"
    FINDING = "finding"
    BLOCKER = "blocker"
    HANDOFF = "handoff"


class MissionEnvironment(StrEnum):
    OFFLINE = "offline"
    SYNTHETIC = "synthetic"
    TEST = "test"
    PRODUCTION = "production"
