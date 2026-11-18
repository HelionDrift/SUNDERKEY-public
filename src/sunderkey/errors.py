"""Errors raised by the SUNDERKEY expert control plane."""


class SunderkeyError(ValueError):
    """Base error for invalid expert control plane data."""


class RegistryError(SunderkeyError):
    """Raised when the expert registry is invalid."""


class MissionError(SunderkeyError):
    """Raised when a mission request or assembled cell is invalid."""


class CollaborationPlanError(SunderkeyError):
    """Raised when a mission collaboration plan is invalid."""


class EventError(SunderkeyError):
    """Raised when a mission event violates the event contract."""


class RoutingError(SunderkeyError):
    """Raised when a capability routing request cannot be satisfied safely."""


class QualificationError(SunderkeyError):
    """Raised when a specialist qualification contract is invalid."""


class StoreError(SunderkeyError):
    """Raised when durable mission storage fails."""


class StoreConflictError(StoreError):
    """Raised when stored state conflicts with a requested write."""


class StoreIntegrityError(StoreError):
    """Raised when durable mission state fails an integrity check."""


class StoreMigrationRequiredError(StoreError):
    """Raised when a legacy mission store requires an explicit migration."""


class MissionControlError(SunderkeyError):
    """Raised when a mission control transition is invalid."""


class MissionStoppedError(MissionControlError):
    """Raised when an operation is blocked by a stopped mission."""


class PrincipalAuthenticationError(SunderkeyError):
    """Raised when signed runtime identity or scope cannot be verified."""


class ApprovalError(SunderkeyError):
    """Raised when an approval queue transition is invalid."""


class ApprovalConflictError(ApprovalError):
    """Raised when approval state or idempotency data conflicts."""


class ApprovalDeniedError(ApprovalError):
    """Raised when an approval is denied or otherwise terminal."""


class ApprovalExpiredError(ApprovalError):
    """Raised when an approval or authorization has expired."""


class SimulationError(SunderkeyError):
    """Raised when a plan-only simulation request is invalid."""


class ContentPolicyError(SunderkeyError):
    """Raised when repository text violates the content policy."""
