"""munio: Agent Safety Platform — pre-execution verification for AI agents.

From guardrails to guarantees.
"""

import importlib
from typing import TYPE_CHECKING, Any

__version__ = "0.1.0"

if TYPE_CHECKING:
    from munio.constraints import (
        ConstraintLoadError,
        ConstraintRegistry,
        load_constraints,
        load_constraints_dir,
    )
    from munio.guard import ActionBlockedError, Guard
    from munio.models import (
        Action,
        CheckType,
        Constraint,
        ConstraintCheck,
        ConstraintCondition,
        ConstraintConfig,
        DeployCheck,
        DeployCheckType,
        FailBehavior,
        MatchMode,
        MunioError,
        OnViolation,
        PolicyResult,
        PolicyVerificationResult,
        ProofAgentError,
        SolverConfig,
        Tier,
        VerificationMode,
        VerificationResult,
        Violation,
        ViolationSeverity,
        ViolationSource,
    )
    from munio.server import ServerConfig, create_server
    from munio.solver import InMemoryTemporalStore, InputTooLargeError, TemporalStore
    from munio.verifier import Verifier, averify_action, verify_action

__all__ = [
    "Action",
    "ActionBlockedError",
    "CheckType",
    "Constraint",
    "ConstraintCheck",
    "ConstraintCondition",
    "ConstraintConfig",
    "ConstraintLoadError",
    "ConstraintRegistry",
    "DeployCheck",
    "DeployCheckType",
    "FailBehavior",
    "Guard",
    "InMemoryTemporalStore",
    "InputTooLargeError",
    "MatchMode",
    "MunioError",
    "OnViolation",
    "PolicyResult",
    "PolicyVerificationResult",
    "ProofAgentError",
    "ServerConfig",
    "SolverConfig",
    "TemporalStore",
    "Tier",
    "VerificationMode",
    "VerificationResult",
    "Verifier",
    "Violation",
    "ViolationSeverity",
    "ViolationSource",
    "__version__",
    "averify_action",
    "create_server",
    "load_constraints",
    "load_constraints_dir",
    "verify_action",
]

_LAZY_IMPORTS: dict[str, tuple[str, str]] = {
    "ConstraintLoadError": ("munio.constraints", "ConstraintLoadError"),
    "ConstraintRegistry": ("munio.constraints", "ConstraintRegistry"),
    "load_constraints": ("munio.constraints", "load_constraints"),
    "load_constraints_dir": ("munio.constraints", "load_constraints_dir"),
    "ActionBlockedError": ("munio.guard", "ActionBlockedError"),
    "Guard": ("munio.guard", "Guard"),
    "Action": ("munio.models", "Action"),
    "CheckType": ("munio.models", "CheckType"),
    "Constraint": ("munio.models", "Constraint"),
    "ConstraintCheck": ("munio.models", "ConstraintCheck"),
    "ConstraintCondition": ("munio.models", "ConstraintCondition"),
    "ConstraintConfig": ("munio.models", "ConstraintConfig"),
    "DeployCheck": ("munio.models", "DeployCheck"),
    "DeployCheckType": ("munio.models", "DeployCheckType"),
    "FailBehavior": ("munio.models", "FailBehavior"),
    "MatchMode": ("munio.models", "MatchMode"),
    "OnViolation": ("munio.models", "OnViolation"),
    "PolicyResult": ("munio.models", "PolicyResult"),
    "MunioError": ("munio.models", "MunioError"),
    "ProofAgentError": ("munio.models", "ProofAgentError"),
    "PolicyVerificationResult": ("munio.models", "PolicyVerificationResult"),
    "SolverConfig": ("munio.models", "SolverConfig"),
    "Tier": ("munio.models", "Tier"),
    "VerificationMode": ("munio.models", "VerificationMode"),
    "VerificationResult": ("munio.models", "VerificationResult"),
    "Violation": ("munio.models", "Violation"),
    "ViolationSeverity": ("munio.models", "ViolationSeverity"),
    "ViolationSource": ("munio.models", "ViolationSource"),
    "ServerConfig": ("munio.server", "ServerConfig"),
    "create_server": ("munio.server", "create_server"),
    "InMemoryTemporalStore": ("munio.solver", "InMemoryTemporalStore"),
    "InputTooLargeError": ("munio.solver", "InputTooLargeError"),
    "TemporalStore": ("munio.solver", "TemporalStore"),
    "Verifier": ("munio.verifier", "Verifier"),
    "averify_action": ("munio.verifier", "averify_action"),
    "verify_action": ("munio.verifier", "verify_action"),
}


def __getattr__(name: str) -> Any:
    if name in _LAZY_IMPORTS:
        module_path, attr_name = _LAZY_IMPORTS[name]
        module = importlib.import_module(module_path)
        value = getattr(module, attr_name)
        globals()[name] = value  # cache for subsequent access
        return value
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
