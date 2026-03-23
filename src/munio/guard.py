"""Guard class: unified tool call security for Python agent frameworks.

Framework-specific adapters live in ``munio.adapters``:
- LangChain: ``from munio.adapters import guard_tool``
- CrewAI: ``from munio.adapters import create_crew_hook``
- OpenAI Agents SDK: ``from munio.adapters import create_guardrail``
- MCP: ``from munio.adapters import create_guarded_mcp``

Universal fallback:
- @guard.verify() decorator works with ANY Python function
- Sync + async support via inspect.iscoroutinefunction
"""

from __future__ import annotations

import asyncio
import functools
import inspect
import logging
from pathlib import Path
from typing import TYPE_CHECKING, Any

from munio.constraints import ConstraintRegistry, load_constraints_dir
from munio.models import (
    Action,
    ConstraintConfig,
    MunioError,
    VerificationMode,
    VerificationResult,
)
from munio.verifier import Verifier

if TYPE_CHECKING:
    from collections.abc import Callable

    from munio._temporal import TemporalStore

__all__ = [
    "ActionBlockedError",
    "Guard",
]

logger = logging.getLogger(__name__)


class ActionBlockedError(MunioError):
    """Raised when a decorated function is blocked by constraint verification.

    Attributes:
        result: The VerificationResult that caused the block.
    """

    __slots__ = ("result",)

    def __init__(self, result: VerificationResult) -> None:
        self.result = result
        violations_summary = "; ".join(v.message for v in result.violations[:3])
        if len(result.violations) > 3:
            violations_summary += f" (+{len(result.violations) - 3} more)"
        super().__init__(f"Action blocked: {violations_summary}")


class Guard:
    """Unified tool call security for Python agent frameworks.

    Usage::

        guard = Guard(constraints="generic")

        # Check an action
        result = guard.check(Action(tool="http_request", args={"url": "..."}))


        # Universal decorator
        @guard.verify()
        def call_tool(url: str, method: str = "GET"):
            return requests.get(url)

    Args:
        constraints: Constraint pack name (default: "generic").
        mode: Verification mode (enforce, shadow, disabled).
        config: Full ConstraintConfig (overrides constraints/mode if provided).
        registry: Pre-built ConstraintRegistry (for testing; skips disk loading).
        constraints_dir: Path to constraints directory (overrides config default).
    """

    __slots__ = ("_config", "_verifier")

    _config: ConstraintConfig
    _verifier: Verifier

    def __init__(
        self,
        *,
        constraints: str = "generic",
        mode: VerificationMode = VerificationMode.ENFORCE,
        config: ConstraintConfig | None = None,
        registry: ConstraintRegistry | None = None,
        constraints_dir: Path | str | None = None,
        temporal_store: TemporalStore | None = None,
    ) -> None:
        # Build config
        if config is not None:
            self._config = config
        else:
            self._config = ConstraintConfig(
                mode=mode,
                constraint_packs=[constraints],
            )

        # Build or use registry
        if registry is not None:
            reg = registry
        else:
            cdir = Path(constraints_dir) if constraints_dir else self._config.constraints_dir
            if not cdir.is_absolute():
                cdir = Path.cwd() / cdir

            if not cdir.is_dir():
                # Fallback to bundled constraints (shipped with the package)
                for candidate in (
                    Path(__file__).resolve().parent
                    / "gate"
                    / "data"
                    / "constraints",  # installed wheel
                    Path(__file__).resolve().parents[2] / "constraints",  # dev mode (src/ layout)
                ):
                    if candidate.is_dir():
                        logger.debug("Using bundled constraints from %s", candidate)
                        cdir = candidate
                        break
                else:
                    logger.warning("No constraints directory found at %s or bundled", cdir)

            reg = load_constraints_dir(cdir, packs=self._config.constraint_packs)

        self._verifier = Verifier(registry=reg, config=self._config, temporal_store=temporal_store)

    @property
    def verifier(self) -> Verifier:
        """Access the underlying Verifier (for advanced use/testing)."""
        return self._verifier

    def check(self, action: Action | dict[str, Any]) -> VerificationResult:
        """Verify an action and return the result (does not raise on violations).

        Args:
            action: Action model or dict with 'tool', 'args', etc.

        Returns:
            VerificationResult with allowed status and violations.

        Raises:
            MunioError: If the action dict fails validation.
        """
        if isinstance(action, dict):
            try:
                action = Action(**action)
            except Exception as exc:
                msg = f"Invalid action format: {exc}"
                raise MunioError(msg) from exc
        return self._verifier.verify(action)

    async def acheck(self, action: Action | dict[str, Any]) -> VerificationResult:
        """Verify an action asynchronously (does not raise).

        Uses asyncio.to_thread to avoid blocking the event loop.
        """
        return await asyncio.to_thread(self.check, action)

    def verify(self, constraints: str | None = None) -> Callable[..., Any]:
        """Universal decorator for verifying function calls.

        Intercepts the call, builds an Action from function arguments,
        verifies against constraints, and raises ActionBlockedError
        if blocked in ENFORCE mode.

        Supports both sync and async functions.

        Args:
            constraints: Reserved for future per-endpoint constraint selection.

        Returns:
            Decorator function.
        """

        def decorator(fn: Callable[..., Any]) -> Callable[..., Any]:
            sig = inspect.signature(fn)

            if inspect.iscoroutinefunction(fn):

                @functools.wraps(fn)
                async def async_wrapper(*args: Any, **kwargs: Any) -> Any:
                    action = _build_action_from_call(fn, sig, args, kwargs)
                    result = await self.acheck(action)
                    if not result.allowed:
                        raise ActionBlockedError(result)
                    return await fn(*args, **kwargs)

                return async_wrapper

            @functools.wraps(fn)
            def sync_wrapper(*args: Any, **kwargs: Any) -> Any:
                action = _build_action_from_call(fn, sig, args, kwargs)
                result = self.check(action)
                if not result.allowed:
                    raise ActionBlockedError(result)
                return fn(*args, **kwargs)

            return sync_wrapper

        return decorator

    def __repr__(self) -> str:
        return (
            f"Guard(mode={self._config.mode.value!r}, constraints={len(self._verifier.registry)})"
        )


def _build_action_from_call(
    fn: Callable[..., Any],
    sig: inspect.Signature,
    call_args: tuple[Any, ...],
    call_kwargs: dict[str, Any],
) -> Action:
    """Build an Action from function call arguments.

    Uses the function's ``__name__`` as the tool name and bound arguments
    as the args dict. Excludes ``self`` and ``cls`` parameters.
    """
    bound = sig.bind(*call_args, **call_kwargs)
    bound.apply_defaults()

    all_args = dict(bound.arguments)
    all_args.pop("self", None)
    all_args.pop("cls", None)

    return Action(tool=fn.__name__, args=all_args)
