"""Tests for munio.guard — Guard facade + decorator."""

from __future__ import annotations

import pytest

from munio.guard import ActionBlockedError, Guard, _build_action_from_call
from munio.models import (
    ConstraintConfig,
    OnViolation,
    ProofAgentError,
    VerificationMode,
    VerificationResult,
    Violation,
)
from tests.core.conftest import (
    CONSTRAINTS_DIR,
)
from tests.core.conftest import (
    make_action as _make_action,
)
from tests.core.conftest import (
    make_denylist_constraint as _make_denylist_constraint,
)
from tests.core.conftest import (
    make_registry as _make_registry,
)

# ── TestActionBlockedError ──


class TestActionBlockedError:
    """Tests for ActionBlockedError exception."""

    def _make_result(self, num_violations: int = 1) -> VerificationResult:
        violations = [
            Violation(
                constraint_name=f"c{i}",
                message=f"Violation {i}",
            )
            for i in range(num_violations)
        ]
        return VerificationResult(allowed=False, violations=violations)

    def test_inherits_munio_error(self) -> None:
        err = ActionBlockedError(self._make_result())
        assert isinstance(err, ProofAgentError)
        assert isinstance(err, Exception)

    def test_holds_result(self) -> None:
        result = self._make_result()
        err = ActionBlockedError(result)
        assert err.result is result

    def test_message_summary(self) -> None:
        err = ActionBlockedError(self._make_result(2))
        assert "Violation 0" in str(err)
        assert "Violation 1" in str(err)

    def test_message_truncates_many_violations(self) -> None:
        err = ActionBlockedError(self._make_result(5))
        assert "+2 more" in str(err)

    def test_catchable_as_munio_error(self) -> None:
        with pytest.raises(ProofAgentError):
            raise ActionBlockedError(self._make_result())


# ── TestGuardInit ──


class TestGuardInit:
    """Tests for Guard initialization."""

    def test_default_init(self) -> None:
        guard = Guard(constraints_dir=CONSTRAINTS_DIR)
        assert len(guard.verifier.registry) > 0

    def test_with_registry(self) -> None:
        c = _make_denylist_constraint(["evil.com"])
        registry = _make_registry(c)
        guard = Guard(registry=registry)
        assert len(guard.verifier.registry) == 1

    def test_with_config(self) -> None:
        config = ConstraintConfig(mode=VerificationMode.SHADOW)
        guard = Guard(config=config, registry=_make_registry())
        result = guard.check(_make_action())
        assert result.mode == VerificationMode.SHADOW

    def test_nonexistent_dir_falls_back_to_bundled(self) -> None:
        """Nonexistent absolute path falls back to bundled constraints."""
        guard = Guard(constraints_dir="/nonexistent/path")
        # Falls back to bundled constraints (shipped with the package)
        assert len(guard.verifier.registry) > 0

    def test_repr(self) -> None:
        c = _make_denylist_constraint(["x"])
        guard = Guard(registry=_make_registry(c))
        r = repr(guard)
        assert "Guard" in r
        assert "enforce" in r
        assert "1" in r


# ── TestGuardCheck ──


class TestGuardCheck:
    """Tests for Guard.check() method."""

    def test_dict_input(self) -> None:
        c = _make_denylist_constraint(["evil.com"])
        guard = Guard(registry=_make_registry(c))
        result = guard.check({"tool": "http_request", "args": {"url": "safe.com"}})
        assert isinstance(result, VerificationResult)

    def test_allows_safe(self) -> None:
        c = _make_denylist_constraint(["evil.com"])
        guard = Guard(registry=_make_registry(c))
        result = guard.check(_make_action(url="safe.com"))
        assert result.allowed is True

    def test_blocks_dangerous(self) -> None:
        c = _make_denylist_constraint(["evil.com"])
        guard = Guard(registry=_make_registry(c))
        result = guard.check(_make_action(url="evil.com"))
        assert result.allowed is False

    def test_invalid_dict_raises(self) -> None:
        guard = Guard(registry=_make_registry())
        with pytest.raises(ProofAgentError, match="Invalid action format"):
            guard.check({"bad_field": 123})


# ── TestGuardAcheck ──


class TestGuardAcheck:
    """Tests for Guard.acheck() async method."""

    @pytest.mark.asyncio
    async def test_returns_same_as_sync(self) -> None:
        c = _make_denylist_constraint(["evil.com"])
        guard = Guard(registry=_make_registry(c))
        action = _make_action(url="evil.com")
        sync_result = guard.check(action)
        async_result = await guard.acheck(action)
        assert sync_result.allowed == async_result.allowed

    @pytest.mark.asyncio
    async def test_async_blocks_dangerous(self) -> None:
        c = _make_denylist_constraint(["evil.com"])
        guard = Guard(registry=_make_registry(c))
        result = await guard.acheck(_make_action(url="evil.com"))
        assert result.allowed is False


# ── TestGuardVerifyDecorator ──


class TestGuardVerifyDecorator:
    """Tests for Guard.verify() decorator."""

    def _make_guard(
        self,
        values: list[str] | None = None,
        mode: VerificationMode = VerificationMode.ENFORCE,
        on_violation: OnViolation = OnViolation.BLOCK,
    ) -> Guard:
        if values is None:
            values = ["evil.com"]
        c = _make_denylist_constraint(values, on_violation=on_violation)
        config = ConstraintConfig(mode=mode)
        return Guard(registry=_make_registry(c), config=config)

    def test_sync_allowed(self) -> None:
        guard = self._make_guard()

        @guard.verify()
        def http_request(url: str) -> str:
            return f"fetched {url}"

        assert http_request(url="safe.com") == "fetched safe.com"

    def test_sync_blocked_raises(self) -> None:
        guard = self._make_guard()

        @guard.verify()
        def http_request(url: str) -> str:
            return f"fetched {url}"

        with pytest.raises(ActionBlockedError):
            http_request(url="evil.com")

    @pytest.mark.asyncio
    async def test_async_allowed(self) -> None:
        guard = self._make_guard()

        @guard.verify()
        async def http_request(url: str) -> str:
            return f"fetched {url}"

        result = await http_request(url="safe.com")
        assert result == "fetched safe.com"

    @pytest.mark.asyncio
    async def test_async_blocked_raises(self) -> None:
        guard = self._make_guard()

        @guard.verify()
        async def http_request(url: str) -> str:
            return f"fetched {url}"

        with pytest.raises(ActionBlockedError):
            await http_request(url="evil.com")

    def test_tool_name_from_function_name(self) -> None:
        c = _make_denylist_constraint(["bad"], action="my_tool", field="data")
        guard = Guard(registry=_make_registry(c))

        @guard.verify()
        def my_tool(data: str) -> str:
            return data

        with pytest.raises(ActionBlockedError):
            my_tool(data="bad")

    def test_args_from_kwargs(self) -> None:
        c = _make_denylist_constraint(["evil.com"], field="url")
        guard = Guard(registry=_make_registry(c))

        @guard.verify()
        def http_request(url: str, method: str = "GET") -> str:
            return f"{method} {url}"

        # Should block because url="evil.com" matches denylist
        with pytest.raises(ActionBlockedError):
            http_request(url="evil.com", method="POST")

    def test_args_with_positional_params(self) -> None:
        c = _make_denylist_constraint(["evil.com"], field="url")
        guard = Guard(registry=_make_registry(c))

        @guard.verify()
        def http_request(url: str) -> str:
            return url

        # Positional arg should work
        with pytest.raises(ActionBlockedError):
            http_request("evil.com")

    def test_shadow_no_raise(self) -> None:
        guard = self._make_guard(mode=VerificationMode.SHADOW)

        @guard.verify()
        def http_request(url: str) -> str:
            return url

        # SHADOW mode: never raises, even with violations
        assert http_request(url="evil.com") == "evil.com"

    def test_disabled_no_raise(self) -> None:
        guard = self._make_guard(mode=VerificationMode.DISABLED)

        @guard.verify()
        def http_request(url: str) -> str:
            return url

        assert http_request(url="evil.com") == "evil.com"

    def test_preserves_function_metadata(self) -> None:
        guard = self._make_guard()

        @guard.verify()
        def my_function(x: int) -> int:
            """My docstring."""
            return x

        assert my_function.__name__ == "my_function"
        assert my_function.__doc__ == "My docstring."

    def test_preserves_return_value(self) -> None:
        guard = self._make_guard()

        @guard.verify()
        def compute(x: int, y: int) -> int:
            return x + y

        assert compute(x=3, y=4) == 7

    def test_decorator_on_method_excludes_self(self) -> None:
        c = _make_denylist_constraint(["bad"], field="data", action="process")
        guard = Guard(registry=_make_registry(c))

        class MyService:
            @guard.verify()
            def process(self, data: str) -> str:
                return data

        svc = MyService()
        # "self" should not appear in Action args
        assert svc.process(data="good") == "good"

        with pytest.raises(ActionBlockedError):
            svc.process(data="bad")

    def test_decorator_on_classmethod_excludes_cls(self) -> None:
        c = _make_denylist_constraint(["bad"], field="data", action="process")
        guard = Guard(registry=_make_registry(c))

        class MyService:
            @classmethod
            @guard.verify()
            def process(cls, data: str) -> str:
                return data

        assert MyService.process(data="good") == "good"

        with pytest.raises(ActionBlockedError):
            MyService.process(data="bad")

    def test_function_exception_propagates_after_guard(self) -> None:
        """If the function passes guard but raises, exception propagates unchanged."""
        guard = self._make_guard()

        @guard.verify()
        def http_request(url: str) -> str:
            raise ValueError("something went wrong")

        with pytest.raises(ValueError, match="something went wrong"):
            http_request(url="safe.com")

    @pytest.mark.asyncio
    async def test_async_function_exception_propagates_after_guard(self) -> None:
        """Async: if the function passes guard but raises, exception propagates."""
        guard = self._make_guard()

        @guard.verify()
        async def http_request(url: str) -> str:
            raise RuntimeError("async failure")

        with pytest.raises(RuntimeError, match="async failure"):
            await http_request(url="safe.com")

    def test_blocked_error_contains_result(self) -> None:
        guard = self._make_guard()

        @guard.verify()
        def http_request(url: str) -> str:
            return url

        with pytest.raises(ActionBlockedError) as exc_info:
            http_request(url="evil.com")

        assert exc_info.value.result.allowed is False
        assert len(exc_info.value.result.violations) > 0


# ── TestBuildActionFromCall ──


class TestBuildActionFromCall:
    """Tests for _build_action_from_call() helper."""

    def test_basic_kwargs(self) -> None:
        import inspect

        def fn(url: str, method: str = "GET") -> None: ...

        sig = inspect.signature(fn)
        action = _build_action_from_call(fn, sig, (), {"url": "example.com"})
        assert action.tool == "fn"
        assert action.args["url"] == "example.com"
        assert action.args["method"] == "GET"

    def test_positional_args(self) -> None:
        import inspect

        def fn(url: str, method: str) -> None: ...

        sig = inspect.signature(fn)
        action = _build_action_from_call(fn, sig, ("example.com", "POST"), {})
        assert action.args["url"] == "example.com"
        assert action.args["method"] == "POST"

    def test_mixed_positional_and_keyword(self) -> None:
        import inspect

        def fn(url: str, method: str = "GET") -> None: ...

        sig = inspect.signature(fn)
        action = _build_action_from_call(fn, sig, ("example.com",), {"method": "PUT"})
        assert action.args["url"] == "example.com"
        assert action.args["method"] == "PUT"

    def test_self_excluded(self) -> None:
        import inspect

        class Svc:
            def process(self, data: str) -> None: ...

        sig = inspect.signature(Svc.process)
        svc = Svc()
        action = _build_action_from_call(Svc.process, sig, (svc, "test"), {})
        assert "self" not in action.args
        assert action.args["data"] == "test"

    def test_cls_excluded(self) -> None:
        import inspect

        class Svc:
            @classmethod
            def process(cls, data: str) -> None: ...

        sig = inspect.signature(Svc.process)
        action = _build_action_from_call(Svc.process, sig, ("test",), {})
        assert "cls" not in action.args

    def test_defaults_applied(self) -> None:
        import inspect

        def fn(url: str, timeout: int = 30) -> None: ...

        sig = inspect.signature(fn)
        action = _build_action_from_call(fn, sig, (), {"url": "test"})
        assert action.args["timeout"] == 30

    def test_no_args_function(self) -> None:
        import inspect

        def fn() -> None: ...

        sig = inspect.signature(fn)
        action = _build_action_from_call(fn, sig, (), {})
        assert action.tool == "fn"
        assert action.args == {}

    def test_varargs_included(self) -> None:
        """*args are captured in action.args under 'args' key."""
        import inspect

        def fn(url: str, *extra: str) -> None: ...

        sig = inspect.signature(fn)
        action = _build_action_from_call(fn, sig, ("example.com", "a", "b"), {})
        assert action.args["url"] == "example.com"
        assert action.args["extra"] == ("a", "b")

    def test_varkwargs_included(self) -> None:
        """**kwargs are captured in action.args under 'kwargs' key."""
        import inspect

        def fn(url: str, **options: str) -> None: ...

        sig = inspect.signature(fn)
        action = _build_action_from_call(fn, sig, ("example.com",), {"timeout": "30"})
        assert action.args["url"] == "example.com"
        assert action.args["options"] == {"timeout": "30"}

    def test_varargs_and_varkwargs_combined(self) -> None:
        import inspect

        def fn(url: str, *args: str, **kwargs: str) -> None: ...

        sig = inspect.signature(fn)
        action = _build_action_from_call(fn, sig, ("example.com", "extra"), {"key": "val"})
        assert action.args["url"] == "example.com"
        assert action.args["args"] == ("extra",)
        assert action.args["kwargs"] == {"key": "val"}


# ── TestGuardParameterPrecedence ──


class TestGuardParameterPrecedence:
    """Tests for conflicting Guard.__init__ parameter handling."""

    def test_config_overrides_mode(self) -> None:
        """When both config and mode are given, config wins."""
        config = ConstraintConfig(mode=VerificationMode.SHADOW)
        guard = Guard(mode=VerificationMode.ENFORCE, config=config, registry=_make_registry())
        result = guard.check(_make_action())
        assert result.mode == VerificationMode.SHADOW

    def test_registry_overrides_constraints_dir(self) -> None:
        """When both registry and constraints_dir are given, registry wins."""
        c = _make_denylist_constraint(["evil.com"])
        guard = Guard(registry=_make_registry(c), constraints_dir="/nonexistent/path")
        assert len(guard.verifier.registry) == 1

    def test_config_overrides_constraints_param(self) -> None:
        """When both config and constraints are given, config determines packs."""
        config = ConstraintConfig(mode=VerificationMode.DISABLED)
        guard = Guard(constraints="nonexistent", config=config, registry=_make_registry())
        result = guard.check(_make_action())
        assert result.mode == VerificationMode.DISABLED


# ── TestGuardVerifyDecoratorEdgeCases ──


class TestGuardVerifyDecoratorEdgeCases:
    """Edge case tests for the verify() decorator."""

    def test_decorator_on_static_method(self) -> None:
        c = _make_denylist_constraint(["bad"], field="data", action="process")
        guard = Guard(registry=_make_registry(c))

        class MyService:
            @staticmethod
            @guard.verify()
            def process(data: str) -> str:
                return data

        assert MyService.process(data="good") == "good"
        with pytest.raises(ActionBlockedError):
            MyService.process(data="bad")

    def test_decorator_with_varargs(self) -> None:
        """Decorated function with *args works correctly."""
        c = _make_denylist_constraint(["evil.com"], field="url")
        guard = Guard(registry=_make_registry(c))

        @guard.verify()
        def http_request(url: str, *headers: str) -> str:
            return url

        assert http_request("safe.com", "Accept: */*") == "safe.com"
        with pytest.raises(ActionBlockedError):
            http_request("evil.com")

    def test_decorator_with_kwargs(self) -> None:
        """Decorated function with **kwargs works correctly."""
        c = _make_denylist_constraint(["evil.com"], field="url")
        guard = Guard(registry=_make_registry(c))

        @guard.verify()
        def http_request(url: str, **options: str) -> str:
            return url

        assert http_request(url="safe.com", timeout="30") == "safe.com"
        with pytest.raises(ActionBlockedError):
            http_request(url="evil.com")


# ── TestGuardTemporalStore ──


class TestGuardTemporalStore:
    """Tests for Guard temporal store integration."""

    def test_guard_passes_temporal_store_to_verifier(self) -> None:
        """Guard passes temporal_store to Verifier."""
        from munio._temporal import InMemoryTemporalStore

        store = InMemoryTemporalStore()
        guard = Guard(registry=_make_registry(), temporal_store=store)
        assert guard.verifier._temporal_store is store

    def test_guard_without_temporal_store_auto_creates(self) -> None:
        """Guard without temporal_store causes Verifier to auto-create one."""
        from munio._temporal import InMemoryTemporalStore

        guard = Guard(registry=_make_registry())
        assert guard.verifier._temporal_store is not None
        assert isinstance(guard.verifier._temporal_store, InMemoryTemporalStore)

    def test_two_guards_shared_store_rate_limit(self) -> None:
        """Two Guards sharing same store enforce rate limit across both."""
        from munio._temporal import InMemoryTemporalStore
        from tests.core.conftest import make_rate_limit_constraint

        store = InMemoryTemporalStore()
        c = make_rate_limit_constraint(max_count=2, window_seconds=60)
        guard_a = Guard(registry=_make_registry(c), temporal_store=store)
        guard_b = Guard(registry=_make_registry(c), temporal_store=store)

        # Call through guard_a
        result1 = guard_a.check(_make_action(tool="http_request"))
        assert result1.allowed is True
        # Call through guard_b
        result2 = guard_b.check(_make_action(tool="http_request"))
        assert result2.allowed is True
        # Third call through either guard should be blocked
        result3 = guard_a.check(_make_action(tool="http_request"))
        assert result3.allowed is False

    def test_separate_stores_independent_rate_limit(self) -> None:
        """Guards with separate stores have independent rate limits."""
        from munio._temporal import InMemoryTemporalStore
        from tests.core.conftest import make_rate_limit_constraint

        c = make_rate_limit_constraint(max_count=1, window_seconds=60)
        guard_a = Guard(registry=_make_registry(c), temporal_store=InMemoryTemporalStore())
        guard_b = Guard(registry=_make_registry(c), temporal_store=InMemoryTemporalStore())

        # Each guard has its own store — both first calls pass
        result_a = guard_a.check(_make_action(tool="http_request"))
        result_b = guard_b.check(_make_action(tool="http_request"))
        assert result_a.allowed is True
        assert result_b.allowed is True
        # Second call on each should be blocked (independent)
        result_a2 = guard_a.check(_make_action(tool="http_request"))
        result_b2 = guard_b.check(_make_action(tool="http_request"))
        assert result_a2.allowed is False
        assert result_b2.allowed is False

    def test_guard_temporal_store_sequence_deny(self) -> None:
        """Guard with temporal store enforces sequence deny."""
        from munio._temporal import InMemoryTemporalStore
        from tests.core.conftest import make_sequence_deny_constraint

        store = InMemoryTemporalStore()
        c = make_sequence_deny_constraint(steps=["read_file", "http_request"], scope="global")
        guard = Guard(registry=_make_registry(c), temporal_store=store)

        result1 = guard.check(_make_action(tool="read_file"))
        assert result1.allowed is True
        result2 = guard.check(_make_action(tool="http_request"))
        assert result2.allowed is False
