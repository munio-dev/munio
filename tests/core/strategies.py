"""Reusable Hypothesis strategies for munio property tests."""

from __future__ import annotations

import ast
import re
import string
from typing import Any

from hypothesis import strategies as st

from munio.models import (
    Action,
    MatchMode,
)

# ── Unicode character sets ────────────────────────────────────────────

ZERO_WIDTH_CHARS = "\u200b\u200c\u200d\ufeff\u00ad\u034f\u2060\u2061\u2062\u2063\u2064\u180e"
BIDI_CHARS = "\u200e\u200f\u202a\u202b\u202c\u202d\u202e\u2066\u2067\u2068\u2069"
CONTROL_CHARS = "\x00\x1b"
VARIATION_SELECTORS = "".join(chr(c) for c in range(0xFE00, 0xFE10))
# NOTE: _STRIP_CHARS in solver.py also includes surrogates (U+D800-U+DFFF),
# but Python st.text() cannot generate lone surrogates, so they are excluded here.
STRIP_ALPHABET = ZERO_WIDTH_CHARS + BIDI_CHARS + CONTROL_CHARS + VARIATION_SELECTORS


# ── String strategies ─────────────────────────────────────────────────

# Strings with zero-width/bidi/control chars interleaved with ASCII
st_adversarial_unicode = st.text(
    alphabet=st.sampled_from(
        list(string.ascii_letters + string.digits + "./-_@") + list(STRIP_ALPHABET)
    ),
    min_size=0,
    max_size=200,
)

# Arbitrary unicode (full BMP)
st_any_unicode = st.text(min_size=0, max_size=500)

# Pure ASCII a-z A-Z 0-9
st_ascii_alphanumeric = st.text(
    alphabet=string.ascii_letters + string.digits,
    min_size=1,
    max_size=100,
)

# Fullwidth Latin characters (NFKC → ASCII, 1:1 length)
st_fullwidth = st.text(
    alphabet="".join(chr(c) for c in range(0xFF01, 0xFF5F)),
    min_size=1,
    max_size=50,
)


# ── Leaf value strategy ──────────────────────────────────────────────


def st_leaf_value() -> st.SearchStrategy[Any]:
    """Strategy for leaf values in args dicts."""
    return st.one_of(
        st.text(min_size=0, max_size=50),
        st.integers(min_value=-10_000, max_value=10_000),
        st.floats(allow_nan=False, allow_infinity=False, min_value=-1e6, max_value=1e6),
        st.booleans(),
        st.none(),
    )


# ── Nested dict strategy ─────────────────────────────────────────────


@st.composite
def st_nested_dict(
    draw: st.DrawFn,
    max_depth: int = 3,
    max_breadth: int = 4,
) -> dict[str, Any]:
    """Strategy for nested dicts with scalar leaves."""
    keys = draw(
        st.lists(
            st.text(alphabet=string.ascii_lowercase, min_size=1, max_size=8),
            min_size=0,
            max_size=max_breadth,
            unique=True,
        )
    )
    result: dict[str, Any] = {}
    for key in keys:
        if max_depth <= 1 or draw(st.booleans()):
            result[key] = draw(st_leaf_value())
        else:
            result[key] = draw(st_nested_dict(max_depth=max_depth - 1, max_breadth=max_breadth))
    return result


# ── Constraint name strategy ─────────────────────────────────────────

st_constraint_name = st.from_regex(
    re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9_.\-]{0,99}$"),
    fullmatch=True,
)


# ── Action strategy ──────────────────────────────────────────────────

st_tool_name = st.text(
    alphabet=string.ascii_lowercase + "_",
    min_size=1,
    max_size=30,
).filter(lambda s: s[0] != "_")


@st.composite
def st_action(draw: st.DrawFn) -> Action:
    """Strategy for valid Action objects."""
    tool = draw(st_tool_name)
    args = draw(st_nested_dict(max_depth=2, max_breadth=4))
    return Action(tool=tool, args=args)


# ── Match mode strategies ────────────────────────────────────────────

st_non_regex_match_mode = st.sampled_from(
    [
        MatchMode.EXACT,
        MatchMode.CONTAINS,
        MatchMode.PREFIX,
        MatchMode.SUFFIX,
    ]
)


# ── Numeric strategies (for COMPOSITE tests) ───────────────────────────

# Practical-range integers and floats
st_numeric_value = st.one_of(
    st.integers(min_value=-10_000, max_value=10_000),
    st.floats(allow_nan=False, allow_infinity=False, min_value=-1e6, max_value=1e6),
)

# Adversarial numeric inputs: NaN, Inf, booleans, non-numeric types
st_adversarial_numeric: st.SearchStrategy[Any] = st.one_of(
    st.just(float("nan")),
    st.just(float("inf")),
    st.just(float("-inf")),
    st.booleans(),
    st.none(),
    st.lists(st.integers(), min_size=0, max_size=3),
    st.dictionaries(st.text(max_size=5), st.integers(), max_size=2),
    st.text(min_size=0, max_size=20),
    st.just("nan"),
    st.just("inf"),
)

# Sampled valid boolean expressions using two variables (x, y)
_SIMPLE_EXPRESSIONS = [
    "x + y <= 10000",
    "x * y <= 10000",
    "x - y >= 0",
    "x >= 0",
    "y >= 0",
    "x + y >= 0",
    "x <= 10000",
    "y <= 10000",
    "x >= 0 and y >= 0",
    "x + y > 0 or x == 0",
]
st_simple_expression = st.sampled_from(_SIMPLE_EXPRESSIONS)


def _extract_variable_names(expression: str) -> set[str]:
    """Extract variable names from an expression using AST (not regex)."""
    try:
        tree = ast.parse(expression, mode="eval")
    except SyntaxError:
        return set()
    return {node.id for node in ast.walk(tree) if isinstance(node, ast.Name)}


@st.composite
def st_composite_constraint_and_args(
    draw: st.DrawFn,
) -> tuple[dict[str, dict[str, Any]], str, dict[str, Any]]:
    """Generate (variables_dict, expression, args_dict) for COMPOSITE tests.

    Returns a tuple suitable for building a COMPOSITE constraint and action args.
    Variable names are extracted from the expression using AST walking.
    """
    expression = draw(st_simple_expression)
    var_names = _extract_variable_names(expression)

    variables: dict[str, dict[str, Any]] = {}
    args: dict[str, Any] = {}
    for name in sorted(var_names):
        val = draw(st_numeric_value)
        variables[name] = {"field": name, "type": "int", "min": -10000, "max": 10000}
        args[name] = val

    return variables, expression, args
