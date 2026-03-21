"""Z3 regex translator and utility functions for L4 formal verification.

Translates Python regex patterns (via ``sre_parse`` AST) to Z3 regex
expressions for formal constraint verification.  Adapted from
munio's ``_z3_regex.py`` for scanning context.

Key difference from munio core: uses ``AllChar()`` for ``.`` (analysis,
not enforcement).  This avoids Z3 returning ``unknown`` for complex
``Intersect/Complement`` expressions.

All ``z3`` imports are lazy (inside functions) to support optional Z3
dependency.
"""

from __future__ import annotations

from typing import Any

__all__ = [
    "check_intersection",
    "check_satisfiability",
    "make_attack_regex",
    "pattern_to_z3",
    "pattern_to_z3_search",
    "z3_available",
]


def _has_end_anchor(pattern: str) -> bool:
    """Check if pattern ends with an unescaped ``$`` anchor.

    Counts consecutive backslashes before the ``$``.  Even count means
    the ``$`` is unescaped (is an anchor); odd count means the ``$``
    itself is escaped (literal dollar sign).
    """
    if not pattern.endswith("$"):
        return False
    bs_count = 0
    for ch in reversed(pattern[:-1]):
        if ch == "\\":
            bs_count += 1
        else:
            break
    return bs_count % 2 == 0


def z3_available() -> bool:
    """Check if Z3 is importable."""
    try:
        import z3  # type: ignore[import-untyped]  # noqa: F401

        return True
    except ImportError:
        return False


def pattern_to_z3(pattern: str) -> Any:
    """Translate a Python regex pattern to Z3 regex expression.

    Uses sre_parse to decompose the pattern into an AST, then maps
    each node to Z3 regex constructors.

    Anchors ``^`` and ``$`` are stripped since Z3 ``InRe()`` has
    fullmatch semantics.

    Raises:
        ValueError: If pattern uses unsupported features (including
            case-insensitive ``(?i)`` flag which Z3 cannot represent).
        re.error: If pattern is invalid regex.
    """
    import re
    import re._parser as sre_parse  # type: ignore[import-untyped,import-not-found]

    # C1 fix: Detect case-insensitive flag — Z3 regex is always
    # case-sensitive, so (?i) would silently produce false SAFE results.
    try:
        compiled = re.compile(pattern)
    except re.error:
        raise
    if compiled.flags & re.IGNORECASE:
        msg = (
            "Case-insensitive flag (re.IGNORECASE / (?i)) is not supported "
            "in Z3 regex: would produce unsound case-sensitive analysis"
        )
        raise ValueError(msg)

    # Strip anchors (Z3 InRe = fullmatch)
    stripped = pattern
    if stripped.startswith("^"):
        stripped = stripped[1:]
    if _has_end_anchor(stripped):
        stripped = stripped[:-1]

    parsed = sre_parse.parse(stripped)
    return _sre_to_z3(parsed)


def pattern_to_z3_search(pattern: str) -> Any:
    """Translate pattern to Z3 regex with JSON Schema search semantics.

    JSON Schema ``pattern`` uses ECMA-262 ``test()`` which has search
    (not fullmatch) semantics.  Unanchored patterns match if the regex
    appears anywhere in the string.

    Wraps unanchored sides with ``Full()`` to model search behavior:
      - ``^...$`` → fullmatch (both anchors)
      - ``^...``  → anchored start, anything after
      - ``...$``  → anything before, anchored end
      - ``...``   → search anywhere

    Raises:
        ValueError: If pattern uses unsupported features.
        re.error: If pattern is invalid regex.
    """
    has_start_anchor = pattern.startswith("^")
    has_end_anchor = _has_end_anchor(pattern)

    result = pattern_to_z3(pattern)

    # Fully anchored = fullmatch semantics already correct
    if has_start_anchor and has_end_anchor:
        return result

    import z3

    rs = z3.ReSort(z3.StringSort())

    if not has_start_anchor and not has_end_anchor:
        return z3.Concat(z3.Full(rs), result, z3.Full(rs))
    if not has_start_anchor:
        return z3.Concat(z3.Full(rs), result)
    # not has_end_anchor
    return z3.Concat(result, z3.Full(rs))


def make_attack_regex(substrings: list[str]) -> Any:
    """Build Z3 regex matching any string containing any of the substrings.

    Returns ``Concat(Full(), Union(Re(s1), Re(s2), ...), Full())``:
    any string that contains at least one of the given substrings.

    Raises:
        ValueError: If *substrings* is empty.
    """
    if not substrings:
        msg = "make_attack_regex requires at least one substring"
        raise ValueError(msg)

    import z3

    rs = z3.ReSort(z3.StringSort())
    parts = [z3.Re(z3.StringVal(s)) for s in substrings]
    inner = parts[0] if len(parts) == 1 else z3.Union(*parts)
    return z3.Concat(z3.Full(rs), inner, z3.Full(rs))


def check_intersection(
    pattern_z3: Any,
    attack_z3: Any,
    *,
    timeout_ms: int = 5000,
    max_length: int | None = None,
) -> tuple[str, str | None]:
    """Check if the intersection of pattern and attack regexes is non-empty.

    Returns:
        ``(result, counterexample)`` where result is ``"sat"``/``"unsat"``/
        ``"unknown"`` and counterexample is the model value if sat.
    """
    import z3

    s = z3.String("s")
    solver = z3.Solver()
    solver.set("timeout", timeout_ms)

    solver.add(z3.InRe(s, z3.Intersect(pattern_z3, attack_z3)))

    if max_length is not None:
        solver.add(z3.Length(s) <= max_length)

    result = solver.check()
    if result == z3.sat:
        model = solver.model()
        val = model[s]
        counterexample = val.as_string() if val is not None else None
        return "sat", counterexample
    if result == z3.unsat:
        return "unsat", None
    return "unknown", None


def check_satisfiability(
    pattern_z3: Any,
    *,
    min_length: int | None = None,
    max_length: int | None = None,
    timeout_ms: int = 5000,
) -> str:
    """Check if a string satisfying both pattern and length constraints exists.

    Returns ``"sat"``, ``"unsat"``, or ``"unknown"``.
    """
    import z3

    s = z3.String("s")
    solver = z3.Solver()
    solver.set("timeout", timeout_ms)

    solver.add(z3.InRe(s, pattern_z3))
    if min_length is not None:
        solver.add(z3.Length(s) >= min_length)
    if max_length is not None:
        solver.add(z3.Length(s) <= max_length)

    result = solver.check()
    if result == z3.sat:
        return "sat"
    if result == z3.unsat:
        return "unsat"
    return "unknown"


# ── Internal: sre_parse to Z3 translator ──────────────────────────────

# Cap explicit loop bounds to prevent Z3 memory exhaustion.
# `a{1,1000000}` expands to a massive Z3 AST.  1000 iterations is
# more than enough for any realistic JSON Schema pattern.
_MAX_LOOP_BOUND = 1000


def _sre_to_z3(parsed: Any) -> Any:
    """Recursively convert sre_parse AST to Z3 regex.

    Optimisations:
    - Consecutive LITERAL ops merged into single ``Re(StringVal("..."))``.
    - ``.*`` uses ``Full()`` for native Z3 performance.
    - ``.`` uses ``AllChar()`` (analysis context, not enforcement).
    """
    import re._parser as sre_parse

    import z3

    # Python 3.11+ atomic groups — attribute may not exist on older versions.
    atomic_group: int | None = getattr(sre_parse, "ATOMIC_GROUP", None)

    rs = z3.ReSort(z3.StringSort())
    items = list(parsed)
    parts: list[Any] = []
    i = 0

    while i < len(items):
        op, av = items[i]

        if op == sre_parse.LITERAL:
            # Merge consecutive LITERALs
            chars = [chr(av)]
            while i + 1 < len(items) and items[i + 1][0] == sre_parse.LITERAL:
                i += 1
                chars.append(chr(items[i][1]))
            parts.append(z3.Re(z3.StringVal("".join(chars))))

        elif op == sre_parse.NOT_LITERAL:
            char_re = z3.Re(z3.StringVal(chr(av)))
            parts.append(z3.Intersect(z3.AllChar(rs), z3.Complement(char_re)))

        elif op == sre_parse.ANY:
            # Analysis context: AllChar matches all characters including \n.
            parts.append(z3.AllChar(rs))

        elif op in (sre_parse.MAX_REPEAT, sre_parse.MIN_REPEAT):
            lo, hi, subpattern = av
            sub_list = list(subpattern)
            is_any = len(sub_list) == 1 and sub_list[0][0] == sre_parse.ANY

            if lo == 0 and hi == sre_parse.MAXREPEAT:
                if is_any:
                    parts.append(z3.Full(rs))
                else:
                    parts.append(z3.Star(_sre_to_z3(subpattern)))
            elif lo == 1 and hi == sre_parse.MAXREPEAT:
                if is_any:
                    parts.append(z3.Plus(z3.AllChar(rs)))
                else:
                    parts.append(z3.Plus(_sre_to_z3(subpattern)))
            elif lo == 0 and hi == 1:
                parts.append(z3.Option(_sre_to_z3(subpattern)))
            elif hi == sre_parse.MAXREPEAT:
                # {n,} = at least n: Loop(n,n) + Star for unbounded tail
                sub_z3 = _sre_to_z3(subpattern)
                capped_lo = min(lo, _MAX_LOOP_BOUND)
                parts.append(z3.Concat(z3.Loop(sub_z3, capped_lo, capped_lo), z3.Star(sub_z3)))
            else:
                # Cap hi to prevent Z3 memory exhaustion on patterns
                # like a{1,1000000} which expand to huge ASTs.
                # Also cap lo to capped_hi: Loop(lo > hi) = empty
                # language = false SAFE soundness bug.
                capped_hi = min(hi, _MAX_LOOP_BOUND)
                capped_lo = min(lo, capped_hi)
                parts.append(z3.Loop(_sre_to_z3(subpattern), capped_lo, capped_hi))

        elif op == sre_parse.SUBPATTERN:
            _, add_flags, del_flags, subpattern = av
            if add_flags or del_flags:
                msg = (
                    f"Inline regex flags (add={add_flags:#x}, del={del_flags:#x}) "
                    "are not supported in Z3 regex"
                )
                raise ValueError(msg)
            parts.append(_sre_to_z3(subpattern))

        elif atomic_group is not None and op == atomic_group:
            # Atomic group (?>...) — Z3 has no backtracking, so atomic
            # vs non-atomic is semantically equivalent for our analysis.
            parts.append(_sre_to_z3(av))

        elif op == sre_parse.BRANCH:
            _, branches = av
            branch_z3 = [_sre_to_z3(b) for b in branches]
            if len(branch_z3) == 1:
                parts.append(branch_z3[0])
            else:
                parts.append(z3.Union(*branch_z3))

        elif op == sre_parse.IN:
            parts.append(_sre_charset_to_z3(av))

        elif op == sre_parse.AT:
            # ^ and $ anchors: safe to skip (Z3 InRe = fullmatch)
            if av in (sre_parse.AT_BOUNDARY, sre_parse.AT_NON_BOUNDARY):
                msg = "Word boundary \\b/\\B is not supported in Z3 regex"
                raise ValueError(msg)

        elif op in (sre_parse.ASSERT, sre_parse.ASSERT_NOT):
            msg = "Lookahead/lookbehind assertions are not supported in Z3 regex"
            raise ValueError(msg)

        elif op == sre_parse.GROUPREF:
            msg = "Backreferences are not supported in Z3 regex"
            raise ValueError(msg)

        else:
            msg = f"Unsupported regex feature: {op}"
            raise ValueError(msg)

        i += 1

    if not parts:
        return z3.Re(z3.StringVal(""))
    if len(parts) == 1:
        return parts[0]
    return z3.Concat(*parts)


def _sre_charset_to_z3(charset: list[Any]) -> Any:
    """Convert sre_parse character class ``[...]`` to Z3 regex."""
    import re._parser as sre_parse

    import z3

    rs = z3.ReSort(z3.StringSort())
    negate = False
    members: list[Any] = []

    for op, av in charset:
        if op == sre_parse.NEGATE:
            negate = True
        elif op == sre_parse.LITERAL:
            members.append(z3.Re(z3.StringVal(chr(av))))
        elif op == sre_parse.RANGE:
            lo_char, hi_char = av
            members.append(z3.Range(chr(lo_char), chr(hi_char)))
        elif op == sre_parse.CATEGORY:
            members.append(_sre_category_to_z3(av))
        else:
            msg = f"Unsupported character class element: {op}"
            raise ValueError(msg)

    if not members:
        combined = z3.Re(z3.StringVal(""))
    elif len(members) == 1:
        combined = members[0]
    else:
        combined = z3.Union(*members)

    if negate:
        combined = z3.Intersect(z3.AllChar(rs), z3.Complement(combined))

    return combined


def _sre_category_to_z3(category: int) -> Any:
    """Map sre_parse category constants to Z3 regex."""
    import re._parser as sre_parse

    import z3

    if category == sre_parse.CATEGORY_DIGIT:
        return z3.Range("0", "9")
    if category == sre_parse.CATEGORY_NOT_DIGIT:
        msg = (
            r"Negated category \D is not supported in Z3 regex: "
            "ASCII vs Unicode mismatch can cause unsound results"
        )
        raise ValueError(msg)
    if category == sre_parse.CATEGORY_WORD:
        return z3.Union(
            z3.Range("a", "z"),
            z3.Range("A", "Z"),
            z3.Range("0", "9"),
            z3.Re(z3.StringVal("_")),
        )
    if category == sre_parse.CATEGORY_NOT_WORD:
        msg = (
            r"Negated category \W is not supported in Z3 regex: "
            "ASCII vs Unicode mismatch can cause unsound results"
        )
        raise ValueError(msg)
    if category == sre_parse.CATEGORY_SPACE:
        return z3.Union(
            z3.Re(z3.StringVal(" ")),
            z3.Re(z3.StringVal("\t")),
            z3.Re(z3.StringVal("\n")),
            z3.Re(z3.StringVal("\r")),
            z3.Re(z3.StringVal("\f")),
            z3.Re(z3.StringVal("\v")),
        )
    if category == sre_parse.CATEGORY_NOT_SPACE:
        msg = (
            r"Negated category \S is not supported in Z3 regex: "
            "ASCII vs Unicode mismatch can cause unsound results"
        )
        raise ValueError(msg)
    msg = f"Unsupported regex category: {category}"
    raise ValueError(msg)
