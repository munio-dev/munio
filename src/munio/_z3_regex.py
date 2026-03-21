"""Python regex to Z3 regex translator.

Translates Python regex patterns (via ``sre_parse`` AST) to Z3 regex
expressions.  Used exclusively by ``PolicyVerifier._check_filter_completeness``
for deploy-time FILTER_COMPLETENESS checks.

Supported features: literals, ``.``, ``*``, ``+``, ``?``, ``{n,m}``, ``|``,
character classes ``[a-z]``/``[^...]``, ``\\d``, ``\\s``, ``\\w``, groups.

Unsupported (raises ``ValueError``): backreferences, lookahead/lookbehind,
inline flags ``(?i)``/``(?s)``, ``\\b``/``\\B`` word boundaries,
negated categories ``\\D``/``\\W``/``\\S`` (ASCII vs Unicode mismatch).

All ``z3`` and ``sre_parse`` imports are lazy (inside functions) to support
subprocess isolation and optional Z3 dependency.
"""

from __future__ import annotations

from typing import Any

__all__ = [
    "_regex_to_z3",
    "_sre_category_to_z3",
    "_sre_charset_to_z3",
    "_sre_to_z3",
    "_z3_dot",
]


def _regex_to_z3(pattern: str) -> Any:
    """Translate a Python regex pattern to a Z3 regex expression.

    Uses sre_parse to decompose the pattern into an AST, then maps
    each AST node to the corresponding Z3 regex constructor.

    Supported: literals, ., *, +, ?, {n,m}, |, [a-z], [^...], \\d, \\s, \\w, groups.
    Unsupported (raises ValueError): backreferences, lookahead/behind, flags.
    """
    import re._parser as sre_parse  # type: ignore[import-untyped,import-not-found,unused-ignore]

    parsed = sre_parse.parse(pattern)
    return _sre_to_z3(parsed)


def _z3_dot() -> Any:
    """Z3 regex equivalent of Python's ``.`` (without DOTALL).

    Matches any character EXCEPT newline, matching Python's default ``.``
    semantics.  Using bare ``AllChar`` is a soundness bug: Z3's AllChar
    matches ``\\n``, but Python's ``.`` does not — causing
    FILTER_COMPLETENESS to report false SAFE when attackers inject newlines.
    """
    import z3  # type: ignore[import-untyped]

    return z3.Intersect(
        z3.AllChar(z3.ReSort(z3.StringSort())),
        z3.Complement(z3.Re(z3.StringVal("\n"))),
    )


def _sre_to_z3(parsed: Any) -> Any:
    """Recursively convert sre_parse AST to Z3 regex.

    Optimisations for Z3 string theory performance:
    - Consecutive LITERAL ops are merged into a single Re(StringVal("..."))
    - .* (Star of ANY) uses Star(_z3_dot()) to match Python's default semantics
    """
    import re._parser as sre_parse

    import z3

    items = list(parsed)
    parts: list[Any] = []
    i = 0

    while i < len(items):
        op, av = items[i]

        # Merge consecutive LITERALs into a single Re(StringVal("..."))
        if op == sre_parse.LITERAL:
            chars = [chr(av)]
            while i + 1 < len(items) and items[i + 1][0] == sre_parse.LITERAL:
                i += 1
                chars.append(chr(items[i][1]))
            parts.append(z3.Re(z3.StringVal("".join(chars))))
        elif op == sre_parse.NOT_LITERAL:
            char_re = z3.Re(z3.StringVal(chr(av)))
            parts.append(
                z3.Intersect(z3.AllChar(z3.ReSort(z3.StringSort())), z3.Complement(char_re))
            )
        elif op == sre_parse.ANY:
            # Python's . does NOT match \n without DOTALL, but Z3's AllChar
            # matches everything.  This is SOUND because _sanitize_string()
            # strips \n (and all C0 controls) before runtime matching, so
            # real inputs never contain \n.  Using AllChar avoids Z3 returning
            # 'unknown' for complex Intersect/Complement expressions.
            parts.append(z3.AllChar(z3.ReSort(z3.StringSort())))
        elif op == sre_parse.MAX_REPEAT or op == sre_parse.MIN_REPEAT:
            lo, hi, subpattern = av
            # Optimisation: .* → Full() which Z3 handles natively
            sub_list = list(subpattern)
            is_any = len(sub_list) == 1 and sub_list[0][0] == sre_parse.ANY
            if lo == 0 and hi == sre_parse.MAXREPEAT:
                if is_any:
                    parts.append(z3.Full(z3.ReSort(z3.StringSort())))
                else:
                    parts.append(z3.Star(_sre_to_z3(subpattern)))
            elif lo == 1 and hi == sre_parse.MAXREPEAT:
                if is_any:
                    parts.append(z3.Plus(z3.AllChar(z3.ReSort(z3.StringSort()))))
                else:
                    parts.append(z3.Plus(_sre_to_z3(subpattern)))
            elif lo == 0 and hi == 1:
                parts.append(z3.Option(_sre_to_z3(subpattern)))
            elif hi == sre_parse.MAXREPEAT:
                # {n,} = at least n repetitions.  Encode as Loop(n,n) + Star
                # instead of truncating to {n, n+50} which causes false SAFE
                # for strings longer than n+50 chars.
                sub_z3 = _sre_to_z3(subpattern)
                parts.append(z3.Concat(z3.Loop(sub_z3, lo, lo), z3.Star(sub_z3)))
            else:
                parts.append(z3.Loop(_sre_to_z3(subpattern), lo, hi))
        elif op == sre_parse.SUBPATTERN:
            _, add_flags, del_flags, subpattern = av
            # Reject inline flags like (?i), (?s), (?m) — silently
            # dropping them changes semantics (e.g. (?s) makes . match \n,
            # (?i) makes matching case-insensitive). Z3 cannot model flags.
            if add_flags or del_flags:
                msg = (
                    f"Inline regex flags (add={add_flags:#x}, del={del_flags:#x}) are not "
                    "supported in Z3 regex — use case_sensitive constraint field instead"
                )
                raise ValueError(msg)
            parts.append(_sre_to_z3(subpattern))
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
            # ^, $ anchors: safe to skip (Z3 regex matches full string)
            # \b word boundary: NOT safe — dropping it broadens the pattern,
            # which can cause false SAFE in FILTER_COMPLETENESS
            if av in (sre_parse.AT_BOUNDARY, sre_parse.AT_NON_BOUNDARY):
                msg = "Word boundary \\b / \\B is not supported in Z3 regex (dropping it changes semantics)"
                raise ValueError(msg)
        elif op == sre_parse.ASSERT or op == sre_parse.ASSERT_NOT:
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
    """Convert sre_parse character class [...] to Z3 regex."""
    import re._parser as sre_parse

    import z3

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
        combined = z3.Intersect(
            z3.AllChar(z3.ReSort(z3.StringSort())),
            z3.Complement(combined),
        )

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
            "Z3 uses ASCII-only definition while Python matches Unicode digits. "
            "The mismatch can cause false SAFE results for deny patterns."
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
            "Z3 uses ASCII-only definition while Python matches Unicode word chars. "
            "The mismatch can cause false SAFE results for deny patterns."
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
            "Z3 uses ASCII-only definition while Python matches Unicode whitespace. "
            "The mismatch can cause false SAFE results for deny patterns."
        )
        raise ValueError(msg)
    msg = f"Unsupported regex category: {category}"
    raise ValueError(msg)
