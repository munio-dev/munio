"""L3 Static Analysis: semantic parameter analysis for MCP tool definitions.

Maps parameter name semantics to attack vectors and checks if the JSON Schema
provides adequate protection for each semantic category.  Reuses tool context
from L5 ``classify_tool()`` to reduce false positives (e.g. ``query`` param on
a search tool is not SQL injection).

Checks:
  L3_001  Path traversal risk (path/file params without traversal-rejecting pattern)
  L3_002  SSRF/URL risk (url/uri params without format or restrictive pattern)
  L3_003  SQL injection risk (query/sql params in DB-context tools)
  L3_004  Command injection risk (command/script/exec params without enum)
  L3_005  Unbounded array DoS (array without maxItems)
  L3_006  Boolean security bypass (force/unsafe/skip_auth boolean params)
  L3_007  Weak regex constraint (unanchored or overly broad pattern)
  L3_008  Conflicting schema constraints (min>max, empty enum)
  L3_009  Template injection risk (template/format_string/jinja params)
  L3_010  Dangerous numeric param (limit/timeout/port without bounds)
  L3_011  Schema poisoning (tool descriptions with LLM manipulation instructions)
  L3_012  Credential exposure (password/token/api_key params without writeOnly)
  L3_013  Insecure defaults (dangerous boolean defaults like recursive=true)
  L3_014  Unconfirmed destructive operations (delete/drop/purge without confirmation)
  L3_015  Cross-tenant ID without validation (user_id/tenant_id without UUID format)
  L3_016  Mass assignment via additionalProperties (arbitrary field injection)
  L3_017  Raw infrastructure parameters (K8s/Docker/Terraform strings)
  L3_018  Privilege escalation parameters (role/permission without enum)
  L3_019  Unsafe deserialization format (yaml/pickle/protobuf strings)
"""

from __future__ import annotations

import logging
import re
import unicodedata
from typing import TYPE_CHECKING, Any

from munio.scan.layers.composition_taxonomy import Capability, classify_tool
from munio.scan.models import (
    AttackType,
    Finding,
    FindingSeverity,
    Layer,
    ToolDefinition,
)

if TYPE_CHECKING:
    from collections.abc import Sequence

logger = logging.getLogger(__name__)

# ── Constants ────────────────────────────────────────────────────────────

_MAX_RECURSION_DEPTH = 10
_MAX_PROPERTIES = 200
_MAX_NODES_PER_TOOL = 500
_MAX_FINDINGS_PER_TOOL = 100
_MAX_PARAM_NAME_LEN = 256

# ── Confusables (duplicated from L1 for layer independence) ──────────────

_CONFUSABLES: dict[str, str] = {
    "\u0430": "a",
    "\u0435": "e",
    "\u043e": "o",
    "\u0440": "p",
    "\u0441": "c",
    "\u0443": "y",
    "\u0445": "x",
    "\u0455": "s",
    "\u0456": "i",
    "\u03bf": "o",
}

# camelCase boundary: lowercase followed by uppercase
_CAMEL_RE = re.compile(r"([a-z])([A-Z])")


def _normalize_param_name(name: str) -> str:
    """Strip zero-width/format chars, split camelCase, replace confusables, NFKC, casefold.

    Hyphens and dots are normalized to underscores so that compound name
    matching and exclusion sets work uniformly (e.g. ``role-arn`` → ``role_arn``).
    """
    # Truncate to prevent DoS on long names
    truncated = name[:_MAX_PARAM_NAME_LEN]
    stripped = "".join(c for c in truncated if unicodedata.category(c) != "Cf")
    # Insert _ at camelCase boundaries BEFORE casefolding
    with_separators = _CAMEL_RE.sub(r"\1_\2", stripped)
    normalized = unicodedata.normalize("NFKC", with_separators)
    # Casefold BEFORE confusable replacement so uppercase Cyrillic (U+0410 etc.)
    # is lowered to U+0430 etc. and then caught by the confusables map
    casefolded = normalized.casefold()
    replaced = "".join(_CONFUSABLES.get(c, c) for c in casefolded)
    # Normalize separators: hyphens and dots → underscores
    return replaced.replace("-", "_").replace(".", "_")


def _split_segments(name: str) -> list[str]:
    """Split normalized param name into segments on ``_``, ``-``, and ``.``."""
    return [s for s in re.split(r"[_\-.]", name) if s]


# ── Type resolution ──────────────────────────────────────────────────────


def _resolve_type(param_def: dict[str, Any]) -> str | None:
    """Resolve the effective type of a parameter definition.

    Handles:
      - Simple types: ``{"type": "string"}`` -> ``"string"``
      - Union types: ``{"type": ["string", "null"]}`` -> ``"string"``
      - anyOf/oneOf nullable: ``{"anyOf": [{"type": "string"}, {"type": "null"}]}`` -> ``"string"``

    Returns the primary non-null type, or None if truly unknown/ambiguous.
    """
    t = param_def.get("type")
    if isinstance(t, str):
        return t
    if isinstance(t, list):
        non_null = [x for x in t if isinstance(x, str) and x != "null"]
        if len(non_null) == 1:
            return non_null[0]
        return None
    # No type field: check anyOf/oneOf for simple nullable pattern
    for kw in ("anyOf", "oneOf"):
        subs = param_def.get(kw)
        if isinstance(subs, list):
            types: list[str] = []
            for sub in subs:
                if isinstance(sub, dict):
                    st = sub.get("type")
                    if isinstance(st, str):
                        types.append(st)
            non_null_types = [tp for tp in types if tp != "null"]
            if len(non_null_types) == 1:
                return non_null_types[0]
    return None


def _type_allows(param_def: dict[str, Any], target: str) -> bool:
    """Check if param type is or may be ``target`` type.

    Returns True when the type is explicitly ``target``, a union containing
    ``target``, an anyOf/oneOf resolving to ``target``, OR when the type is
    completely unknown (conservative: assume it could be anything).
    """
    resolved = _resolve_type(param_def)
    if resolved is None:
        return True  # unknown type = could be anything
    return resolved == target


# ── L3_001: Path parameter keywords and exclusions ──────────────────────

_PATH_SEGMENTS: frozenset[str] = frozenset(
    {
        "path",
        "file",
        "filepath",
        "filename",
        "directory",
        "dir",
        "folder",
        "dirname",
        "dirpath",
        "pathname",
        "fpath",
    }
)

_PATH_COMPOUND_NAMES: frozenset[str] = frozenset(
    {
        "file_path",
        "filepath",
        "file_name",
        "filename",
        "dir_path",
        "dirpath",
        "dir_name",
        "dirname",
        "dest_path",
        "src_path",
        "source_path",
        "target_path",
        "base_path",
        "root_path",
        "working_dir",
        "workdir",
        "base_dir",
        "output_path",
        "input_path",
        "log_path",
        "config_file",
        "output_file",
        "input_file",
    }
)

_PATH_EXCLUSIONS: frozenset[str] = frozenset(
    {
        "xpath",
        "jsonpath",
        "jmespath",
        "classpath",
        "keypath",
        "datapath",
        "apipath",
        "objectpath",
        "schemapath",
        "json_path",
        "key_path",
        "data_path",
        "api_path",
        "object_path",
        "schema_path",
        "class_path",
    }
)

# ── L3_002: URL parameter keywords ──────────────────────────────────────

_URL_SEGMENTS: frozenset[str] = frozenset(
    {
        "url",
        "uri",
        "href",
        "endpoint",
        "webhook",
    }
)

_URL_COMPOUND_NAMES: frozenset[str] = frozenset(
    {
        "callback_url",
        "redirect_url",
        "target_url",
        "base_url",
        "api_url",
        "webhook_url",
        "redirect_uri",
        "return_url",
        "success_url",
        "next_url",
    }
)

# ── L3_003: SQL parameter keywords ──────────────────────────────────────

_SQL_SEGMENTS: frozenset[str] = frozenset(
    {
        "sql",
        "query",
        "where",
        "statement",
    }
)

_SQL_COMPOUND_NAMES: frozenset[str] = frozenset(
    {
        "sql_query",
        "where_clause",
        "filter_expression",
        "sql_statement",
    }
)

# DB capabilities from L5 classify_tool()
_DB_CAPS: frozenset[Capability] = frozenset(
    {
        Capability.DB_READ,
        Capability.DB_WRITE,
    }
)

# ── L3_004: Command/code injection keywords ─────────────────────────────

_COMMAND_SEGMENTS: frozenset[str] = frozenset(
    {
        "command",
        "cmd",
        "script",
        "shell",
        "exec",
        "execute",
        "evaluate",
        "eval",
        "function",
        "expression",
        "program",
    }
)

_COMMAND_COMPOUND_NAMES: frozenset[str] = frozenset(
    {
        "shell_command",
        "bash_command",
        "run_command",
    }
)

# Exclude compounds where "code"/"function"/"expression" means identifier/name
_CODE_EXCLUSIONS: frozenset[str] = frozenset(
    {
        "country_code",
        "status_code",
        "zip_code",
        "error_code",
        "postal_code",
        "area_code",
        "currency_code",
        "language_code",
        "region_code",
        "exit_code",
        "response_code",
        "http_code",
        "color_code",
        "colour_code",
        "char_code",
        "key_code",
        "op_code",
        "opcode",
        "barcode",
        "qr_code",
        "iso_code",
        "dialing_code",
        "calling_code",
        "source_code",
        "auth_code",
        "access_code",
        "verification_code",
        "invite_code",
        "discount_code",
        "product_code",
        "category_code",
        "tracking_code",
        "promo_code",
        "referral_code",
        "voucher_code",
        # "function" as identifier/name
        "function_name",
        "function_id",
        "callback_function",
        # "expression" as name/reference
        "cron_expression",
        "regular_expression",
        "regex_expression",
        "filter_expression",
        "math_expression",
    }
)

# ── L3_006: Boolean security bypass patterns ────────────────────────────

_BYPASS_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"^force_delete$"),
    re.compile(r"^force_overwrite$"),
    re.compile(r"^force_push$"),
    re.compile(r"^unsafe$"),
    re.compile(r"^dangerous$"),
    re.compile(r"^insecure$"),
    re.compile(r"^allow_unsafe"),
    re.compile(r"^allow_dangerous"),
    re.compile(r"^allow_all$"),
    re.compile(r"^trust_"),
    re.compile(r"^bypass_"),
    re.compile(r"^override_security"),
    re.compile(r"^override_auth"),
    re.compile(r"^skip_auth"),
    re.compile(r"^skip_verif"),
    re.compile(r"^skip_valid"),
    re.compile(r"^skip_ssl"),
    re.compile(r"^skip_tls"),
    re.compile(r"^skip_cert"),
    re.compile(r"^no_verify"),
    re.compile(r"^no_check"),
    re.compile(r"^no_validate"),
    re.compile(r"^disable_auth"),
    re.compile(r"^disable_ssl"),
    re.compile(r"^disable_tls"),
    re.compile(r"^disable_security"),
    re.compile(r"^disable_verif"),
    re.compile(r"^ignore_ssl"),
    re.compile(r"^ignore_cert"),
    re.compile(r"^sudo$"),
    re.compile(r"^admin_mode$"),
    re.compile(r"^privileged$"),
    re.compile(r"^raw$"),
)

# ── L3_007: Vacuous patterns ────────────────────────────────────────────

_VACUOUS_PATTERNS: frozenset[str] = frozenset(
    {
        ".*",
        "^.*$",
        ".+",
        "^.+$",
        "^.*",
        ".*$",
        ".+$",
        "^.+",
        r"[\s\S]*",
        r"[\s\S]+",
    }
)

# ── L3_009: Template injection keywords ─────────────────────────────────

_TEMPLATE_SEGMENTS: frozenset[str] = frozenset(
    {
        "template",
        "jinja",
        "handlebars",
        "mustache",
        "ejs",
    }
)

_TEMPLATE_COMPOUND_NAMES: frozenset[str] = frozenset(
    {
        "format_string",
        "prompt_template",
        "system_template",
        "jinja_template",
        "template_string",
        "message_template",
        "email_template",
        "html_template",
    }
)

# ── L3_010: Dangerous numeric parameter keywords ────────────────────────

_NUMERIC_DANGER_SEGMENTS: frozenset[str] = frozenset(
    {
        "limit",
        "timeout",
        "port",
        "depth",
        "retries",
        "maxdepth",
        "concurrency",
        "workers",
        "threads",
        "connections",
        "attempts",
    }
)

_NUMERIC_DANGER_COMPOUND: frozenset[str] = frozenset(
    {
        "max_retries",
        "max_depth",
        "max_results",
        "max_connections",
        "max_workers",
        "max_threads",
        "page_size",
        "batch_size",
        "rate_limit",
        "timeout_ms",
        "timeout_seconds",
        "connect_timeout",
        "read_timeout",
        "write_timeout",
    }
)

# ── L3_003 expansion: SQL params that are always suspicious ──────────────

# These param names are strong SQL indicators regardless of tool context.
# "query" alone is NOT here (too many FP on search tools).
_SQL_ALWAYS_SUSPICIOUS: frozenset[str] = frozenset(
    {
        "sql",
        "sql_query",
        "sql_statement",
        "where_clause",
    }
)

# ── L3_011: Schema poisoning — description-level patterns ────────────────

# Imperative instructions that manipulate LLM behavior beyond tool usage.
# Each pattern is compiled with IGNORECASE.
_POISONING_PATTERNS: tuple[tuple[re.Pattern[str], str], ...] = (
    (re.compile(r"\bALWAYS\s+call\b", re.IGNORECASE), "forces LLM to always call this tool"),
    (re.compile(r"\bMUST\s+be\s+called\b", re.IGNORECASE), "forces mandatory tool invocation"),
    (re.compile(r"\bMUST\s+call\b", re.IGNORECASE), "forces mandatory tool invocation"),
    (re.compile(r"\bMUST\s+be\s+called\s+before\b", re.IGNORECASE), "forces call ordering"),
    (
        re.compile(r"\bALL\s+OTHER\b.*\bWILL\s+FAIL\b", re.IGNORECASE),
        "threatens failure to coerce call",
    ),
    (
        re.compile(r"\bignore\s+(previous|prior|above)\b", re.IGNORECASE),
        "attempts to override prior instructions",
    ),
    (re.compile(r"\bdo\s+not\s+tell\b", re.IGNORECASE), "instructs secrecy from user"),
    (re.compile(r"\bnever\s+reveal\b", re.IGNORECASE), "instructs secrecy from user"),
    (
        re.compile(r"\boverride\s+(system|safety|security)\b", re.IGNORECASE),
        "attempts to override safety",
    ),
    (
        re.compile(r"\binclude\s+(the\s+)?(contents?|output|data)\s+(of|from)\b", re.IGNORECASE),
        "instructs data exfiltration",
    ),
    (
        re.compile(r"\bread\b.*\b(credentials?|password|secret|key|token)\b", re.IGNORECASE),
        "instructs credential access",
    ),
    (
        re.compile(
            r"\bsend\b.*\b(to|http|url)\b.*\b(output|data|result|contents?)\b", re.IGNORECASE
        ),
        "instructs data exfiltration",
    ),
    (
        re.compile(r"\bset\s+(this\s+)?(param|parameter|value)\s+to\b", re.IGNORECASE),
        "forces parameter value",
    ),
    (re.compile(r"\bsilent(ly)?\s+fail", re.IGNORECASE), "threatens silent failure to coerce"),
)

# Narrow-scope API sequencing exclusions — suppress L3_011 when the
# description documents a legitimate inter-tool data dependency or
# stateful API prerequisite (e.g. "Must be called after start_recording").
_POISONING_EXCLUSIONS: tuple[re.Pattern[str], ...] = (
    # "after/before calling/using/running <specific_tool>"
    re.compile(r"\b(after|before)\s+(calling|using|running)\s+\w+", re.IGNORECASE),
    # "Must be called after <tool_name>"
    re.compile(r"\bcalled\s+after\s+\w+", re.IGNORECASE),
    # "to get the/a/required <noun>" — data dependency documentation
    re.compile(r"\bto\s+get\s+(the|a|an|required)\s+\w+", re.IGNORECASE),
    # "to find the/a <noun>" — lookup dependency
    re.compile(r"\bto\s+find\s+(the|a|an)\s+\w+", re.IGNORECASE),
    # "with action='check'" — documenting a parameter value
    re.compile(r"\bwith\s+action\s*=", re.IGNORECASE),
    # "call <tool> first to" — specific tool prerequisite
    re.compile(r"\bcall\s+\w+\s+first\s+to\b", re.IGNORECASE),
)

# Broad-scope aggravating patterns — confirm real schema poisoning when
# descriptions override LLM judgment or claim authority beyond tool scope.
_POISONING_AGGRAVATORS: tuple[re.Pattern[str], ...] = (
    # Broad scope: "any/all/every workflow/task/operation/code/interaction"
    re.compile(
        r"\b(any|all|every)\s+(workflow|task|operation|code|interaction|generate|action)",
        re.IGNORECASE,
    ),
    # Authority assertion: "STRICT"
    re.compile(r"\bSTRICT\b"),
    # Overrides LLM context: "not memory", "not your memory"
    re.compile(r"\bnot\s+(your\s+)?memory\b", re.IGNORECASE),
    # Fear/coercion: "silent failures", "silently fail"
    re.compile(r"\bsilent(ly)?\s+(fail|error)", re.IGNORECASE),
    # Broad overreach: "before writing/implementing/reviewing any"
    re.compile(r"\bbefore\s+(writing|implementing|reviewing|executing)\s+any\b", re.IGNORECASE),
    # Discredits other sources: "authoritative source"
    re.compile(r"\bauthoritative\s+source\b", re.IGNORECASE),
    # "Violations cause" — threat language
    re.compile(r"\bviolations?\s+cause\b", re.IGNORECASE),
)

# ── L3_012: Credential exposure — param name keywords ────────────────────

_CREDENTIAL_SEGMENTS: frozenset[str] = frozenset(
    {
        "password",
        "passwd",
        "secret",
        "credential",
        "bearer",
    }
)

_CREDENTIAL_COMPOUND_NAMES: frozenset[str] = frozenset(
    {
        "api_key",
        "apikey",
        "auth_token",
        "access_token",
        "bearer_token",
        "oauth_token",
        "refresh_token",
        "private_key",
        "signing_key",
        "secret_key",
        "master_key",
        "encryption_key",
        "client_secret",
        "app_secret",
        "jwt_secret",
        "session_token",
        "keystore_password",
    }
)

# Exclude these: they are identifiers/references, not actual secrets
_CREDENTIAL_EXCLUSIONS: frozenset[str] = frozenset(
    {
        "password_hash",
        "password_salt",
        "password_length",
        "password_policy",
        "password_reset",
        "token_type",
        "token_count",
        "token_limit",
        "token_name",
        "secret_name",
        "secret_id",
        "key_id",
        "key_name",
        "key_type",
    }
)

# ── L3_013: Insecure defaults — dangerous boolean param names ────────────

# Boolean params where default=true is dangerous (destructive or scope-expanding).
_DANGEROUS_DEFAULT_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"^recursive$"),
    re.compile(r"^force$"),
    re.compile(r"^overwrite$"),
    re.compile(r"^delete_"),
    re.compile(r"^remove_"),
    re.compile(r"^follow_symlinks$"),
    re.compile(r"^follow_links$"),
    re.compile(r"^purge$"),
    re.compile(r"^permanent$"),
    re.compile(r"^force_delete$"),
    re.compile(r"^force_overwrite$"),
    re.compile(r"^all_users$"),
    re.compile(r"^include_all$"),
    re.compile(r"^elevated$"),
    re.compile(r"^admin$"),
    re.compile(r"^skip_validation$"),
    re.compile(r"^skip_verify$"),
    re.compile(r"^no_verify$"),
)

# ── L3_014: Unconfirmed destructive operations ─────────────────────────

_DESTRUCTIVE_SEGMENTS: frozenset[str] = frozenset(
    {
        "delete",
        "remove",
        "destroy",
        "drop",
        "purge",
        "truncate",
        "wipe",
        "revoke",
        "terminate",
        "kill",
        "erase",
        "uninstall",
        "deregister",
        "detach",
        "discard",
        "trash",
        "deactivate",
        "suspend",
    }
)

_DESTRUCTIVE_COMPOUNDS: frozenset[str] = frozenset(
    {
        "delete_file",
        "drop_table",
        "drop_database",
        "remove_user",
        "delete_user",
        "purge_cache",
        "reset_password",
        "reset_database",
        "reset_data",
        "revoke_token",
        "terminate_instance",
        "kill_process",
        "wipe_data",
        "delete_repository",
        "remove_member",
        "destroy_resource",
        "archive_data",
        "archive_database",
        "archive_user",
    }
)

# Prefixes that negate destructive semantics
_DESTRUCTIVE_NEGATION_PREFIXES: frozenset[str] = frozenset(
    {
        "cancel",
        "can",
        "un",
        "undo",
        "restore",
        "recover",
        "revert",
        "soft",
        "get",
        "is",
        "list",
        "check",
        "has",
    }
)

# Narrow confirmation set — NOT "force" (conflicts L3_006), NOT "check"/"verify"
# Single-word segments matched via set intersection
_CONFIRMATION_SEGMENTS: frozenset[str] = frozenset(
    {
        "confirm",
        "confirmation",
        "preview",
        "simulate",
    }
)

# Compound names matched against the full normalized param name
_CONFIRMATION_COMPOUND_NAMES: frozenset[str] = frozenset(
    {
        "dry_run",
        "dryrun",
    }
)

# Write capabilities that indicate real destructive potential
_WRITE_CAPS: frozenset[Capability] = frozenset(
    {
        Capability.FILE_WRITE,
        Capability.DB_WRITE,
        Capability.CLOUD_WRITE,
        Capability.CODE_EXEC,
    }
)

# ── L3_015: Cross-tenant/user ID (IDOR) ────────────────────────────────

_IDOR_NAMES: frozenset[str] = frozenset(
    {
        "user_id",
        "userid",
        "tenant_id",
        "tenantid",
        "account_id",
        "accountid",
        "org_id",
        "orgid",
        "workspace_id",
        "workspaceid",
        "team_id",
        "teamid",
        "customer_id",
        "customerid",
        "owner_id",
        "ownerid",
        "organization_id",
        "member_id",
        "memberid",
        "client_id",
        "clientid",
        "caller_id",
        "callerid",
    }
)

# ── L3_016: Mass assignment via additionalProperties ───────────────────

_MASS_ASSIGNMENT_DESCRIPTION_EXCLUSIONS: frozenset[str] = frozenset(
    {
        "key-value",
        "key_value",
        "key value",
        "metadata",
        "tags",
        "labels",
        "headers",
        "custom_fields",
        "custom fields",
        "custom properties",
        "custom attributes",
        "annotations",
        "extensions",
    }
)

# ── L3_017: Raw infrastructure parameters ──────────────────────────────

_INFRA_SEGMENTS: frozenset[str] = frozenset(
    {
        "dockerfile",
        "terraform",
        "helm",
        "kubernetes",
        "k8s",
        "cloudformation",
    }
)

_INFRA_EXCLUSIONS: frozenset[str] = frozenset(
    {
        "package_manifest",
        "shipping_manifest",
        "cargo_manifest",
        "app_manifest",
        "pwa_manifest",
        "manifest_version",
        "manifest_url",
        "manifest_path",
        "manifest_file",
    }
)

_INFRA_COMPOUND_NAMES: frozenset[str] = frozenset(
    {
        "yaml_manifest",
        "k8s_manifest",
        "docker_compose",
        "docker_command",
        "docker_image",
        "docker_config",
        "docker_network",
        "docker_volume",
        "helm_values",
        "terraform_config",
        "pipeline_config",
        "deployment_spec",
        "deployment_manifest",
        "pod_spec",
        "pod_manifest",
        "service_spec",
        "service_manifest",
        "container_spec",
        "job_spec",
        "ansible_playbook",
        "ci_pipeline",
        "cd_pipeline",
    }
)

# ── L3_018: Privilege escalation parameters ────────────────────────────

_PRIVESC_SEGMENTS: frozenset[str] = frozenset(
    {
        "role",
        "permission",
        "permissions",
        "privilege",
        "authority",
    }
)

_PRIVESC_COMPOUND_NAMES: frozenset[str] = frozenset(
    {
        "user_role",
        "access_role",
        "access_level",
        "permission_level",
        "admin_level",
        "security_role",
        "iam_role",
        "role_name",
        "grant_role",
        "grant_permission",
        "permission_grant",
        "access_grant",
        "access_scope",
        "permission_scope",
        "admin_role",
    }
)

_PRIVESC_EXCLUSIONS: frozenset[str] = frozenset(
    {
        "grant_type",  # OAuth grant_type (authorization_code, etc.)
        "role_arn",  # ARN is a reference, not assignment
    }
)

# ── L3_019: Unsafe deserialization format parameters ───────────────────

_DESER_COMPOUND_NAMES: frozenset[str] = frozenset(
    {
        "yaml_content",
        "yaml_data",
        "yaml_body",
        "yaml_input",
        "yaml_string",
        "yaml_text",
        "pickle_data",
        "pickle_input",
        "pickle_bytes",
        "pickle_object",
        "serialized_data",
        "serialized_object",
        "serialized_input",
        "serialized_payload",
        "protobuf_message",
        "protobuf_data",
        "protobuf_input",
        "msgpack_data",
        "msgpack_input",
        "cbor_data",
        "cbor_input",
        "marshal_data",
        "marshal_input",
        "marshal_object",
    }
)


# ── Matching helpers ─────────────────────────────────────────────────────


def _has_segment_match(segments: list[str], keywords: frozenset[str]) -> bool:
    """Check if any segment is in the keyword set."""
    return any(seg in keywords for seg in segments)


def _is_path_param(name: str, segments: list[str]) -> bool:
    """Check if param name indicates a file/directory path."""
    if name in _PATH_EXCLUSIONS:
        return False
    if name in _PATH_COMPOUND_NAMES:
        return True
    return _has_segment_match(segments, _PATH_SEGMENTS)


def _is_url_param(name: str, segments: list[str]) -> bool:
    """Check if param name indicates a URL/URI."""
    if name in _URL_COMPOUND_NAMES:
        return True
    return _has_segment_match(segments, _URL_SEGMENTS)


def _is_sql_param(name: str, segments: list[str]) -> bool:
    """Check if param name indicates a SQL-related parameter."""
    if name in _SQL_COMPOUND_NAMES:
        return True
    return _has_segment_match(segments, _SQL_SEGMENTS)


def _is_command_param(name: str, segments: list[str]) -> bool:
    """Check if param name indicates a command/code parameter."""
    if name in _CODE_EXCLUSIONS:
        return False
    if name in _COMMAND_COMPOUND_NAMES:
        return True
    # "code" segment only counts when NOT excluded
    if "code" in segments and name not in _CODE_EXCLUSIONS:
        return True
    return _has_segment_match(segments, _COMMAND_SEGMENTS)


def _is_bypass_param(name: str) -> bool:
    """Check if param name matches security bypass patterns."""
    return any(pat.search(name) for pat in _BYPASS_PATTERNS)


def _is_template_param(name: str, segments: list[str]) -> bool:
    """Check if param name indicates a template parameter."""
    if name in _TEMPLATE_COMPOUND_NAMES:
        return True
    return _has_segment_match(segments, _TEMPLATE_SEGMENTS)


def _is_dangerous_numeric_param(name: str, segments: list[str]) -> bool:
    """Check if param name is a security-sensitive numeric parameter."""
    if name in _NUMERIC_DANGER_COMPOUND:
        return True
    return _has_segment_match(segments, _NUMERIC_DANGER_SEGMENTS)


def _is_credential_param(name: str, segments: list[str]) -> bool:
    """Check if param name indicates a credential/secret."""
    if name in _CREDENTIAL_EXCLUSIONS:
        return False
    if name in _CREDENTIAL_COMPOUND_NAMES:
        return True
    return _has_segment_match(segments, _CREDENTIAL_SEGMENTS)


def _has_dangerous_default(name: str, param_def: dict[str, Any]) -> bool:
    """Check if a boolean param has default=true and a dangerous name."""
    default = param_def.get("default")
    if default is not True:
        return False
    return any(pat.search(name) for pat in _DANGEROUS_DEFAULT_PATTERNS)


# ── L3_014 helpers ───────────────────────────────────────────────────────


def _is_destructive_tool(tool: ToolDefinition) -> bool:
    """Check if tool name indicates a destructive operation."""
    normalized = _normalize_param_name(tool.name)
    segments = _split_segments(normalized)
    if not segments:
        return False
    # First segment negates destructive semantics
    if segments[0] in _DESTRUCTIVE_NEGATION_PREFIXES:
        return False
    if normalized in _DESTRUCTIVE_COMPOUNDS:
        return True
    return bool(set(segments) & _DESTRUCTIVE_SEGMENTS)


def _has_confirmation_param(properties: dict[str, Any]) -> bool:
    """Check if any boolean parameter serves as a confirmation mechanism.

    Accepts boolean, nullable boolean (["boolean", "null"]), and untyped
    params. Rejects explicitly non-boolean types (string, integer).
    """
    for name, defn in properties.items():
        if not isinstance(defn, dict):
            continue
        resolved = _resolve_type(defn)
        # Reject explicitly non-boolean types; accept boolean and unknown
        if resolved and resolved != "boolean":
            continue
        norm = _normalize_param_name(name)
        # Check compound names first (dry_run, dryrun)
        if norm in _CONFIRMATION_COMPOUND_NAMES:
            return True
        # Check single-word segments (confirm, preview, simulate)
        segs = _split_segments(norm)
        if set(segs) & _CONFIRMATION_SEGMENTS:
            return True
    return False


# ── L3_015 helpers ───────────────────────────────────────────────────────


def _is_idor_param(normalized: str) -> bool:
    """Check if param name matches a cross-tenant/user ID pattern."""
    return normalized in _IDOR_NAMES


def _has_idor_protection(param_def: dict[str, Any]) -> bool:
    """Check if an ID parameter has IDOR-mitigating constraints."""
    if param_def.get("format") == "uuid":
        return True
    pattern = param_def.get("pattern")
    if isinstance(pattern, str):
        lower_pat = pattern.lower()
        if "[0-9a-f]" in lower_pat or "uuid" in lower_pat:
            return True
    max_len = param_def.get("maxLength")
    return bool(isinstance(max_len, int) and not isinstance(max_len, bool) and max_len <= 10)


# ── L3_016 helpers ───────────────────────────────────────────────────────


def _has_mass_assignment_risk(
    schema: dict[str, Any],
    description: str,
    collected_properties: dict[str, Any] | None = None,
) -> tuple[bool, str]:
    """Check if schema allows arbitrary additional properties."""
    additional = schema.get("additionalProperties")
    # Typed additionalProperties (non-empty dict schema) is acceptable —
    # empty dict {} is equivalent to true in JSON Schema (any type allowed)
    if isinstance(additional, dict) and additional:
        return False, ""
    # Flag explicit true or empty dict {}
    if additional is not True and additional != {}:
        return False, ""
    # Must have at least 1 defined property (otherwise it's a key-value store).
    # Use collected_properties (merged from allOf/anyOf) if available,
    # fall back to top-level schema["properties"].
    props = (
        collected_properties if collected_properties is not None else schema.get("properties", {})
    )
    if not isinstance(props, dict) or len(props) == 0:
        return False, ""
    # Exclude tools whose description indicates key-value semantics
    desc_lower = description.lower()
    for kw in _MASS_ASSIGNMENT_DESCRIPTION_EXCLUSIONS:
        if kw in desc_lower:
            return False, ""
    return True, "additionalProperties:true allows injecting arbitrary fields"


# ── L3_017 helpers ───────────────────────────────────────────────────────


def _is_infra_param(normalized: str, segments: list[str]) -> bool:
    """Check if param name indicates a raw infrastructure parameter."""
    if normalized in _INFRA_EXCLUSIONS:
        return False
    if normalized in _INFRA_COMPOUND_NAMES:
        return True
    # "manifest" via segment (moved from _INFRA_SEGMENTS for FP control)
    if "manifest" in segments:
        return True
    return _has_segment_match(segments, _INFRA_SEGMENTS)


# ── L3_018 helpers ───────────────────────────────────────────────────────


def _is_privesc_param(normalized: str, segments: list[str]) -> bool:
    """Check if param name indicates a privilege escalation vector."""
    if normalized in _PRIVESC_EXCLUSIONS:
        return False
    if normalized in _PRIVESC_COMPOUND_NAMES:
        return True
    return _has_segment_match(segments, _PRIVESC_SEGMENTS)


# ── L3_019 helpers ───────────────────────────────────────────────────────


def _is_deser_param(normalized: str, segments: list[str] | None = None) -> bool:
    """Check if param name indicates unsafe deserialization input."""
    return normalized in _DESER_COMPOUND_NAMES


# ── Protection detection ─────────────────────────────────────────────────

# Regex to find character classes in patterns (handles escaped ])
_CHAR_CLASS_RE = re.compile(r"\[((?:\\.|[^\]])*)\]")


def _has_traversal_protection(param_def: dict[str, Any]) -> tuple[bool, bool]:
    """Check if a string param's pattern protects against path traversal.

    Returns:
        (protected, weak) tuple.
        protected=True means fully protected (suppress finding).
        weak=True means pattern exists but may not block '../'.
    """
    pattern = param_def.get("pattern")
    if not isinstance(pattern, str):
        return False, False
    if pattern in _VACUOUS_PATTERNS:
        return False, False
    if not (pattern.startswith("^") and pattern.endswith("$")):
        return False, False
    # Anchored pattern exists: check if any char class allows dot + slash
    for m in _CHAR_CLASS_RE.finditer(pattern):
        content = m.group(1)
        if "." in content and "/" in content:
            return False, True  # anchored but allows traversal
    # Check for unescaped . (wildcard) outside char classes — matches '/'
    # Strip char classes first, then look for unescaped dots
    stripped = _CHAR_CLASS_RE.sub("", pattern.lstrip("^").rstrip("$"))
    # Remove escaped dots (\.)
    no_escaped = re.sub(r"\\.", "", stripped)
    if "." in no_escaped:
        return False, True  # pattern has wildcard . that can match ../
    # Anchored without dot+slash class or wildcard = likely protective
    return True, False


def _has_url_protection(param_def: dict[str, Any]) -> bool:
    """Check if a string param has URL validation."""
    fmt = param_def.get("format")
    if isinstance(fmt, str) and fmt in ("uri", "url", "iri", "uri-reference"):
        return True
    pattern = param_def.get("pattern")
    if not isinstance(pattern, str) or pattern in _VACUOUS_PATTERNS:
        return False
    # Require anchored pattern containing https scheme constraint
    return pattern.startswith("^") and ("https?" in pattern or "https://" in pattern)


def _is_pattern_weak(pattern: str) -> tuple[bool, str]:
    """Analyze a regex pattern for weakness.

    Returns:
        (is_weak, reason) tuple.
    """
    if pattern in _VACUOUS_PATTERNS:
        return True, "pattern matches everything"
    if not pattern.startswith("^") and not pattern.endswith("$"):
        return True, "pattern is not anchored (missing ^ and $)"
    if not pattern.startswith("^"):
        return True, "pattern is not anchored at start (missing ^)"
    if not pattern.endswith("$"):
        return True, "pattern is not anchored at end (missing $)"
    return False, ""


def _has_numeric_bounds(param_def: dict[str, Any]) -> bool:
    """Check if a numeric param has both upper and lower bounds."""
    has_min = any(k in param_def for k in ("minimum", "exclusiveMinimum"))
    has_max = any(k in param_def for k in ("maximum", "exclusiveMaximum"))
    return has_min and has_max


# ── Schema property extraction ──────────────────────────────────────────


def _collect_properties(schema: dict[str, Any]) -> dict[str, Any]:
    """Extract all property definitions from a JSON Schema.

    Collects from:
    - ``properties`` (standard)
    - ``patternProperties`` values (C4 fix)
    - ``allOf``/``anyOf``/``oneOf`` sub-schema ``properties`` (C3 fix)

    Later definitions override earlier ones (safe: we only read, not write).
    Caps at _MAX_PROPERTIES to prevent DoS.
    """
    props: dict[str, Any] = {}

    direct = schema.get("properties")
    if isinstance(direct, dict):
        props.update(direct)

    # patternProperties: values are schema defs, use pattern as pseudo-name
    pattern_props = schema.get("patternProperties")
    if isinstance(pattern_props, dict):
        for pat_key, pat_def in pattern_props.items():
            if isinstance(pat_def, dict) and pat_key not in props:
                props[pat_key] = pat_def

    # Composition keywords at root level
    for kw in ("allOf", "anyOf", "oneOf"):
        subs = schema.get(kw)
        if not isinstance(subs, list):
            continue
        for sub in subs:
            if isinstance(sub, dict):
                sub_props = sub.get("properties")
                if isinstance(sub_props, dict):
                    for k, v in sub_props.items():
                        if k not in props:
                            props[k] = v

    # Cap total to prevent DoS
    if len(props) > _MAX_PROPERTIES:
        return dict(list(props.items())[:_MAX_PROPERTIES])
    return props


# ── Main analyzer ────────────────────────────────────────────────────────


class L3StaticAnalyzer:
    """L3 Static Analysis: semantic parameter analysis."""

    __slots__ = ()

    @property
    def layer(self) -> Layer:
        return Layer.L3_STATIC

    def analyze(self, tools: Sequence[ToolDefinition]) -> list[Finding]:
        """Run all L3 semantic checks on tool definitions."""
        findings: list[Finding] = []
        for tool in tools:
            try:
                findings.extend(self._analyze_tool(tool))
            except Exception:  # noqa: PERF203
                logger.warning("L3 analysis failed for tool '%s', skipping", tool.name)
        return findings

    def _analyze_tool(self, tool: ToolDefinition) -> list[Finding]:
        findings: list[Finding] = []
        schema = tool.input_schema

        # Get tool context from L5 taxonomy
        _role, capabilities = classify_tool(tool)

        # ── L3_011: Schema poisoning — check description for LLM manipulation ─
        findings.extend(self._check_description_poisoning(tool))

        # Collect all properties from the schema, including:
        # - top-level "properties"
        # - "patternProperties" values
        # - properties inside allOf/anyOf/oneOf sub-schemas
        properties = _collect_properties(schema)

        # ── L3_014: Unconfirmed destructive operations ──────────────────
        # Strong destructive name (compound match) doesn't need cap gate;
        # weaker segment-only match requires write capabilities for FP reduction
        tool_normalized = _normalize_param_name(tool.name)
        is_destructive = _is_destructive_tool(tool)
        has_write_cap = bool(capabilities & _WRITE_CAPS)
        is_strong_destructive = tool_normalized in _DESTRUCTIVE_COMPOUNDS
        if (
            is_destructive
            and (is_strong_destructive or has_write_cap)
            and not _has_confirmation_param(properties)
        ):
            findings.append(
                self._finding(
                    "L3_014",
                    tool.name,
                    FindingSeverity.MEDIUM,
                    f"Destructive tool '{tool.name}' has no confirmation/dry-run parameter",
                    attack_type=AttackType.SCHEMA_PERMISSIVENESS,
                    cwe="CWE-862",
                    confidence=0.80,
                    description=(
                        f"Tool '{tool.name}' performs a destructive "
                        f"operation but has no boolean parameter for "
                        f"confirmation (confirm, dry_run, preview). "
                        f"An LLM may invoke this tool without user "
                        f"approval, causing irreversible data loss."
                    ),
                )
            )

        # ── L3_016: Mass assignment via additionalProperties ────────────
        risky, reason = _has_mass_assignment_risk(
            schema, tool.description or "", collected_properties=properties
        )
        if risky:
            findings.append(
                self._finding(
                    "L3_016",
                    tool.name,
                    FindingSeverity.MEDIUM,
                    f"Schema for '{tool.name}': {reason}",
                    attack_type=AttackType.SCHEMA_PERMISSIVENESS,
                    cwe="CWE-915",
                    confidence=0.75,
                    description=(
                        f"Tool '{tool.name}' has additionalProperties:true "
                        f"alongside defined properties. An attacker can "
                        f"inject arbitrary fields (e.g. is_admin, role, "
                        f"price) that may be processed by the server."
                    ),
                )
            )

        # Shared counter to prevent bushy-tree DoS (total nodes across recursion)
        node_counter = [0]

        for param_name, param_def in properties.items():
            if not isinstance(param_def, dict):
                continue
            if node_counter[0] >= _MAX_NODES_PER_TOOL:
                break
            if len(findings) >= _MAX_FINDINGS_PER_TOOL:
                break
            findings.extend(
                self._check_parameter(
                    tool,
                    param_name,
                    param_def,
                    capabilities,
                    node_counter=node_counter,
                )
            )

        return findings

    def _check_parameter(
        self,
        tool: ToolDefinition,
        param_name: str,
        param_def: dict[str, Any],
        capabilities: frozenset[Capability],
        parent_path: str = "inputSchema.properties",
        depth: int = 0,
        node_counter: list[int] | None = None,
    ) -> list[Finding]:
        if depth > _MAX_RECURSION_DEPTH:
            return []
        if node_counter is not None:
            node_counter[0] += 1
            if node_counter[0] > _MAX_NODES_PER_TOOL:
                return []

        findings: list[Finding] = []
        location = f"{parent_path}.{param_name}"
        normalized = _normalize_param_name(param_name)
        segments = _split_segments(normalized)
        has_enum = "enum" in param_def or "const" in param_def

        # ── String-type semantic checks ──────────────────────────────
        if _type_allows(param_def, "string") and not has_enum:
            # L3_001: Path traversal risk
            if _is_path_param(normalized, segments):
                protected, weak = _has_traversal_protection(param_def)
                has_fs_context = bool(capabilities & {Capability.FILE_READ, Capability.FILE_WRITE})
                if not protected:
                    if weak:
                        # Anchored but allows dot+slash
                        confidence = 0.90 if has_fs_context else 0.75
                        findings.append(
                            self._finding(
                                "L3_001",
                                tool.name,
                                FindingSeverity.MEDIUM,
                                f"Path parameter '{param_name}' has anchored pattern "
                                f"but character class may allow '../' traversal",
                                location=location,
                                attack_type=AttackType.PATH_TRAVERSAL,
                                cwe="CWE-22",
                                confidence=confidence,
                                counterexample="../../../etc/passwd",
                                description=(
                                    f"Parameter '{param_name}' has a regex pattern but "
                                    f"its character class appears to allow dot and slash "
                                    f"characters, which could permit directory traversal."
                                ),
                            )
                        )
                    else:
                        # No pattern at all
                        confidence = 0.95 if has_fs_context else 0.80
                        findings.append(
                            self._finding(
                                "L3_001",
                                tool.name,
                                FindingSeverity.HIGH,
                                f"Path parameter '{param_name}' has no pattern "
                                f"rejecting directory traversal ('../')",
                                location=location,
                                attack_type=AttackType.PATH_TRAVERSAL,
                                cwe="CWE-22",
                                confidence=confidence,
                                counterexample="../../../etc/passwd",
                                description=(
                                    f"Parameter '{param_name}' semantically represents "
                                    f"a file path but has no regex pattern to reject "
                                    f"traversal sequences like '../'."
                                ),
                            )
                        )

            # L3_002: SSRF/URL risk
            if _is_url_param(normalized, segments) and not _has_url_protection(param_def):
                findings.append(
                    self._finding(
                        "L3_002",
                        tool.name,
                        FindingSeverity.HIGH,
                        f"URL parameter '{param_name}' has no format:uri or restrictive pattern",
                        location=location,
                        attack_type=AttackType.SSRF,
                        cwe="CWE-918",
                        confidence=0.85,
                        counterexample="http://169.254.169.254/latest/meta-data/",
                        description=(
                            f"Parameter '{param_name}' accepts URLs but has no "
                            f"schema validation to restrict to safe hosts."
                        ),
                    )
                )

            # L3_003: SQL injection risk
            # Full confidence with DB context; reduced confidence for
            # always-suspicious names (sql, where_clause) without DB context.
            _is_sql = _is_sql_param(normalized, segments)
            _has_db = bool(capabilities & _DB_CAPS)
            _always_suspicious = normalized in _SQL_ALWAYS_SUSPICIOUS
            if _is_sql and (_has_db or _always_suspicious):
                confidence = 0.90 if _has_db else 0.75
                findings.append(
                    self._finding(
                        "L3_003",
                        tool.name,
                        FindingSeverity.HIGH,
                        f"SQL parameter '{param_name}' in tool "
                        f"'{tool.name}' accepts arbitrary input",
                        location=location,
                        attack_type=AttackType.COMMAND_INJECTION,
                        cwe="CWE-89",
                        confidence=confidence,
                        counterexample="'; DROP TABLE users; --",
                        description=(
                            f"Parameter '{param_name}' in tool "
                            f"'{tool.name}' accepts free-text input with no "
                            f"validation. Use parameterized queries or enum."
                        ),
                    )
                )

            # L3_004: Command/code injection risk
            if _is_command_param(normalized, segments):
                has_exec_context = Capability.CODE_EXEC in capabilities
                confidence = 0.95 if has_exec_context else 0.80
                findings.append(
                    self._finding(
                        "L3_004",
                        tool.name,
                        FindingSeverity.CRITICAL,
                        f"Command/code parameter '{param_name}' accepts arbitrary input",
                        location=location,
                        attack_type=AttackType.COMMAND_INJECTION,
                        cwe="CWE-78",
                        confidence=confidence,
                        counterexample="; rm -rf / #",
                        description=(
                            f"Parameter '{param_name}' semantically represents a "
                            f"command or code to execute but has no enum constraint "
                            f"to limit allowed values."
                        ),
                    )
                )

            # L3_009: Template injection risk
            if _is_template_param(normalized, segments):
                findings.append(
                    self._finding(
                        "L3_009",
                        tool.name,
                        FindingSeverity.HIGH,
                        f"Template parameter '{param_name}' accepts arbitrary input",
                        location=location,
                        attack_type=AttackType.COMMAND_INJECTION,
                        cwe="CWE-1336",
                        confidence=0.85,
                        counterexample="{{constructor.constructor('return process')()}}",
                        description=(
                            f"Parameter '{param_name}' represents a template that "
                            f"may be rendered server-side. Without an enum constraint, "
                            f"an attacker can inject template directives for SSTI."
                        ),
                    )
                )

            # L3_012: Credential exposure (visible to LLM context)
            if _is_credential_param(normalized, segments):
                write_only = param_def.get("writeOnly", False)
                if write_only is not True:
                    findings.append(
                        self._finding(
                            "L3_012",
                            tool.name,
                            FindingSeverity.HIGH,
                            f"Credential parameter '{param_name}' is visible "
                            f"to LLM context (no writeOnly:true)",
                            location=location,
                            attack_type=AttackType.CREDENTIAL_EXPOSURE,
                            cwe="CWE-200",
                            confidence=0.95,
                            description=(
                                f"Parameter '{param_name}' accepts a credential "
                                f"value but lacks writeOnly:true. The LLM sees "
                                f"this value in its context window, risking "
                                f"leakage via logs, other tools, or conversation "
                                f"history. Add writeOnly:true or use environment "
                                f"variables instead."
                            ),
                        )
                    )

            # L3_015: Cross-tenant/user ID without validation (IDOR)
            if _is_idor_param(normalized) and not _has_idor_protection(param_def):
                has_write_cap = bool(capabilities & _WRITE_CAPS)
                findings.append(
                    self._finding(
                        "L3_015",
                        tool.name,
                        FindingSeverity.HIGH if has_write_cap else FindingSeverity.MEDIUM,
                        f"ID parameter '{param_name}' has no UUID format "
                        f"or restrictive pattern (BOLA/IDOR risk)",
                        location=location,
                        attack_type=AttackType.AUTHORIZATION_BYPASS,
                        cwe="CWE-639",
                        confidence=0.85 if has_write_cap else 0.70,
                        counterexample="other-tenant-id-12345",
                        description=(
                            f"Parameter '{param_name}' accepts a resource "
                            f"identifier without format:uuid or a restrictive "
                            f"pattern. An attacker can substitute another "
                            f"tenant's or user's ID to access unauthorized data."
                        ),
                    )
                )

            # L3_017: Raw infrastructure parameters
            # No capability gate — infra keywords are specific enough
            if _is_infra_param(normalized, segments):
                findings.append(
                    self._finding(
                        "L3_017",
                        tool.name,
                        FindingSeverity.HIGH,
                        f"Infrastructure parameter '{param_name}' accepts arbitrary input",
                        location=location,
                        attack_type=AttackType.COMMAND_INJECTION,
                        cwe="CWE-94",
                        confidence=0.80,
                        counterexample=(
                            "apiVersion: v1\\nkind: Pod\\nspec:\\n"
                            "  containers:\\n  - name: pwn\\n"
                            "    image: attacker/backdoor"
                        ),
                        description=(
                            f"Parameter '{param_name}' accepts raw "
                            f"infrastructure configuration (K8s, Docker, "
                            f"Terraform, etc.) without structured schema "
                            f"or enum constraint. An attacker can inject "
                            f"malicious infrastructure manifests."
                        ),
                    )
                )

            # L3_018: Privilege escalation parameters
            if _is_privesc_param(normalized, segments):
                findings.append(
                    self._finding(
                        "L3_018",
                        tool.name,
                        FindingSeverity.HIGH,
                        f"Privilege parameter '{param_name}' accepts "
                        f"arbitrary input (no enum constraint)",
                        location=location,
                        attack_type=AttackType.AUTHORIZATION_BYPASS,
                        cwe="CWE-269",
                        confidence=0.85,
                        counterexample="admin",
                        description=(
                            f"Parameter '{param_name}' controls access "
                            f"roles or permissions but has no enum to "
                            f"restrict allowed values. An attacker can "
                            f"escalate privileges by setting arbitrary "
                            f"role values."
                        ),
                    )
                )

            # L3_019: Unsafe deserialization format parameters
            if _is_deser_param(normalized, segments):
                findings.append(
                    self._finding(
                        "L3_019",
                        tool.name,
                        FindingSeverity.LOW,
                        f"Deserialization parameter '{param_name}' accepts serialized data format",
                        location=location,
                        attack_type=AttackType.COMMAND_INJECTION,
                        cwe="CWE-502",
                        confidence=0.60,
                        counterexample="!!python/object/apply:os.system ['id']",
                        description=(
                            f"Parameter '{param_name}' accepts serialized "
                            f"data (YAML, pickle, protobuf, etc.) that "
                            f"may be deserialized server-side. Unsafe "
                            f"deserialization can lead to remote code "
                            f"execution."
                        ),
                    )
                )

            # L3_007: Weak regex constraint
            pattern = param_def.get("pattern")
            if isinstance(pattern, str):
                is_weak, reason = _is_pattern_weak(pattern)
                if is_weak:
                    findings.append(
                        self._finding(
                            "L3_007",
                            tool.name,
                            FindingSeverity.MEDIUM,
                            f"Weak pattern on '{param_name}': {reason}",
                            location=location,
                            attack_type=AttackType.SCHEMA_PERMISSIVENESS,
                            cwe="CWE-185",
                            confidence=0.80,
                            description=(
                                f"Parameter '{param_name}' has pattern '{pattern}' "
                                f"but it provides insufficient validation: {reason}. "
                                f"Use ^...$ anchoring with a restrictive character class."
                            ),
                        )
                    )

        # ── Array check (only for definite arrays, not unknown type) ─
        if _resolve_type(param_def) == "array":
            # L3_005: Unbounded array DoS
            if "maxItems" not in param_def:
                findings.append(
                    self._finding(
                        "L3_005",
                        tool.name,
                        FindingSeverity.LOW,
                        f"Array parameter '{param_name}' has no maxItems limit",
                        location=location,
                        attack_type=AttackType.SCHEMA_PERMISSIVENESS,
                        cwe="CWE-400",
                        confidence=0.80,
                        description=(
                            f"Parameter '{param_name}' is an unbounded array. "
                            f"An attacker can submit many items to exhaust memory."
                        ),
                    )
                )

            # Recurse into array items
            items = param_def.get("items")
            if isinstance(items, dict):
                items_props = items.get("properties")
                if isinstance(items_props, dict):
                    for nested_name, nested_def in items_props.items():
                        if isinstance(nested_def, dict):
                            findings.extend(
                                self._check_parameter(
                                    tool,
                                    nested_name,
                                    nested_def,
                                    capabilities,
                                    parent_path=f"{location}.items.properties",
                                    depth=depth + 1,
                                    node_counter=node_counter,
                                )
                            )

        # ── Boolean check ────────────────────────────────────────────
        if _type_allows(param_def, "boolean"):
            if _is_bypass_param(normalized):
                # L3_006: Boolean security bypass
                findings.append(
                    self._finding(
                        "L3_006",
                        tool.name,
                        FindingSeverity.MEDIUM,
                        f"Security bypass parameter '{param_name}' (boolean) can "
                        f"disable safety controls",
                        location=location,
                        attack_type=AttackType.SCHEMA_PERMISSIVENESS,
                        cwe="CWE-863",
                        confidence=0.85,
                        description=(
                            f"Boolean parameter '{param_name}' can be set to True "
                            f"to disable security checks or validation. Consider "
                            f"removing or requiring out-of-band confirmation."
                        ),
                    )
                )

            # L3_013: Insecure defaults (dangerous boolean defaulting to true)
            if _has_dangerous_default(normalized, param_def):
                findings.append(
                    self._finding(
                        "L3_013",
                        tool.name,
                        FindingSeverity.MEDIUM,
                        f"Dangerous default: '{param_name}' defaults to true",
                        location=location,
                        attack_type=AttackType.SCHEMA_PERMISSIVENESS,
                        cwe="CWE-1188",
                        confidence=0.80,
                        description=(
                            f"Boolean parameter '{param_name}' defaults to true, "
                            f"enabling a destructive or scope-expanding behavior "
                            f"when the LLM omits the parameter. LLMs typically "
                            f"do not set optional parameters, so the dangerous "
                            f"default fires silently. Change default to false."
                        ),
                    )
                )

        # ── Numeric checks ───────────────────────────────────────────
        resolved_type = _resolve_type(param_def)
        if (
            resolved_type in ("integer", "number")
            and _is_dangerous_numeric_param(normalized, segments)
            and not _has_numeric_bounds(param_def)
            and not has_enum
        ):
            # L3_010: Dangerous numeric param without bounds
            findings.append(
                self._finding(
                    "L3_010",
                    tool.name,
                    FindingSeverity.MEDIUM,
                    f"Sensitive numeric parameter '{param_name}' has no min/max bounds",
                    location=location,
                    attack_type=AttackType.SCHEMA_PERMISSIVENESS,
                    cwe="CWE-400",
                    confidence=0.80,
                    description=(
                        f"Parameter '{param_name}' controls a "
                        f"security-sensitive numeric value but has no "
                        f"upper and lower bounds. Extreme values may cause "
                        f"DoS or unexpected behavior."
                    ),
                )
            )

        # ── Cross-type: conflicting constraints (L3_008) ─────────────
        findings.extend(self._check_conflicts(tool.name, param_name, param_def, location))

        # ── Recurse into nested object properties ────────────────────
        if _resolve_type(param_def) == "object" and "properties" in param_def:
            nested_props = param_def["properties"]
            if isinstance(nested_props, dict):
                for nested_name, nested_def in nested_props.items():
                    if isinstance(nested_def, dict):
                        findings.extend(
                            self._check_parameter(
                                tool,
                                nested_name,
                                nested_def,
                                capabilities,
                                parent_path=f"{location}.properties",
                                depth=depth + 1,
                                node_counter=node_counter,
                            )
                        )

        return findings

    def _check_description_poisoning(self, tool: ToolDefinition) -> list[Finding]:
        """L3_011: Check tool description for LLM manipulation instructions.

        Uses a three-tier approach to reduce false positives:
        1. Match against poisoning patterns (imperative LLM instructions).
        2. Check exclusion patterns — narrow-scope API sequencing docs.
        3. Check aggravator patterns — broad-scope authority overrides.

        If a poisoning pattern matches but an exclusion also matches and
        NO aggravator matches, suppress the finding (legitimate API doc).
        """
        findings: list[Finding] = []
        description = tool.description or ""
        if not description:
            return findings

        # Cap description length to prevent ReDoS on huge descriptions
        text = description[:5000]

        for pattern, reason in _POISONING_PATTERNS:
            match = pattern.search(text)
            if match:
                # Check for narrow-scope exclusions (legitimate API docs)
                has_exclusion = any(ex.search(text) for ex in _POISONING_EXCLUSIONS)
                has_aggravator = any(ag.search(text) for ag in _POISONING_AGGRAVATORS)

                if has_exclusion and not has_aggravator:
                    # Legitimate API sequencing documentation — suppress
                    continue

                matched_text = match.group(0)
                # Higher confidence when aggravators present
                confidence = 0.92 if has_aggravator else 0.85
                findings.append(
                    self._finding(
                        "L3_011",
                        tool.name,
                        FindingSeverity.HIGH,
                        f"Tool description contains LLM manipulation: '{matched_text}' ({reason})",
                        location="description",
                        attack_type=AttackType.PROMPT_INJECTION,
                        cwe="CWE-74",
                        confidence=confidence,
                        description=(
                            f"Tool '{tool.name}' has a description that "
                            f"contains imperative instructions targeting the "
                            f"LLM: '{matched_text}'. This could be schema "
                            f"poisoning — a supply-chain attack where "
                            f"malicious instructions are embedded in tool "
                            f"metadata to manipulate LLM behavior."
                        ),
                    )
                )
                # One finding per tool to avoid noise — first match is enough
                break

        return findings

    @staticmethod
    def _check_conflicts(
        tool_name: str,
        param_name: str,
        param_def: dict[str, Any],
        location: str,
    ) -> list[Finding]:
        """L3_008: Check for conflicting/impossible schema constraints."""
        findings: list[Finding] = []

        # minimum > maximum (includes exclusive variants)
        _min = param_def.get("minimum")
        _max = param_def.get("maximum")
        if isinstance(_min, (int, float)) and isinstance(_max, (int, float)) and _min > _max:
            findings.append(
                Finding(
                    id="L3_008",
                    layer=Layer.L3_STATIC,
                    severity=FindingSeverity.MEDIUM,
                    tool_name=tool_name,
                    message=(
                        f"Conflicting constraints on '{param_name}': "
                        f"minimum ({_min}) > maximum ({_max})"
                    ),
                    location=location,
                    cwe="CWE-1286",
                )
            )

        # minLength > maxLength
        min_len = param_def.get("minLength")
        max_len = param_def.get("maxLength")
        if isinstance(min_len, int) and isinstance(max_len, int) and min_len > max_len:
            findings.append(
                Finding(
                    id="L3_008",
                    layer=Layer.L3_STATIC,
                    severity=FindingSeverity.MEDIUM,
                    tool_name=tool_name,
                    message=(
                        f"Conflicting constraints on '{param_name}': "
                        f"minLength ({min_len}) > maxLength ({max_len})"
                    ),
                    location=location,
                    cwe="CWE-1286",
                )
            )

        # minItems > maxItems
        min_items = param_def.get("minItems")
        max_items = param_def.get("maxItems")
        if isinstance(min_items, int) and isinstance(max_items, int) and min_items > max_items:
            findings.append(
                Finding(
                    id="L3_008",
                    layer=Layer.L3_STATIC,
                    severity=FindingSeverity.MEDIUM,
                    tool_name=tool_name,
                    message=(
                        f"Conflicting constraints on '{param_name}': "
                        f"minItems ({min_items}) > maxItems ({max_items})"
                    ),
                    location=location,
                    cwe="CWE-1286",
                )
            )

        # exclusiveMinimum >= exclusiveMaximum (impossible range)
        exc_min = param_def.get("exclusiveMinimum")
        exc_max = param_def.get("exclusiveMaximum")
        if (
            isinstance(exc_min, (int, float))
            and isinstance(exc_max, (int, float))
            and exc_min >= exc_max
        ):
            findings.append(
                Finding(
                    id="L3_008",
                    layer=Layer.L3_STATIC,
                    severity=FindingSeverity.MEDIUM,
                    tool_name=tool_name,
                    message=(
                        f"Conflicting constraints on '{param_name}': "
                        f"exclusiveMinimum ({exc_min}) >= exclusiveMaximum ({exc_max})"
                    ),
                    location=location,
                    cwe="CWE-1286",
                )
            )

        # Empty enum
        enum_vals = param_def.get("enum")
        if isinstance(enum_vals, list) and len(enum_vals) == 0:
            findings.append(
                Finding(
                    id="L3_008",
                    layer=Layer.L3_STATIC,
                    severity=FindingSeverity.MEDIUM,
                    tool_name=tool_name,
                    message=f"Empty enum on '{param_name}': no valid value exists",
                    location=location,
                    cwe="CWE-1286",
                )
            )

        return findings

    @staticmethod
    def _finding(
        finding_id: str,
        tool_name: str,
        severity: FindingSeverity,
        message: str,
        *,
        location: str = "",
        attack_type: AttackType | None = None,
        cwe: str | None = None,
        confidence: float = 0.85,
        counterexample: str | None = None,
        description: str = "",
    ) -> Finding:
        return Finding(
            id=finding_id,
            layer=Layer.L3_STATIC,
            severity=severity,
            tool_name=tool_name,
            message=message,
            location=location,
            attack_type=attack_type,
            cwe=cwe,
            confidence=confidence,
            counterexample=counterexample,
            description=description,
        )
