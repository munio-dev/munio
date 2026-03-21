"""P/U/S taxonomy, capability categories, toxic flow rules, and tool classification.

Provides the knowledge base for L5 Compositional Analysis:
- ToolRole: P (Private source), U (Untrusted input), S (State-changing Sink)
- Capability: Fine-grained tool capability categories
- ToxicFlowRule: Capability-combination rules for detecting dangerous flows
- DangerousCombo: Known-dangerous source->sink tool pairs from vulnerability corpus
- classify_tool(): Classify a ToolDefinition by role and capabilities
"""

from __future__ import annotations

import logging
from enum import Enum, Flag, auto
from typing import TYPE_CHECKING, NamedTuple

if TYPE_CHECKING:
    from munio.scan.models import ToolDefinition

__all__ = [
    "Capability",
    "DangerousCombo",
    "ToolRole",
    "ToxicFlowRule",
    "classify_tool",
    "classify_tool_detailed",
    "find_known_combo",
    "match_toxic_rules",
]

logger = logging.getLogger(__name__)


# ── Enums ──────────────────────────────────────────────────────────────


class ToolRole(Flag):
    """P/U/S classification flags. A tool can have multiple roles."""

    NONE = 0
    P = auto()  # Private data source
    U = auto()  # Untrusted input source
    S = auto()  # State-changing Sink


class Capability(str, Enum):
    """Tool capability categories for toxic flow rules."""

    CREDENTIAL_READ = "credential_read"
    FILE_READ = "file_read"
    DB_READ = "db_read"
    SYSTEM_READ = "system_read"
    COMMS_READ = "comms_read"
    CODE_READ = "code_read"
    NETWORK_EXFIL = "network_exfil"
    EMAIL_SEND = "email_send"
    COMMS_SEND = "comms_send"
    FILE_WRITE = "file_write"
    CODE_EXEC = "code_exec"
    CLOUD_WRITE = "cloud_write"
    DB_WRITE = "db_write"
    BROWSER_ACTION = "browser_action"
    VCS_PUSH = "vcs_push"
    FETCH_UNTRUSTED = "fetch_untrusted"


# ── Named tuples ──────────────────────────────────────────────────────


class ToxicFlowRule(NamedTuple):
    """Capability-combination rule for detecting dangerous flows."""

    source_caps: frozenset[Capability]
    sink_caps: frozenset[Capability]
    risk: str  # "CRITICAL" | "HIGH" | "MEDIUM"
    description: str
    cwe: str


class DangerousCombo(NamedTuple):
    """Known dangerous source->sink tool pair from vulnerability corpus."""

    source: str
    sink: str
    risk: str
    description: str
    real_world: str
    cwe: str


# ── Static taxonomy (50 tools from corpus part3) ─────────────────────

_KNOWN_TOOLS: dict[str, tuple[ToolRole, frozenset[Capability]]] = {
    # filesystem
    "read_file": (ToolRole.P, frozenset({Capability.FILE_READ})),
    "write_file": (ToolRole.S, frozenset({Capability.FILE_WRITE})),
    "list_directory": (ToolRole.P, frozenset({Capability.FILE_READ})),
    "delete_file": (ToolRole.S, frozenset({Capability.FILE_WRITE})),
    "move_file": (ToolRole.S, frozenset({Capability.FILE_WRITE})),
    "search_files": (ToolRole.P, frozenset({Capability.FILE_READ})),
    # web
    "fetch_url": (ToolRole.U, frozenset({Capability.FETCH_UNTRUSTED})),
    "http_request": (
        ToolRole.U | ToolRole.S,
        frozenset({Capability.FETCH_UNTRUSTED, Capability.NETWORK_EXFIL}),
    ),
    "web_scrape": (ToolRole.U, frozenset({Capability.FETCH_UNTRUSTED})),
    "webhook_send": (ToolRole.S, frozenset({Capability.NETWORK_EXFIL})),
    # communication
    "send_email": (ToolRole.S, frozenset({Capability.EMAIL_SEND})),
    "read_email": (ToolRole.P | ToolRole.U, frozenset({Capability.COMMS_READ})),
    "send_slack_message": (ToolRole.S, frozenset({Capability.COMMS_SEND})),
    "read_slack_messages": (
        ToolRole.P | ToolRole.U,
        frozenset({Capability.COMMS_READ}),
    ),
    "send_sms": (ToolRole.S, frozenset({Capability.COMMS_SEND})),
    "read_sms": (ToolRole.P | ToolRole.U, frozenset({Capability.COMMS_READ})),
    # database
    "database_query": (ToolRole.P, frozenset({Capability.DB_READ})),
    "database_write": (ToolRole.S, frozenset({Capability.DB_WRITE})),
    "database_schema": (ToolRole.P, frozenset({Capability.DB_READ})),
    "redis_get": (ToolRole.P, frozenset({Capability.DB_READ})),
    "redis_set": (ToolRole.S, frozenset({Capability.DB_WRITE})),
    # system
    "execute_command": (
        ToolRole.P | ToolRole.S,
        frozenset({Capability.SYSTEM_READ, Capability.CODE_EXEC}),
    ),
    "execute_script": (
        ToolRole.P | ToolRole.S,
        frozenset({Capability.SYSTEM_READ, Capability.CODE_EXEC}),
    ),
    "get_env_var": (ToolRole.P, frozenset({Capability.SYSTEM_READ})),
    "set_env_var": (ToolRole.S, frozenset({Capability.CODE_EXEC})),
    "create_process": (ToolRole.S, frozenset({Capability.CODE_EXEC})),
    "read_clipboard": (ToolRole.P, frozenset({Capability.SYSTEM_READ})),
    # vcs
    "git_clone": (
        ToolRole.U | ToolRole.S,
        frozenset({Capability.FETCH_UNTRUSTED, Capability.FILE_WRITE}),
    ),
    "git_diff": (ToolRole.P, frozenset({Capability.CODE_READ})),
    "git_push": (ToolRole.S, frozenset({Capability.VCS_PUSH})),
    "git_log": (ToolRole.P, frozenset({Capability.CODE_READ})),
    # container
    "docker_run": (
        ToolRole.U | ToolRole.S,
        frozenset({Capability.FETCH_UNTRUSTED, Capability.CODE_EXEC}),
    ),
    "docker_exec": (
        ToolRole.P | ToolRole.S,
        frozenset({Capability.SYSTEM_READ, Capability.CODE_EXEC}),
    ),
    "docker_logs": (ToolRole.P, frozenset({Capability.SYSTEM_READ})),
    "kubernetes_get": (ToolRole.P, frozenset({Capability.SYSTEM_READ})),
    "kubernetes_apply": (ToolRole.S, frozenset({Capability.CLOUD_WRITE})),
    # cloud
    "s3_read": (ToolRole.P, frozenset({Capability.FILE_READ})),
    "s3_write": (ToolRole.S, frozenset({Capability.CLOUD_WRITE})),
    "cloud_function_invoke": (
        ToolRole.P | ToolRole.U | ToolRole.S,
        frozenset({Capability.SYSTEM_READ, Capability.FETCH_UNTRUSTED, Capability.CLOUD_WRITE}),
    ),
    # credential
    "secrets_manager_read": (ToolRole.P, frozenset({Capability.CREDENTIAL_READ})),
    "password_store_read": (ToolRole.P, frozenset({Capability.CREDENTIAL_READ})),
    "oauth_token_get": (ToolRole.P, frozenset({Capability.CREDENTIAL_READ})),
    # productivity
    "calendar_read": (ToolRole.P, frozenset({Capability.COMMS_READ})),
    "calendar_create": (ToolRole.S, frozenset({Capability.COMMS_SEND})),
    "contacts_read": (ToolRole.P, frozenset({Capability.COMMS_READ})),
    # browser
    "browser_navigate": (
        ToolRole.U | ToolRole.S,
        frozenset({Capability.FETCH_UNTRUSTED, Capability.BROWSER_ACTION}),
    ),
    "browser_screenshot": (ToolRole.P, frozenset({Capability.CODE_READ})),
    "browser_click": (ToolRole.S, frozenset({Capability.BROWSER_ACTION})),
    "browser_fill_form": (ToolRole.S, frozenset({Capability.BROWSER_ACTION})),
    # network
    "dns_resolve": (ToolRole.U, frozenset({Capability.FETCH_UNTRUSTED})),
}


# ── Toxic flow rules (10 capability-combination rules) ───────────────

_TOXIC_FLOW_RULES: tuple[ToxicFlowRule, ...] = (
    ToxicFlowRule(
        source_caps=frozenset({Capability.CREDENTIAL_READ}),
        sink_caps=frozenset(
            {Capability.NETWORK_EXFIL, Capability.EMAIL_SEND, Capability.COMMS_SEND}
        ),
        risk="CRITICAL",
        description="Credentials or secrets can be exfiltrated via network",
        cwe="CWE-200",
    ),
    ToxicFlowRule(
        source_caps=frozenset({Capability.SYSTEM_READ}),
        sink_caps=frozenset(
            {Capability.NETWORK_EXFIL, Capability.EMAIL_SEND, Capability.COMMS_SEND}
        ),
        risk="HIGH",
        description="System information (env vars, process data) can be exfiltrated",
        cwe="CWE-200",
    ),
    ToxicFlowRule(
        source_caps=frozenset({Capability.FILE_READ}),
        sink_caps=frozenset(
            {
                Capability.NETWORK_EXFIL,
                Capability.EMAIL_SEND,
                Capability.COMMS_SEND,
                Capability.VCS_PUSH,
                Capability.CLOUD_WRITE,
            }
        ),
        risk="CRITICAL",
        description="File contents (may contain secrets) can be exfiltrated",
        cwe="CWE-200",
    ),
    ToxicFlowRule(
        source_caps=frozenset({Capability.DB_READ}),
        sink_caps=frozenset(
            {
                Capability.NETWORK_EXFIL,
                Capability.EMAIL_SEND,
                Capability.COMMS_SEND,
                Capability.CLOUD_WRITE,
                Capability.VCS_PUSH,
            }
        ),
        risk="CRITICAL",
        description="Database records (PII/financial) can be exfiltrated",
        cwe="CWE-200",
    ),
    ToxicFlowRule(
        source_caps=frozenset({Capability.FETCH_UNTRUSTED}),
        sink_caps=frozenset({Capability.CODE_EXEC}),
        risk="CRITICAL",
        description="Untrusted external data can reach code execution",
        cwe="CWE-94",
    ),
    ToxicFlowRule(
        source_caps=frozenset({Capability.FETCH_UNTRUSTED}),
        sink_caps=frozenset({Capability.FILE_WRITE}),
        risk="HIGH",
        description="Untrusted external data can be written to disk",
        cwe="CWE-829",
    ),
    ToxicFlowRule(
        source_caps=frozenset({Capability.FETCH_UNTRUSTED}),
        sink_caps=frozenset({Capability.DB_WRITE}),
        risk="HIGH",
        description="Untrusted external data can be injected into database",
        cwe="CWE-74",
    ),
    ToxicFlowRule(
        source_caps=frozenset({Capability.COMMS_READ}),
        sink_caps=frozenset(
            {
                Capability.NETWORK_EXFIL,
                Capability.EMAIL_SEND,
                Capability.COMMS_SEND,
                Capability.CLOUD_WRITE,
                Capability.VCS_PUSH,
            }
        ),
        risk="HIGH",
        description="Private communications can be forwarded or exfiltrated",
        cwe="CWE-200",
    ),
    ToxicFlowRule(
        source_caps=frozenset({Capability.CODE_READ}),
        sink_caps=frozenset({Capability.NETWORK_EXFIL, Capability.EMAIL_SEND}),
        risk="HIGH",
        description="Source code or VCS data can be exfiltrated",
        cwe="CWE-200",
    ),
    ToxicFlowRule(
        source_caps=frozenset({Capability.FETCH_UNTRUSTED}),
        sink_caps=frozenset({Capability.BROWSER_ACTION}),
        risk="HIGH",
        description="Untrusted content can drive browser actions",
        cwe="CWE-74",
    ),
    ToxicFlowRule(
        source_caps=frozenset({Capability.SYSTEM_READ, Capability.CREDENTIAL_READ}),
        sink_caps=frozenset({Capability.CLOUD_WRITE}),
        risk="HIGH",
        description="System or credential data can reach cloud infrastructure",
        cwe="CWE-200",
    ),
    # Additional rules from review
    ToxicFlowRule(
        source_caps=frozenset({Capability.CREDENTIAL_READ}),
        sink_caps=frozenset({Capability.CODE_EXEC}),
        risk="CRITICAL",
        description="Stolen credentials can be used in code execution for lateral movement",
        cwe="CWE-522",
    ),
    ToxicFlowRule(
        source_caps=frozenset({Capability.FILE_READ}),
        sink_caps=frozenset({Capability.FILE_WRITE}),
        risk="MEDIUM",
        description="Files can be read and modified in place (config tampering, data corruption)",
        cwe="CWE-829",
    ),
    ToxicFlowRule(
        source_caps=frozenset({Capability.DB_READ}),
        sink_caps=frozenset({Capability.DB_WRITE}),
        risk="HIGH",
        description="Database records can be moved or corrupted across databases",
        cwe="CWE-915",
    ),
)


# ── Known dangerous combos (26 from corpus part4) ────────────────────

_DANGEROUS_COMBOS: tuple[DangerousCombo, ...] = (
    DangerousCombo(
        "read_file",
        "send_email",
        "CRITICAL",
        "Read credentials/PII then email to attacker",
        "Invariant Labs WhatsApp+SSH demo (2025)",
        "CWE-200",
    ),
    DangerousCombo(
        "read_file",
        "http_request",
        "CRITICAL",
        "Read sensitive files then POST to attacker endpoint",
        "Trivial Trojans weather+banking PoC (arXiv:2507.19880)",
        "CWE-200",
    ),
    DangerousCombo(
        "read_file",
        "webhook_send",
        "CRITICAL",
        "Read credentials/PII then exfiltrate via webhook",
        "MCPTox benchmark attack template",
        "CWE-200",
    ),
    DangerousCombo(
        "database_query",
        "http_request",
        "CRITICAL",
        "Query PII/financial records then POST externally",
        "Elastic Security Labs cross-tool exfiltration",
        "CWE-200",
    ),
    DangerousCombo(
        "database_query",
        "send_email",
        "CRITICAL",
        "Dump customer data then email to attacker",
        "MCPTox Parameter Tampering attack",
        "CWE-200",
    ),
    DangerousCombo(
        "secrets_manager_read",
        "http_request",
        "CRITICAL",
        "Retrieve API keys/tokens then POST to attacker",
        "CyberArk ATPA credential harvesting",
        "CWE-200",
    ),
    DangerousCombo(
        "secrets_manager_read",
        "send_email",
        "CRITICAL",
        "Read secrets from vault and email externally",
        "HiddenLayer parameter abuse",
        "CWE-200",
    ),
    DangerousCombo(
        "get_env_var",
        "http_request",
        "CRITICAL",
        "Read env vars (AWS_SECRET_KEY) then POST externally",
        "MCPTox Function Hijacking",
        "CWE-200",
    ),
    DangerousCombo(
        "read_email",
        "send_email",
        "HIGH",
        "Read private emails then forward to attacker",
        "Invariant Labs cross-server email forwarding",
        "CWE-200",
    ),
    DangerousCombo(
        "read_email",
        "http_request",
        "HIGH",
        "Read email contents then POST to external URL",
        "MCPTox Implicit Trigger",
        "CWE-200",
    ),
    DangerousCombo(
        "read_slack_messages",
        "http_request",
        "HIGH",
        "Read private Slack messages then exfiltrate via HTTP",
        "Cross-server shadowing pattern",
        "CWE-200",
    ),
    DangerousCombo(
        "read_sms",
        "send_sms",
        "HIGH",
        "Read SMS history then forward to attacker number",
        "Invariant Labs WhatsApp takeover (SMS variant)",
        "CWE-200",
    ),
    DangerousCombo(
        "git_diff",
        "http_request",
        "HIGH",
        "Read code diffs (may contain secrets) then POST externally",
        "Elastic Security Labs GitHub injection",
        "CWE-200",
    ),
    DangerousCombo(
        "browser_screenshot",
        "http_request",
        "HIGH",
        "Capture sensitive page screenshot then upload to attacker",
        "Rehberger YOLO mode attack chain",
        "CWE-200",
    ),
    DangerousCombo(
        "docker_logs",
        "send_email",
        "HIGH",
        "Collect container logs (may have secrets) then email",
        "MCPTox container environment attack",
        "CWE-200",
    ),
    DangerousCombo(
        "fetch_url",
        "execute_command",
        "CRITICAL",
        "Fetch malicious script from URL then execute via shell",
        "CVE-2025-6514 mcp-remote RCE chain",
        "CWE-94",
    ),
    DangerousCombo(
        "fetch_url",
        "write_file",
        "HIGH",
        "Download malicious payload then write to disk (dropper)",
        "Rehberger malicious MCP server config injection",
        "CWE-829",
    ),
    DangerousCombo(
        "read_clipboard",
        "http_request",
        "HIGH",
        "Read clipboard (may contain passwords) then POST externally",
        "HiddenLayer parameter abuse (clipboard variant)",
        "CWE-200",
    ),
    DangerousCombo(
        "kubernetes_get",
        "http_request",
        "CRITICAL",
        "Dump K8s secrets/configmaps then exfiltrate via HTTP",
        "Microsoft MarkItDown SSRF research",
        "CWE-200",
    ),
    DangerousCombo(
        "oauth_token_get",
        "http_request",
        "CRITICAL",
        "Steal OAuth tokens then send for account takeover",
        "CyberArk credential harvesting via tool composition",
        "CWE-200",
    ),
    DangerousCombo(
        "contacts_read",
        "send_email",
        "MEDIUM",
        "Harvest contact list then send phishing emails",
        "MCPTox social engineering attack",
        "CWE-200",
    ),
    DangerousCombo(
        "calendar_read",
        "http_request",
        "MEDIUM",
        "Read calendar events then exfiltrate for social engineering",
        "Enterprise targeted attack pattern",
        "CWE-200",
    ),
    DangerousCombo(
        "fetch_url",
        "database_write",
        "HIGH",
        "Fetch untrusted data then inject into database",
        "MCP-to-database injection chain",
        "CWE-74",
    ),
    DangerousCombo(
        "web_scrape",
        "browser_fill_form",
        "HIGH",
        "Receive injected instructions from scraped page then fill form",
        "Rehberger indirect prompt injection via web",
        "CWE-74",
    ),
    DangerousCombo(
        "read_file",
        "git_push",
        "HIGH",
        "Read private files then commit and push to public repo",
        "Elastic Security Labs private-to-public exfiltration",
        "CWE-200",
    ),
    DangerousCombo(
        "s3_read",
        "s3_write",
        "HIGH",
        "Read from private bucket then copy to attacker-controlled bucket",
        "Cloud data movement attack pattern",
        "CWE-200",
    ),
)


def _normalize_name(name: str) -> str:
    """Normalize tool name for taxonomy lookup."""
    return name.lower().replace("-", "_")


# Precomputed index for O(1) lookup (normalized keys)
_COMBO_INDEX: dict[tuple[str, str], DangerousCombo] = {
    (_normalize_name(c.source), _normalize_name(c.sink)): c for c in _DANGEROUS_COMBOS
}


# ── Keyword heuristics for unknown tools ─────────────────────────────

# Name keywords for heuristic classification.
# Compound keywords (multi-word) preferred to reduce FP.
# Short keywords only for high-specificity terms.
_CAPABILITY_NAME_KEYWORDS: dict[Capability, frozenset[str]] = {
    Capability.FILE_READ: frozenset(
        {
            "read_file",
            "read_text_file",
            "read_media_file",
            "read_multiple_files",
            "get_file",
            "open_file",
            "cat_file",
            "read_document",
            "load_file",
            "list_dir",
            "list_file",
            "find_file",
            "search_file",
            "get_file_info",
            "file_content",
            "s3_download",
            "download_file",
            "list_folder",
            "get_folder",
            "directory_tree",
            "list_allowed",
            "retrieve_a_page",
            "gdrive_search",
            "gsheets_read",
        }
    ),
    Capability.FILE_WRITE: frozenset(
        {
            "write_file",
            "save_file",
            "create_file",
            "upload_file",
            "put_file",
            "move_file",
            "copy_file",
            "rename_file",
            "edit_file",
            "create_dir",
            "create_directory",
            "mkdir",
            "move_to_folder",
        }
    ),
    Capability.CREDENTIAL_READ: frozenset(
        {
            "get_secret",
            "read_secret",
            "list_secret",
            "fetch_secret",
            "credential",
            "password",
            "api_key",
            "vault",
            "keychain",
            "get_token",
            "read_token",
            "oauth_token",
        }
    ),
    Capability.SYSTEM_READ: frozenset(
        {
            "env_var",
            "environment",
            "clipboard",
            "system_info",
            "process_list",
            "list_container",
            "list_process",
            "list_pod",
            "list_node",
            "docker_log",
            "whoami",
        }
    ),
    Capability.DB_READ: frozenset(
        {
            "database_query",
            "db_query",
            "sql_query",
            "query_table",
            "select_from",
            "query",
            "query_data",
            "list_table",
            "describe_table",
            "show_table",
            "run_query",
            "execute_query",
            "execute_sql",
            "run_sql",
            "exec_sql",
            "read_graph",
            "search_node",
            "open_node",
            "read_query",
        }
    ),
    Capability.DB_WRITE: frozenset(
        {
            "database_write",
            "db_write",
            "sql_insert",
            "sql_update",
            "insert_into",
            "insert_record",
            "update_record",
            "delete_record",
            "upsert",
            "truncate_table",
            "drop_table",
        }
    ),
    Capability.COMMS_READ: frozenset(
        {
            "read_email",
            "read_message",
            "inbox",
            "read_slack",
            "read_sms",
            "read_chat",
            "search_message",
            "get_message",
            "list_channel",
            "list_conversation",
            "read_channel",
            "read_thread",
            "read_canvas",
            "read_user",
            "search_user",
            "search_channel",
            "search_issue",
        }
    ),
    Capability.NETWORK_EXFIL: frozenset(
        {
            "http_request",
            "http_post",
            "webhook",
            "post_data",
            "api_call",
            "http_put",
            "send_request",
        }
    ),
    Capability.EMAIL_SEND: frozenset(
        {"send_email", "send_mail", "email_send", "mail_send", "forward_email"}
    ),
    Capability.COMMS_SEND: frozenset(
        {
            "send_slack",
            "send_sms",
            "send_message",
            "post_message",
            "send_chat",
            "send_notification",
            "push_notification",
            "add_reaction",
            "reply_to_message",
            "reply_to_thread",
            "create_issue",
            "create_comment",
        }
    ),
    Capability.CODE_EXEC: frozenset(
        {
            "execute_command",
            "run_command",
            "exec_command",
            "shell_exec",
            "eval_code",
            "evaluate",
            "execute_js",
            "spawn_process",
            "execute_script",
            "run_script",
            "run_code",
            "exec_in_container",
            "run_container",
            "build_image",
            "compose_up",
            "docker_compose",
            "browser_install",
        }
    ),
    Capability.CODE_READ: frozenset(
        {
            "git_diff",
            "git_log",
            "git_show",
            "source_code",
            "screenshot",
            "screen_capture",
            "git_status",
            "get_page_content",
            "get_text_content",
            "get_html_content",
            "git_checkout",
            "git_branch",
            "git_blame",
            "browser_console",
            "browser_network",
            "browser_snapshot",
        }
    ),
    Capability.CLOUD_WRITE: frozenset(
        {
            "s3_write",
            "s3_put",
            "s3_upload",
            "cloud_deploy",
            "k8s_apply",
            "lambda_invoke",
            "deploy_function",
            "deploy_app",
            "create_instance",
            "terminate_instance",
            "stop_container",
        }
    ),
    Capability.BROWSER_ACTION: frozenset(
        {
            "browser_click",
            "fill_form",
            "submit_form",
            "browser_navigate",
            "page_click",
            "navigate_to",
            "click_element",
            "type_text",
            "close_browser",
            "browser_close",
            "browser_resize",
            "browser_drag",
            "browser_handle",
            "browser_press",
            "browser_tabs",
            "browser_wait",
            "browser_file_upload",
            "browser_type",
        }
    ),
    Capability.VCS_PUSH: frozenset(
        {
            "git_push",
            "git_commit",
            "git_add",
            "git_reset",
            "git_create_branch",
            "push_code",
            "push_file",
            "publish_repo",
            "merge_pull",
        }
    ),
    Capability.FETCH_UNTRUSTED: frozenset(
        {
            "fetch_url",
            "web_scrape",
            "crawl",
            "browse_url",
            "dns_resolve",
            "download_url",
            "search_web",
            "web_search",
            "search_internet",
            "navigate",
            "pull_image",
            "git_clone_url",
            "brave_web",
            "brave_local",
            "brave_video",
            "brave_image",
            "brave_news",
            "brave_summarizer",
            "maps_geocode",
            "maps_search",
            "maps_direction",
        }
    ),
}

# Short keywords that match as substrings — restricted to very specific terms.
# These are checked separately with word-boundary awareness to reduce FP.
_SHORT_KEYWORDS: dict[Capability, frozenset[str]] = {
    Capability.NETWORK_EXFIL: frozenset({"post", "put"}),
    Capability.FETCH_UNTRUSTED: frozenset({"fetch"}),
    Capability.BROWSER_ACTION: frozenset({"click", "navigate", "fill", "select", "hover"}),
}

# Verb prefixes that indicate write/mutate operations on otherwise-read keywords.
_WRITE_VERB_PREFIXES: tuple[str, ...] = (
    "set_",
    "delete_",
    "remove_",
    "rotate_",
    "revoke_",
    "destroy_",
    "update_",
    "create_",
    "drop_",
    "reset_",
    "add_",
    "rename_",
    "move_",
    "share_",
    "merge_",
    "push_",
    "patch_",
    "fork_",
    "append_",
)

# Noun-to-capability mapping for verb-prefix tools where no compound keyword matched.
# Used to infer a more specific write capability than the default NETWORK_EXFIL.
_WRITE_NOUN_CAPS: dict[str, Capability] = {
    # File/filesystem
    "file": Capability.FILE_WRITE,
    "dir": Capability.FILE_WRITE,
    "directory": Capability.FILE_WRITE,
    "folder": Capability.FILE_WRITE,
    "item": Capability.FILE_WRITE,
    "page": Capability.FILE_WRITE,
    # Credentials/cloud
    "secret": Capability.CLOUD_WRITE,
    "credential": Capability.CLOUD_WRITE,
    "password": Capability.CLOUD_WRITE,
    "token": Capability.CLOUD_WRITE,
    "permission": Capability.CLOUD_WRITE,
    "branch": Capability.VCS_PUSH,
    "project": Capability.CLOUD_WRITE,
    # Database
    "database": Capability.DB_WRITE,
    "db": Capability.DB_WRITE,
    "table": Capability.DB_WRITE,
    "record": Capability.DB_WRITE,
    "entit": Capability.DB_WRITE,  # entities, entity
    "relation": Capability.DB_WRITE,
    "observation": Capability.DB_WRITE,
    "node": Capability.DB_WRITE,
    # Infrastructure
    "container": Capability.CLOUD_WRITE,
    "instance": Capability.CLOUD_WRITE,
    # Communication
    "email": Capability.EMAIL_SEND,
    "message": Capability.COMMS_SEND,
    "comment": Capability.COMMS_SEND,
    "issue": Capability.COMMS_SEND,
    "canvas": Capability.COMMS_SEND,
    # Files/content
    "block": Capability.FILE_WRITE,
    "data_source": Capability.DB_WRITE,
    "cell": Capability.DB_WRITE,
    # VCS
    "repositor": Capability.VCS_PUSH,
}

# Namespace prefixes stripped before verb matching (API-*, slack_*, etc.)
_NAMESPACE_PREFIXES: tuple[str, ...] = ("api_", "slack_", "gsheets_", "gdrive_")

# Read verb prefixes — symmetric with _WRITE_VERB_PREFIXES.
# Used as fallback when compound/short keywords don't match.
_READ_VERB_PREFIXES: tuple[str, ...] = (
    "list_",
    "get_",
    "find_",
    "search_",
    "retrieve_",
    "describe_",
    "show_",
)

# Noun-to-capability mapping for read-verb tools (symmetric with _WRITE_NOUN_CAPS).
# Order matters: first match wins. Put longer/more-specific nouns first.
_READ_NOUN_CAPS: dict[str, Capability] = {
    # Multi-word (longest first to prevent partial substring matches)
    "pull_request": Capability.CODE_READ,
    "data_source": Capability.DB_READ,
    # Communication/social
    "organization": Capability.COMMS_READ,
    "comment": Capability.COMMS_READ,
    "review": Capability.COMMS_READ,
    "channel": Capability.COMMS_READ,
    "thread": Capability.COMMS_READ,
    "profile": Capability.COMMS_READ,
    "message": Capability.COMMS_READ,
    "issue": Capability.COMMS_READ,
    "user": Capability.COMMS_READ,
    "team": Capability.COMMS_READ,
    "project": Capability.COMMS_READ,
    # Files/documents
    "attachment": Capability.FILE_READ,
    "block": Capability.FILE_READ,
    "page": Capability.FILE_READ,
    "document": Capability.FILE_READ,
    "doc": Capability.FILE_READ,
    "file": Capability.FILE_READ,
    # VCS/code
    "repositor": Capability.CODE_READ,
    "commit": Capability.CODE_READ,
    "release": Capability.CODE_READ,
    "code": Capability.CODE_READ,
    "pull": Capability.CODE_READ,
    # Database
    "database": Capability.DB_READ,
    "template": Capability.DB_READ,
    "table": Capability.DB_READ,
    "record": Capability.DB_READ,
    "graph": Capability.DB_READ,
    "node": Capability.DB_READ,
    # System/monitoring
    "event": Capability.SYSTEM_READ,
    "trace": Capability.SYSTEM_READ,
    "dsn": Capability.SYSTEM_READ,
    "log": Capability.SYSTEM_READ,
    "env": Capability.SYSTEM_READ,
}


# Description keywords — searched as substrings in lowercased description.
_P_DESC_KEYWORDS: frozenset[str] = frozenset(
    {
        "returns file contents",
        "reads from",
        "retrieves credentials",
        "retrieves secrets",
        "returns private",
        "returns sensitive",
        "reads database",
        "reads environment",
        "reads clipboard",
    }
)

_U_DESC_KEYWORDS: frozenset[str] = frozenset(
    {
        "untrusted",
        "external url",
        "arbitrary url",
        "user-provided url",
        "remote server",
        "third-party",
        "from the internet",
    }
)

_S_DESC_KEYWORDS: frozenset[str] = frozenset(
    {
        "sends data",
        "writes to",
        "deletes",
        "creates file",
        "modifies",
        "posts to",
        "uploads to",
        "publishes",
        "executes command",
        "deploys",
        "submits",
    }
)

# Parameter name keywords for capability inference.
_S_PARAM_NAMES: frozenset[str] = frozenset(
    {
        "recipient",
        "to",
        "destination",
        "webhook_url",
        "endpoint",
        "target_url",
        "email",
        "phone",
        "command",
    }
)

_P_PARAM_NAMES: frozenset[str] = frozenset(
    {
        "file_path",
        "path",
        "filename",
        "query",
        "sql",
        "secret_name",
        "key_name",
        "bucket",
        "container_id",
    }
)


# ── Classification ───────────────────────────────────────────────────


def _classify_by_taxonomy(normalized: str) -> tuple[ToolRole, frozenset[Capability]] | None:
    """Look up tool in known taxonomy. Returns None if not found."""
    return _KNOWN_TOOLS.get(normalized)


# Role derivation constants — which capabilities map to which P/U/S roles.
_SOURCE_CAPS: frozenset[Capability] = frozenset(
    {
        Capability.FILE_READ,
        Capability.CREDENTIAL_READ,
        Capability.SYSTEM_READ,
        Capability.DB_READ,
        Capability.COMMS_READ,
        Capability.CODE_READ,
    }
)
_SINK_CAPS: frozenset[Capability] = frozenset(
    {
        Capability.NETWORK_EXFIL,
        Capability.EMAIL_SEND,
        Capability.COMMS_SEND,
        Capability.FILE_WRITE,
        Capability.CODE_EXEC,
        Capability.CLOUD_WRITE,
        Capability.DB_WRITE,
        Capability.BROWSER_ACTION,
        Capability.VCS_PUSH,
    }
)
_UNTRUSTED_CAPS: frozenset[Capability] = frozenset({Capability.FETCH_UNTRUSTED})

# Default capabilities inferred from role when description/param heuristics
# set a role but no specific capability was matched by name keywords.
_DEFAULT_SOURCE_CAP: Capability = Capability.FILE_READ
_DEFAULT_SINK_CAP: Capability = Capability.NETWORK_EXFIL
_DEFAULT_UNTRUSTED_CAP: Capability = Capability.FETCH_UNTRUSTED


def _classify_by_name_keywords(normalized: str) -> tuple[ToolRole, frozenset[Capability]]:
    """Classify by matching name segments against capability keywords.

    Uses five layers:
    1. Namespace prefix stripping (api_, slack_, etc.)
    2. Compound keyword substring matching (multi-word, low FP)
    3. Short keyword matching with word-boundary checks (single-word, controlled FP)
    4. Write-verb prefix + noun inference (set_secret → CLOUD_WRITE)
    5. Read-verb prefix + noun inference (get_issue → COMMS_READ)
    """
    role = ToolRole.NONE
    caps: set[Capability] = set()

    # 1. Strip namespace prefix for effective matching
    effective = normalized
    for ns in _NAMESPACE_PREFIXES:
        if normalized.startswith(ns):
            effective = normalized[len(ns) :]
            break

    # Check verb prefixes on effective name (after namespace strip)
    is_write_verb = any(effective.startswith(prefix) for prefix in _WRITE_VERB_PREFIXES)
    is_read_verb = any(effective.startswith(prefix) for prefix in _READ_VERB_PREFIXES)

    # 2. Compound keyword matching — try both original and effective names
    for cap, keywords in _CAPABILITY_NAME_KEYWORDS.items():
        for kw in keywords:
            if kw in normalized or (effective != normalized and kw in effective):
                # If write-verb + read capability → skip (will be caught as S later)
                if is_write_verb and cap in _SOURCE_CAPS:
                    continue
                caps.add(cap)
                break

    # 3. Short keyword matching — word-boundary: keyword appears as a word segment
    segments = set(effective.split("_"))
    for cap, short_kws in _SHORT_KEYWORDS.items():
        if short_kws & segments:
            # "get" is ambiguous: get_secret = read (not fetch untrusted).
            # If tool already has a source cap (e.g. CREDENTIAL_READ from compound
            # match), skip FETCH_UNTRUSTED — the tool reads local data, not
            # untrusted external input.
            if cap == Capability.FETCH_UNTRUSTED and caps & _SOURCE_CAPS:
                continue
            caps.add(cap)

    # 4. Write-verb prefix + noun inference: write-verb on read-related name → S role
    if is_write_verb and not caps:
        role = role | ToolRole.S
        # Infer specific write cap from noun part (e.g. set_secret → CLOUD_WRITE)
        rest = effective
        for prefix in _WRITE_VERB_PREFIXES:
            if effective.startswith(prefix):
                rest = effective[len(prefix) :]
                break
        for noun, cap in _WRITE_NOUN_CAPS.items():
            if noun in rest:
                caps.add(cap)
                break

    # 5. Read-verb prefix + noun inference: get_issue → COMMS_READ, list_events → SYSTEM_READ
    # Only fires as fallback when no compound/short/write-verb matched.
    # Does NOT set role if no noun matches (avoids FP for get_sum, get_tiny_image).
    if is_read_verb and not caps:
        rest = effective
        for prefix in _READ_VERB_PREFIXES:
            if effective.startswith(prefix):
                rest = effective[len(prefix) :]
                break
        for noun, cap in _READ_NOUN_CAPS.items():
            if noun in rest:
                # Avoid FP: "doc" matches "documentation" but API docs search
                # is not file reading.  Check the noun isn't embedded mid-word
                # by verifying nothing follows except _, digits, or "s" (plural).
                idx = rest.find(noun)
                tail = rest[idx + len(noun) :]
                if tail and tail[0] not in ("_", "s") and not tail[0].isdigit():
                    continue
                caps.add(cap)
                break

    # Derive role from capabilities
    if caps & _SOURCE_CAPS:
        role = role | ToolRole.P
    if caps & _UNTRUSTED_CAPS:
        role = role | ToolRole.U
    if caps & _SINK_CAPS:
        role = role | ToolRole.S

    return role, frozenset(caps)


def _classify_by_description(description: str) -> ToolRole:
    """Classify by description keyword matching. Returns role only (no caps)."""
    if not description:
        return ToolRole.NONE

    desc_lower = description.lower()
    role = ToolRole.NONE

    if any(kw in desc_lower for kw in _P_DESC_KEYWORDS):
        role = role | ToolRole.P
    if any(kw in desc_lower for kw in _U_DESC_KEYWORDS):
        role = role | ToolRole.U
    if any(kw in desc_lower for kw in _S_DESC_KEYWORDS):
        role = role | ToolRole.S

    return role


def _classify_by_params(schema: dict[str, object]) -> ToolRole:
    """Classify by parameter names in input_schema."""
    props = schema.get("properties")
    if not isinstance(props, dict):
        return ToolRole.NONE

    param_names = {k.lower() for k in props}
    role = ToolRole.NONE

    if param_names & _P_PARAM_NAMES:
        role = role | ToolRole.P
    if param_names & _S_PARAM_NAMES:
        role = role | ToolRole.S

    return role


def classify_tool(tool: ToolDefinition) -> tuple[ToolRole, frozenset[Capability]]:
    """Classify a tool by P/U/S role and capabilities.

    Classification priority:
    1. Known taxonomy lookup (exact name match after normalization)
    2. Name keyword heuristic (compound + short keywords)
    3. Description keyword heuristic (adds role)
    4. Parameter name heuristic (adds role)
    5. Annotation adjustments (destructiveHint → S role only)
    6. Default capability inference (role without caps → infer defaults)

    Returns:
        (role, capabilities) tuple. role may be NONE if no match.
    """
    normalized = _normalize_name(tool.name)

    # 1. Known taxonomy
    known = _classify_by_taxonomy(normalized)
    if known is not None:
        return known

    # 2. Name keywords
    role, caps = _classify_by_name_keywords(normalized)

    # 3. Description (adds to role, no new caps)
    desc_role = _classify_by_description(tool.description)
    role = role | desc_role

    # 4. Parameter names (adds to role, no new caps)
    param_role = _classify_by_params(tool.input_schema)
    role = role | param_role

    # 5. Annotation-based adjustments
    # destructiveHint=True strengthens S classification (does NOT add CODE_EXEC —
    # a destructive tool may be delete_user, not code execution)
    if tool.annotations and tool.annotations.get("destructiveHint") is True:
        role = role | ToolRole.S

    # 6. Default capability inference: when role is set but caps is empty,
    #    assign a generic capability so toxic flow rules can match.
    if role != ToolRole.NONE and not caps:
        inferred: set[Capability] = set()
        if role & ToolRole.P:
            inferred.add(_DEFAULT_SOURCE_CAP)
        if role & ToolRole.U:
            inferred.add(_DEFAULT_UNTRUSTED_CAP)
        if role & ToolRole.S:
            inferred.add(_DEFAULT_SINK_CAP)
        caps = frozenset(inferred)

    return role, frozenset(caps)


def classify_tool_detailed(
    tool: ToolDefinition,
) -> tuple[ToolRole, frozenset[Capability], bool]:
    """Classify a tool and indicate if it matched known taxonomy.

    Returns:
        (role, capabilities, is_known) where is_known=True means the tool
        was matched from the static taxonomy, not keyword heuristics.
    """
    normalized = _normalize_name(tool.name)

    # 1. Known taxonomy
    known = _classify_by_taxonomy(normalized)
    if known is not None:
        return known[0], known[1], True

    # 2. Name keywords
    role, caps = _classify_by_name_keywords(normalized)

    # 3. Description (adds to role, no new caps)
    desc_role = _classify_by_description(tool.description)
    role = role | desc_role

    # 4. Parameter names (adds to role, no new caps)
    param_role = _classify_by_params(tool.input_schema)
    role = role | param_role

    # 5. Annotation-based adjustments
    if tool.annotations and tool.annotations.get("destructiveHint") is True:
        role = role | ToolRole.S

    # 6. Default capability inference
    if role != ToolRole.NONE and not caps:
        inferred: set[Capability] = set()
        if role & ToolRole.P:
            inferred.add(_DEFAULT_SOURCE_CAP)
        if role & ToolRole.U:
            inferred.add(_DEFAULT_UNTRUSTED_CAP)
        if role & ToolRole.S:
            inferred.add(_DEFAULT_SINK_CAP)
        caps = frozenset(inferred)

    return role, frozenset(caps), False


# ── Lookup functions ─────────────────────────────────────────────────


def find_known_combo(source_name: str, sink_name: str) -> DangerousCombo | None:
    """Look up a known dangerous source->sink combo by normalized names."""
    src = _normalize_name(source_name)
    snk = _normalize_name(sink_name)
    return _COMBO_INDEX.get((src, snk))


def match_toxic_rules(
    source_caps: frozenset[Capability],
    sink_caps: frozenset[Capability],
) -> list[ToxicFlowRule]:
    """Find all toxic flow rules that match given source and sink capabilities.

    A rule matches when source_caps intersects rule.source_caps AND
    sink_caps intersects rule.sink_caps.
    """
    return [
        rule
        for rule in _TOXIC_FLOW_RULES
        if source_caps & rule.source_caps and sink_caps & rule.sink_caps
    ]
