#!/usr/bin/env python3
"""
Generate rules metadata YAML from infra.windows_ops task files.

Parses the STIG task files for each Windows Server version (2019, 2022, 2025)
and produces a rules YAML file compatible with the AAP Compliance Dashboard.

Usage:
    python scripts/generate_rules_metadata.py \
      --source /path/to/infra.windows_ops \
      --overrides rules/aap_impact_overrides.yml \
      --output rules/
"""

import argparse
import logging
import os
import re
import sys
from datetime import datetime, timezone

import yaml

logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
logger = logging.getLogger(__name__)

# ── Severity normalisation ──────────────────────────────────────────────────

SEVERITY_MAP = {
    "CAT I": "high",
    "CAT II": "medium",
    "CAT III": "low",
}


def normalise_severity(raw: str) -> str:
    return SEVERITY_MAP.get(raw.strip(), "medium")


# ── Benchmark version mapping ──────────────────────────────────────────────

BENCHMARK_VERSIONS = {
    "2019": "V3R7",
    "2022": "V2R7",
    "2025": "V1R0-1",
}


# ── Module mapping for fix_text synthesis ───────────────────────────────────

# Category name (as used in the task file category field or deduced from
# the file name) -> Ansible module + parameter mapping.

CATEGORY_MODULE_MAP = {
    "account_policies": {
        "module": "community.windows.win_security_policy",
        "params": ["section", "key", "value"],
    },
    "registry_settings": {
        "module": "ansible.windows.win_regedit",
        "params": ["path", "name", "data", "type"],
    },
    "security_options": {
        "module": "ansible.windows.win_regedit",
        "params": ["path", "name", "data", "type"],
    },
    "audit_policies": {
        "module": "ansible.windows.win_powershell",
        "params": ["subcategory"],
    },
    "user_rights_assignment": {
        "module": "ansible.windows.win_user_right",
        "params": ["right", "users"],
    },
    "system_services": {
        "module": "ansible.windows.win_service",
        "params": ["name", "state", "start_mode"],
    },
    "manual_controls": None,  # no fix_text
}


# ── Template variable resolution ───────────────────────────────────────────

def load_defaults(source_root: str) -> dict:
    """Load defaults/main.yml and build a variable lookup dict."""
    defaults_path = os.path.join(
        source_root,
        "roles", "windows_manage_stig", "defaults", "main.yml",
    )
    if not os.path.isfile(defaults_path):
        logger.warning("defaults/main.yml not found at %s", defaults_path)
        return {}

    with open(defaults_path, "r") as fh:
        data = yaml.safe_load(fh) or {}

    lookup = {}
    for key, value in data.items():
        lookup[key] = value
    return lookup


_TEMPLATE_RE = re.compile(r"\{\{\s*([\w]+)\s*(?:\|[^}]*)?\}\}")


def resolve_template(value, defaults: dict):
    """Replace {{ var_name }} (with optional Jinja filters) with defaults."""
    if not isinstance(value, str):
        return value
    def _replace(m):
        var_name = m.group(1)
        if var_name in defaults:
            resolved = defaults[var_name]
            # Convert booleans to int-string for policy values
            if isinstance(resolved, bool):
                return str(int(resolved))
            return str(resolved)
        return m.group(0)  # keep literal if no default
    return _TEMPLATE_RE.sub(_replace, value)


# ── fix_text generation ────────────────────────────────────────────────────

def generate_fix_text(rule: dict, category: str, defaults: dict) -> str | None:
    """Synthesise a fix_text block for the given rule and category."""
    mapping = CATEGORY_MODULE_MAP.get(category)
    if mapping is None:
        return None

    module = mapping["module"]
    stig_id = rule.get("stig_id", "unknown")
    title = rule.get("title") or rule.get("description", "")

    if category == "account_policies":
        section = rule.get("section", "")
        key = rule.get("key", "")
        value = resolve_template(rule.get("value", ""), defaults)
        return (
            f'- name: "STIG {stig_id}: {title}"\n'
            f"  {module}:\n"
            f'    section: "{section}"\n'
            f"    key: {key}\n"
            f'    value: "{value}"'
        )

    if category in ("registry_settings", "security_options"):
        path = rule.get("path", "")
        name = rule.get("name", "")
        data = resolve_template(rule.get("data", ""), defaults)
        reg_type = rule.get("type", "dword")
        # Special handling for list data (multistring)
        if isinstance(data, list):
            data_repr = str(data)
        else:
            data_repr = str(data)
        return (
            f'- name: "STIG {stig_id}: {title}"\n'
            f"  {module}:\n"
            f"    path: {path}\n"
            f"    name: {name}\n"
            f"    data: {data_repr}\n"
            f"    type: {reg_type}"
        )

    if category == "audit_policies":
        subcategory = rule.get("subcategory", "")
        success = rule.get("success", False)
        failure = rule.get("failure", False)
        if success and failure:
            setting = "SuccessAndFailure"
        elif success:
            setting = "Success"
        elif failure:
            setting = "Failure"
        else:
            setting = "NoAuditing"
        return (
            f'- name: "STIG {stig_id}: {title}"\n'
            f"  {module}:\n"
            f"    script: |\n"
            f'      auditpol /set /subcategory:"{subcategory}" /success:{("enable" if success else "disable")} /failure:{("enable" if failure else "disable")}'
        )

    if category == "user_rights_assignment":
        right = rule.get("right", "")
        users = rule.get("users", [])
        if isinstance(users, list):
            users_repr = str(users)
        else:
            users_repr = str(users)
        return (
            f'- name: "STIG {stig_id}: {title}"\n'
            f"  {module}:\n"
            f"    name: {right}\n"
            f"    users: {users_repr}\n"
            f"    action: set"
        )

    if category == "system_services":
        # Some versions (2019/2025) use feature_name for Windows features
        feature_name = rule.get("feature_name")
        if feature_name:
            return (
                f'- name: "STIG {stig_id}: {title}"\n'
                f"  ansible.windows.win_feature:\n"
                f"    name: {feature_name}\n"
                f"    state: absent"
            )
        svc_name = rule.get("name", "")
        state = resolve_template(rule.get("state", ""), defaults)
        start_mode = resolve_template(rule.get("start_mode", ""), defaults)
        return (
            f'- name: "STIG {stig_id}: {title}"\n'
            f"  {module}:\n"
            f"    name: {svc_name}\n"
            f"    state: {state}\n"
            f"    start_mode: {start_mode}"
        )

    return None


# ── YAML parsers per pattern ────────────────────────────────────────────────

def _find_set_fact_var(data: list[dict], expected_prefix: str) -> tuple[str, object] | None:
    """Walk the top-level task list, find the first set_fact task whose
    variable name starts with *expected_prefix*, return (var_name, value)."""
    for task in data:
        if not isinstance(task, dict):
            continue
        sf = task.get("ansible.builtin.set_fact")
        if not sf or not isinstance(sf, dict):
            continue
        for var_name, var_value in sf.items():
            if var_name.startswith(expected_prefix):
                return var_name, var_value
    return None


def parse_flat_list(filepath: str, category: str) -> list[dict]:
    """Pattern 1: flat list in set_fact variable."""
    with open(filepath, "r") as fh:
        data = yaml.safe_load(fh)
    if not isinstance(data, list):
        logger.warning("Expected list at top level: %s", filepath)
        return []

    # Determine expected variable prefix from category
    prefix_map = {
        "account_policies": "windows_manage_stig_account_polic",
        "registry_settings": "windows_manage_stig_registry_setting",
        "audit_policies": "windows_manage_stig_audit_polic",
        "user_rights_assignment": "windows_manage_stig_user_right",
    }
    prefix = prefix_map.get(category, "windows_manage_stig_")
    result = _find_set_fact_var(data, prefix)
    if result is None:
        logger.warning("No set_fact variable found in %s", filepath)
        return []

    _, value = result
    if not isinstance(value, list):
        logger.warning("set_fact value is not a list in %s", filepath)
        return []
    return value


def parse_nested(filepath: str, category: str) -> list[dict]:
    """Pattern 2: nested sub-category keys, each containing a list.
    Also handles the variant where 2019/2025 system_services use a flat
    list under a different variable name (windows_manage_stig_features_to_remove)."""
    with open(filepath, "r") as fh:
        data = yaml.safe_load(fh)
    if not isinstance(data, list):
        logger.warning("Expected list at top level: %s", filepath)
        return []

    prefix_map = {
        "security_options": "windows_manage_stig_security_option",
        "system_services": "windows_manage_stig_system_service",
    }
    prefix = prefix_map.get(category, "windows_manage_stig_")
    result = _find_set_fact_var(data, prefix)

    # Fallback: 2019/2025 system_services use windows_manage_stig_features_to_remove
    if result is None and category == "system_services":
        result = _find_set_fact_var(data, "windows_manage_stig_features_to_remove")
        if result is not None:
            _, value = result
            if isinstance(value, list):
                return value
            logger.warning("features_to_remove value is not a list in %s", filepath)
            return []

    if result is None:
        logger.warning("No set_fact variable found in %s", filepath)
        return []

    _, value = result
    if not isinstance(value, dict):
        # Could be a flat list (some versions)
        if isinstance(value, list):
            return value
        logger.warning("set_fact value is not a dict (nested) in %s", filepath)
        return []

    # Flatten all sub-category lists
    rules = []
    for subcat_name, subcat_list in value.items():
        if not isinstance(subcat_list, list):
            continue
        for item in subcat_list:
            if isinstance(item, dict):
                rules.append(item)
    return rules


def parse_manual_controls(filepath: str) -> list[dict]:
    """Pattern 3: rules in a loop: directive on a task."""
    with open(filepath, "r") as fh:
        data = yaml.safe_load(fh)
    if not isinstance(data, list):
        logger.warning("Expected list at top level: %s", filepath)
        return []

    rules = []
    for task in data:
        if not isinstance(task, dict):
            continue
        loop_items = task.get("loop")
        if not isinstance(loop_items, list):
            continue
        for item in loop_items:
            if isinstance(item, dict) and "stig_id" in item:
                # Normalise: manual_controls items have 'notes' instead of
                # 'description', and may lack severity
                rule = {
                    "stig_id": item.get("stig_id", ""),
                    "title": item.get("title", ""),
                    "severity": item.get("severity", "CAT II"),
                    "notes": item.get("notes", ""),
                }
                rules.append(rule)
    return rules


# ── stig_id helpers ─────────────────────────────────────────────────────────

def base_stig_id(sid: str) -> str:
    """Strip compound suffix: V-254248-1 -> V-254248.
    Only removes suffixes after a V-NNNNNN base (i.e. the third segment)."""
    m = re.match(r"^(V-\d+)(-\d+)?$", sid)
    if m:
        return m.group(1)
    return sid


# ── Main rule-building logic ───────────────────────────────────────────────

SKIP_FILES = {"advanced_features.yml"}

CATEGORY_FROM_FILENAME = {
    "account_policies.yml": "account_policies",
    "registry_settings.yml": "registry_settings",
    "audit_policies.yml": "audit_policies",
    "user_rights_assignment.yml": "user_rights_assignment",
    "security_options.yml": "security_options",
    "system_services.yml": "system_services",
    "manual_controls.yml": "manual_controls",
}

FLAT_CATEGORIES = {"account_policies", "registry_settings", "audit_policies", "user_rights_assignment"}
NESTED_CATEGORIES = {"security_options", "system_services"}


def build_rules_for_version(
    source_root: str,
    version: str,
    defaults: dict,
    overrides: dict,
) -> list[dict]:
    """Parse all task files for a version and return a list of rule dicts."""
    tasks_dir = os.path.join(
        source_root,
        "roles", "windows_manage_stig", "tasks", version,
    )
    if not os.path.isdir(tasks_dir):
        logger.warning("Tasks directory not found: %s", tasks_dir)
        return []

    seen_ids: dict[str, str] = {}  # stig_id -> category (for dedup)
    all_rules: list[dict] = []

    for filename in sorted(os.listdir(tasks_dir)):
        if filename in SKIP_FILES:
            logger.info("  Skipping %s (excluded)", filename)
            continue
        if filename not in CATEGORY_FROM_FILENAME:
            logger.info("  Skipping unknown file %s", filename)
            continue

        category = CATEGORY_FROM_FILENAME[filename]
        filepath = os.path.join(tasks_dir, filename)
        logger.info("  Parsing %s (category=%s)", filename, category)

        if category == "manual_controls":
            raw_rules = parse_manual_controls(filepath)
        elif category in FLAT_CATEGORIES:
            raw_rules = parse_flat_list(filepath, category)
        elif category in NESTED_CATEGORIES:
            raw_rules = parse_nested(filepath, category)
        else:
            continue

        for raw in raw_rules:
            stig_id = str(raw.get("stig_id", "")).strip()
            if not stig_id:
                continue

            # Skip stig_ids that look like placeholders
            if not stig_id.startswith("V-"):
                logger.warning("  Skipping non-standard stig_id: %s", stig_id)
                continue

            bid = base_stig_id(stig_id)

            # Deduplication
            if stig_id in seen_ids:
                logger.warning(
                    "  Duplicate stig_id %s (first in %s, also in %s) -- skipping",
                    stig_id, seen_ids[stig_id], category,
                )
                continue
            seen_ids[stig_id] = category

            severity_raw = raw.get("severity", "CAT II")
            severity = normalise_severity(str(severity_raw))
            # Title: prefer 'title', fall back to 'description' (2019/2025
            # system_services and some nested items use 'description' as title)
            title = str(raw.get("title") or raw.get("description", "")).strip()

            # fix_text
            is_manual = category == "manual_controls"
            fix_text_str = None
            if not is_manual:
                fix_text_str = generate_fix_text(raw, category, defaults)

            # aap_impact from overrides
            override = overrides.get(stig_id, overrides.get(bid, {}))
            aap_impact = override.get("aap_impact", "safe")
            aap_impact_reason = override.get("aap_impact_reason", "")

            rule = {
                "id": stig_id,
                "stig_id": bid,
                "title": title,
                "severity": severity,
                "category": category,
            }

            if fix_text_str is not None:
                rule["fix_text"] = fix_text_str
            else:
                rule["fix_text"] = ""

            if is_manual:
                rule["automation_available"] = False

            rule["aap_impact"] = aap_impact
            rule["aap_impact_reason"] = aap_impact_reason

            all_rules.append(rule)

    return all_rules


# ── YAML output ─────────────────────────────────────────────────────────────

class LiteralStr(str):
    """Wrapper to force literal block style in YAML output."""
    pass


def literal_representer(dumper, data):
    return dumper.represent_scalar("tag:yaml.org,2002:str", data, style="|")


yaml.add_representer(LiteralStr, literal_representer)


def _prepare_rule_for_yaml(rule: dict) -> dict:
    """Convert fix_text to LiteralStr for block-style output."""
    out = dict(rule)
    if out.get("fix_text"):
        out["fix_text"] = LiteralStr(out["fix_text"])
    return out


def write_output(
    rules: list[dict],
    version: str,
    output_dir: str,
) -> str:
    """Write rules YAML for one version. Returns the output path."""
    os.makedirs(output_dir, exist_ok=True)
    out_path = os.path.join(output_dir, f"stig_windows_{version}.yml")

    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    benchmark_version = BENCHMARK_VERSIONS.get(version, "unknown")

    doc = {
        "profile": {
            "id": f"stig_windows_{version}",
            "name": f"DISA STIG for Windows Server {version}",
            "version": benchmark_version,
            "framework": "DISA_STIG",
            "rule_count": len(rules),
            "source_collection": "infra.windows_ops",
            "generated_at": now,
        },
        "rules": [_prepare_rule_for_yaml(r) for r in rules],
    }

    header = (
        f"# AUTO-GENERATED by scripts/generate_rules_metadata.py\n"
        f"# Source: infra.windows_ops (roles/windows_manage_stig/tasks/{version}/)\n"
        f"# Re-generate: python scripts/generate_rules_metadata.py --source <path> --output rules/\n"
        f"# Do NOT edit -- curated overrides go in rules/aap_impact_overrides.yml\n"
    )

    with open(out_path, "w") as fh:
        fh.write(header)
        yaml.dump(
            doc,
            fh,
            default_flow_style=False,
            sort_keys=False,
            allow_unicode=True,
            width=120,
        )

    return out_path


# ── Overrides loader ────────────────────────────────────────────────────────

def load_overrides(path: str | None) -> dict:
    """Load aap_impact_overrides.yml -> dict keyed by stig_id."""
    if path is None or not os.path.isfile(path):
        logger.info("No overrides file found (path=%s)", path)
        return {}

    with open(path, "r") as fh:
        data = yaml.safe_load(fh) or {}

    raw = data.get("overrides", {})
    if not isinstance(raw, dict):
        logger.warning("overrides key is not a dict in %s", path)
        return {}
    return raw


# ── CLI ─────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Generate rules metadata YAML from infra.windows_ops task files.",
    )
    parser.add_argument(
        "--source",
        required=True,
        help="Path to infra.windows_ops repo root",
    )
    parser.add_argument(
        "--overrides",
        default=None,
        help="Path to aap_impact_overrides.yml",
    )
    parser.add_argument(
        "--output",
        default="rules/",
        help="Output directory for generated YAML files",
    )
    parser.add_argument(
        "--versions",
        nargs="*",
        default=None,
        help="Specific versions to generate (default: auto-detect from tasks/)",
    )
    args = parser.parse_args()

    source_root = os.path.abspath(args.source)
    if not os.path.isdir(source_root):
        logger.error("Source directory not found: %s", source_root)
        sys.exit(1)

    # Auto-detect available versions
    tasks_base = os.path.join(source_root, "roles", "windows_manage_stig", "tasks")
    if args.versions:
        versions = args.versions
    else:
        if not os.path.isdir(tasks_base):
            logger.error("Tasks base directory not found: %s", tasks_base)
            sys.exit(1)
        versions = sorted([
            d for d in os.listdir(tasks_base)
            if os.path.isdir(os.path.join(tasks_base, d)) and d.isdigit()
        ])
    if not versions:
        logger.error("No version directories found under %s", tasks_base)
        sys.exit(1)

    logger.info("Source: %s", source_root)
    logger.info("Versions: %s", ", ".join(versions))

    # Load defaults and overrides
    defaults = load_defaults(source_root)
    logger.info("Loaded %d default variables", len(defaults))

    overrides = load_overrides(args.overrides)
    logger.info("Loaded %d override entries", len(overrides))

    # Process each version
    output_dir = os.path.abspath(args.output)
    total_rules = 0
    for version in versions:
        logger.info("Processing Windows Server %s ...", version)
        rules = build_rules_for_version(source_root, version, defaults, overrides)
        out_path = write_output(rules, version, output_dir)
        logger.info(
            "  -> %s (%d rules)", os.path.relpath(out_path), len(rules),
        )
        total_rules += len(rules)

    logger.info("Done. %d total rules across %d version(s).", total_rules, len(versions))


if __name__ == "__main__":
    main()
