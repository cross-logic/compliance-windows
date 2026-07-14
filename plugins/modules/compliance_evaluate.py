#!/usr/bin/python
# -*- coding: utf-8 -*-

# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

DOCUMENTATION = r"""
---
module: compliance_evaluate
short_description: Evaluate gathered facts against Windows STIG/CIS compliance rules
description:
  - Runs on localhost (inside the EE), NOT on target hosts.
  - Receives gathered compliance facts and evaluates them against rules.
  - Rules are defined as data (YAML) in the collection.
  - Produces structured findings in Common Findings Format (CFF) with
    pass/fail status, severity, and evidence.
  - Scanner-agnostic — evaluation logic is decoupled from fact gathering.
version_added: "0.1.0"
options:
  facts:
    description:
      - Compliance facts gathered by the compliance_gather role.
      - "Expected sections: registry, secpol, auditpol, services."
    type: dict
    required: true
  rules:
    description:
      - List of compliance rules to evaluate.
      - Each rule must have id, check type, path, expected value, and metadata.
    type: list
    elements: dict
    required: true
  profile:
    description: Compliance profile name for reporting.
    type: str
    default: stig
  host:
    description: Hostname these facts belong to (for reporting).
    type: str
    required: true
author:
  - Steve Fulmer (@stevefulme1)
"""

EXAMPLES = r"""
- name: Evaluate compliance facts against Windows STIG rules
  security.compliance_windows.compliance_evaluate:
    facts: "{{ compliance_gather_facts }}"
    rules: "{{ stig_rules }}"
    host: "{{ inventory_hostname }}"
    profile: stig
  register: evaluation
  delegate_to: localhost

- name: Evaluate with rules loaded from file
  block:
    - name: Load Windows Server 2022 STIG rules
      ansible.builtin.include_vars:
        file: rules/stig_windows_server_2022.yml
        name: stig_content

    - name: Run evaluation
      security.compliance_windows.compliance_evaluate:
        facts: "{{ compliance_gather_facts }}"
        rules: "{{ stig_content.rules }}"
        host: win-server01.example.com
      register: evaluation

- name: Display failing findings
  ansible.builtin.debug:
    msg: "FAIL: {{ item.title }} ({{ item.severity }})"
  loop: "{{ evaluation.findings | selectattr('status', 'eq', 'fail') }}"
"""

RETURN = r"""
findings:
  description: List of compliance findings in CFF format.
  returned: always
  type: list
  elements: dict
  contains:
    ruleId:
      description: Rule identifier.
      type: str
    stigId:
      description: DISA STIG V-ID.
      type: str
    title:
      description: Rule title.
      type: str
    severity:
      description: Severity category.
      type: str
    status:
      description: Evaluation result.
      type: str
    detail:
      description: Evidence detail.
      type: str
summary:
  description: Summary counts of findings by status.
  returned: always
  type: dict
  contains:
    total:
      description: Total findings evaluated.
      type: int
    pass:
      description: Findings that passed.
      type: int
    fail:
      description: Findings that failed.
      type: int
    notchecked:
      description: Findings that could not be evaluated.
      type: int
host:
  description: Hostname these findings belong to.
  returned: always
  type: str
"""

from ansible.module_utils.basic import AnsibleModule

SEVERITY_MAP = {
    "high": "CAT_I",
    "medium": "CAT_II",
    "low": "CAT_III",
    "cat_i": "CAT_I",
    "cat_ii": "CAT_II",
    "cat_iii": "CAT_III",
}

def _safe_int(v):
    """Parse an integer, handling hex (0x...) and string representations."""
    s = str(v).strip()
    return int(s, 0) if s.startswith(('0x', '0X')) else int(s)

OPERATORS = {
    "eq": lambda a, e: str(a) == str(e),
    "ne": lambda a, e: str(a) != str(e),
    "ge": lambda a, e: _safe_int(a) >= _safe_int(e),
    "le": lambda a, e: _safe_int(a) <= _safe_int(e),
    "gt": lambda a, e: _safe_int(a) > _safe_int(e),
    "lt": lambda a, e: _safe_int(a) < _safe_int(e),
    "contains": lambda a, e: str(e) in str(a),
    "not_contains": lambda a, e: str(e) not in str(a),
}


def _map_severity(raw):
    return SEVERITY_MAP.get(str(raw).lower(), "CAT_II")


def _get_actual_value(facts, rule):
    """Extract the actual value from gathered facts based on check type."""
    check = rule.get("check", {})
    check_type = check.get("type", rule.get("check_type", "registry"))
    params = check.get("params", {})
    path = params.get("key", params.get("path", rule.get("path", "")))
    prop = params.get("property", rule.get("property", ""))

    if check_type == "registry":
        section = facts.get("registry", {})
        reg_key = section.get(path, {})
        return reg_key.get(prop) if prop else reg_key

    if check_type == "secpol":
        return facts.get("secpol", {}).get(path)

    if check_type == "auditpol":
        return facts.get("auditpol", {}).get(path)

    if check_type == "service":
        services = facts.get("services", [])
        svc = next((s for s in services if s.get("name") == path or s.get("Name") == path), None)
        if svc is None:
            return None
        return svc.get(prop, svc.get("Status"))

    return None


def evaluate_single_rule(rule, facts):
    """Evaluate a single rule against gathered facts."""
    check = rule.get("check", {})
    params = check.get("params", {})
    expected = params.get("value", rule.get("expected"))
    operator = params.get("operator", rule.get("operator", "eq"))

    severity = _map_severity(rule.get("severity", "medium"))

    finding = {
        "ruleId": rule.get("id", "unknown"),
        "stigId": rule.get("stig_id", ""),
        "title": rule.get("title", ""),
        "description": rule.get("description", ""),
        "severity": severity,
        "category": rule.get("category", ""),
        "disruption": rule.get("disruption", "low"),
        "fixText": rule.get("fix_text", ""),
        "checkText": rule.get("check_text", ""),
        "parameters": rule.get("parameters", []),
    }

    try:
        actual = _get_actual_value(facts, rule)

        if actual is None:
            finding["status"] = "notchecked"
            finding["detail"] = "Setting not found"
            return finding

        op_func = OPERATORS.get(operator)
        if op_func is None:
            finding["status"] = "notchecked"
            finding["detail"] = "Unknown operator: %s" % operator
            return finding

        passed = op_func(actual, expected)
        finding["status"] = "pass" if passed else "fail"
        finding["detail"] = "Expected %s %s, got %s" % (operator, expected, actual)
        finding["actual_value"] = str(actual)
        finding["expected_value"] = str(expected)

    except Exception as exc:
        finding["status"] = "notchecked"
        finding["detail"] = "Evaluation error: %s" % str(exc)

    return finding


def main():
    module = AnsibleModule(
        argument_spec=dict(
            facts=dict(type="dict", required=True),
            rules=dict(type="list", elements="dict", required=True),
            profile=dict(type="str", default="stig"),
            host=dict(type="str", required=True),
        ),
        supports_check_mode=True,
    )

    facts = module.params["facts"]
    rules = module.params["rules"]
    host = module.params["host"]

    findings = []
    for rule in rules:
        finding = evaluate_single_rule(rule, facts)
        findings.append(finding)

    summary = {
        "total": len(findings),
        "pass": len([f for f in findings if f["status"] == "pass"]),
        "fail": len([f for f in findings if f["status"] == "fail"]),
        "notchecked": len([f for f in findings if f["status"] == "notchecked"]),
        "error": len([f for f in findings if f["status"] == "error"]),
        "notapplicable": len([f for f in findings if f["status"] == "notapplicable"]),
    }

    module.exit_json(
        changed=False,
        findings=findings,
        summary=summary,
        host=host,
    )


if __name__ == "__main__":
    main()
