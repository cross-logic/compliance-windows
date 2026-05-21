"""Filters to transform compliance results to Common Findings Format (CFF).

Outputs both camelCase fields (for Backstage aap-compliance-pipelines plugin)
and snake_case fields (for standalone / legacy consumers).
"""

import json

_STATUS_MAP = {
    "PASS": "pass",
    "FAIL": "fail",
    "MANUAL": "notchecked",
    "ERROR": "error",
    "NOT_APPLICABLE": "notapplicable",
}

_SEVERITY_MAP = {
    "CAT I": "CAT_I",
    "CAT II": "CAT_II",
    "CAT III": "CAT_III",
}

_SEVERITY_LABEL_MAP = {
    "high": "CAT_I",
    "medium": "CAT_II",
    "low": "CAT_III",
}

_EMPTY_FINDING = {
    "ruleId": "",
    "rule_id": "",
    "stigId": "",
    "stig_id": "",
    "title": "",
    "description": "",
    "fixText": "",
    "fix_text": "",
    "checkText": "",
    "check_text": "",
    "status": "error",
    "severity": "",
    "category": "",
    "disruption": "low",
    "section": "",
    "actualValue": "",
    "actual_value": "",
    "expectedValue": "",
    "expected_value": "",
    "checkType": "automated",
    "check_type": "automated",
    "parameters": [],
}


def _safe_str(value):
    if value is None:
        return ""
    if isinstance(value, (str, int, float, bool)):
        return str(value)
    try:
        return json.dumps(value)
    except (TypeError, ValueError):
        return str(value)


def _map_severity(raw):
    """Map severity through CAT notation or high/medium/low labels."""
    if raw in _SEVERITY_MAP:
        return _SEVERITY_MAP[raw]
    lower = str(raw).lower()
    if lower in _SEVERITY_LABEL_MAP:
        return _SEVERITY_LABEL_MAP[lower]
    return raw


class FilterModule:
    """CFF transformation filters for compliance normalization."""

    def filters(self):
        return {
            "to_cff_stig": self.to_cff_stig,
            "to_cff_cis": self.to_cff_cis,
            "to_cff_powerstig": self.to_cff_powerstig,
        }

    @staticmethod
    def to_cff_stig(result):
        """Transform a single STIG result dict to CFF format.

        Outputs both camelCase (Backstage) and snake_case (standalone) fields.
        """
        if not result or not isinstance(result, dict):
            return dict(_EMPTY_FINDING)
        raw_status = result.get("status", "MANUAL")
        rule_id = result.get("stig_id", result.get("rule_id", ""))
        stig_id = result.get("vuln_id", result.get("stig_id", ""))
        severity = _map_severity(result.get("severity", ""))
        actual = _safe_str(result.get("current_value", ""))
        expected = _safe_str(result.get("expected_value", result.get("value", "")))
        fix_text = result.get("fix_text", result.get("fixText", ""))
        check_text = result.get("check_text", result.get("checkText", ""))
        disruption = result.get("disruption", "low")
        parameters = result.get("parameters", [])

        return {
            # camelCase (Backstage plugin)
            "ruleId": rule_id,
            "stigId": stig_id,
            "fixText": fix_text,
            "checkText": check_text,
            "actualValue": actual,
            "expectedValue": expected,
            "checkType": result.get("check_type", "automated"),
            # snake_case (standalone)
            "rule_id": rule_id,
            "stig_id": stig_id,
            "fix_text": fix_text,
            "check_text": check_text,
            "actual_value": actual,
            "expected_value": expected,
            "check_type": result.get("check_type", "automated"),
            # shared fields
            "title": result.get("title", ""),
            "description": result.get("description", ""),
            "status": _STATUS_MAP.get(raw_status, "notchecked"),
            "severity": severity,
            "category": result.get("category", ""),
            "disruption": disruption,
            "section": result.get("section", ""),
            "parameters": parameters,
        }

    @staticmethod
    def to_cff_cis(result):
        """Transform a single CIS result dict to CFF format.

        Outputs both camelCase (Backstage) and snake_case (standalone) fields.
        """
        if not result or not isinstance(result, dict):
            return dict(_EMPTY_FINDING)
        raw_status = result.get("status", "MANUAL")
        rule_id = result.get("cis_id", result.get("rule_id", ""))
        stig_id = result.get("vuln_id", result.get("stig_id", ""))
        severity = _map_severity(result.get("level", result.get("profile", "")))
        actual = _safe_str(result.get("current_value", ""))
        expected = _safe_str(result.get("expected_value", result.get("value", "")))
        fix_text = result.get("fix_text", result.get("fixText", ""))
        check_text = result.get("check_text", result.get("checkText", ""))
        disruption = result.get("disruption", "low")
        parameters = result.get("parameters", [])

        return {
            # camelCase (Backstage plugin)
            "ruleId": rule_id,
            "stigId": stig_id,
            "fixText": fix_text,
            "checkText": check_text,
            "actualValue": actual,
            "expectedValue": expected,
            "checkType": result.get("check_type", "automated"),
            # snake_case (standalone)
            "rule_id": rule_id,
            "stig_id": stig_id,
            "fix_text": fix_text,
            "check_text": check_text,
            "actual_value": actual,
            "expected_value": expected,
            "check_type": result.get("check_type", "automated"),
            # shared fields
            "title": result.get("title", ""),
            "description": result.get("description", ""),
            "status": _STATUS_MAP.get(raw_status, "notchecked"),
            "severity": severity,
            "category": result.get("category", result.get("section", "")),
            "disruption": disruption,
            "section": result.get("section", ""),
            "parameters": parameters,
        }

    @staticmethod
    def to_cff_powerstig(result):
        """Transform a PowerSTIG DSC result to CFF format.

        Outputs both camelCase (Backstage) and snake_case (standalone) fields.
        """
        if not result or not isinstance(result, dict):
            return dict(_EMPTY_FINDING)
        powerstig_status = {
            "True": "pass",
            "False": "fail",
            True: "pass",
            False: "fail",
        }
        in_desired = result.get("InDesiredState", result.get("inDesiredState", ""))
        rule_id = result.get("RuleId", result.get("ruleId", ""))
        stig_id = result.get("VulnId", result.get("vulnId", rule_id))
        severity = _map_severity(result.get("Severity", result.get("severity", "")))
        fix_text = result.get("FixText", result.get("fixText", ""))
        check_text = result.get("CheckText", result.get("checkText", ""))
        disruption = result.get("Disruption", result.get("disruption", "low"))
        actual = _safe_str(result.get("ActualValue", ""))
        expected = _safe_str(result.get("ExpectedValue", ""))
        parameters = result.get("Parameters", result.get("parameters", []))

        return {
            # camelCase (Backstage plugin)
            "ruleId": rule_id,
            "stigId": stig_id,
            "fixText": fix_text,
            "checkText": check_text,
            "actualValue": actual,
            "expectedValue": expected,
            "checkType": "automated",
            # snake_case (standalone)
            "rule_id": rule_id,
            "stig_id": stig_id,
            "fix_text": fix_text,
            "check_text": check_text,
            "actual_value": actual,
            "expected_value": expected,
            "check_type": "automated",
            # shared fields
            "title": result.get("ResourceId", result.get("resourceId", "")),
            "description": result.get("ModuleName", ""),
            "status": powerstig_status.get(in_desired, "notchecked"),
            "severity": severity,
            "category": "PowerSTIG",
            "disruption": disruption,
            "section": result.get("DscResource", result.get("dscResource", "")),
            "parameters": parameters,
            "scanner": "powerstig",
        }


def evaluate_rule(rule, gathered_facts):
    """Evaluate a single compliance rule against gathered system facts.

    Args:
        rule: dict with keys: id, title, check_type, path, expected, operator
        gathered_facts: dict from compliance_gather role

    Returns:
        dict in CFF finding format with status pass/fail/notchecked
    """
    rule_id = rule.get("id", "unknown")
    stig_id = rule.get("stig_id", "")
    title = rule.get("title", "")
    check_type = rule.get("check_type", "registry")
    path = rule.get("path", "")
    property_name = rule.get("property", "")
    expected = rule.get("expected")
    operator = rule.get("operator", "eq")
    severity = _map_severity(rule.get("severity", "medium"))
    disruption = rule.get("disruption", "low")
    fix_text = rule.get("fix_text", "")
    check_text = rule.get("check_text", "")
    parameters = rule.get("parameters", [])

    result = {
        # camelCase (Backstage)
        "ruleId": rule_id,
        "stigId": stig_id,
        "fixText": fix_text,
        "checkText": check_text,
        "checkType": check_type,
        # snake_case (standalone)
        "rule_id": rule_id,
        "stig_id": stig_id,
        "fix_text": fix_text,
        "check_text": check_text,
        "check_type": check_type,
        # shared
        "title": _safe_str(title),
        "severity": severity,
        "disruption": disruption,
        "category": rule.get("category", ""),
        "parameters": parameters,
    }

    try:
        if check_type == "registry":
            section = gathered_facts.get("registry", {})
            reg_key = section.get(path, {})
            actual = reg_key.get(property_name)
        elif check_type == "secpol":
            section = gathered_facts.get("secpol", {})
            actual = section.get(path)
        elif check_type == "auditpol":
            section = gathered_facts.get("auditpol", {})
            actual = section.get(path)
        elif check_type == "service":
            section = gathered_facts.get("services", {})
            svc = section.get(path, {})
            actual = svc.get(property_name, svc.get("Status"))
        else:
            result["status"] = "notchecked"
            result["detail"] = "Unknown check_type: %s" % check_type
            return result

        if actual is None:
            result["status"] = "notchecked"
            result["detail"] = "Setting not found: %s" % path
            return result

        if operator == "eq":
            passed = str(actual) == str(expected)
        elif operator == "ne":
            passed = str(actual) != str(expected)
        elif operator == "ge":
            passed = int(actual) >= int(expected)
        elif operator == "le":
            passed = int(actual) <= int(expected)
        elif operator == "gt":
            passed = int(actual) > int(expected)
        elif operator == "lt":
            passed = int(actual) < int(expected)
        elif operator == "contains":
            passed = str(expected) in str(actual)
        elif operator == "not_contains":
            passed = str(expected) not in str(actual)
        else:
            result["status"] = "notchecked"
            result["detail"] = "Unknown operator: %s" % operator
            return result

        result["status"] = "pass" if passed else "fail"
        result["detail"] = "Expected %s %s %s, got %s" % (
            path,
            operator,
            expected,
            actual,
        )
        result["actual_value"] = str(actual)
        result["expected_value"] = str(expected)
        result["actualValue"] = str(actual)
        result["expectedValue"] = str(expected)

    except Exception as exc:
        result["status"] = "notchecked"
        result["detail"] = "Error evaluating rule: %s" % str(exc)

    return result
