"""Filters to transform compliance results to Common Findings Format (CFF)."""

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

_EMPTY_FINDING = {
    "ruleId": "",
    "title": "",
    "description": "",
    "status": "error",
    "severity": "",
    "category": "",
    "section": "",
    "actualValue": "",
    "expectedValue": "",
    "checkType": "automated",
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
        """Transform a single STIG result dict to CFF format."""
        if not result or not isinstance(result, dict):
            return _EMPTY_FINDING
        raw_status = result.get("status", "MANUAL")
        return {
            "ruleId": result.get("stig_id", ""),
            "title": result.get("title", ""),
            "description": result.get("description", ""),
            "status": _STATUS_MAP.get(raw_status, "notchecked"),
            "severity": _SEVERITY_MAP.get(
                result.get("severity", ""), result.get("severity", "")
            ),
            "category": result.get("category", ""),
            "section": result.get("section", ""),
            "actualValue": _safe_str(result.get("current_value", "")),
            "expectedValue": _safe_str(
                result.get("expected_value", result.get("value", ""))
            ),
            "checkType": result.get("check_type", "automated"),
        }

    @staticmethod
    def to_cff_cis(result):
        """Transform a single CIS result dict to CFF format."""
        if not result or not isinstance(result, dict):
            return _EMPTY_FINDING
        raw_status = result.get("status", "MANUAL")
        return {
            "ruleId": result.get("cis_id", result.get("rule_id", "")),
            "title": result.get("title", ""),
            "description": result.get("description", ""),
            "status": _STATUS_MAP.get(raw_status, "notchecked"),
            "severity": result.get("level", result.get("profile", "")),
            "category": result.get("category", result.get("section", "")),
            "section": result.get("section", ""),
            "actualValue": _safe_str(result.get("current_value", "")),
            "expectedValue": _safe_str(
                result.get("expected_value", result.get("value", ""))
            ),
            "checkType": result.get("check_type", "automated"),
        }

    @staticmethod
    def to_cff_powerstig(result):
        """Transform a PowerSTIG DSC result to CFF format."""
        if not result or not isinstance(result, dict):
            return _EMPTY_FINDING
        powerstig_status = {
            "True": "pass",
            "False": "fail",
            True: "pass",
            False: "fail",
        }
        in_desired = result.get("InDesiredState", result.get("inDesiredState", ""))
        return {
            "ruleId": result.get("RuleId", result.get("ruleId", "")),
            "title": result.get("ResourceId", result.get("resourceId", "")),
            "description": result.get("ModuleName", ""),
            "status": powerstig_status.get(in_desired, "notchecked"),
            "severity": result.get("Severity", result.get("severity", "")),
            "category": "PowerSTIG",
            "section": result.get("DscResource", result.get("dscResource", "")),
            "actualValue": _safe_str(result.get("ActualValue", "")),
            "expectedValue": _safe_str(result.get("ExpectedValue", "")),
            "checkType": "automated",
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
    title = rule.get("title", "")
    check_type = rule.get("check_type", "registry")
    path = rule.get("path", "")
    property_name = rule.get("property", "")
    expected = rule.get("expected")
    operator = rule.get("operator", "eq")
    severity = rule.get("severity", "medium")

    result = {
        "rule_id": rule_id,
        "title": _safe_str(title),
        "severity": severity,
        "check_type": check_type,
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

    except Exception as exc:
        result["status"] = "notchecked"
        result["detail"] = "Error evaluating rule: %s" % str(exc)

    return result
