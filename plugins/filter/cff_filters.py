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



# NOTE: Rule evaluation logic lives in plugins/modules/compliance_evaluate.py.
# The evaluate_rule() function that was here has been removed to eliminate
# duplication (Q1). Use the compliance_evaluate module for rule evaluation.
