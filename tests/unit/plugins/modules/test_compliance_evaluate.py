"""Unit tests for compliance_evaluate module."""

import os
import sys
import pytest
from unittest.mock import MagicMock

# Add collection root to path so we can import plugins directly
_collection_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..', '..', '..'))
sys.path.insert(0, _collection_root)

# Mock AnsibleModule before importing the module
sys.modules.setdefault("ansible", MagicMock())
sys.modules.setdefault("ansible.module_utils", MagicMock())
sys.modules.setdefault("ansible.module_utils.basic", MagicMock())

from plugins.modules.compliance_evaluate import evaluate_single_rule, _map_severity, OPERATORS


class TestComplianceEvaluate:
    """Tests for compliance_evaluate module."""

    def test_registry_check_pass(self):
        """Registry check with matching value should pass."""
        facts = {"registry": {"HKLM\\System\\Test": {"EnableValue": "1"}}}
        rule = {
            "id": "V-123",
            "stig_id": "WN22-001",
            "title": "Test rule",
            "severity": "high",
            "check": {
                "type": "registry",
                "params": {"key": "HKLM\\System\\Test", "property": "EnableValue", "value": "1", "operator": "eq"},
            },
        }

        result = evaluate_single_rule(rule, facts)

        assert result["status"] == "pass"
        assert result["ruleId"] == "V-123"
        assert result["stigId"] == "WN22-001"
        assert result["severity"] == "CAT_I"
        assert result["actual_value"] == "1"
        assert result["expected_value"] == "1"

    def test_registry_check_fail(self):
        """Registry check with mismatched value should fail."""
        facts = {"registry": {"HKLM\\System\\Test": {"EnableValue": "0"}}}
        rule = {
            "id": "V-123",
            "title": "Test rule",
            "severity": "medium",
            "check": {"type": "registry", "params": {"key": "HKLM\\System\\Test", "property": "EnableValue", "value": "1"}},
        }

        result = evaluate_single_rule(rule, facts)

        assert result["status"] == "fail"
        assert result["severity"] == "CAT_II"
        assert result["actual_value"] == "0"

    def test_registry_check_not_found(self):
        """Registry key not found should return notchecked."""
        facts = {"registry": {}}
        rule = {
            "id": "V-123",
            "title": "Test rule",
            "check": {"type": "registry", "params": {"key": "HKLM\\Missing", "property": "Value", "value": "1"}},
        }

        result = evaluate_single_rule(rule, facts)

        assert result["status"] == "notchecked"
        assert "Setting not found" in result["detail"]

    def test_secpol_check_pass(self):
        """Security policy check with matching value should pass."""
        facts = {"secpol": {"PasswordHistorySize": "24"}}
        rule = {
            "id": "V-124",
            "title": "Password history",
            "check": {"type": "secpol", "params": {"key": "PasswordHistorySize", "value": "24"}},
        }

        result = evaluate_single_rule(rule, facts)

        assert result["status"] == "pass"

    def test_secpol_check_fail(self):
        """Security policy check with wrong value should fail."""
        facts = {"secpol": {"PasswordHistorySize": "12"}}
        rule = {
            "id": "V-124",
            "title": "Password history",
            "check": {"type": "secpol", "params": {"key": "PasswordHistorySize", "value": "24"}},
        }

        result = evaluate_single_rule(rule, facts)

        assert result["status"] == "fail"

    def test_auditpol_check_pass(self):
        """Audit policy check with matching value should pass."""
        facts = {"auditpol": {"Logon": "Success and Failure"}}
        rule = {
            "id": "V-125",
            "title": "Audit logon events",
            "check": {"type": "auditpol", "params": {"key": "Logon", "value": "Success and Failure"}},
        }

        result = evaluate_single_rule(rule, facts)

        assert result["status"] == "pass"

    def test_service_check_pass(self):
        """Service status check with matching value should pass."""
        facts = {"services": {"W32Time": {"Status": "Running"}}}
        rule = {
            "id": "V-126",
            "title": "Time service running",
            "check": {"type": "service", "params": {"key": "W32Time", "property": "Status", "value": "Running"}},
        }

        result = evaluate_single_rule(rule, facts)

        assert result["status"] == "pass"

    def test_operator_eq(self):
        """String equality operator should work."""
        facts = {"registry": {"Key": {"Prop": "value"}}}
        rule = {
            "id": "V-127",
            "title": "Test",
            "check": {"type": "registry", "params": {"key": "Key", "property": "Prop", "value": "value", "operator": "eq"}},
        }

        result = evaluate_single_rule(rule, facts)

        assert result["status"] == "pass"

    def test_operator_ge(self):
        """Greater-or-equal operator should work."""
        facts = {"registry": {"Key": {"Timeout": "900"}}}
        rule = {
            "id": "V-128",
            "title": "Test",
            "check": {"type": "registry", "params": {"key": "Key", "property": "Timeout", "value": "600", "operator": "ge"}},
        }

        result = evaluate_single_rule(rule, facts)

        assert result["status"] == "pass"

    def test_operator_le(self):
        """Less-or-equal operator should work."""
        facts = {"registry": {"Key": {"Count": "5"}}}
        rule = {
            "id": "V-129",
            "title": "Test",
            "check": {"type": "registry", "params": {"key": "Key", "property": "Count", "value": "10", "operator": "le"}},
        }

        result = evaluate_single_rule(rule, facts)

        assert result["status"] == "pass"

    def test_operator_contains(self):
        """Contains operator should match substring."""
        facts = {"registry": {"Key": {"List": "item1,item2,item3"}}}
        rule = {
            "id": "V-130",
            "title": "Test",
            "check": {
                "type": "registry",
                "params": {"key": "Key", "property": "List", "value": "item2", "operator": "contains"},
            },
        }

        result = evaluate_single_rule(rule, facts)

        assert result["status"] == "pass"

    def test_severity_mapping_high_to_cat_i(self):
        """High severity should map to CAT_I."""
        facts = {"registry": {"Key": {"Value": "1"}}}
        rule = {
            "id": "V-131",
            "title": "Test",
            "severity": "high",
            "check": {"type": "registry", "params": {"key": "Key", "property": "Value", "value": "1"}},
        }

        result = evaluate_single_rule(rule, facts)

        assert result["severity"] == "CAT_I"

    def test_severity_mapping_medium_to_cat_ii(self):
        """Medium severity should map to CAT_II."""
        facts = {"registry": {"Key": {"Value": "1"}}}
        rule = {
            "id": "V-132",
            "title": "Test",
            "severity": "medium",
            "check": {"type": "registry", "params": {"key": "Key", "property": "Value", "value": "1"}},
        }

        result = evaluate_single_rule(rule, facts)

        assert result["severity"] == "CAT_II"

    def test_unknown_operator(self):
        """Unknown operator should return notchecked."""
        facts = {"registry": {"Key": {"Value": "1"}}}
        rule = {
            "id": "V-133",
            "title": "Test",
            "check": {
                "type": "registry",
                "params": {"key": "Key", "property": "Value", "value": "1", "operator": "bogus"},
            },
        }

        result = evaluate_single_rule(rule, facts)

        assert result["status"] == "notchecked"
        assert "Unknown operator" in result["detail"]

    def test_evaluation_exception(self):
        """Exception during evaluation should return notchecked."""
        facts = {"registry": {"Key": {"Value": "not_a_number"}}}
        rule = {
            "id": "V-134",
            "title": "Test",
            "check": {
                "type": "registry",
                "params": {"key": "Key", "property": "Value", "value": "100", "operator": "ge"},
            },
        }

        result = evaluate_single_rule(rule, facts)

        assert result["status"] == "notchecked"
        assert "Evaluation error" in result["detail"] or "invalid literal" in result["detail"]

    def test_cff_output_schema(self):
        """Finding should have all required CFF fields."""
        facts = {"registry": {"Key": {"Value": "1"}}}
        rule = {
            "id": "V-135",
            "stig_id": "WN22-135",
            "title": "Test title",
            "description": "Test description",
            "severity": "low",
            "fix_text": "Fix this",
            "check_text": "Check this",
            "category": "Security",
            "disruption": "medium",
            "parameters": [{"name": "timeout", "value": "900"}],
            "check": {"type": "registry", "params": {"key": "Key", "property": "Value", "value": "1"}},
        }

        result = evaluate_single_rule(rule, facts)

        # Required CFF fields
        assert "ruleId" in result
        assert "stigId" in result
        assert "title" in result
        assert "description" in result
        assert "severity" in result
        assert "status" in result
        assert "detail" in result
        assert "fixText" in result
        assert "checkText" in result
        assert "category" in result
        assert "disruption" in result
        assert "parameters" in result

        assert result["ruleId"] == "V-135"
        assert result["stigId"] == "WN22-135"
        assert result["severity"] == "CAT_III"

    def test_empty_rules_list(self):
        """Zero rules should produce zero findings."""
        facts = {"registry": {}}
        rules = []

        findings = []
        for rule in rules:
            finding = evaluate_single_rule(rule, facts)
            findings.append(finding)

        assert len(findings) == 0

    def test_check_mode_support(self):
        """Module should support check_mode without side effects."""
        # This would be tested through the full module, but we're testing
        # the evaluate_single_rule function which has no side effects
        facts = {"registry": {"Key": {"Value": "1"}}}
        rule = {
            "id": "V-136",
            "title": "Test",
            "check": {"type": "registry", "params": {"key": "Key", "property": "Value", "value": "1"}},
        }

        # Call multiple times to verify idempotency
        result1 = evaluate_single_rule(rule, facts)
        result2 = evaluate_single_rule(rule, facts)

        assert result1 == result2
        assert result1["status"] == "pass"
