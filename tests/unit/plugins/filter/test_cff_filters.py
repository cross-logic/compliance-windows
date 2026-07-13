"""Unit tests for CFF transformation filters."""

import os
import sys
import pytest

_collection_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..', '..', '..'))
sys.path.insert(0, _collection_root)

from plugins.filter.cff_filters import FilterModule


class TestCffFilters:
    """Tests for CFF transformation filters."""

    def setup_method(self):
        """Set up test fixtures."""
        self.filter_module = FilterModule()
        self.filters = self.filter_module.filters()

    def test_to_cff_stig_pass_mapping(self):
        """PASS status should map to pass."""
        result = {"status": "PASS", "stig_id": "V-123", "title": "Test"}

        cff = self.filters["to_cff_stig"](result)

        assert cff["status"] == "pass"

    def test_to_cff_stig_fail_mapping(self):
        """FAIL status should map to fail."""
        result = {"status": "FAIL", "stig_id": "V-124", "title": "Test"}

        cff = self.filters["to_cff_stig"](result)

        assert cff["status"] == "fail"

    def test_to_cff_stig_manual_mapping(self):
        """MANUAL status should map to notchecked."""
        result = {"status": "MANUAL", "stig_id": "V-125", "title": "Test"}

        cff = self.filters["to_cff_stig"](result)

        assert cff["status"] == "notchecked"

    def test_to_cff_stig_severity_mapping_cat_i(self):
        """CAT I severity should map to CAT_I."""
        result = {"status": "PASS", "stig_id": "V-126", "severity": "CAT I", "title": "Test"}

        cff = self.filters["to_cff_stig"](result)

        assert cff["severity"] == "CAT_I"

    def test_to_cff_stig_severity_mapping_cat_ii(self):
        """CAT II severity should map to CAT_II."""
        result = {"status": "PASS", "stig_id": "V-127", "severity": "CAT II", "title": "Test"}

        cff = self.filters["to_cff_stig"](result)

        assert cff["severity"] == "CAT_II"

    def test_to_cff_stig_severity_label_high_to_cat_i(self):
        """High severity label should map to CAT_I."""
        result = {"status": "PASS", "stig_id": "V-128", "severity": "high", "title": "Test"}

        cff = self.filters["to_cff_stig"](result)

        assert cff["severity"] == "CAT_I"

    def test_to_cff_stig_severity_label_medium_to_cat_ii(self):
        """Medium severity label should map to CAT_II."""
        result = {"status": "PASS", "stig_id": "V-129", "severity": "medium", "title": "Test"}

        cff = self.filters["to_cff_stig"](result)

        assert cff["severity"] == "CAT_II"

    def test_to_cff_stig_dual_output(self):
        """Output should have both camelCase and snake_case fields."""
        result = {
            "status": "PASS",
            "stig_id": "V-130",
            "rule_id": "SRG-001",
            "title": "Test",
            "fix_text": "Fix this",
            "check_text": "Check this",
        }

        cff = self.filters["to_cff_stig"](result)

        # camelCase
        assert "ruleId" in cff
        assert "stigId" in cff
        assert "fixText" in cff
        assert "checkText" in cff
        assert "actualValue" in cff
        assert "expectedValue" in cff

        # snake_case
        assert "rule_id" in cff
        assert "stig_id" in cff
        assert "fix_text" in cff
        assert "check_text" in cff
        assert "actual_value" in cff
        assert "expected_value" in cff

    def test_to_cff_stig_empty_input(self):
        """Empty input should return default empty finding."""
        cff = self.filters["to_cff_stig"](None)

        assert cff["status"] == "error"
        assert cff["ruleId"] == ""
        assert cff["title"] == ""

    def test_to_cff_stig_empty_dict(self):
        """Empty dict should return default empty finding with error status."""
        cff = self.filters["to_cff_stig"]({})

        assert cff["status"] == "error"

    def test_to_cff_cis_rule_id_from_cis_id(self):
        """CIS ID should be used as ruleId."""
        result = {"cis_id": "1.1.1", "title": "Test", "status": "PASS"}

        cff = self.filters["to_cff_cis"](result)

        assert cff["ruleId"] == "1.1.1"
        assert cff["rule_id"] == "1.1.1"

    def test_to_cff_cis_severity_from_level(self):
        """CIS level should be passed through as severity."""
        result = {"cis_id": "1.1.2", "level": "1", "status": "PASS"}

        cff = self.filters["to_cff_cis"](result)

        # Level "1" doesn't map to a known severity label, passed through as-is
        assert cff["severity"] == "1"

    def test_to_cff_powerstig_in_desired_state_true(self):
        """InDesiredState True should map to pass."""
        result = {"ResourceId": "Test-001", "InDesiredState": True}

        cff = self.filters["to_cff_powerstig"](result)

        assert cff["status"] == "pass"

    def test_to_cff_powerstig_in_desired_state_false(self):
        """InDesiredState False should map to fail."""
        result = {"ResourceId": "Test-002", "InDesiredState": False}

        cff = self.filters["to_cff_powerstig"](result)

        assert cff["status"] == "fail"

    def test_to_cff_powerstig_resource_fields(self):
        """PowerSTIG result fields should map correctly."""
        result = {
            "ResourceId": "STIG-WN22-001",
            "ModuleName": "SecurityPolicyDsc",
            "DscResource": "AccountPolicy",
            "InDesiredState": True,
            "severity": "high",
        }

        cff = self.filters["to_cff_powerstig"](result)

        assert cff["title"] == "STIG-WN22-001"
        assert cff["description"] == "SecurityPolicyDsc"
        assert cff["section"] == "AccountPolicy"
        assert cff["category"] == "PowerSTIG"
        assert cff["scanner"] == "powerstig"
