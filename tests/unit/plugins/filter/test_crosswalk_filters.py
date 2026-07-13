"""Unit tests for crosswalk mapping filters."""

import os
import sys
import pytest

_collection_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..', '..', '..'))
sys.path.insert(0, _collection_root)

from plugins.filter.crosswalk_filters import FilterModule


class TestCrosswalkFilters:
    """Tests for crosswalk mapping filters."""

    def setup_method(self):
        """Set up test fixtures."""
        self.filter_module = FilterModule()
        self.filters = self.filter_module.filters()

    def test_map_controls_basic_mapping(self):
        """Finding with ruleId matching a STIG control should get regulatory_controls."""
        findings = [{"ruleId": "V-254238", "status": "pass"}]

        crosswalk = {
            "framework": "HIPAA",
            "controls": [
                {
                    "id": "164.308(a)(1)(i)",
                    "title": "Security Management Process",
                    "stig_rules": ["V-254238", "V-254239"],
                }
            ],
        }

        result = self.filters["map_controls"](findings, crosswalk, "STIG")

        assert len(result) == 1
        assert "regulatory_controls" in result[0]
        assert len(result[0]["regulatory_controls"]) == 1
        assert result[0]["regulatory_controls"][0]["control_id"] == "164.308(a)(1)(i)"
        assert result[0]["regulatory_controls"][0]["framework"] == "HIPAA"

    def test_map_controls_unmapped_rule(self):
        """Finding with ruleId not in any control should get empty regulatory_controls."""
        findings = [{"ruleId": "V-999999", "status": "pass"}]

        crosswalk = {
            "framework": "HIPAA",
            "controls": [{"id": "164.308(a)(1)(i)", "title": "Test", "stig_rules": ["V-254238"]}],
        }

        result = self.filters["map_controls"](findings, crosswalk, "STIG")

        assert len(result) == 1
        assert "regulatory_controls" in result[0]
        assert len(result[0]["regulatory_controls"]) == 0

    def test_map_controls_cis_source(self):
        """source_framework='CIS' should use cis_rules for lookup."""
        findings = [{"ruleId": "1.1.1", "status": "pass"}]

        crosswalk = {
            "framework": "PCI-DSS",
            "controls": [{"id": "1.1.1", "title": "Firewall configuration", "cis_rules": ["1.1.1", "1.1.2"]}],
        }

        result = self.filters["map_controls"](findings, crosswalk, "CIS")

        assert len(result) == 1
        assert len(result[0]["regulatory_controls"]) == 1
        assert result[0]["regulatory_controls"][0]["control_id"] == "1.1.1"

    def test_map_controls_stig_source(self):
        """source_framework='STIG' should use stig_rules for lookup."""
        findings = [{"ruleId": "V-254238", "status": "pass"}]

        crosswalk = {
            "framework": "HIPAA",
            "controls": [
                {
                    "id": "164.308(a)(1)(i)",
                    "title": "Security Management",
                    "stig_rules": ["V-254238"],
                    "cis_rules": ["5.1.1"],
                }
            ],
        }

        result = self.filters["map_controls"](findings, crosswalk, "STIG")

        assert len(result) == 1
        assert len(result[0]["regulatory_controls"]) == 1

    def test_map_controls_empty_findings(self):
        """Empty findings list should return empty list."""
        crosswalk = {"framework": "HIPAA", "controls": []}

        result = self.filters["map_controls"]([], crosswalk, "STIG")

        assert result == []

    def test_map_controls_empty_crosswalk(self):
        """Empty crosswalk (no controls) should return findings unchanged."""
        findings = [{"ruleId": "V-254238", "status": "pass"}]

        result = self.filters["map_controls"](findings, {}, "STIG")

        assert len(result) == 1
        assert result[0]["ruleId"] == "V-254238"

    def test_crosswalk_summary_all_pass(self):
        """All mapped rules pass should result in control status 'pass'."""
        findings = [
            {"ruleId": "V-254238", "status": "pass"},
            {"ruleId": "V-254239", "status": "pass"},
        ]

        crosswalk = {
            "framework": "HIPAA",
            "controls": [
                {
                    "id": "164.308(a)(1)(i)",
                    "title": "Security Management",
                    "stig_rules": ["V-254238", "V-254239"],
                }
            ],
        }

        result = self.filters["crosswalk_summary"](findings, crosswalk, "STIG")

        assert len(result) == 1
        assert result[0]["status"] == "pass"
        assert result[0]["passed"] == 2
        assert result[0]["failed"] == 0
        assert result[0]["mapped_rules"] == 2

    def test_crosswalk_summary_some_fail(self):
        """Any fail should result in control status 'fail'."""
        findings = [
            {"ruleId": "V-254238", "status": "pass"},
            {"ruleId": "V-254239", "status": "fail"},
        ]

        crosswalk = {
            "framework": "HIPAA",
            "controls": [
                {
                    "id": "164.308(a)(1)(i)",
                    "title": "Security Management",
                    "stig_rules": ["V-254238", "V-254239"],
                }
            ],
        }

        result = self.filters["crosswalk_summary"](findings, crosswalk, "STIG")

        assert len(result) == 1
        assert result[0]["status"] == "fail"
        assert result[0]["passed"] == 1
        assert result[0]["failed"] == 1

    def test_crosswalk_summary_partial(self):
        """Mix of pass and notchecked should result in 'partial'."""
        findings = [
            {"ruleId": "V-254238", "status": "pass"},
            {"ruleId": "V-254239", "status": "notchecked"},
        ]

        crosswalk = {
            "framework": "HIPAA",
            "controls": [
                {
                    "id": "164.308(a)(1)(i)",
                    "title": "Security Management",
                    "stig_rules": ["V-254238", "V-254239"],
                }
            ],
        }

        result = self.filters["crosswalk_summary"](findings, crosswalk, "STIG")

        assert len(result) == 1
        assert result[0]["status"] == "partial"

    def test_crosswalk_summary_gap(self):
        """Control marked gap:true should result in status 'gap' regardless of rules."""
        findings = [{"ruleId": "V-254238", "status": "pass"}]

        crosswalk = {
            "framework": "HIPAA",
            "controls": [
                {
                    "id": "164.308(a)(1)(i)",
                    "title": "Security Management",
                    "stig_rules": ["V-254238"],
                    "gap": True,
                    "gap_note": "Manual review required",
                }
            ],
        }

        result = self.filters["crosswalk_summary"](findings, crosswalk, "STIG")

        assert len(result) == 1
        assert result[0]["status"] == "gap"
        assert result[0]["gap"] is True
        assert result[0]["gap_note"] == "Manual review required"

    def test_crosswalk_summary_unmapped(self):
        """Control with zero mapped rules should result in status 'unmapped'."""
        findings = []

        crosswalk = {
            "framework": "HIPAA",
            "controls": [{"id": "164.308(a)(1)(i)", "title": "Security Management", "stig_rules": []}],
        }

        result = self.filters["crosswalk_summary"](findings, crosswalk, "STIG")

        assert len(result) == 1
        assert result[0]["status"] == "unmapped"
        assert result[0]["mapped_rules"] == 0

    def test_crosswalk_summary_gap_note_preserved(self):
        """Gap note string should be carried through."""
        findings = []

        crosswalk = {
            "framework": "HIPAA",
            "controls": [
                {
                    "id": "164.308(a)(1)(i)",
                    "title": "Security Management",
                    "stig_rules": [],
                    "gap": True,
                    "gap_note": "Requires manual policy review and documentation",
                }
            ],
        }

        result = self.filters["crosswalk_summary"](findings, crosswalk, "STIG")

        assert len(result) == 1
        assert result[0]["gap_note"] == "Requires manual policy review and documentation"
