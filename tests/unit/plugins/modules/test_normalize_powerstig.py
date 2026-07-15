"""Unit tests for normalize_powerstig module."""

import json
import os
import sys
import tempfile
import pytest
from unittest.mock import MagicMock

_collection_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..', '..', '..'))
sys.path.insert(0, _collection_root)

sys.modules.setdefault("ansible", MagicMock())
sys.modules.setdefault("ansible.module_utils", MagicMock())
sys.modules.setdefault("ansible.module_utils.basic", MagicMock())

from plugins.modules.normalize_powerstig import (
    load_rules_metadata,
    run_normalize_powerstig,
    ARGUMENT_SPEC,
)


def _make_cff(target_host, findings, scanner="powerstig", framework="DISA_STIG"):
    return {
        "schema_version": "1.0.0",
        "scan_id": "test-scan-001",
        "scan_type": "scan",
        "framework": framework,
        "benchmark": "PowerSTIG DISA STIG",
        "benchmark_version": "4.21.0",
        "target_host": target_host,
        "target_os": "Windows Server 10.0.20348",
        "scan_timestamp": "2026-07-15T10:00:00Z",
        "scanner": scanner,
        "findings": findings,
    }


def _make_finding(rule_id="V-254239", status="pass", severity="CAT_II"):
    return {
        "ruleId": rule_id,
        "rule_id": rule_id,
        "stigId": rule_id,
        "stig_id": rule_id,
        "title": f"Test rule {rule_id}",
        "description": "Test description",
        "status": status,
        "severity": severity,
        "fixText": "",
        "fix_text": "",
        "checkText": "",
        "check_text": "",
        "category": "PowerSTIG",
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


def _make_module(params, check_mode=False):
    module = MagicMock()
    module.params = params
    module.check_mode = check_mode
    module.warn = MagicMock()
    module.exit_json = MagicMock()
    module.fail_json = MagicMock()
    return module


class TestArgumentSpec:
    def test_required_fields(self):
        assert ARGUMENT_SPEC['cff_files']['required'] is True
        assert ARGUMENT_SPEC['output_dir']['required'] is True
        assert ARGUMENT_SPEC['scan_id']['required'] is True

    def test_ingest_token_is_no_log(self):
        assert ARGUMENT_SPEC['ingest_token']['no_log'] is True

    def test_certification_choices(self):
        assert 'certified' in ARGUMENT_SPEC['certification_status']['choices']
        assert 'uncertified' in ARGUMENT_SPEC['certification_status']['choices']


class TestLoadRulesMetadata:
    def test_empty_path(self):
        assert load_rules_metadata('') == {}
        assert load_rules_metadata(None) == {}

    def test_nonexistent_file(self):
        assert load_rules_metadata('/nonexistent/path.yml') == {}

    def test_loads_rules_list(self, tmp_path):
        rules_file = tmp_path / "rules.yml"
        rules_file.write_text(
            "rules:\n"
            "  - id: V-254239\n"
            "    aap_impact: safe\n"
            "    fix_text: 'Set password history'\n"
            "  - id: V-254240\n"
            "    aap_impact: breaks-connectivity\n"
            "    aap_impact_reason: 'Changes firewall rules'\n"
        )
        result = load_rules_metadata(str(rules_file))
        assert 'V-254239' in result
        assert result['V-254239']['aap_impact'] == 'safe'
        assert 'V-254240' in result
        assert result['V-254240']['aap_impact_reason'] == 'Changes firewall rules'

    def test_loads_rules_dict(self, tmp_path):
        rules_file = tmp_path / "rules.yml"
        rules_file.write_text(
            "V-254239:\n"
            "  aap_impact: safe\n"
        )
        result = load_rules_metadata(str(rules_file))
        assert 'V-254239' in result


class TestRunNormalizePowerstig:
    def test_single_host_ndjson_output(self, tmp_path):
        cff = _make_cff("win-server-01", [
            _make_finding("V-254239", "pass"),
            _make_finding("V-254240", "fail"),
        ])
        cff_file = tmp_path / "cff-win-server-01.json"
        cff_file.write_text(json.dumps(cff))

        output_dir = tmp_path / "output"

        module = _make_module({
            'cff_files': [str(cff_file)],
            'output_dir': str(output_dir),
            'scan_id': 'test-scan-001',
            'ingest_token': 'tok-secret',
            'finalize_last': True,
            'certification_status': 'uncertified',
            'certification_authority': '',
            'rules_metadata_file': '',
        })

        run_normalize_powerstig(module)

        module.exit_json.assert_called_once()
        result = module.exit_json.call_args[1]
        assert result['hosts_processed'] == 1
        assert result['total_findings'] == 2
        assert result['summary']['pass'] == 1
        assert result['summary']['fail'] == 1
        assert len(result['ndjson_files']) == 1

        ndjson_file = result['ndjson_files'][0]
        assert os.path.exists(ndjson_file)

        with open(ndjson_file) as f:
            lines = f.readlines()

        assert len(lines) == 3  # preamble + 2 findings
        preamble = json.loads(lines[0])
        assert preamble['_meta'] is True
        assert preamble['scanId'] == 'test-scan-001'
        assert preamble['ingestToken'] == 'tok-secret'
        assert preamble['finalize'] is True
        assert preamble['scanner'] == 'powerstig'

        finding1 = json.loads(lines[1])
        assert finding1['rule_id'] == 'V-254239'

    def test_multi_host_finalize_only_last(self, tmp_path):
        cff1 = _make_cff("host-a", [_make_finding("V-001", "pass")])
        cff2 = _make_cff("host-b", [_make_finding("V-002", "fail")])

        f1 = tmp_path / "cff-host-a.json"
        f2 = tmp_path / "cff-host-b.json"
        f1.write_text(json.dumps(cff1))
        f2.write_text(json.dumps(cff2))

        output_dir = tmp_path / "output"
        module = _make_module({
            'cff_files': [str(f1), str(f2)],
            'output_dir': str(output_dir),
            'scan_id': 'scan-multi',
            'ingest_token': '',
            'finalize_last': True,
            'certification_status': 'uncertified',
            'certification_authority': '',
            'rules_metadata_file': '',
        })

        run_normalize_powerstig(module)

        result = module.exit_json.call_args[1]
        assert result['hosts_processed'] == 2
        assert len(result['ndjson_files']) == 2

        # First file should NOT have finalize=true
        with open(result['ndjson_files'][0]) as f:
            preamble = json.loads(f.readline())
        assert preamble['finalize'] is False

        # Last file SHOULD have finalize=true
        with open(result['ndjson_files'][1]) as f:
            preamble = json.loads(f.readline())
        assert preamble['finalize'] is True

    def test_missing_cff_file_warns(self, tmp_path):
        output_dir = tmp_path / "output"
        module = _make_module({
            'cff_files': ['/nonexistent/cff.json'],
            'output_dir': str(output_dir),
            'scan_id': 'scan-missing',
            'ingest_token': '',
            'finalize_last': True,
            'certification_status': 'uncertified',
            'certification_authority': '',
            'rules_metadata_file': '',
        })

        run_normalize_powerstig(module)

        module.warn.assert_called()
        result = module.exit_json.call_args[1]
        assert result['hosts_processed'] == 0

    def test_rules_metadata_merge(self, tmp_path):
        cff = _make_cff("host-x", [_make_finding("V-254239", "fail")])
        cff_file = tmp_path / "cff.json"
        cff_file.write_text(json.dumps(cff))

        rules_file = tmp_path / "rules.yml"
        rules_file.write_text(
            "rules:\n"
            "  - id: V-254239\n"
            "    aap_impact: breaks-connectivity\n"
            "    aap_impact_reason: Modifies firewall\n"
            "    fix_text: 'Set password history to 24'\n"
        )

        output_dir = tmp_path / "output"
        module = _make_module({
            'cff_files': [str(cff_file)],
            'output_dir': str(output_dir),
            'scan_id': 'scan-rules',
            'ingest_token': '',
            'finalize_last': True,
            'certification_status': 'uncertified',
            'certification_authority': '',
            'rules_metadata_file': str(rules_file),
        })

        run_normalize_powerstig(module)

        ndjson_file = module.exit_json.call_args[1]['ndjson_files'][0]
        with open(ndjson_file) as f:
            lines = f.readlines()

        finding = json.loads(lines[1])
        assert finding['aap_impact'] == 'breaks-connectivity'
        assert finding['aap_impact_reason'] == 'Modifies firewall'
        assert finding['fix_text'] == 'Set password history to 24'
        assert finding['fixText'] == 'Set password history to 24'

    def test_check_mode_no_writes(self, tmp_path):
        cff = _make_cff("host-check", [_make_finding("V-001", "pass")])
        cff_file = tmp_path / "cff.json"
        cff_file.write_text(json.dumps(cff))

        output_dir = tmp_path / "output"
        module = _make_module({
            'cff_files': [str(cff_file)],
            'output_dir': str(output_dir),
            'scan_id': 'scan-check',
            'ingest_token': '',
            'finalize_last': True,
            'certification_status': 'uncertified',
            'certification_authority': '',
            'rules_metadata_file': '',
        }, check_mode=True)

        run_normalize_powerstig(module)

        result = module.exit_json.call_args[1]
        assert result['changed'] is False
        assert len(result['ndjson_files']) == 1
        assert not os.path.exists(result['ndjson_files'][0])

    def test_status_counting_matches_cff_values(self, tmp_path):
        """Verify status keys match CFF filter output (notchecked, not not_checked)."""
        cff = _make_cff("host-status", [
            _make_finding("V-001", "pass"),
            _make_finding("V-002", "pass"),
            _make_finding("V-003", "fail"),
            _make_finding("V-004", "notchecked"),
            _make_finding("V-005", "notapplicable"),
            _make_finding("V-006", "error"),
        ])
        cff_file = tmp_path / "cff.json"
        cff_file.write_text(json.dumps(cff))

        output_dir = tmp_path / "output"
        module = _make_module({
            'cff_files': [str(cff_file)],
            'output_dir': str(output_dir),
            'scan_id': 'scan-status',
            'ingest_token': '',
            'finalize_last': True,
            'certification_status': 'uncertified',
            'certification_authority': '',
            'rules_metadata_file': '',
        })

        run_normalize_powerstig(module)

        summary = module.exit_json.call_args[1]['summary']
        assert summary['pass'] == 2
        assert summary['fail'] == 1
        assert summary['notchecked'] == 1
        assert summary['notapplicable'] == 1
        assert summary['error'] == 1

    def test_ndjson_compact_json(self, tmp_path):
        """NDJSON lines should use compact separators (no spaces)."""
        cff = _make_cff("host-compact", [_make_finding("V-001", "pass")])
        cff_file = tmp_path / "cff.json"
        cff_file.write_text(json.dumps(cff))

        output_dir = tmp_path / "output"
        module = _make_module({
            'cff_files': [str(cff_file)],
            'output_dir': str(output_dir),
            'scan_id': 'scan-compact',
            'ingest_token': '',
            'finalize_last': True,
            'certification_status': 'uncertified',
            'certification_authority': '',
            'rules_metadata_file': '',
        })

        run_normalize_powerstig(module)

        ndjson_file = module.exit_json.call_args[1]['ndjson_files'][0]
        with open(ndjson_file) as f:
            line = f.readline()

        assert ': ' not in line  # compact separators
        assert ', ' not in line

    def test_certification_in_preamble(self, tmp_path):
        cff = _make_cff("host-cert", [_make_finding("V-001", "pass")])
        cff_file = tmp_path / "cff.json"
        cff_file.write_text(json.dumps(cff))

        output_dir = tmp_path / "output"
        module = _make_module({
            'cff_files': [str(cff_file)],
            'output_dir': str(output_dir),
            'scan_id': 'scan-cert',
            'ingest_token': '',
            'finalize_last': True,
            'certification_status': 'certified',
            'certification_authority': 'SCAP 1.3',
            'rules_metadata_file': '',
        })

        run_normalize_powerstig(module)

        ndjson_file = module.exit_json.call_args[1]['ndjson_files'][0]
        with open(ndjson_file) as f:
            preamble = json.loads(f.readline())

        assert preamble['certification']['status'] == 'certified'
        assert preamble['certification']['authority'] == 'SCAP 1.3'
