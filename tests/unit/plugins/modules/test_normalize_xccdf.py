"""Unit tests for normalize_xccdf module (XCCDF normalizer).

The XCCDF normalizer is the PRIMARY scanner path -- DISA SCC is the default
scanner for Windows STIG compliance.  These tests cover the full API surface
of normalize_common.py as consumed through normalize_xccdf.py.
"""

import json
import os
import sys
import pytest
from unittest.mock import MagicMock

# ---------------------------------------------------------------------------
# Path setup -- mirrors test_normalize_powerstig.py
# ---------------------------------------------------------------------------
_collection_root = os.path.abspath(
    os.path.join(os.path.dirname(__file__), '..', '..', '..', '..')
)
sys.path.insert(0, _collection_root)

sys.modules.setdefault("ansible", MagicMock())
sys.modules.setdefault("ansible.module_utils", MagicMock())
sys.modules.setdefault("ansible.module_utils.basic", MagicMock())

from plugins.module_utils.normalize_common import (
    parse_xccdf_results,
    run_normalize,
    load_rules_metadata_map,
    extract_host_from_filename,
    ARGUMENT_SPEC,
    SEVERITY_MAP,
    STATUS_MAP,
    SKIP_STATUSES,
)


# ---------------------------------------------------------------------------
# XML helpers
# ---------------------------------------------------------------------------
XCCDF_12_NS = 'http://checklists.nist.gov/xccdf/1.2'
XCCDF_11_NS = 'http://checklists.nist.gov/xccdf/1.1'


def _xccdf_doc(rules_xml, results_xml, ns=XCCDF_12_NS):
    """Build a minimal but valid XCCDF Benchmark document."""
    return (
        f'<?xml version="1.0" encoding="UTF-8"?>'
        f'<Benchmark xmlns="{ns}">'
        f'{rules_xml}'
        f'<TestResult>'
        f'{results_xml}'
        f'</TestResult>'
        f'</Benchmark>'
    )


def _rule_xml(rule_id, severity='medium', title='Test Rule',
              description='Test description', stig_id='', cis_id='',
              cce_id='', fix_text='', rationale=''):
    """Build a single <Rule> element with optional children."""
    parts = [f'<Rule id="{rule_id}" severity="{severity}">']
    parts.append(f'  <title>{title}</title>')
    parts.append(f'  <description>{description}</description>')
    if stig_id:
        parts.append(
            f'  <ident system="http://iase.disa.mil/cci">{stig_id}</ident>'
        )
    if cce_id:
        parts.append(
            f'  <ident system="http://cce.mitre.org">{cce_id}</ident>'
        )
    if cis_id:
        parts.append(
            f'  <reference href="https://www.cisecurity.org/benchmark">{cis_id}</reference>'
        )
    if fix_text:
        parts.append(f'  <fixtext>{fix_text}</fixtext>')
    if rationale:
        parts.append(f'  <rationale>{rationale}</rationale>')
    parts.append('</Rule>')
    return '\n'.join(parts)


def _rule_result_xml(idref, status='pass', severity='medium'):
    """Build a single <rule-result> element."""
    return (
        f'<rule-result idref="{idref}" severity="{severity}">'
        f'  <result>{status}</result>'
        f'</rule-result>'
    )


def _write_xccdf(tmp_path, filename, xml_content):
    """Write XML content to a file and return the path string."""
    p = tmp_path / filename
    p.write_text(xml_content, encoding='utf-8')
    return str(p)


# ---------------------------------------------------------------------------
# Module mock helper -- same pattern as test_normalize_powerstig.py
# ---------------------------------------------------------------------------
def _make_module(params, check_mode=False):
    module = MagicMock()
    module.params = params
    module.check_mode = check_mode
    module.warn = MagicMock()
    module.exit_json = MagicMock()
    module.fail_json = MagicMock()
    return module


def _default_params(tmp_path, **overrides):
    """Return a params dict with sensible defaults matching ARGUMENT_SPEC."""
    defaults = {
        'results_files': [],
        'output_file': str(tmp_path / 'output.json'),
        'profile_name': None,
        'framework': 'auto',
        'certification_status': 'uncertified',
        'certification_authority': '',
        'rules_metadata_file': '',
        'scanner_name': 'openscap',
        'compose_post_body': False,
        'scan_id': '',
        'ingest_token': '',
        'finalize': False,
        'post_body_format': 'ndjson',
    }
    defaults.update(overrides)
    return defaults


# ===================================================================
# TestArgumentSpec
# ===================================================================
class TestArgumentSpec:
    """Verify ARGUMENT_SPEC declares required fields and defaults correctly."""

    def test_required_fields(self):
        assert ARGUMENT_SPEC['results_files']['required'] is True
        assert ARGUMENT_SPEC['output_file']['required'] is True

    def test_scanner_name_default_is_openscap(self):
        assert ARGUMENT_SPEC['scanner_name']['default'] == 'openscap'

    def test_ingest_token_has_no_log(self):
        assert ARGUMENT_SPEC['ingest_token']['no_log'] is True

    def test_framework_choices(self):
        choices = ARGUMENT_SPEC['framework']['choices']
        assert 'auto' in choices
        assert 'DISA_STIG' in choices
        assert 'CIS' in choices

    def test_certification_status_choices(self):
        choices = ARGUMENT_SPEC['certification_status']['choices']
        assert 'certified' in choices
        assert 'conformant' in choices
        assert 'uncertified' in choices


# ===================================================================
# TestParseXccdfResults
# ===================================================================
class TestParseXccdfResults:
    """Tests for parse_xccdf_results() -- the core XCCDF parser."""

    def test_minimal_pass_fail(self, tmp_path):
        """Parse a minimal valid XCCDF 1.2 document with pass/fail results."""
        rules = (
            _rule_xml('rule_pass', severity='medium', title='Pass Rule',
                       stig_id='V-100001')
            + _rule_xml('rule_fail', severity='high', title='Fail Rule',
                         stig_id='V-100002')
        )
        results = (
            _rule_result_xml('rule_pass', 'pass', 'medium')
            + _rule_result_xml('rule_fail', 'fail', 'high')
        )
        xml = _xccdf_doc(rules, results)
        filepath = _write_xccdf(tmp_path, 'xccdf-results-server01.xml', xml)

        host, findings = parse_xccdf_results(filepath)

        assert host == 'server01'
        assert len(findings) == 2

        by_id = {f['rule_id']: f for f in findings}
        assert by_id['rule_pass']['status'] == 'pass'
        assert by_id['rule_pass']['title'] == 'Pass Rule'
        assert by_id['rule_fail']['status'] == 'fail'
        assert by_id['rule_fail']['title'] == 'Fail Rule'

    def test_xccdf_11_namespace(self, tmp_path):
        """Parser handles XCCDF 1.1 namespace correctly."""
        rules = _rule_xml('rule_11', severity='low', title='XCCDF 1.1 Rule')
        results = _rule_result_xml('rule_11', 'pass', 'low')
        xml = _xccdf_doc(rules, results, ns=XCCDF_11_NS)
        filepath = _write_xccdf(tmp_path, 'xccdf-results-legacy.xml', xml)

        host, findings = parse_xccdf_results(filepath)

        assert host == 'legacy'
        assert len(findings) == 1
        assert findings[0]['rule_id'] == 'rule_11'
        assert findings[0]['status'] == 'pass'

    def test_missing_test_result_returns_empty(self, tmp_path):
        """When <TestResult> is absent, returns the host but no findings."""
        xml = (
            '<?xml version="1.0"?>'
            f'<Benchmark xmlns="{XCCDF_12_NS}">'
            '  <Rule id="orphan" severity="medium">'
            '    <title>Orphaned Rule</title>'
            '    <description>No TestResult</description>'
            '  </Rule>'
            '</Benchmark>'
        )
        filepath = _write_xccdf(tmp_path, 'xccdf-results-notest.xml', xml)

        host, findings = parse_xccdf_results(filepath)

        assert host == 'notest'
        assert findings == []

    def test_severity_mapping(self, tmp_path):
        """Verify XCCDF severity attributes map to CAT levels."""
        rules = (
            _rule_xml('r_high', severity='high')
            + _rule_xml('r_medium', severity='medium')
            + _rule_xml('r_low', severity='low')
        )
        results = (
            _rule_result_xml('r_high', 'fail', 'high')
            + _rule_result_xml('r_medium', 'fail', 'medium')
            + _rule_result_xml('r_low', 'fail', 'low')
        )
        xml = _xccdf_doc(rules, results)
        filepath = _write_xccdf(tmp_path, 'xccdf-results-sev.xml', xml)

        _, findings = parse_xccdf_results(filepath)
        by_id = {f['rule_id']: f for f in findings}

        assert by_id['r_high']['severity'] == 'CAT_I'
        assert by_id['r_medium']['severity'] == 'CAT_II'
        assert by_id['r_low']['severity'] == 'CAT_III'

    def test_status_mapping(self, tmp_path):
        """Verify XCCDF result statuses map to normalized values."""
        rules = ''.join(
            _rule_xml(f'r_{s}', severity='medium')
            for s in ['pass', 'fail', 'error', 'notapplicable', 'fixed', 'informational']
        )
        results = ''.join(
            _rule_result_xml(f'r_{s}', s, 'medium')
            for s in ['pass', 'fail', 'error', 'notapplicable', 'fixed', 'informational']
        )
        xml = _xccdf_doc(rules, results)
        filepath = _write_xccdf(tmp_path, 'xccdf-results-status.xml', xml)

        _, findings = parse_xccdf_results(filepath)
        by_id = {f['rule_id']: f for f in findings}

        assert by_id['r_pass']['status'] == 'pass'
        assert by_id['r_fail']['status'] == 'fail'
        assert by_id['r_error']['status'] == 'error'
        assert by_id['r_notapplicable']['status'] == 'not_applicable'
        assert by_id['r_fixed']['status'] == 'pass'
        assert by_id['r_informational']['status'] == 'pass'

    def test_skip_statuses_excluded(self, tmp_path):
        """notselected and notchecked are excluded from findings entirely."""
        rules = (
            _rule_xml('r_keep', severity='medium')
            + _rule_xml('r_notselected', severity='medium')
            + _rule_xml('r_notchecked', severity='medium')
        )
        results = (
            _rule_result_xml('r_keep', 'pass', 'medium')
            + _rule_result_xml('r_notselected', 'notselected', 'medium')
            + _rule_result_xml('r_notchecked', 'notchecked', 'medium')
        )
        xml = _xccdf_doc(rules, results)
        filepath = _write_xccdf(tmp_path, 'xccdf-results-skip.xml', xml)

        _, findings = parse_xccdf_results(filepath)

        assert len(findings) == 1
        assert findings[0]['rule_id'] == 'r_keep'

    def test_skip_statuses_constant(self):
        """Verify the SKIP_STATUSES set contains exactly the expected values."""
        assert SKIP_STATUSES == {'notselected', 'notchecked'}

    def test_host_extraction_from_filename(self, tmp_path):
        """Extract hostname from xccdf-results-HOST.xml pattern."""
        rules = _rule_xml('r1', severity='medium')
        results = _rule_result_xml('r1', 'pass', 'medium')
        xml = _xccdf_doc(rules, results)

        filepath = _write_xccdf(
            tmp_path, 'xccdf-results-webserver-prod-01.xml', xml
        )
        host, _ = parse_xccdf_results(filepath)
        assert host == 'webserver-prod-01'

    def test_host_extraction_fallback(self, tmp_path):
        """Non-matching filename falls back to the full basename."""
        rules = _rule_xml('r1', severity='medium')
        results = _rule_result_xml('r1', 'pass', 'medium')
        xml = _xccdf_doc(rules, results)

        filepath = _write_xccdf(tmp_path, 'scan-output.xml', xml)
        host, _ = parse_xccdf_results(filepath)
        assert host == 'scan-output.xml'

    def test_framework_disa_stig_prefers_stig_id(self, tmp_path):
        """DISA_STIG framework selects stig_id over cis_id."""
        rules = _rule_xml(
            'r_disa', severity='medium', stig_id='V-254244', cis_id='1.1.1'
        )
        results = _rule_result_xml('r_disa', 'pass', 'medium')
        xml = _xccdf_doc(rules, results)
        filepath = _write_xccdf(tmp_path, 'xccdf-results-disa.xml', xml)

        _, findings = parse_xccdf_results(filepath, framework='DISA_STIG')

        assert findings[0]['stig_id'] == 'V-254244'

    def test_framework_cis_prefers_cis_id(self, tmp_path):
        """CIS framework selects cis_id over stig_id."""
        rules = _rule_xml(
            'r_cis', severity='medium', stig_id='V-254244', cis_id='1.1.1'
        )
        results = _rule_result_xml('r_cis', 'pass', 'medium')
        xml = _xccdf_doc(rules, results)
        filepath = _write_xccdf(tmp_path, 'xccdf-results-cis.xml', xml)

        _, findings = parse_xccdf_results(filepath, framework='CIS')

        assert findings[0]['stig_id'] == '1.1.1'

    def test_framework_auto_prefers_stig_then_cis(self, tmp_path):
        """Auto framework prefers stig_id, falls back to cis_id."""
        rules_both = _rule_xml(
            'r_both', severity='medium', stig_id='V-254244', cis_id='1.1.1'
        )
        rules_cis_only = _rule_xml(
            'r_cis_only', severity='medium', cis_id='2.2.2'
        )
        results = (
            _rule_result_xml('r_both', 'pass', 'medium')
            + _rule_result_xml('r_cis_only', 'pass', 'medium')
        )
        xml = _xccdf_doc(rules_both + rules_cis_only, results)
        filepath = _write_xccdf(tmp_path, 'xccdf-results-auto.xml', xml)

        _, findings = parse_xccdf_results(filepath, framework='auto')
        by_id = {f['rule_id']: f for f in findings}

        assert by_id['r_both']['stig_id'] == 'V-254244'
        assert by_id['r_cis_only']['stig_id'] == '2.2.2'

    def test_scanner_name_appears_in_findings(self, tmp_path):
        """The scanner_name parameter propagates to each finding's scanner field."""
        rules = _rule_xml('r1', severity='medium')
        results = _rule_result_xml('r1', 'pass', 'medium')
        xml = _xccdf_doc(rules, results)
        filepath = _write_xccdf(tmp_path, 'xccdf-results-h1.xml', xml)

        _, findings = parse_xccdf_results(filepath, scanner_name='scc')

        assert findings[0]['scanner'] == 'scc'

    def test_scanner_name_default_is_openscap(self, tmp_path):
        """Default scanner_name is 'openscap' when not specified."""
        rules = _rule_xml('r1', severity='medium')
        results = _rule_result_xml('r1', 'pass', 'medium')
        xml = _xccdf_doc(rules, results)
        filepath = _write_xccdf(tmp_path, 'xccdf-results-h2.xml', xml)

        _, findings = parse_xccdf_results(filepath)

        assert findings[0]['scanner'] == 'openscap'

    def test_vuln_discussion_extraction(self, tmp_path):
        """VulnDiscussion markup in description is extracted cleanly."""
        desc = '<VulnDiscussion>This is the real description.</VulnDiscussion><FalsePositives/>'
        rules = _rule_xml('r_vd', severity='medium', description=desc)
        results = _rule_result_xml('r_vd', 'fail', 'medium')
        xml = _xccdf_doc(rules, results)
        filepath = _write_xccdf(tmp_path, 'xccdf-results-vd.xml', xml)

        _, findings = parse_xccdf_results(filepath)

        assert findings[0]['description'] == 'This is the real description.'

    def test_finding_evidence_structure(self, tmp_path):
        """Each finding includes evidence with actual, expected, and message."""
        rules = _rule_xml('r_ev', severity='medium', title='Evidence Rule')
        results = _rule_result_xml('r_ev', 'fail', 'medium')
        xml = _xccdf_doc(rules, results)
        filepath = _write_xccdf(tmp_path, 'xccdf-results-ev.xml', xml)

        _, findings = parse_xccdf_results(filepath)

        ev = findings[0]['evidence']
        assert ev['actual'] == 'fail'
        assert ev['expected'] == 'pass'
        assert 'Evidence Rule' in ev['message']


# ===================================================================
# TestExtractHostFromFilename
# ===================================================================
class TestExtractHostFromFilename:
    """Tests for extract_host_from_filename()."""

    def test_standard_pattern(self):
        assert extract_host_from_filename('/tmp/xccdf-results-server01.xml') == 'server01'

    def test_hyphenated_hostname(self):
        assert extract_host_from_filename('/data/xccdf-results-web-prod-01.xml') == 'web-prod-01'

    def test_indexed_filename_strips_double_underscore_suffix(self):
        """SCC multi-file scans produce xccdf-results-<host>__<n>.xml — strip the index."""
        assert extract_host_from_filename('/tmp/xccdf-results-nm-prod-win202503__1.xml') == 'nm-prod-win202503'
        assert extract_host_from_filename('/tmp/xccdf-results-nm-prod-win202503__22.xml') == 'nm-prod-win202503'

    def test_indexed_filename_preserves_hyphenated_host(self):
        assert extract_host_from_filename('/tmp/xccdf-results-server-01__3.xml') == 'server-01'

    def test_non_matching_returns_basename(self):
        assert extract_host_from_filename('/tmp/scan-output.xml') == 'scan-output.xml'

    def test_bare_filename(self):
        assert extract_host_from_filename('xccdf-results-localhost.xml') == 'localhost'


# ===================================================================
# TestLoadRulesMetadataMap
# ===================================================================
class TestLoadRulesMetadataMap:
    """Tests for load_rules_metadata_map()."""

    def test_empty_path_returns_empty(self):
        assert load_rules_metadata_map('') == {}
        assert load_rules_metadata_map(None) == {}

    def test_nonexistent_file_returns_empty(self):
        assert load_rules_metadata_map('/nonexistent/rules.yml') == {}

    def test_loads_rules_keyed_by_id_and_stig_id(self, tmp_path):
        rules_file = tmp_path / 'rules.yml'
        rules_file.write_text(
            "rules:\n"
            "  - id: xccdf_rule_password_history\n"
            "    stig_id: V-254239\n"
            "    aap_impact: safe\n"
            "    aap_impact_reason: 'No service impact'\n"
            "    fix_text: 'Set password history to 24'\n"
        )
        result = load_rules_metadata_map(str(rules_file))

        # Keyed by both rule id and stig_id
        assert 'xccdf_rule_password_history' in result
        assert 'V-254239' in result

        # Same entry object
        assert result['xccdf_rule_password_history'] is result['V-254239']

        # Fields present
        entry = result['xccdf_rule_password_history']
        assert entry['aap_impact'] == 'safe'
        assert entry['aap_impact_reason'] == 'No service impact'
        assert entry['fix_text'] == 'Set password history to 24'

    def test_rule_without_stig_id_only_keyed_by_id(self, tmp_path):
        rules_file = tmp_path / 'rules.yml'
        rules_file.write_text(
            "rules:\n"
            "  - id: custom_rule_42\n"
            "    aap_impact: breaks-connectivity\n"
        )
        result = load_rules_metadata_map(str(rules_file))

        assert 'custom_rule_42' in result
        assert len(result) == 1

    def test_empty_yaml_returns_empty(self, tmp_path):
        rules_file = tmp_path / 'rules.yml'
        rules_file.write_text('')
        assert load_rules_metadata_map(str(rules_file)) == {}


# ===================================================================
# TestRunNormalize
# ===================================================================
class TestRunNormalize:
    """Tests for run_normalize() -- the main entry point."""

    def _make_single_host_xccdf(self, tmp_path, hostname='server01',
                                 scanner_name='openscap'):
        """Helper: create one XCCDF file with 2 findings (pass + fail)."""
        rules = (
            _rule_xml('r_pass', severity='low', title='Pass Rule',
                       stig_id='V-100001')
            + _rule_xml('r_fail', severity='high', title='Fail Rule',
                         stig_id='V-100002')
        )
        results = (
            _rule_result_xml('r_pass', 'pass', 'low')
            + _rule_result_xml('r_fail', 'fail', 'high')
        )
        xml = _xccdf_doc(rules, results)
        return _write_xccdf(
            tmp_path, f'xccdf-results-{hostname}.xml', xml
        )

    def test_single_host_json_report_structure(self, tmp_path):
        """Single host produces JSON report with correct top-level structure."""
        xccdf_file = self._make_single_host_xccdf(tmp_path)
        output_file = str(tmp_path / 'report.json')

        module = _make_module(_default_params(
            tmp_path,
            results_files=[xccdf_file],
            output_file=output_file,
        ))

        run_normalize(module)

        module.exit_json.assert_called_once()
        result = module.exit_json.call_args[1]

        assert result['hosts_processed'] == 1
        assert result['total_findings'] == 2
        assert result['summary']['pass'] == 1
        assert result['summary']['fail'] == 1
        assert result['output_file'] == output_file

        # Verify the JSON file was written with expected structure
        with open(output_file) as f:
            report = json.load(f)

        assert report['schema_version'] == '1.0.0'
        assert report['scanner'] == 'openscap'
        assert report['hosts_processed'] == 1
        assert report['total_findings'] == 2
        assert len(report['findings']) == 2

    def test_scanner_name_scc_in_report(self, tmp_path):
        """scanner_name='scc' produces 'scc' in report, not hardcoded 'openscap'.

        This is the critical correctness test for the SCC default scanner fix.
        """
        xccdf_file = self._make_single_host_xccdf(tmp_path)
        output_file = str(tmp_path / 'report-scc.json')

        module = _make_module(_default_params(
            tmp_path,
            results_files=[xccdf_file],
            output_file=output_file,
            scanner_name='scc',
        ))

        run_normalize(module)

        with open(output_file) as f:
            report = json.load(f)

        assert report['scanner'] == 'scc'

    def test_scanner_name_scc_in_per_finding_scanner_field(self, tmp_path):
        """scanner_name='scc' propagates to each finding's scanner field."""
        xccdf_file = self._make_single_host_xccdf(tmp_path)
        output_file = str(tmp_path / 'report-scc-findings.json')

        module = _make_module(_default_params(
            tmp_path,
            results_files=[xccdf_file],
            output_file=output_file,
            scanner_name='scc',
        ))

        run_normalize(module)

        with open(output_file) as f:
            report = json.load(f)

        for finding in report['findings']:
            assert finding['scanner'] == 'scc', (
                f"Finding {finding['rule_id']} has scanner "
                f"'{finding['scanner']}' instead of 'scc'"
            )

    def test_rules_metadata_merge(self, tmp_path):
        """Rules metadata YAML overrides aap_impact and fix_text in findings."""
        xccdf_file = self._make_single_host_xccdf(tmp_path)
        output_file = str(tmp_path / 'report-meta.json')

        rules_file = tmp_path / 'rules.yml'
        rules_file.write_text(
            "rules:\n"
            "  - id: r_fail\n"
            "    aap_impact: breaks-connectivity\n"
            "    aap_impact_reason: Modifies firewall rules\n"
            "    fix_text: 'ansible.builtin.win_security_policy:'\n"
        )

        module = _make_module(_default_params(
            tmp_path,
            results_files=[xccdf_file],
            output_file=output_file,
            rules_metadata_file=str(rules_file),
        ))

        run_normalize(module)

        with open(output_file) as f:
            report = json.load(f)

        by_id = {f['rule_id']: f for f in report['findings']}
        assert by_id['r_fail']['aap_impact'] == 'breaks-connectivity'
        assert by_id['r_fail']['aap_impact_reason'] == 'Modifies firewall rules'
        assert 'win_security_policy' in by_id['r_fail']['fix_text']

        # Unmatched rule retains default
        assert by_id['r_pass']['aap_impact'] == 'safe'

    def test_ndjson_preamble_structure(self, tmp_path):
        """NDJSON composition includes scanner, framework, certification in preamble."""
        xccdf_file = self._make_single_host_xccdf(tmp_path)
        output_file = str(tmp_path / 'report-ndjson.json')

        module = _make_module(_default_params(
            tmp_path,
            results_files=[xccdf_file],
            output_file=output_file,
            scanner_name='scc',
            framework='DISA_STIG',
            compose_post_body=True,
            scan_id='scan-001',
            ingest_token='tok-secret',
            finalize=True,
            certification_status='certified',
            certification_authority='SCAP 1.3',
        ))

        run_normalize(module)

        result = module.exit_json.call_args[1]
        post_file = result['post_file']
        assert os.path.exists(post_file)

        with open(post_file) as f:
            lines = f.readlines()

        # Preamble + 2 findings
        assert len(lines) == 3

        preamble = json.loads(lines[0])
        assert preamble['_meta'] is True
        assert preamble['scanId'] == 'scan-001'
        assert preamble['ingestToken'] == 'tok-secret'
        assert preamble['finalize'] is True
        assert preamble['scanner'] == 'scc'
        assert preamble['framework'] == 'DISA_STIG'
        assert preamble['certification']['status'] == 'certified'
        assert preamble['certification']['authority'] == 'SCAP 1.3'

        # Each finding line is valid JSON
        finding1 = json.loads(lines[1])
        assert 'rule_id' in finding1

    def test_ndjson_compact_separators(self, tmp_path):
        """NDJSON lines use compact JSON separators (no spaces)."""
        xccdf_file = self._make_single_host_xccdf(tmp_path)
        output_file = str(tmp_path / 'report-compact.json')

        module = _make_module(_default_params(
            tmp_path,
            results_files=[xccdf_file],
            output_file=output_file,
            compose_post_body=True,
            scan_id='scan-compact',
        ))

        run_normalize(module)

        post_file = module.exit_json.call_args[1]['post_file']
        with open(post_file) as f:
            line = f.readline()

        assert ': ' not in line
        assert ', ' not in line

    def test_check_mode_no_file_writes(self, tmp_path):
        """check_mode produces no file writes but still returns results."""
        xccdf_file = self._make_single_host_xccdf(tmp_path)
        output_file = str(tmp_path / 'report-check.json')

        module = _make_module(
            _default_params(
                tmp_path,
                results_files=[xccdf_file],
                output_file=output_file,
            ),
            check_mode=True,
        )

        run_normalize(module)

        result = module.exit_json.call_args[1]
        assert result['changed'] is False
        assert result['hosts_processed'] == 1
        assert result['total_findings'] == 2
        assert not os.path.exists(output_file)

    def test_missing_results_file_warns_but_succeeds(self, tmp_path):
        """A missing results file triggers warn() but processing continues."""
        output_file = str(tmp_path / 'report-missing.json')

        module = _make_module(_default_params(
            tmp_path,
            results_files=['/nonexistent/xccdf-results-ghost.xml'],
            output_file=output_file,
        ))

        run_normalize(module)

        module.warn.assert_called()
        warn_msg = module.warn.call_args[0][0]
        assert 'not found' in warn_msg.lower() or 'nonexistent' in warn_msg.lower()

        result = module.exit_json.call_args[1]
        assert result['hosts_processed'] == 0
        assert result['total_findings'] == 0

    def test_multi_host_aggregation(self, tmp_path):
        """Multiple XCCDF files are aggregated into one report."""
        xccdf1 = self._make_single_host_xccdf(tmp_path, hostname='host-a')
        xccdf2 = self._make_single_host_xccdf(tmp_path, hostname='host-b')
        output_file = str(tmp_path / 'report-multi.json')

        module = _make_module(_default_params(
            tmp_path,
            results_files=[xccdf1, xccdf2],
            output_file=output_file,
        ))

        run_normalize(module)

        result = module.exit_json.call_args[1]
        assert result['hosts_processed'] == 2
        assert result['total_findings'] == 4  # 2 findings x 2 hosts

        with open(output_file) as f:
            report = json.load(f)

        hosts = {f['host'] for f in report['findings']}
        assert hosts == {'host-a', 'host-b'}

    def test_compose_post_body_skipped_without_scan_id(self, tmp_path):
        """compose_post_body=True but empty scan_id warns and skips NDJSON."""
        xccdf_file = self._make_single_host_xccdf(tmp_path)
        output_file = str(tmp_path / 'report-no-scanid.json')

        module = _make_module(_default_params(
            tmp_path,
            results_files=[xccdf_file],
            output_file=output_file,
            compose_post_body=True,
            scan_id='',
        ))

        run_normalize(module)

        module.warn.assert_called()
        result = module.exit_json.call_args[1]
        assert 'post_file' not in result

    def test_post_body_json_format(self, tmp_path):
        """post_body_format='json' produces a .post.json file."""
        xccdf_file = self._make_single_host_xccdf(tmp_path)
        output_file = str(tmp_path / 'report-json-post.json')

        module = _make_module(_default_params(
            tmp_path,
            results_files=[xccdf_file],
            output_file=output_file,
            compose_post_body=True,
            scan_id='scan-json',
            post_body_format='json',
        ))

        run_normalize(module)

        result = module.exit_json.call_args[1]
        post_file = result['post_file']
        assert post_file.endswith('.post.json')

        with open(post_file) as f:
            body = json.load(f)

        assert body['scanId'] == 'scan-json'
        assert isinstance(body['findings'], list)
        assert len(body['findings']) == 2

    def test_profile_name_in_report(self, tmp_path):
        """Custom profile_name appears in report; default falls back to generic."""
        xccdf_file = self._make_single_host_xccdf(tmp_path)

        # With custom name
        output1 = str(tmp_path / 'report-named.json')
        module1 = _make_module(_default_params(
            tmp_path,
            results_files=[xccdf_file],
            output_file=output1,
            profile_name='Windows Server 2022 STIG v2r1',
        ))
        run_normalize(module1)

        with open(output1) as f:
            report1 = json.load(f)
        assert report1['profile'] == 'Windows Server 2022 STIG v2r1'

        # Without custom name (default)
        output2 = str(tmp_path / 'report-default.json')
        module2 = _make_module(_default_params(
            tmp_path,
            results_files=[xccdf_file],
            output_file=output2,
        ))
        run_normalize(module2)

        with open(output2) as f:
            report2 = json.load(f)
        assert report2['profile'] == 'XCCDF Compliance Scan'

    def test_summary_counts_all_statuses(self, tmp_path):
        """Summary dict counts pass, fail, error, not_applicable, not_checked."""
        rules = ''.join(
            _rule_xml(f'r_{i}', severity='medium')
            for i in range(5)
        )
        results = (
            _rule_result_xml('r_0', 'pass', 'medium')
            + _rule_result_xml('r_1', 'pass', 'medium')
            + _rule_result_xml('r_2', 'fail', 'medium')
            + _rule_result_xml('r_3', 'error', 'medium')
            + _rule_result_xml('r_4', 'notapplicable', 'medium')
        )
        xml = _xccdf_doc(rules, results)
        xccdf_file = _write_xccdf(tmp_path, 'xccdf-results-counts.xml', xml)
        output_file = str(tmp_path / 'report-counts.json')

        module = _make_module(_default_params(
            tmp_path,
            results_files=[xccdf_file],
            output_file=output_file,
        ))

        run_normalize(module)

        result = module.exit_json.call_args[1]
        assert result['summary']['pass'] == 2
        assert result['summary']['fail'] == 1
        assert result['summary']['error'] == 1
        assert result['summary']['not_applicable'] == 1


# ===================================================================
# TestSeverityAndStatusMaps
# ===================================================================
class TestSeverityAndStatusMaps:
    """Direct tests on the exported mapping constants."""

    def test_severity_map_completeness(self):
        assert SEVERITY_MAP['high'] == 'CAT_I'
        assert SEVERITY_MAP['medium'] == 'CAT_II'
        assert SEVERITY_MAP['low'] == 'CAT_III'
        assert SEVERITY_MAP['unknown'] == 'CAT_II'

    def test_status_map_completeness(self):
        assert STATUS_MAP['pass'] == 'pass'
        assert STATUS_MAP['fail'] == 'fail'
        assert STATUS_MAP['error'] == 'error'
        assert STATUS_MAP['unknown'] == 'error'
        assert STATUS_MAP['notapplicable'] == 'not_applicable'
        assert STATUS_MAP['notchecked'] == 'not_checked'
        assert STATUS_MAP['informational'] == 'pass'
        assert STATUS_MAP['fixed'] == 'pass'
