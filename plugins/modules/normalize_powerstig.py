#!/usr/bin/python
# -*- coding: utf-8 -*-

# GNU General Public License v3.0+

DOCUMENTATION = r'''
---
module: normalize_powerstig
short_description: Compose NDJSON POST body from PowerSTIG CFF JSON
description:
  - Reads CFF JSON files produced by the normalize_powerstig role.
  - Composes NDJSON POST body files for streaming to the compliance API.
  - Each NDJSON file contains a preamble line followed by one finding per line.
  - This keeps findings out of Ansible variable space (ADR-033 OOM prevention).
version_added: "0.1.0"
options:
  cff_files:
    description: List of CFF JSON file paths to process
    type: list
    elements: str
    required: true
  output_dir:
    description: Directory to write NDJSON output files
    type: str
    required: true
  scan_id:
    description: Scan identifier for the NDJSON preamble
    type: str
    required: true
  ingest_token:
    description: Per-scan security token for API authentication
    type: str
    required: false
    default: ""
  finalize_last:
    description: Set finalize=true on the last file's preamble
    type: bool
    required: false
    default: true
  certification_status:
    description: Scanner certification level
    type: str
    required: false
    default: uncertified
    choices: [certified, conformant, uncertified]
  certification_authority:
    description: Certifying body
    type: str
    required: false
    default: ""
  rules_metadata_file:
    description: Path to rules YAML with aap_impact and fix_text metadata
    type: str
    required: false
    default: ""
author:
  - Ansible Security Team (@ansible)
'''

EXAMPLES = r'''
- name: Compose NDJSON from PowerSTIG CFF results
  security.compliance_windows.normalize_powerstig:
    cff_files:
      - /tmp/compliance-results/cff-webserver01.json
      - /tmp/compliance-results/cff-webserver02.json
    output_dir: /tmp/compliance-results
    scan_id: "{{ scan_id }}"
    ingest_token: "{{ ingest_token }}"
  register: normalized
'''

RETURN = r'''
hosts_processed:
  description: Number of hosts whose results were processed
  returned: always
  type: int
total_findings:
  description: Total findings across all hosts
  returned: always
  type: int
ndjson_files:
  description: List of NDJSON files written
  returned: always
  type: list
summary:
  description: Aggregate pass/fail counts
  returned: always
  type: dict
'''

import json
import os

try:
    import yaml
    HAS_YAML = True
except ImportError:
    HAS_YAML = False

from ansible.module_utils.basic import AnsibleModule


def load_rules_metadata(filepath):
    """Load aap_impact and fix_text from rules YAML."""
    if not filepath or not os.path.exists(filepath):
        return {}
    if not HAS_YAML:
        return {}
    with open(filepath, 'r') as f:
        data = yaml.safe_load(f) or {}
    rules = data.get('rules', data) if isinstance(data, dict) else data
    if isinstance(rules, list):
        return {r['id']: r for r in rules if isinstance(r, dict) and 'id' in r}
    return rules


def run_normalize_powerstig(module):
    cff_files = module.params['cff_files']
    output_dir = module.params['output_dir']
    scan_id = module.params['scan_id']
    ingest_token = module.params.get('ingest_token', '')
    finalize_last = module.params.get('finalize_last', True)
    cert_status = module.params.get('certification_status', 'uncertified')
    cert_authority = module.params.get('certification_authority', '')
    rules_metadata_file = module.params.get('rules_metadata_file', '')

    rules_map = load_rules_metadata(rules_metadata_file)

    if not os.path.exists(output_dir):
        os.makedirs(output_dir)

    hosts_processed = 0
    total_findings = 0
    ndjson_files = []
    summary = {'pass': 0, 'fail': 0, 'error': 0, 'notapplicable': 0, 'notchecked': 0}

    sorted_files = sorted(cff_files)

    for idx, filepath in enumerate(sorted_files):
        if not os.path.exists(filepath):
            module.warn(f'CFF file not found: {filepath}')
            continue

        try:
            with open(filepath, 'r') as f:
                cff = json.load(f)
        except (json.JSONDecodeError, OSError) as e:
            module.warn(f'Failed to read {filepath}: {e}')
            continue

        findings = cff.get('findings', [])
        host = cff.get('target_host', os.path.basename(filepath))
        hosts_processed += 1
        total_findings += len(findings)

        if rules_map:
            for finding in findings:
                rule_id = finding.get('rule_id', finding.get('ruleId', ''))
                meta = rules_map.get(rule_id)
                if meta:
                    if meta.get('aap_impact'):
                        finding['aap_impact'] = meta['aap_impact']
                        finding['aap_impact_reason'] = meta.get('aap_impact_reason', '')
                    if meta.get('fix_text'):
                        finding['fix_text'] = meta['fix_text']
                        finding['fixText'] = meta['fix_text']

        for finding in findings:
            status = finding.get('status', 'error')
            if status in summary:
                summary[status] += 1

        is_last = (idx == len(sorted_files) - 1)
        finalize = finalize_last and is_last

        ndjson_path = os.path.join(output_dir, f'findings-{host}.json.ndjson')

        if not module.check_mode:
            with open(ndjson_path, 'w') as f:
                preamble = {
                    '_meta': True,
                    'scanId': scan_id,
                    'ingestToken': ingest_token,
                    'finalize': finalize,
                    'scanner': cff.get('scanner', 'powerstig'),
                    'framework': cff.get('framework', 'DISA_STIG'),
                    'certification': {
                        'status': cert_status,
                        'authority': cert_authority,
                    },
                }
                f.write(json.dumps(preamble, separators=(',', ':')) + '\n')
                for finding in findings:
                    f.write(json.dumps(finding, separators=(',', ':')) + '\n')

        ndjson_files.append(ndjson_path)

    module.exit_json(
        changed=not module.check_mode,
        hosts_processed=hosts_processed,
        total_findings=total_findings,
        ndjson_files=ndjson_files,
        summary=summary,
    )


ARGUMENT_SPEC = dict(
    cff_files=dict(type='list', elements='str', required=True),
    output_dir=dict(type='str', required=True),
    scan_id=dict(type='str', required=True),
    ingest_token=dict(type='str', required=False, default='', no_log=True),
    finalize_last=dict(type='bool', required=False, default=True),
    certification_status=dict(type='str', required=False, default='uncertified',
                              choices=['certified', 'conformant', 'uncertified']),
    certification_authority=dict(type='str', required=False, default=''),
    rules_metadata_file=dict(type='str', required=False, default=''),
)


def main():
    module = AnsibleModule(
        argument_spec=ARGUMENT_SPEC,
        supports_check_mode=True,
    )
    run_normalize_powerstig(module)


if __name__ == '__main__':
    main()
