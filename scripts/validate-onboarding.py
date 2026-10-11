#!/usr/bin/env python3
"""Validate non-secret onboarding evidence. Never accesses a vault or network.

Implements only the JSON Schema keywords present in docs/onboarding-schemas;
unknown keywords fail closed. Execution claims and human receipts remain trusted
inputs, not cryptographic attestations. Pair readiness is computed from both
local results and a separately approved policy, never from the model's verdict.
"""
import argparse
from datetime import datetime, timezone
import json
from pathlib import Path
import re
import sys

REJECTION_ACTIONS = ['review_quarantine_records', 'confirm_identical_accepted_commit',
                     'confirm_author_approved_at_acceptance', 'confirm_rejection_set_stable']
SCHEMAS = Path(__file__).resolve().parents[1] / 'docs/onboarding-schemas'
KEYWORDS = {'$schema', 'type', 'properties', 'required', 'additionalProperties',
            'propertyNames', 'minProperties', 'maxProperties', 'items', 'minItems',
            'maxItems', 'minLength', 'maxLength', 'pattern', 'enum', 'minimum',
            'maximum', 'anyOf'}


def validate(value, schema, path='$'):
    if set(schema) - KEYWORDS:
        raise ValueError('unsupported_schema_keyword')
    if 'anyOf' in schema:
        for choice in schema['anyOf']:
            try:
                validate(value, choice, path)
                return
            except ValueError:
                pass
        raise ValueError('schema_type:' + path)
    kinds = {'object': dict, 'array': list, 'string': str, 'integer': int,
             'boolean': bool, 'null': type(None)}
    if type(value) is not kinds[schema['type']]:
        raise ValueError('schema_type:' + path)
    if 'enum' in schema and value not in schema['enum']:
        raise ValueError('schema_enum:' + path)
    if isinstance(value, dict):
        if set(schema.get('required', [])) - value.keys():
            raise ValueError('schema_missing:' + path)
        if not schema.get('minProperties', 0) <= len(value) <= schema.get('maxProperties', 1000):
            raise ValueError('schema_size:' + path)
        for key, item in value.items():
            if 'propertyNames' in schema:
                validate(key, schema['propertyNames'], path + '.key')
            child = schema.get('properties', {}).get(key, schema.get('additionalProperties', True))
            if child is False:
                raise ValueError('schema_extra:' + path)
            if isinstance(child, dict):
                validate(item, child, path + '.' + key)
    elif isinstance(value, list):
        if not schema.get('minItems', 0) <= len(value) <= schema.get('maxItems', 1000):
            raise ValueError('schema_size:' + path)
        for i, item in enumerate(value):
            validate(item, schema['items'], path + '.' + str(i))
    elif isinstance(value, str):
        if not schema.get('minLength', 0) <= len(value) <= schema.get('maxLength', 100000):
            raise ValueError('schema_size:' + path)
        if 'pattern' in schema and not re.fullmatch(schema['pattern'], value):
            raise ValueError('schema_pattern:' + path)
    elif type(value) is int:
        if value < schema.get('minimum', value) or value > schema.get('maximum', value):
            raise ValueError('schema_range:' + path)


def schema_check(value, name):
    validate(value, json.loads((SCHEMAS / (name + '.schema.json')).read_text()))


def read_json(path):
    def pairs(items):
        out = {}
        for key, value in items:
            if key in out:
                raise ValueError('duplicate_json_key')
            out[key] = value
        return out
    with Path(path).open('rb') as handle:
        data = handle.read(1024 * 1024 + 1)
    if len(data) > 1024 * 1024:
        raise ValueError('input_too_large')
    return json.loads(data, object_pairs_hook=pairs,
                      parse_constant=lambda _: (_ for _ in ()).throw(ValueError('nonfinite_json')))


def moment(value):
    try:
        if not isinstance(value, str) or not re.fullmatch(r'[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z', value):
            raise ValueError()
        return datetime.strptime(value, '%Y-%m-%dT%H:%M:%SZ').replace(tzinfo=timezone.utc)
    except ValueError:
        raise ValueError('invalid_utc_time') from None


def roster(members):
    result = {}
    for member in members:
        fp = member['fingerprint']
        if fp in result:
            raise ValueError('duplicate_member')
        result[fp] = (member['role'], member['status'], member['owner'])
    return result


def safe_probe(probe):
    # Deliberately narrow onboarding path: no query, percent encoding, shell
    # metacharacters, network-path reference, or traversal. General API support
    # is unchanged. Callers must pass separate argv, never interpolate a shell.
    path = probe['path']
    if not re.fullmatch(r'/[A-Za-z0-9/_-]*', path) or path.startswith('//'):
        raise ValueError('invalid_probe_input')


def policy_check(policy):
    schema_check(policy, 'policy')
    safe_probe(policy['probe'])
    expected = roster(policy['expected_members'])
    a, b = policy['A_fingerprint'], policy['B_fingerprint']
    if a == b or expected.get(a) != ('admin', 'active', True) or expected.get(b) != (policy['B_role'], 'active', False):
        raise ValueError('invalid_expected_roster')
    if sum(m['owner'] for m in policy['expected_members']) != 1:
        raise ValueError('invalid_expected_roster')
    if policy['credential_class'] == 'real' and policy['isolation_confirmed'] is not True:
        raise ValueError('production_isolation_unconfirmed')


def local_failures(result, policy, now):
    schema_check(result, 'local')
    safe_probe(result['probe'])
    failures = set(result['failed_checks'])
    if result['local_result'] != 'pass':
        failures.add('local_result_not_pass')
    if result['version'] != '0.1.0' or result['version_evidence'] == 'unknown':
        failures.add('version_unverified')
    artifact = result['artifact_receipt']
    if artifact is None or (result['version_evidence'] == 'brew' and artifact['tap_commit'] is None) or (result['version_evidence'] == 'human_reported' and artifact['tap_commit'] is not None):
        failures.add('artifact_identity_unverified')
    if artifact != policy['artifact_receipts'][result['role']]:
        failures.add('artifact_identity_mismatch')
    if (result['credential_class'], result['isolation_confirmed']) != (policy['credential_class'], policy['isolation_confirmed']):
        failures.add('execution_context_mismatch')
    if result['connection_id'] != policy['connection_id'] or result['probe'] != policy['probe']:
        failures.add('probe_mismatch')
    checks = result['checks']
    if any(checks[k] != 'pass' for k in ['agent_binary', 'runtime_config_present', 'connection_visible', 'expected_response']) or checks['readonly_request_exit'] != 0 or checks['service_http_status'] != policy['probe']['expected_http_status']:
        failures.add('readonly_request_unverified')
    receipt = result['human_receipt']
    if receipt is None:
        failures.add('human_receipt_missing')
        return sorted(failures)
    a, b = policy['A_fingerprint'], policy['B_fingerprint']
    if receipt['self_fingerprint'] != policy[result['role'] + '_fingerprint']:
        failures.add('self_fingerprint_role_mismatch')
    if receipt['planned_A_fingerprint'] != a or receipt['planned_B_fingerprint'] != b:
        failures.add('planned_fingerprint_mismatch')
    if receipt['env_id'] != policy['env_id'] or receipt['project'] != policy['project'] or receipt['environment'] != policy['environment']:
        failures.add('environment_mismatch')
    if roster(receipt['members']) != roster(policy['expected_members']):
        failures.add('unexpected_member_present')
    if not receipt['writes_paused_for_check']:
        failures.add('writes_not_paused')
    try:
        checked = moment(result['checked_at'])
        paused = moment(receipt['writes_paused_since'])
        times = [moment(s['sampled_at']) for s in receipt['status_samples']]
        if any(not -30 <= (now - t).total_seconds() <= 600 for t in [checked, *times]):
            failures.add('stale_or_future_evidence')
        if (times[1] - times[0]).total_seconds() < 5 or paused > times[0] or any(not -30 <= (checked - t).total_seconds() <= 600 for t in times):
            failures.add('invalid_sampling_interval')
    except ValueError:
        failures.add('invalid_utc_time')
    for sample in receipt['status_samples']:
        if sample['rejected_commits']:
            failures.add('rejected_commits_nonzero')
        if sample['skipped_ops'] or sample['pending_deferred']:
            failures.add('unresolved_team_state')
        if set(sample['vector']) - roster(policy['expected_members']).keys():
            failures.add('unknown_vector_author')
        total = sum(sample['vector'].values())
        if total <= 0 or sample['commits_folded'] != total:
            failures.add('invalid_vector_count')
    if receipt['status_samples'][0]['vector'] != receipt['status_samples'][1]['vector']:
        failures.add('unstable_vector')
    return sorted(failures)


def installation_failures(result, now, expected_artifact):
    schema_check(expected_artifact, 'artifact')
    schema_check(result, 'install')
    failures = set(result['failed_checks'])
    if result['install_isolation_confirmed'] is not True:
        failures.add('installation_isolation_unconfirmed')
    if result['result'] != 'pass':
        failures.add('installation_not_pass')
    if result['version'] != '0.1.0' or result['all_five_binaries_present'] is not True or result['brew_test_exit'] != 0 or result['demo_exit'] != 0 or result['demo_checks'] != 47:
        failures.add('installation_checks_failed')
    if result['action'] in ['install', 'reinstall'] and result['install_exit'] != 0:
        failures.add('installation_exit_failed')
    if result['action'] == 'verify_existing' and result['install_exit'] is not None:
        failures.add('unexecuted_install_exit')
    if result['action'] == 'none':
        failures.add('installation_action_missing')
    artifact = result['artifact_receipt']
    if artifact != expected_artifact:
        failures.add('artifact_identity_mismatch')
    if artifact is None or artifact['tap_commit'] is None or artifact['archive_sha256'] != '7f7218e467f2f913e73bbc20785caeb96bc9f63a916fdca4e217abcdd37deef9':
        failures.add('artifact_identity_unverified')
    try:
        if not -30 <= (now - moment(result['checked_at'])).total_seconds() <= 600:
            failures.add('stale_or_future_evidence')
    except ValueError:
        failures.add('invalid_utc_time')
    return sorted(failures)


def compare(a, b, policy, now):
    policy_check(policy)
    failures = set(local_failures(a, policy, now) + local_failures(b, policy, now))
    if a['role'] != 'A' or b['role'] != 'B':
        failures.add('role_mismatch')
    ar, br = a['human_receipt'], b['human_receipt']
    members = bool(ar and br and roster(ar['members']) == roster(br['members']) == roster(policy['expected_members']))
    vectors = bool(ar and br and ar['status_samples'][1]['vector'] == br['status_samples'][1]['vector'])
    env = ar['env_id'] if ar and br and ar['env_id'] == br['env_id'] else None
    if not members:
        failures.add('members_mismatch')
    if not vectors:
        failures.add('vectors_mismatch')
    if env is None:
        failures.add('environment_mismatch')
    if not ar or not br or (ar['verification_session_id'], ar['writes_paused_since']) != (br['verification_session_id'], br['writes_paused_since']):
        failures.add('verification_session_mismatch')
    readonly = all(r['checks']['readonly_request_exit'] == 0 and r['checks']['service_http_status'] == policy['probe']['expected_http_status'] and r['checks']['expected_response'] == 'pass' for r in [a, b])
    result = {'schema': 'zeropw-onboarding-pair/2', 'result': 'blocked' if failures else 'ready', 'env_id': env, 'members_match': members, 'vectors_match': vectors, 'readonly_requests_passed': readonly, 'credential_class': policy['credential_class'], 'isolation_confirmed': policy['isolation_confirmed'], 'receipt_source': 'human_reported', 'failed_checks': sorted(failures), 'human_next_actions': REJECTION_ACTIONS if 'rejected_commits_nonzero' in failures else (['review_evidence_and_repeat'] if failures else [])}
    schema_check(result, 'pair')
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('mode', choices=['install', 'local', 'pair'])
    parser.add_argument('files', nargs='+')
    parser.add_argument('--policy')
    parser.add_argument('--artifact', help='Independently human-approved installation artifact receipt')
    parser.add_argument('--reported', help='Pair JSON from the model; compared to the computed result')
    args = parser.parse_args()
    try:
        now = datetime.now(timezone.utc)
        values = [read_json(p) for p in args.files]
        if args.mode == 'install' and len(values) == 1 and args.artifact and not args.reported:
            errors = installation_failures(values[0], now, read_json(args.artifact))
            result = {'result': 'blocked' if errors else 'pass', 'failed_checks': errors}
        elif args.mode == 'local' and len(values) == 1 and args.policy and not args.reported:
            policy = read_json(args.policy)
            policy_check(policy)
            errors = local_failures(values[0], policy, now)
            result = {'result': 'blocked' if errors else 'pass', 'failed_checks': errors}
        elif args.mode == 'pair' and len(values) == 2 and args.policy:
            result = compare(*values, read_json(args.policy), now)
            if args.reported:
                reported = read_json(args.reported)
                schema_check(reported, 'pair')
                if reported != result:
                    result['result'] = 'blocked'
                    result['failed_checks'] = sorted(set(result['failed_checks']) | {'reported_pair_mismatch'})
                    if not result['human_next_actions']:
                        result['human_next_actions'] = ['review_evidence_and_repeat']
            errors = result['failed_checks']
        else:
            raise ValueError('invalid_arguments')
        print(json.dumps(result, sort_keys=True))
        return 1 if errors else 0
    except (ValueError, TypeError, KeyError, OSError, RecursionError) as error:
        # Never echo untrusted input, paths or exception text that might contain
        # authentication material. Schema errors expose only fixed categories.
        code = str(error).split(':', 1)[0] if isinstance(error, ValueError) else 'invalid_input'
        if not re.fullmatch(r'[a-z_]+', code):
            code = 'invalid_input'
        print(json.dumps({'result': 'blocked', 'failed_checks': [code]}))
        return 1


if __name__ == '__main__':
    sys.exit(main())
