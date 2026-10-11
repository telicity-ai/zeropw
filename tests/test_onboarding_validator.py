import copy
from datetime import datetime, timezone
import importlib.util
import json
from pathlib import Path
import tempfile
import subprocess
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('onboarding', ROOT / 'scripts/validate-onboarding.py')
v = importlib.util.module_from_spec(spec)
spec.loader.exec_module(v)
NOW = datetime(2026, 10, 11, 12, 0, 20, tzinfo=timezone.utc)
A, B, C = 'a' * 26, 'b' * 26, 'c' * 26
ARTIFACT = {'release_tag': 'v0.1.0', 'archive_sha256': '7f7218e467f2f913e73bbc20785caeb96bc9f63a916fdca4e217abcdd37deef9', 'tap_commit': 'd' * 40, 'source': 'human_verified_release', 'formula_sha256': 'f01165bea5b6dfadfcdb57b3ed7f82eaa91478f026e7354df2663c45dd79bf2d'}
MEMBERS = [{'fingerprint': A, 'role': 'admin', 'status': 'active', 'owner': True}, {'fingerprint': B, 'role': 'user', 'status': 'active', 'owner': False}]
PROBE = {'method': 'GET', 'path': '/v1/items', 'expected_http_status': 200, 'expected_response_rule': 'items_array'}
POLICY = {'env_id': A + '-' + 'e' * 32, 'A_fingerprint': A, 'B_fingerprint': B, 'B_role': 'user', 'expected_members': MEMBERS, 'project': 'team-app', 'environment': 'dev', 'connection_id': 'service-api', 'probe': PROBE, 'credential_class': 'synthetic', 'isolation_confirmed': False, 'artifact_receipts': {'A': ARTIFACT, 'B': ARTIFACT}}


def local(role):
    samples = [{'sampled_at': t, 'vector': {A: 5}, 'commits_folded': 5, 'skipped_ops': 0, 'rejected_commits': 0, 'pending_deferred': 0} for t in ['2026-10-11T12:00:00Z', '2026-10-11T12:00:05Z']]
    return copy.deepcopy({'schema': 'zeropw-onboarding-check/2', 'role': role, 'checked_at': '2026-10-11T12:00:10Z', 'version': '0.1.0', 'version_evidence': 'brew', 'artifact_receipt': ARTIFACT, 'observed_tap_commit': ARTIFACT['tap_commit'], 'observed_formula_sha256': ARTIFACT['formula_sha256'], 'installed_tap_commit': ARTIFACT['tap_commit'], 'installed_spec': 'stable', 'binaries_resolve_to_keg': True, 'credential_class': 'synthetic', 'isolation_confirmed': False, 'local_result': 'pass', 'team_result': 'pending_peer', 'checks': {'agent_binary': 'pass', 'runtime_config_present': 'pass', 'connection_visible': 'pass', 'readonly_request_exit': 0, 'service_http_status': 200, 'expected_response': 'pass'}, 'connection_id': 'service-api', 'probe': PROBE, 'human_receipt': {'env_id': A + '-' + 'e' * 32, 'project': 'team-app', 'environment': 'dev', 'self_fingerprint': A if role == 'A' else B, 'planned_A_fingerprint': A, 'planned_B_fingerprint': B, 'writes_paused_for_check': True, 'members': MEMBERS, 'status_samples': samples, 'verification_session_id': 'session-1', 'writes_paused_since': '2026-10-11T11:59:59Z'}, 'receipt_source': 'human_reported', 'failed_checks': [], 'human_next_actions': []})


class ValidatorTests(unittest.TestCase):
    def blocked(self, a, b, policy=None, code=None):
        try:
            result = v.compare(a, b, copy.deepcopy(POLICY) if policy is None else policy, NOW)
            self.assertEqual(result['result'], 'blocked')
            self.assertTrue(result['failed_checks'])
            if code: self.assertIn(code, result['failed_checks'])
        except ValueError as error:
            if code: self.assertEqual(str(error).split(':')[0], code)
            else: raise

    def test_positive_synthetic_is_labeled(self):
        result = v.compare(local('A'), local('B'), POLICY, NOW)
        self.assertEqual(result['result'], 'ready')
        self.assertEqual(result['credential_class'], 'synthetic')
        self.assertFalse(result['isolation_confirmed'])

    def test_boundary_matrix(self):
        # Mutations represent contradictory or forged metadata, never live state.
        for field, value in [('local_result', 'blocked'), ('version', 'unknown'), ('version_evidence', 'unknown'), ('failed_checks', ['prior_failure']), ('artifact_receipt', None), ('isolation_confirmed', True), ('credential_class', 'real'), ('connection_id', 'other'), ('checked_at', None), ('checked_at', '2026-10-11T11:49:00Z'), ('checked_at', '2026-10-11T12:01:00Z'), ('checked_at', '2026-10-11T12:00:10+00:00')]:
            with self.subTest(field=field, value=value):
                b = local('B'); b[field] = value; self.blocked(local('A'), b, code={'local_result':'local_result_not_pass','version':'version_unverified','version_evidence':'version_unverified','failed_checks':'prior_failure','artifact_receipt':'artifact_identity_unverified','isolation_confirmed':'execution_context_mismatch','credential_class':'execution_context_mismatch','connection_id':'probe_mismatch','checked_at':('invalid_utc_time' if value is None else ('schema_type' if '+' in str(value) else 'stale_or_future_evidence'))}[field])
        for field, value in [('readonly_request_exit', True), ('readonly_request_exit', '0'), ('readonly_request_exit', 1), ('service_http_status', 401), ('expected_response', 'unknown'), ('connection_visible', 'failed')]:
            with self.subTest(check=field, value=value):
                b = local('B'); b['checks'][field] = value; self.blocked(local('A'), b, code='schema_type' if type(value) in [str,bool] and field=='readonly_request_exit' else 'readonly_request_unverified')
        for field, value in [('self_fingerprint', A), ('planned_A_fingerprint', C), ('project', 'other'), ('env_id', 'different'), ('writes_paused_for_check', False), ('verification_session_id', 'different'), ('writes_paused_since', '2026-10-11T12:00:01Z')]:
            with self.subTest(receipt=field):
                b = local('B'); b['human_receipt'][field] = value; self.blocked(local('A'), b, code={'self_fingerprint':'self_fingerprint_role_mismatch','planned_A_fingerprint':'planned_fingerprint_mismatch','project':'environment_mismatch','env_id':'environment_mismatch','writes_paused_for_check':'writes_not_paused','verification_session_id':'verification_session_mismatch','writes_paused_since':'invalid_sampling_interval'}[field])
        for field, value in [('rejected_commits', 1), ('skipped_ops', 1), ('pending_deferred', 1), ('commits_folded', 4), ('vector', {A: 6}), ('vector', {A: 0}), ('vector', {}), ('vector', {A: True}), ('sampled_at', '2026-10-11T12:00:02Z')]:
            with self.subTest(sample=field, value=value):
                b = local('B'); b['human_receipt']['status_samples'][1][field] = value; self.blocked(local('A'), b, code={'rejected_commits':'rejected_commits_nonzero','skipped_ops':'unresolved_team_state','pending_deferred':'unresolved_team_state','commits_folded':'invalid_vector_count','vector': 'schema_type' if isinstance(value,dict) and (not value or any(type(n) is bool for n in value.values())) else 'invalid_vector_count', 'sampled_at':'invalid_sampling_interval'}[field])

    def test_matching_extra_member_is_not_authorized(self):
        a, b = local('A'), local('B')
        extra = {'fingerprint': C, 'role': 'admin', 'status': 'active', 'owner': False}
        for r in [a, b]: r['human_receipt']['members'].append(extra)
        self.blocked(a, b, code='unexpected_member_present')

    def test_duplicate_and_extra_owner(self):
        for extra in [MEMBERS[0], {'fingerprint': C, 'role': 'admin', 'status': 'active', 'owner': True}]:
            a, b = local('A'), local('B')
            for r in [a, b]: r['human_receipt']['members'].append(extra)
            self.blocked(a, b, code='duplicate_member' if extra == MEMBERS[0] else 'unexpected_member_present')

    def test_approved_additional_member_allowed(self):
        a, b, p = local('A'), local('B'), copy.deepcopy(POLICY)
        extra = {'fingerprint': C, 'role': 'user', 'status': 'active', 'owner': False}
        for r in [a, b]: r['human_receipt']['members'].append(extra)
        p['expected_members'].append(extra)
        self.assertEqual(v.compare(a, b, p, NOW)['result'], 'ready')

    def test_input_injection_and_paths(self):
        for path in ['//host/x', '/a/../b', '/a%2e%2e', "/x';id", '/x$(id)', '/x?token=secret', '/x\\y', '/x\ny', 'https://host/x']:
            with self.subTest(path=path):
                a,b,p = local('A'),local('B'),copy.deepcopy(POLICY)
                for item in [a,b,p]: item['probe']['path'] = path
                self.blocked(a, b, p, code='invalid_probe_input')

    def test_real_requires_isolation(self):
        p = copy.deepcopy(POLICY); p['credential_class'] = 'real'
        a,b=local('A'),local('B')
        for item in [a,b]: item['credential_class']='real'
        self.blocked(a, b, p, code='production_isolation_unconfirmed')

    def test_changed_session_and_short_sampling(self):
        b = local('B'); b['human_receipt']['status_samples'][1]['sampled_at'] = '2026-10-11T12:00:04Z'
        self.blocked(local('A'), b, code='invalid_sampling_interval')
        b=local('B');b['human_receipt']['verification_session_id']='another-session'
        self.blocked(local('A'),b,code='verification_session_mismatch')

    def test_strict_json_and_unknown_fields(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / 'input.json'
            for text in ['{"schema":1,"schema":2}', '{"value":NaN}', '```json\n{}\n```', '{} trailing']:
                p.write_text(text)
                with self.assertRaises(ValueError): v.read_json(p)
        b = local('B'); b['execution_details'] = 'secret'
        self.blocked(local('A'), b, code='schema_extra')
        with self.assertRaises(ValueError): v.validate({}, {'type': 'object', 'unsupported': True})

    def test_installation_false_pass_and_provenance(self):
        r = {'schema': 'zeropw-install-check/2', 'install_isolation_confirmed': True, 'checked_at': '2026-10-11T12:00:10Z', 'artifact_receipt': ARTIFACT, 'observed_tap_commit': ARTIFACT['tap_commit'], 'observed_formula_sha256': ARTIFACT['formula_sha256'], 'installed_tap_commit': ARTIFACT['tap_commit'], 'installed_spec': 'stable', 'binaries_resolve_to_keg': True, 'version': '0.1.0', 'action': 'reinstall', 'result': 'pass', 'all_five_binaries_present': True, 'install_exit': 0, 'brew_test_exit': 0, 'demo_exit': 0, 'demo_checks': 47, 'failed_checks': [], 'human_next_actions': []}
        self.assertEqual(v.installation_failures(r, NOW, ARTIFACT), [])
        for key, value in [('failed_checks', ['clock_failed']), ('brew_test_exit', 1), ('demo_checks', 46), ('artifact_receipt', None), ('install_exit', None), ('install_isolation_confirmed', False), ('observed_tap_commit', 'e'*40), ('observed_formula_sha256', 'f'*64), ('installed_tap_commit','e'*40), ('installed_spec','head'), ('binaries_resolve_to_keg',False)]:
            bad = copy.deepcopy(r); bad[key] = value
            expected={'failed_checks':'clock_failed','brew_test_exit':'installation_checks_failed','demo_checks':'installation_checks_failed','artifact_receipt':'artifact_identity_unverified','install_exit':'installation_exit_failed','install_isolation_confirmed':'installation_isolation_unconfirmed','observed_tap_commit':'artifact_identity_mismatch','observed_formula_sha256':'artifact_identity_mismatch','installed_tap_commit':'artifact_identity_unverified','installed_spec':'artifact_identity_unverified','binaries_resolve_to_keg':'artifact_identity_unverified'}[key]
            self.assertIn(expected,v.installation_failures(bad, NOW, ARTIFACT))
        for field,value in [('tap_commit',None),('formula_sha256',None),('archive_sha256','c8c48db2dab796790248115cc74b366c5be7ecba3bb9c40db9b308697297ac75')]:
            bad=copy.deepcopy(r);approved=copy.deepcopy(ARTIFACT)
            bad['artifact_receipt'][field]=value;approved[field]=value
            if field=='tap_commit':bad['observed_tap_commit']=None;bad['installed_tap_commit']=None
            if field=='formula_sha256':bad['observed_formula_sha256']=None
            self.assertEqual(v.installation_failures(bad,NOW,approved),['artifact_identity_unverified'])
        existing=copy.deepcopy(r);existing['action']='verify_existing';existing['install_exit']=None
        self.assertEqual(v.installation_failures(existing,NOW,ARTIFACT),['artifact_identity_unverified'])
        bad = copy.deepcopy(r); bad['brew_test_exit'] = True
        with self.assertRaises(ValueError): v.installation_failures(bad, NOW, ARTIFACT)


    def test_vector_authors_must_be_approved(self):
        a,b=local('A'),local('B')
        for result in [a,b]:
            for sample in result['human_receipt']['status_samples']:
                sample['vector']={C:5}
        self.blocked(a,b,code='unknown_vector_author')

    def test_provenance_and_connection_flags(self):
        b=local('B');b['artifact_receipt']['tap_commit']=None
        p=copy.deepcopy(POLICY);p['artifact_receipts']['B']['tap_commit']=None
        self.blocked(local('A'),b,p,code='artifact_identity_unverified')
        for identifier in ['-h','--method','..','.']:
            a,b,p=local('A'),local('B'),copy.deepcopy(POLICY)
            for x in [a,b,p]:x['connection_id']=identifier
            self.blocked(a,b,p,code='schema_pattern')

    def test_unicode_time_and_rejection_actions(self):
        b=local('B');b['checked_at']='２０２６-10-11T12:00:10Z'
        self.blocked(local('A'),b,code='schema_type')
        b=local('B');b['human_receipt']['status_samples'][0]['rejected_commits']=1
        result=v.compare(local('A'),b,POLICY,NOW)
        self.assertIn('rejected_commits_nonzero',result['failed_checks'])
        self.assertEqual(result['human_next_actions'],v.REJECTION_ACTIONS)

    def test_cli_exit_sanitization_and_reported_mismatch(self):
        from datetime import timedelta
        with tempfile.TemporaryDirectory() as directory:
            d=Path(directory);a,b=local('A'),local('B');now=datetime.now(timezone.utc).replace(microsecond=0)
            for result in [a,b]:
                result['checked_at']=now.strftime('%Y-%m-%dT%H:%M:%SZ')
                result['human_receipt']['writes_paused_since']=(now-timedelta(seconds=10)).strftime('%Y-%m-%dT%H:%M:%SZ')
                for sample,seconds in zip(result['human_receipt']['status_samples'],[9,3]):sample['sampled_at']=(now-timedelta(seconds=seconds)).strftime('%Y-%m-%dT%H:%M:%SZ')
            for name,value in [('A',a),('B',b),('policy',POLICY)]: (d/(name+'.json')).write_text(json.dumps(value))
            command=[sys.executable,str(ROOT/'scripts/validate-onboarding.py'),'pair',str(d/'A.json'),str(d/'B.json'),'--policy',str(d/'policy.json')]
            run=subprocess.run(command,capture_output=True,text=True)
            self.assertEqual(run.returncode,0);computed=json.loads(run.stdout);self.assertEqual(computed['result'],'ready')
            computed['vectors_match']=False;(d/'reported.json').write_text(json.dumps(computed))
            run=subprocess.run(command+['--reported',str(d/'reported.json')],capture_output=True,text=True)
            self.assertEqual(run.returncode,1);out=json.loads(run.stdout);self.assertEqual(out['result'],'blocked');self.assertTrue(out['vectors_match']);self.assertIn('reported_pair_mismatch',out['failed_checks'])
            # The computed original cause is retained alongside model mismatch.
            b['human_receipt']['status_samples'][0]['rejected_commits']=1;(d/'B.json').write_text(json.dumps(b))
            run=subprocess.run(command+['--reported',str(d/'reported.json')],capture_output=True,text=True)
            out=json.loads(run.stdout);self.assertIn('rejected_commits_nonzero',out['failed_checks']);self.assertIn('reported_pair_mismatch',out['failed_checks'])
            (d/'B.json').write_text('{"sensitive-secret":invalid-json}')
            run=subprocess.run(command,capture_output=True,text=True)
            self.assertEqual(run.returncode,1);self.assertNotIn('sensitive-secret',run.stdout+run.stderr);self.assertEqual(json.loads(run.stdout)['result'],'blocked')


    def test_homebrew_local_keg_binding(self):
        for field,value in [('installed_tap_commit','e'*40),('installed_spec','head'),('installed_spec',None),('binaries_resolve_to_keg',False),('binaries_resolve_to_keg',None)]:
            b=local('B');b[field]=value
            self.blocked(local('A'),b,code='artifact_identity_unverified')


if __name__ == '__main__':
    unittest.main()
