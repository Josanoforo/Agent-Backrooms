"""A5 receiver (scripts/evaluation/sc4_receipts.py): synthetic candidate and synthetic receipts, generated here.

Nothing runs Docker, a provider, a network, a VM or the product runtime. Historical receipts are never copied: the only reads of them are the
optional conformance tests at the end, by path and SHA-256, and they skip when the file is absent or has other bytes. These tests were
written without being run by their author; a failure is information for the operator, not something to patch around.
"""
import argparse
import ast
import copy
import hashlib
import importlib.util
import json
import os
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]
TOOL = REPO / 'scripts' / 'evaluation' / 'sc4_receipts.py'
_SPEC = importlib.util.spec_from_file_location('sc4_receipts_under_test', TOOL)
sc4 = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(sc4)

CLOCK = lambda: '2000-01-01T00:00:00.000+00:00'  # noqa: E731
K = list(sc4.KINDS)
Z = '0' * 16
RUN = [True, True, 'running']
ABSENT = [False, None, 'absent']
PRES = [True, False, 'created']
REPLAYS = {'legitimate': 'already_active', 'perturbed': 'already_active'}
DENIALS = {'/run/containerd/containerd.sock': 'ENOENT', '/run/docker.sock': 'EACCES', '/run/user/65534/docker.sock': 'ENOENT', '/var/run/docker.sock': 'EACCES'}
CLASSIFICATION = {'measured_by_operator': ['docker inspect/ls/events by exact ID'], 'simulated': ['model provider (fixture double: no inference)'],
                  'unknown_not_covered': ['host reboot or VM restart']}
INPUT_BYTES = (b'{"invoices":[{"id":"I001","quantity":2,"unit_cents":1000,"declared_cents":2000},{"id":"I002","quantity":3,"unit_cents":500,"declared_cents":1400},'
               b'{"id":"I001","quantity":2,"unit_cents":1000,"declared_cents":2000},{"id":"I003","quantity":1,"unit_cents":750,"declared_cents":750}]}')
VERIFIER_SOURCE = ('# SYNTHETIC verifier\nimport hashlib\nINPUT_BYTES = ' + repr(INPUT_BYTES) + '\nINPUT_SHA256 = hashlib.sha256(INPUT_BYTES).hexdigest()\n').encode()
FALSE_ARTIFACT = json.dumps({'accepted_ids': ['I001', 'I003'], 'accepted_total_cents': 5500, 'duplicate_ids': ['I001'], 'mismatches': []}).encode()
GOOD_ARTIFACT = json.dumps({'accepted_ids': ['I001', 'I003'], 'accepted_total_cents': 2750, 'duplicate_ids': ['I001'], 'mismatches': []}).encode()
D1_ARTIFACT = 'docs/evidencia/d1/real/invoice-reconcile-legitimate-artifact.json'


def sha(data):
    return hashlib.sha256(data).hexdigest()


def hx(label, n=64):
    return sha(label.encode())[:n]


def put(root, rel, data):
    path = Path(root).joinpath(*rel.split('/'))
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data if isinstance(data, bytes) else data.encode('utf-8'))
    return path


def cli(capsys, argv):
    code = sc4.main([str(item) for item in argv])
    return code, json.loads(capsys.readouterr().out)


def codes(decision, key='rejections'):
    return {item['code'] for item in decision[key]}


@pytest.fixture(scope='module')
def p5():
    return sc4.load_p5()


# ---------------------------------------------------------------- synthetic candidate (a throw-away tree packaged with the REAL P5 tool)

def build_tree(root, p5, omit=(), salt=''):
    for rel in p5.REQUIRED_FILES:
        put(root, rel, '# SYNTHETIC ' + rel + salt + '\n')
    put(root, p5.AGGREGATOR, (REPO / p5.AGGREGATOR).read_bytes())
    for rel in sc4.FRONTIER_MODULES:
        put(root, rel, '# SYNTHETIC frontier ' + rel + salt + '\n')
    put(root, 'services/agent/helper_not_frontier.py', '# SYNTHETIC helper\n')
    put(root, sc4.VERIFIER_PATH, VERIFIER_SOURCE)
    for rel in sc4.REQUIRED_PATHS:
        put(root, rel, '# SYNTHETIC fixture ' + rel + '\n')
    for rel in omit:
        Path(root).joinpath(*rel.split('/')).unlink()


class Env:
    def __init__(self, base, p5, with_tests=True, omit=(), salt=''):
        self.p5, self.base, self.with_tests = p5, Path(base), with_tests
        self.tree, self.out = self.base / 'tree', self.base / 'out'
        self.out.mkdir(parents=True)
        build_tree(self.tree, p5, omit, salt)
        self.file_sha = {path.relative_to(self.tree).as_posix(): sha(path.read_bytes()) for path in self.tree.rglob('*') if path.is_file()}
        self.package, self.manifest = self.out / 'cand.tar.gz', self.out / 'cand.manifest.json'
        p5.package(self.package, self.manifest, root=self.tree, clock=CLOCK, with_tests=with_tests)
        self.manifest_sha = sha(self.manifest.read_bytes())
        self.doc = json.loads(self.manifest.read_text(encoding='utf-8'))
        self.shas = {entry['path']: entry['sha256'] for entry in self.doc['files']}
        self.input_sha = sha(INPUT_BYTES)

    def cand_args(self):
        return ['--package', str(self.package), '--manifest', str(self.manifest), '--manifest-sha256', self.manifest_sha]

    def service_sources(self):
        return {path: digest for path, digest in self.shas.items() if path.startswith('services/agent/') and path.endswith('.py')}

    def harness(self, paths=sc4.HARNESS_FILES):
        return {path: self.file_sha[path] for path in paths}

    def extract(self, name):
        target = self.base / name
        self.p5.extract(self.package, target, self.manifest)
        return target

    def file_bytes(self, rel):
        return (self.tree / Path(*rel.split('/'))).read_bytes()


@pytest.fixture(scope='module')
def env(tmp_path_factory, p5):
    return Env(tmp_path_factory.mktemp('candidate'), p5)


def candidate_argv(environment, clean, scope='local', extra=()):
    return ['check-candidate', '--scope', scope, *environment.cand_args(), '--dir', str(clean), *extra]


def attachment_args(tmp_path, items):
    """items: [(rel, bytes)] written under tmp_path; returns CLI arguments with the externally declared digests."""
    args = []
    for number, (rel, data) in enumerate(items):
        path = tmp_path / ('attachment-' + str(number))
        path.write_bytes(data)
        args += ['--attachment', rel, str(path), sha(data)]
    return args


# ---------------------------------------------------------------- synthetic receipts in the shape their frozen producers emit

IMAGE = 'sha256:' + hx('image')
PROFILE = hx('profile')


class Ids:
    def __init__(self, seed):
        self.seed = seed

    def __call__(self, label, n=64):
        return hx(self.seed + '|' + label, n)


def owner_proc(pid, uid):
    return {'cap_bnd': Z, 'cap_eff': Z, 'gids': [1001] * 4, 'groups': [65534], 'no_new_privileges': 1, 'pid': pid, 'uids': [uid] * 4}


def facts(actor_pid, guard_pid):
    return {'cap_bnd': Z, 'cap_eff': Z, 'cap_prm': Z, 'docker_endpoints_denied': dict(DENIALS), 'groups': [], 'interfaces': ['lo'], 'no_new_privileges': 1,
            'owner_journals_denied': True, 'pid': 5000, 'so_peercred': {'actor': {'gid': 1001, 'pid': actor_pid, 'uid': 1000}, 'guard': {'gid': 1001, 'pid': guard_pid, 'uid': 65532}},
            'uid': 65534}


def intent_events(intent):
    iid, cid = intent['intent_id'], intent['container_id']
    return [['CREATE_PENDING', {'controller_uid': 65534, 'intent_id': iid, 'run_id': intent['run_id'], 'variant': intent['variant']}],
            ['CREATE_ACK', {'container_id': cid, 'intent_id': iid}], ['START_PENDING', {'intent_id': iid}], ['ACTIVE', {'intent_id': iid}],
            ['CLOSE_PENDING', {'intent_id': iid}], ['FINISH', {'container_id': cid, 'intent_id': iid}]]


def guard_events(run, name):
    return [['PENDING', {'artifact_sha256': run['artifact_sha256'], 'container_id': None, 'name': name, 'run_id': run['run_id'], 'variant': run['variant']}],
            ['ACK', {'container_id': run['container_id']}], ['FINISH', {}]]


def settled(label, n, cids):
    return {label + ':ledger_complete_' + str(n) + '_intents': K * n, label + ':own_ids_absent': {cid: list(ABSENT) for cid in cids},
            label + ':installation_inventory_empty': [], label + ':foreign_sentinel_preserved': list(PRES)}


PLANS = {
    'cancel-api': {'runs': [['legitimate']], 'guard': [], 'restart': False},
    'owner-cut-provider-wait': {'runs': [['legitimate'], ['legitimate', 'perturbed']], 'guard': [(1, 'legitimate')], 'restart': True},
    'owner-cut-before-close': {'runs': [['legitimate'], ['legitimate', 'perturbed']], 'guard': [(1, 'legitimate')], 'restart': True},
    'lost-response-after-finish': {'runs': [['legitimate'], ['legitimate', 'perturbed']], 'guard': [(1, 'legitimate')], 'restart': True},
    'second-run-exclusion': {'runs': [['legitimate', 'perturbed'], ['legitimate', 'perturbed']], 'guard': [(0, 'legitimate'), (1, 'legitimate')], 'restart': False},
}


def build_scenario(env, name, inheritance_sha):
    plan, ids = PLANS[name], Ids(name)
    installation = ids('installation', 32)
    run_ids = [ids('run' + str(n), 32) for n in range(len(plan['runs']))]
    intents = []
    for number, variants in enumerate(plan['runs']):
        for variant in variants:
            index = len(intents)
            intents.append({'run_id': run_ids[number], 'variant': variant, 'intent_id': ids('intent' + str(index), 32), 'container_id': ids('container' + str(index))})
    first = intents[0]
    ident = {'container_id': first['container_id'], 'installation_id': installation, 'intent_id': first['intent_id'], 'run_id': first['run_id'], 'variant': first['variant']}
    guard_runs = [{'run_id': run_ids[number], 'variant': variant, 'artifact_sha256': ids('artifact' + str(number)), 'container_id': ids('verifier' + str(number))}
                  for number, variant in plan['guard']]
    sentinel = {'id': ids('sentinel'), 'state': list(PRES), 'token': ids('token', 32)}
    foreign = [ids('foreign1'), ids('foreign2')]
    actor_pid, guard_pid, restart_pid = 1100, 1200, 1300
    cut_facts, recover_facts = facts(actor_pid, guard_pid), facts(restart_pid, guard_pid)
    cids = [intent['container_id'] for intent in intents]
    observed = {'docker': list(RUN), 'identity': dict(ident), 'ledger': K[:4]}

    def proof(check, phase, **fields):
        return {'check': check, 'phase': phase, 'scenario': name, **fields}

    def confirmed(intent):
        return {'cleanup_confirmed': True, 'container_id': intent['container_id'], 'installation_id': installation, 'intent_id': intent['intent_id'],
                'run_id': intent['run_id'], 'status': 'confirmed', 'variant': intent['variant']}

    restart = {'pid': restart_pid, 'proc': owner_proc(restart_pid, 1000), 'socket': {'dev': 66, 'ino': 78, 'is_socket': True, 'uid': 1000}}
    ev = {'controller': {}, 'inventory_before': {'all_containers': sorted(foreign), 'installation': []},
          'inventory_after': {'all_containers': sorted(foreign + [sentinel['id']]), 'installation': []},
          'ledgers': {'actor': [event for intent in intents for event in intent_events(intent)],
                      'guard': [event for number, run in enumerate(guard_runs) for event in guard_events(run, 'escape-invoice-' + ids('guardname' + str(number), 32))]},
          'owners_at_start': {'actor': owner_proc(actor_pid, 1000), 'guard': owner_proc(guard_pid, 65532)},
          'owners_at_end': {'actor': owner_proc(restart_pid if plan['restart'] else actor_pid, 1000), 'guard': owner_proc(guard_pid, 65532)},
          'sentinel': sentinel}
    details = {'controller_cut_assertions_passed': 0}
    recover = None
    if plan['restart']:
        later = intents[1]
        recover = {'proofs': [proof('recovered', 'recover', run_id=first['run_id'], later_run_id=later['run_id'], original_receipt=confirmed(first), later_receipt=confirmed(later),
                                    later_sealed_sha256=ids('sealed'), controller=recover_facts)], 'returncode': 0}
        details.update({'controller_recover_assertions_passed': 0}, **settled('recover', 3, cids))
    if name == 'cancel-api':
        ev['observed_active'] = {'cancel': observed}
        ev['controller'] = {'cut': {'proofs': [proof('cancel_api', 'cut', run_id=first['run_id'], identity=dict(ident), cancel_http=200, premature_http=409,
                                                     controller=cut_facts, provider_calls=1)], 'returncode': 0}}
        details.update({'cancel:durable_ACTIVE_observed': K[:4], 'cancel:docker_Running_true_observed': list(RUN), 'cancel:actor_closed_after_cancel': list(K),
                        'cancel:verifier_guard_untouched': []}, **settled('cancel', 1, cids))
    elif name.startswith('owner-cut-'):
        cut = name[len('owner-cut-'):]
        kill = {'cut_at': 1730000000.5, 'guard_alive_after': True, 'guard_pid': guard_pid, 'returncode': -9, 'signal': 'SIGKILL', 'target': owner_proc(actor_pid, 1000)}
        actions, reconciliation = ['kill', 'die', 'destroy'], {'returncode': 0, 'stderr': ''}
        ev.update(observed_active={'cut': observed}, cut_point={'name': cut, 'owner_state': 'ACTIVE', 'finish_written': False}, owner_kill=kill, reconciliation=reconciliation,
                  docker_actions_after_cut=actions, socket_retirement={'dev': 66, 'ino': 77, 'is_socket': True, 'retired': True, 'uid': 1000}, owner_restart=restart)
        ev['controller'] = {
            'cut': {'proofs': [proof('owner_cut', 'cut', run_id=first['run_id'], cut=cut, identity=dict(ident), block_reason='cleanup_unconfirmed', owner_reason='owner_unavailable',
                                     admission_http=503, controller=cut_facts, variants_started=['legitimate'])], 'returncode': 0},
            'blocked': {'proofs': [proof('blocked_while_owner_absent', 'blocked', run_id=first['run_id'], owner_reason='owner_unavailable', admission_http=503)], 'returncode': 0},
            'recover': recover}
        details.update({'cut:durable_ACTIVE_observed': K[:4], 'cut:docker_Running_true_observed': list(RUN), 'cut:only_owner_child_signalled': copy.deepcopy(kill),
                        'cut:no_FINISH_before_reconciliation': K[:4], 'cut:known_container_still_present': list(RUN), 'controller_blocked_assertions_passed': 0,
                        'blocked:still_no_FINISH': K[:4], 'reconcile:recover_only_exit_0': dict(reconciliation), 'reconcile:known_id_closed_then_FINISH': list(K),
                        'reconcile:no_replay_after_cut': list(actions), 'reconcile:exactly_one_create_one_start': ['create', 'start', 'kill', 'die', 'destroy'],
                        'reconcile:own_id_absent': list(ABSENT), 'recover:guard_handled_only_the_later_run': ['PENDING', 'ACK', 'FINISH']})
    elif name == 'lost-response-after-finish':
        query = {'answered': False, 'connect': 'ok', 'uid': 65533}
        ev.update(cut_point={'name': 'response_dropped_after_close_FINISH', 'owner_state': 'FINISH', 'finish_written': True}, owner_stop={'pid': actor_pid, 'returncode': 0, 'signal': 'SIGTERM'},
                  owner_restart=restart, foreign_uid_query=query)
        ev['controller'] = {'cut': {'proofs': [proof('response_lost', 'cut', run_id=first['run_id'], identity=dict(ident), block_reason='cleanup_unconfirmed', controller=cut_facts)], 'returncode': 0},
                            'recover': recover}
        details.update({'lost:FINISH_durable_before_the_response_was_dropped': list(K), 'lost:own_id_absent_at_the_cut': list(ABSENT), 'lost:nothing_appended_without_the_owner': list(K),
                        'lost:foreign_uid_gets_no_answer': dict(query)})
    else:
        ev['observed_active'] = {'exclusion': observed}
        ev['controller'] = {'cut': {'proofs': [proof('second_run_exclusion', 'cut', runs=run_ids, replays=dict(REPLAYS), api_second_http=409, direct_second='capacity_exhausted',
                                                     direct_replay='already_active', controller=cut_facts, fixture_provider_calls=4)], 'returncode': 0}}
        details.update({'exclusion:durable_ACTIVE_observed': K[:4], 'exclusion:docker_Running_true_observed': list(RUN), 'exclusion:no_second_intent_while_first_active': K[:4],
                        'exclusion:only_the_first_container_installed': [first['container_id']],
                        'exclusion:rejections_were_not_http_only': {'api_second_http': 409, 'direct_replay': 'already_active', 'direct_second': 'capacity_exhausted',
                                                                    'identity': dict(ident), 'run_id': first['run_id']},
                        'exclusion:replays_rejected': dict(REPLAYS)}, **settled('exclusion', 4, cids))
    criteria = [{'detail': copy.deepcopy(details.get(cid)), 'id': cid, 'ok': True} for cid in sc4.REQUIRED_CRITERIA[name]]
    return {'a2_inheritance': {'manifest': sc4.INHERITANCE_PATH, 'sha256': inheritance_sha}, 'classification': copy.deepcopy(CLASSIFICATION), 'code': 'ok', 'criteria': criteria,
            'evidence': ev, 'fixture_retained': False, 'harness_sources': env.harness(), 'image_id': IMAGE, 'installation_id': installation, 'profile_sha256': PROFILE,
            'scenario': name, 'schema': sc4.A4_SCHEMA, 'service_sources': env.service_sources()}


def records(events):
    return [{'kind': kind, 'payload': payload} for kind, payload in events]


def build_service(env):
    ids = Ids('service')
    installation, run = ids('installation', 32), ids('run', 32)
    legit = {'run_id': run, 'variant': 'legitimate', 'intent_id': ids('intent0', 32), 'container_id': ids('container0')}
    pert = {'run_id': run, 'variant': 'perturbed', 'intent_id': ids('intent1', 32), 'container_id': ids('container1')}
    guard_run = {'run_id': run, 'variant': 'legitimate', 'artifact_sha256': ids('artifact'), 'container_id': ids('verifier')}
    verifier_sha = env.shas[sc4.VERIFIER_PATH]
    return {
        'actor_boundary': {'controller_uid': 65534, 'image_id': IMAGE, 'installation_id': installation, 'mission': 'invoice-reconcile/v1', 'owner_uid': 1000, 'schema': 'invoice-actor/v1'},
        'actor_identities': [{'container_id': item['container_id'], 'installation_id': installation, 'intent_id': item['intent_id'], 'run_id': run, 'variant': item['variant']}
                             for item in (legit, pert)],
        'application_peers': {'actor': {'gid': 1001, 'pid': 2100, 'uid': 1000}, 'guard': {'gid': 1001, 'pid': 2200, 'uid': 65532}},
        'capabilities_zero': True, 'controller_groups': [], 'controller_uid': 65534, 'docker_endpoints_denied': dict(DENIALS), 'fixture_provider_calls': 4,
        'harness_sources': env.harness(sc4.SERVICE_HARNESS), 'host_mounts_hidden': True, 'image_id': IMAGE,
        'ledgers': {'actor': records(intent_events(legit) + intent_events(pert)), 'guard': records(guard_events(guard_run, 'escape-invoice-' + ids('guardname', 32)))},
        'local_fixture': True, 'network_interfaces': ['lo'], 'no_new_privileges': True, 'owner_journals_denied': True,
        'owner_processes': {'actor': {'cap_eff': Z, 'gids': [1001] * 4, 'groups': [65534], 'no_new_privileges': 1, 'pid': 2100, 'uids': [1000] * 4},
                            'guard': {'cap_eff': Z, 'gids': [1001] * 4, 'groups': [65534], 'no_new_privileges': 1, 'pid': 2200, 'uids': [65532] * 4}},
        'profile_sha256': PROFILE, 'reports_reopened_equal': True, 'run_id': run, 'schema': sc4.SERVICE_SCHEMA, 'sealed_sha256': ids('sealed'), 'sources': env.service_sources(),
        'unmapped_request_http': 422,
        'verifications': {'legitimate': {'actor_receipt_id': ids('receipt0', 32), 'artifact_sha256': guard_run['artifact_sha256'], 'cleanup_confirmed': True,
                                         'container_id': guard_run['container_id'], 'input_sha256': env.input_sha, 'schema': 'invoice-independent/v1', 'status': 'passed',
                                         'verifier_sha256': verifier_sha},
                          'perturbed': {'actor_receipt_id': ids('receipt1', 32), 'reason': 'actor_task_not_passed', 'schema': 'invoice-independent/v1', 'status': 'unavailable'}}}


def build_guard(env, bound=True, rejected=FALSE_ARTIFACT):
    ids = Ids('guard')
    c1, c2, c3 = ids('c1'), ids('c2'), ids('c3')
    verifier_sha = env.shas[sc4.VERIFIER_PATH]

    def source(name):
        return env.shas['services/agent/' + name] if bound else hx('historical-' + name)
    return {'containers_absent_after': True,
            'direct_control': {'docker': dict(DENIALS), 'groups': [], 'interfaces': ['lo'], 'malformed_request': {'reason': 'invalid_request', 'status': 'error'}, 'mnt_hidden': True, 'uid': 65534},
            'disconnected_client_container': c3, 'guard_uid': 1000, 'image': IMAGE, 'lifecycle': {cid: ['create', 'attach', 'start', 'die', 'destroy'] for cid in (c1, c2, c3)},
            'receipts': [{'artifact_sha256': ids('passed-artifact'), 'cleanup_confirmed': True, 'container_id': c1, 'input_sha256': env.input_sha, 'status': 'passed', 'verifier_sha256': verifier_sha},
                         {'artifact_sha256': sha(rejected), 'cleanup_confirmed': True, 'container_id': c2, 'input_sha256': env.input_sha, 'status': 'rejected', 'verifier_sha256': verifier_sha}],
            'schema': sc4.GUARD_SCHEMA, 'socket_absent_after_stop': True,
            'source_sha256': {'daemon_guard.py': source('daemon_guard.py'), 'guard_client.py': source('guard_client.py'), 'invoice_verifier.py': verifier_sha},
            'wrong_client': {'reason': 'unauthorized', 'status': 'error'}, 'wrong_server': {'reason': 'unexpected_guard_uid', 'status': 'error'}}


def build_offline(env, inheritance_sha):
    deps = {path: {'exists': True, 'sha256': env.file_sha[path]} for path in sc4.HARNESS_FILES}
    deps[sc4.INHERITANCE_PATH] = {'exists': True, 'sha256': inheritance_sha}
    return {'branches': [{'branch': 'synthetic branch', 'status': 'soporte aislado (M1, una plaza)'}], 'classification': copy.deepcopy(CLASSIFICATION), 'code': 'ok',
            'command': ['python', '-m', 'pytest'], 'dependencies': deps, 'docker_used': False, 'linux_docker_scenarios': 'not run in --offline',
            'output_tail': '49 passed, 4 deselected in 2.80s\n', 'returncode': 0, 'schema': sc4.OFFLINE_SCHEMA}


def build_inheritance(env):
    receipts = {'docs/evidencia/sc3-lifecycle/' + stem + '.json': ('{"synthetic": "' + stem + '"}').encode() for stem in sc4.A2_RECEIPT_STEMS}
    deps = []
    for path in sc4.A2_DEPENDENCIES:
        current = env.shas[path]
        old = hx('a2-' + path) if path.endswith('workflow.py') else current
        deps.append({'a2_sha256': old, 'changed': old != current, 'current_sha256': current, 'path': path})
    doc = {'schema': sc4.INHERITANCE_SCHEMA, 'receipts': [{'inherited_scope': sc4.A2_SCOPE, 'path': path, 'sha256': sha(data)} for path, data in receipts.items()],
           'dependencies': deps, 'decision': 'inherit four A2 guard scenarios; workflow integration requires A4 delta',
           'diff_review': ['workflow changes session selection; the guard modules are unchanged']}
    return doc, json.dumps(doc, sort_keys=True).encode(), receipts


def build_diff(env):
    paths = ['services/agent/invoice_actor_service.py', 'services/agent/invoice_actor_broker.py']
    return {'a4_reception_requirement': 'record actual digests', 'base_path': 'development/claude/bases/synthetic.json', 'base_sha256': hx('base'), 'interface_change': False,
            'journal_or_protocol_change': False, 'reason': 'synthetic', 'schema': sc4.DIFF_SCHEMA, 'verified_cases': ['synthetic'],
            'runtime_changes': [{'a4_base_sha256': hx('old-' + path), 'candidate_sha256': env.shas[path], 'path': path} for path in paths]}


class World:
    """Everything a check-receipts run consumes, as plain dicts a test can alter before it is written to disk."""

    def __init__(self, environment):
        self.env = environment
        self.inheritance_doc, self.inheritance_bytes, self.a2_receipts = build_inheritance(environment)
        self.inheritance_sha = sha(self.inheritance_bytes)
        self.docs = {name: build_scenario(environment, name, self.inheritance_sha) for name in sc4.SCENARIOS}
        self.order = list(sc4.SCENARIOS)
        self.service, self.guard, self.offline = build_service(environment), None, None
        self.attachments = [(sc4.INHERITANCE_PATH, self.inheritance_bytes)] + list(self.a2_receipts.items())
        self.scope, self.extra, self.raw = 'local', [], {}


def run(world, tmp_path, capsys):
    argv = ['check-receipts', '--scope', world.scope, *world.env.cand_args()]
    files = tmp_path / 'receipts'
    files.mkdir(exist_ok=True)

    def write(file_name, doc):
        path = files / file_name
        path.write_bytes(world.raw[file_name] if file_name in world.raw else json.dumps(doc, sort_keys=True).encode())
        return str(path)
    for number, name in enumerate(world.order):
        argv += ['--scenario-receipt', write('scenario-' + str(number) + '.json', world.docs[name])]
    for flag, file_name, doc in (('--service-receipt', 'service.json', world.service), ('--guard-receipt', 'guard.json', world.guard),
                                 ('--offline-receipt', 'offline.json', world.offline)):
        if doc is not None:
            argv += [flag, write(file_name, doc)]
    return cli(capsys, argv + attachment_args(tmp_path, world.attachments) + world.extra)


@pytest.fixture
def world(env):
    return World(env)


# ================================================================ unit level: strict JSON, exact types, tool hygiene

def test_strict_loader_rejects_duplicates_non_finite_numbers_and_depth():
    for raw, code in ((b'{"a": {"b": 1, "b": 2}}', 'json_duplicate_key'), (b'[{"a": 1, "a": 1}]', 'json_duplicate_key'), (b'{"a": NaN}', 'json_invalid'),
                      (b'{"a": 1e999}', 'json_invalid'), (b'\xff\xfe', 'json_invalid'), (b'[' * 60 + b']' * 60, 'json_too_large')):
        with pytest.raises(sc4.ReceiptError) as caught:
            sc4.strict_loads(raw)
        assert caught.value.code == code, raw[:20]
    assert sc4.strict_loads(b'{"a": [1, 2.5, true, null]}') == {'a': [1, 2.5, True, None]}


def test_same_keeps_json_types_apart():
    assert not sc4.same(True, 1) and not sc4.same([True], [1]) and not sc4.same({'a': 1}, {'a': True}) and not sc4.same(1.0, 1) and not sc4.same(0, False)
    assert sc4.same({'a': [1, 'x', None, True]}, {'a': [1, 'x', None, True]}) and not sc4.same({'a': 1}, {'a': 1, 'b': 2})
    assert sc4.is_int(1) and not sc4.is_int(True) and not sc4.is_int(1.0)


def test_tool_is_stdlib_only_and_never_runs_or_fetches_anything():
    tree = ast.parse(TOOL.read_text(encoding='utf-8'))
    imported = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported.update(alias.name.split('.')[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            imported.add((node.module or '').split('.')[0])
    assert imported <= {'argparse', 'ast', 'hashlib', 'importlib', 'json', 'math', 'os', 're', 'sys', 'pathlib'}, imported
    called = {node.func.id for node in ast.walk(tree) if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)}
    assert not called & {'exec', 'eval', 'compile', '__import__', 'open_url', 'system'}, called


def test_p5_loader_blocks_the_product_runtime(tmp_path):
    scripts = tmp_path / 'scripts'
    scripts.mkdir()
    (scripts / 'p5_candidate.py').write_bytes(sc4.P5_PATH.read_bytes())
    for rel in ('services/__init__.py', 'services/agent/__init__.py', 'services/agent/recovery.py'):
        put(tmp_path, rel, 'raise RuntimeError("the product runtime was imported")\n')
    before = {name: module for name, module in sys.modules.items() if name == 'services' or name.startswith('services.')}
    path_before = list(sys.path)
    module = sc4.load_p5(str(scripts / 'p5_candidate.py'))
    assert module.recovery is None and callable(module.read_package) and callable(module.verify_dir)
    assert {name: mod for name, mod in sys.modules.items() if name == 'services' or name.startswith('services.')} == before
    assert sys.path == path_before


@pytest.mark.parametrize('module', sc4.FRONTIER_MODULES)
def test_each_current_frontier_module_is_individually_required(module):
    cand = sc4.Candidate()
    cand.entries = {path: {'sha256': hx(path), 'size': 10} for path in sc4.FRONTIER_MODULES if path != module}
    rep = sc4.Report()
    sc4.check_frontier(sc4.Ctx(rep, 'candidate'), cand)
    assert [item['code'] for item in rep.rejections] == ['frontier_module_absent'] and module in rep.rejections[0]['where']
    cand.entries[module] = {'sha256': hx(module), 'size': 0}
    rep = sc4.Report()
    sc4.check_frontier(sc4.Ctx(rep, 'candidate'), cand)
    assert [item['code'] for item in rep.rejections] == ['frontier_module_empty']


# ================================================================ check-candidate

def test_candidate_roundtrip_local(env, capsys):
    clean = env.extract('clean-roundtrip')
    code, out = cli(capsys, candidate_argv(env, clean))
    assert code == 0 and out['decision'] == 'accepted' and out['ok'] is True and out['scope_requested'] == 'local', out['rejections'] + out['incomplete']
    assert out['candidate']['candidate_id'] == env.doc['candidate_id'] and out['candidate']['files_sha256'] == env.doc['files_sha256']
    assert out['candidate']['manifest_sha256_external'] == env.manifest_sha and out['candidate']['archive_sha256'] == env.doc['archive']['sha256']
    assert out['extraction']['verified'] is True and out['accredits'] and out['does_not_accredit'] and out['rejections'] == [] and out['pending_fields'] == []
    assert {item['path'] for item in out['sources']} == set(sc4.REQUIRED_PATHS) and all(item['via'] == 'manifest' for item in out['sources'])
    assert any('authenticity' in item for item in out['does_not_accredit'])


def test_matching_pins_are_accepted(env, capsys):
    pins = ['--candidate-id', env.doc['candidate_id'], '--files-sha256', env.doc['files_sha256'], '--expect-tool-sha256', sc4.file_sha(TOOL), '--expect-p5-sha256', sc4.file_sha(sc4.P5_PATH)]
    code, out = cli(capsys, candidate_argv(env, env.extract('clean-pins'), extra=pins))
    assert code == 0 and out['decision'] == 'accepted' and out['tool']['sources_sha256']['sc4_receipts.py'] == sc4.file_sha(TOOL)


@pytest.mark.parametrize('flag,value,expected', [('--candidate-id', 'f' * 16, 'candidate_id_pin_mismatch'), ('--files-sha256', 'f' * 64, 'files_sha256_pin_mismatch'),
                                                 ('--expect-tool-sha256', '0' * 64, 'tool_pin_mismatch'), ('--expect-p5-sha256', '0' * 64, 'tool_pin_mismatch')])
def test_wrong_pins_are_refused(env, capsys, flag, value, expected):
    code, out = cli(capsys, candidate_argv(env, env.extract('clean-wrong' + flag.strip('-')), extra=[flag, value]))
    assert code == 2 and out['decision'] == 'rejected' and expected in codes(out) and out['accredits'] == []


def test_external_manifest_digest_is_required_and_must_match(env, capsys):
    clean = env.extract('clean-digest')
    base = ['check-candidate', '--scope', 'local', '--package', str(env.package), '--manifest', str(env.manifest), '--dir', str(clean)]
    code, out = cli(capsys, base + ['--manifest-sha256', '0' * 64])
    assert code == 2 and 'manifest_digest_mismatch' in codes(out) and out['candidate'] is None
    code, out = cli(capsys, base + ['--manifest-sha256', 'NOT-A-DIGEST'])
    assert code == 2 and 'manifest_digest_invalid' in codes(out)
    code, out = cli(capsys, base)                       # absent: a usage decision, never a traceback
    assert code == 2 and 'usage' in codes(out) and out['decision'] == 'rejected'


def test_altered_package_and_edited_manifest_are_refused(env, tmp_path, capsys):
    data = bytearray(env.package.read_bytes())
    data[-1] ^= 0xFF
    broken = tmp_path / 'broken.tar.gz'
    broken.write_bytes(bytes(data))
    clean = env.extract('clean-altered')
    code, out = cli(capsys, ['check-candidate', '--scope', 'local', '--package', str(broken), '--manifest', str(env.manifest), '--manifest-sha256', env.manifest_sha, '--dir', str(clean)])
    assert code == 2 and 'archive_hash_mismatch' in codes(out)
    doc = json.loads(env.manifest.read_text(encoding='utf-8'))
    doc['files'][0]['sha256'] = '0' * 64                 # the operator even pins the edited manifest: the file list no longer matches files_sha256
    edited = tmp_path / 'edited.manifest.json'
    edited.write_text(json.dumps(doc, sort_keys=True), encoding='utf-8')
    code, out = cli(capsys, ['check-candidate', '--scope', 'local', '--package', str(env.package), '--manifest', str(edited), '--manifest-sha256', sha(edited.read_bytes()), '--dir', str(clean)])
    assert code == 2 and 'manifest_hash_mismatch' in codes(out)


def test_modified_added_or_missing_files_in_the_clean_copy_are_refused(env, tmp_path, capsys):
    modified = env.extract('clean-modified')
    (modified / 'requirements.txt').write_text('changed\n')
    added = env.extract('clean-added')
    (added / 'unlisted-file.txt').write_text('x')
    for clean in (modified, added, tmp_path / 'does-not-exist'):
        code, out = cli(capsys, candidate_argv(env, clean))
        assert code == 2 and out['decision'] == 'rejected' and out['accredits'] == []
        assert codes(out) & {'directory_mismatch', 'missing_directory'}
    assert out['extraction'] is None or out['extraction'] == {'verified': False} or out['extraction']['verified'] is False


def test_missing_frontier_module_is_refused_although_p5_verifies(tmp_path, p5, capsys):
    environment = Env(tmp_path / 'e', p5, omit=('services/agent/guard_state.py',))
    code, out = cli(capsys, candidate_argv(environment, environment.extract('clean')))
    assert code == 2 and 'frontier_module_absent' in codes(out) and out['extraction']['verified'] is True


def test_fixtures_are_reachable_by_manifest_or_by_explicit_attachment(tmp_path, p5, capsys):
    environment = Env(tmp_path / 'notests', p5, with_tests=False)
    clean = environment.extract('clean')
    code, out = cli(capsys, candidate_argv(environment, clean))
    assert code == 2 and 'fixture_absent' in codes(out)            # negative control: no tests in the manifest, nothing attached
    items = [(rel, environment.file_bytes(rel)) for rel in sc4.REQUIRED_PATHS]
    code, out = cli(capsys, candidate_argv(environment, clean, extra=attachment_args(tmp_path, items)))
    assert code == 0, out['rejections']
    assert all(item['via'] == ('manifest' if item['path'] in environment.shas else 'attachment')
               for item in out['sources'])


def test_attachment_digest_conflict_duplicate_and_path_rules(env, tmp_path, capsys):
    clean = env.extract('clean-att')
    data = b'{"synthetic": true}'
    path = tmp_path / 'att'
    path.write_bytes(data)
    cases = [(['--attachment', D1_ARTIFACT, str(path), '0' * 64], 'attachment_hash_mismatch'), (['--attachment', '../x', str(path), sha(data)], 'attachment_path_invalid'),
             (['--attachment', D1_ARTIFACT, str(path), sha(data)] * 2, 'attachment_duplicate'), (['--attachment', D1_ARTIFACT, str(path), 'XYZ'], 'attachment_digest_invalid'),
             (['--attachment', 'tests/integration/guard_boundary_local.py', str(path), sha(data)], 'attachment_conflicts_manifest')]
    for extra, expected in cases:
        code, out = cli(capsys, candidate_argv(env, clean, extra=extra))
        assert code == 2 and expected in codes(out), expected


def test_extra_required_path_and_required_attachment(env, tmp_path, capsys):
    clean = env.extract('clean-require')
    code, out = cli(capsys, candidate_argv(env, clean, extra=['--require-path', 'tests/backend/test_daemon_guard.py']))
    assert code == 2 and 'fixture_absent' in codes(out)
    code, out = cli(capsys, candidate_argv(env, clean, extra=['--require-attachment', D1_ARTIFACT]))
    assert code == 2 and out['decision'] == 'incomplete' and 'attachment_missing' in codes(out, 'incomplete') and out['rejections'] == []
    code, out = cli(capsys, candidate_argv(env, clean, extra=['--require-attachment', D1_ARTIFACT, *attachment_args(tmp_path, [(D1_ARTIFACT, b'{"x": 1}')])]))
    assert code == 0 and D1_ARTIFACT in out['attachments']


def test_deploy_candidate_must_be_test_free_with_identical_bytes(env, tmp_path, p5, capsys):
    clean = env.extract('clean-deploy')
    deploy = Env(tmp_path / 'deploy', p5, with_tests=False)
    code, out = cli(capsys, candidate_argv(env, clean, extra=['--deploy-manifest', str(deploy.manifest), '--deploy-manifest-sha256', deploy.manifest_sha]))
    assert code == 0 and out['deploy_candidate']['candidate_id'] == deploy.doc['candidate_id'], out['rejections']
    other = Env(tmp_path / 'other', p5, with_tests=False, salt='-changed')
    code, out = cli(capsys, candidate_argv(env, clean, extra=['--deploy-manifest', str(other.manifest), '--deploy-manifest-sha256', other.manifest_sha]))
    assert code == 2 and 'deploy_file_differs_in_receipt_package' in codes(out)
    code, out = cli(capsys, candidate_argv(env, clean, extra=['--deploy-manifest', str(env.manifest), '--deploy-manifest-sha256', env.manifest_sha]))
    assert code == 2 and 'deploy_includes_tests' in codes(out)
    code, out = cli(capsys, candidate_argv(env, clean, extra=['--deploy-manifest', str(deploy.manifest)]))
    assert code == 2 and 'usage' in codes(out)


@pytest.mark.parametrize('scope', ['private', 'independent', 'global'])
def test_candidate_scope_beyond_local_is_incomplete_with_pending_fields(env, capsys, scope):
    code, out = cli(capsys, candidate_argv(env, env.extract('clean-scope-' + scope), scope=scope))
    assert code == 2 and out['decision'] == 'incomplete' and out['ok'] is False and out['accredits'] == [] and out['rejections'] == []
    assert out['local_layer']['decision'] == 'accepted'
    fields = {item['field']: item for item in out['pending_fields']}
    assert {'private.vm_identities', 'private.positive_report', 'private.f_guard_receipt', 'private.crash_recovery_receipt'} <= set(fields)
    assert 'daemon' in fields['private.vm_identities']['note']
    assert ('independent.reproduction_report' in fields) == (scope != 'private') and ('global.sc2_3_controller_separation' in fields) == (scope == 'global')


def test_usage_errors_are_json_decisions(capsys):
    for argv in ([], ['check-candidate'], ['check-receipts', '--scope', 'central'], ['unknown-command']):
        code, out = cli(capsys, argv)
        assert code == 2 and out['decision'] == 'rejected' and out['ok'] is False and 'usage' in codes(out)


# ================================================================ check-receipts

C, P, B, L, X = sc4.SCENARIOS


def ev(w, name):
    return w.docs[name]['evidence']


def crit(w, name, cid):
    return next(item for item in w.docs[name]['criteria'] if item['id'] == cid)


def proof0(w, name, phase='cut'):
    return ev(w, name)['controller'][phase]['proofs'][0]


def test_receipts_roundtrip_local(world, tmp_path, capsys):
    code, out = run(world, tmp_path, capsys)
    assert code == 0 and out['decision'] == 'accepted' and out['ok'] is True, out['rejections'] + out['incomplete']
    assert out['scope_requested'] == 'local' and out['accredits'] and out['pending_fields'] == [] and out['rejections'] == [] and out['incomplete'] == []
    assert set(out['scenarios']) == set(sc4.SCENARIOS) and all(item['verdict'] == 'accepted' and item['code'] == 'ok' for item in out['scenarios'].values())
    assert out['controls']['positive']['status'] == out['controls']['f_veto']['status'] == 'established_local_provider_double'
    assert out['controls']['f_guard']['status'] == 'not_supplied'
    assert out['a2_inheritance']['status'] == 'bound' and out['a2_inheritance']['changed_dependencies'] == ['services/agent/workflow.py']
    assert out['a2_inheritance']['scope'] == 'verifier guard lifecycle only'
    assert any('M1 local' in item for item in out['accredits']) and not any('F-guard' in item for item in out['accredits'])
    assert any('private acceptance' in item for item in out['does_not_accredit']) and out['evidence_classes']['simulation']
    assert out['candidate']['candidate_id'] == world.env.doc['candidate_id']


# ---- one alteration per link: each must be rejected with its own stable code ----------------------------------------------

MUTATIONS = []


def mutation(expected):
    def register(fn):
        MUTATIONS.append(pytest.param(fn, expected, id=fn.__name__))
        return fn
    return register


@mutation('criteria_empty')
def criteria_list_empty(w):
    w.docs[C]['criteria'] = []


@mutation('criteria_duplicate')
def criterion_duplicated(w):
    w.docs[C]['criteria'].append(copy.deepcopy(w.docs[C]['criteria'][2]))


@mutation('criteria_missing')
def criterion_removed(w):
    del w.docs[C]['criteria'][5]


@mutation('criterion_false')
def criterion_false_under_code_ok(w):
    w.docs[C]['criteria'][5]['ok'] = False


@mutation('type_mismatch')
def criterion_ok_is_an_integer(w):
    w.docs[C]['criteria'][5]['ok'] = 1


@mutation('fixture_retained')
def fixture_retained_true(w):
    w.docs[C]['fixture_retained'] = True


@mutation('type_mismatch')
def fixture_retained_is_an_integer(w):
    w.docs[C]['fixture_retained'] = 0


@mutation('criterion_detail_mismatch')
def container_state_unknown(w):
    detail = crit(w, C, 'cancel:own_ids_absent')['detail']
    detail[next(iter(detail))][2] = 'unknown'


@mutation('finish_absent')
def actor_ledger_without_finish(w):
    ev(w, C)['ledgers']['actor'].pop()


@mutation('final_observation_missing')
def final_inventory_absent(w):
    del ev(w, C)['inventory_after']


@mutation('final_observation_missing')
def harness_reported_a_final_observation_error(w):
    ev(w, C)['final_observation_error'] = 'owner journal unreadable'


@mutation('uid_crossed')
def owner_uids_crossed(w):
    ev(w, C)['owners_at_start']['actor']['uids'] = [65532] * 4


@mutation('capabilities_not_zero')
def owner_holds_a_capability(w):
    ev(w, C)['owners_at_start']['actor']['cap_eff'] = '0000000000000001'


@mutation('no_new_privs_not_set')
def owner_without_no_new_privs(w):
    ev(w, C)['owners_at_start']['guard']['no_new_privileges'] = 0


@mutation('invalid_pid')
def pid_is_a_boolean(w):
    ev(w, C)['owners_at_start']['actor']['pid'] = True


@mutation('owners_same_process')
def actor_and_guard_share_a_process(w):
    ev(w, C)['owners_at_start']['guard']['pid'] = ev(w, C)['owners_at_start']['actor']['pid']


@mutation('installation_crossed')
def identity_of_another_installation(w):
    ev(w, C)['observed_active']['cancel']['identity']['installation_id'] = hx('other-installation', 32)


@mutation('identity_ledger_mismatch')
def observed_identity_not_in_the_ledger(w):
    ev(w, C)['observed_active']['cancel']['identity']['intent_id'] = hx('other-intent', 32)


@mutation('controller_uid_mismatch')
def controller_is_not_65534(w):
    proof0(w, C)['controller']['uid'] = 1000


@mutation('controller_groups')
def controller_has_a_group(w):
    proof0(w, C)['controller']['groups'] = [1000]


@mutation('docker_path_not_denied')
def docker_socket_reachable(w):
    proof0(w, C)['controller']['docker_endpoints_denied']['/run/docker.sock'] = 'OK'


@mutation('docker_denial_unproven')
def docker_only_absent_paths_were_seen(w):
    denied = proof0(w, C)['controller']['docker_endpoints_denied']
    for key in denied:
        denied[key] = 'ENOENT'


@mutation('so_peercred_pid_mismatch')
def peer_is_not_the_observed_owner(w):
    proof0(w, C)['controller']['so_peercred']['actor']['pid'] = 9999


@mutation('so_peercred_uid_mismatch')
def peer_uid_crossed(w):
    proof0(w, C)['controller']['so_peercred']['actor']['uid'] = 65532


@mutation('sentinel_not_preserved')
def sentinel_gone_at_the_end(w):
    ev(w, C)['inventory_after']['all_containers'].remove(ev(w, C)['sentinel']['id'])


@mutation('installation_not_empty_after')
def installation_not_empty_at_the_end(w):
    ev(w, C)['inventory_after']['installation'] = [hx('left-over')]


@mutation('foreign_container_removed')
def foreign_container_removed(w):
    ev(w, C)['inventory_after']['all_containers'].remove(ev(w, C)['inventory_before']['all_containers'][0])


@mutation('own_container_present_at_end')
def actor_container_still_listed(w):
    ev(w, C)['inventory_after']['all_containers'].append(ev(w, C)['ledgers']['actor'][1][1]['container_id'])


@mutation('controller_uid_mismatch')
def ledger_intent_opened_by_a_boolean_uid(w):
    ev(w, C)['ledgers']['actor'][0][1]['controller_uid'] = True


@mutation('ledger_duplicate_identity')
def container_repeated_in_the_ledger(w):
    ledger = ev(w, P)['ledgers']['actor']
    for index in (7, 11):
        ledger[index][1]['container_id'] = ledger[1][1]['container_id']


@mutation('ledger_run_structure')
def second_run_lost_its_perturbed_intent(w):
    del ev(w, X)['ledgers']['actor'][-6:]


@mutation('signal_before_observation')
def signalled_before_active_was_observed(w):
    items = w.docs[P]['criteria']
    index = next(number for number, item in enumerate(items) if item['id'] == 'cut:only_owner_child_signalled')
    items.insert(2, items.pop(index))


@mutation('signal_target_mismatch')
def killed_another_process(w):
    ev(w, P)['owner_kill']['target']['pid'] = 4242


@mutation('replay_after_cut')
def start_replayed_after_the_cut(w):
    ev(w, B)['docker_actions_after_cut'].append('start')


@mutation('owner_not_restarted')
def restart_has_the_pid_of_the_cut(w):
    restart = ev(w, P)['owner_restart']
    restart['pid'] = restart['proc']['pid'] = 1100


@mutation('guard_saw_failed_variant')
def guard_handled_the_failed_variant(w):
    ev(w, P)['ledgers']['guard'][0][1]['variant'] = 'perturbed'


@mutation('guard_finish_absent')
def guard_ledger_without_finish(w):
    ev(w, P)['ledgers']['guard'].pop()


@mutation('receipt_not_confirmed')
def recovered_receipt_still_pending(w):
    proof0(w, P, 'recover')['original_receipt']['status'] = 'pending'


@mutation('foreign_query_unobserved')
def foreign_query_without_an_outcome(w):
    ev(w, L)['foreign_uid_query'] = {'uid': 65533}


@mutation('foreign_uid_answered')
def foreign_uid_received_an_answer(w):
    ev(w, L)['foreign_uid_query'] = {'answered': True, 'connect': 'ok', 'uid': 65533}


@mutation('replay_not_rejected')
def replay_created_something(w):
    proof0(w, X)['replays']['perturbed'] = 'created'


@mutation('http_status_mismatch')
def cancel_status_is_a_boolean(w):
    proof0(w, C)['cancel_http'] = True


@mutation('controller_phase_failed')
def controller_return_code_is_false(w):
    ev(w, C)['controller']['cut']['returncode'] = False


@mutation('proof_identity_mismatch')
def proof_belongs_to_another_phase(w):
    proof0(w, C)['phase'] = 'recover'


@mutation('product_source_mismatch')
def product_source_changed(w):
    w.docs[C]['service_sources']['services/agent/main.py'] = hx('other')


@mutation('product_source_mismatch')
def product_source_not_in_the_candidate(w):
    w.docs[C]['service_sources']['services/agent/not_in_candidate.py'] = hx('x')


@mutation('harness_source_mismatch')
def harness_source_changed(w):
    w.docs[C]['harness_sources'][sc4.OPERATOR_HARNESS] = hx('other')


@mutation('image_id_crossed')
def image_of_another_scenario(w):
    w.docs[X]['image_id'] = 'sha256:' + hx('other-image')


@mutation('profile_sha256_crossed')
def profile_of_another_scenario(w):
    w.docs[X]['profile_sha256'] = hx('other-profile')


@mutation('a2_inheritance_sha256_crossed')
def a2_reference_differs_between_receipts(w):
    w.docs[C]['a2_inheritance']['sha256'] = hx('other-a2')


@mutation('a2_inheritance_absent')
def a2_reference_absent(w):
    w.docs[C]['a2_inheritance']['sha256'] = None


@mutation('a2_inheritance_path')
def a2_manifest_elsewhere(w):
    w.docs[C]['a2_inheritance']['manifest'] = 'docs/evidencia/other.json'


@mutation('identity_reused_across_receipts')
def sentinel_copied_between_receipts(w):
    ev(w, X)['sentinel']['id'] = ev(w, C)['sentinel']['id']


@mutation('schema_mismatch')
def another_schema(w):
    w.docs[C]['schema'] = 'sc2-actor-compatibility-a4/v2'


@mutation('provider_double_undeclared')
def simulation_not_declared(w):
    w.docs[C]['classification']['simulated'] = ['nothing is simulated']


@mutation('field_unexpected')
def receipt_claims_a_private_scope(w):
    w.docs[C]['evidence_scope'] = 'private'


@mutation('field_missing')
def receipt_lacks_the_a2_block(w):
    del w.docs[C]['a2_inheritance']


@mutation('scenario_unknown')
def scenario_name_is_not_one_of_the_five(w):
    w.docs[C]['scenario'] = 'cancel-api-v2'


# the actor service receipt: positive control and F-veto, local with a provider double
@mutation('f_veto_not_demonstrated')
def perturbed_verdict_is_rejected_not_unavailable(w):
    w.service['verifications']['perturbed']['status'] = 'rejected'


@mutation('guard_saw_failed_variant')
def service_guard_ledger_has_the_perturbed_variant(w):
    w.service['ledgers']['guard'][0]['payload']['variant'] = 'perturbed'


@mutation('product_source_mismatch')
def service_receipt_from_another_photo(w):
    w.service['sources']['services/agent/workflow.py'] = hx('older-photo')


@mutation('harness_source_mismatch')
def service_receipt_harness_from_another_photo(w):
    w.service['harness_sources'][sc4.SERVICE_HARNESS[0]] = hx('older-harness')


@mutation('not_a_local_fixture')
def service_receipt_not_a_local_fixture(w):
    w.service['local_fixture'] = False


@mutation('controller_uid_mismatch')
def service_controller_uid_is_a_boolean(w):
    w.service['controller_uid'] = True


@mutation('verifier_digest_mismatch')
def verdict_produced_by_other_verifier_code(w):
    w.service['verifications']['legitimate']['verifier_sha256'] = hx('other-verifier')


@mutation('verifier_input_mismatch')
def verdict_for_another_input(w):
    w.service['verifications']['legitimate']['input_sha256'] = hx('other-input')


@mutation('guard_container_mismatch')
def guard_ack_names_another_container(w):
    w.service['ledgers']['guard'][1]['payload']['container_id'] = hx('another-container')


@mutation('guard_artifact_mismatch')
def verdict_artifact_differs_from_the_guard_ledger(w):
    w.service['verifications']['legitimate']['artifact_sha256'] = hx('another-artifact')


@mutation('verifier_cleanup_unconfirmed')
def verifier_cleanup_not_confirmed(w):
    w.service['verifications']['legitimate']['cleanup_confirmed'] = False


@mutation('verdict_not_passed')
def legitimate_verdict_rejected(w):
    w.service['verifications']['legitimate']['status'] = 'rejected'


@mutation('identity_run_crossed')
def service_identity_of_another_run(w):
    w.service['actor_identities'][1]['run_id'] = hx('other-run', 32)


@mutation('identity_ledger_mismatch')
def service_ledger_names_another_container(w):
    w.service['actor_identities'][0]['container_id'] = hx('other-container')


@mutation('finish_absent')
def service_ledger_without_finish(w):
    w.service['ledgers']['actor'].pop()


@mutation('image_id_crossed')
def service_image_differs_from_the_scenarios(w):
    w.service['image_id'] = 'sha256:' + hx('another-image')


@mutation('observation_not_true')
def service_host_mounts_not_hidden(w):
    w.service['host_mounts_hidden'] = 1


@pytest.mark.parametrize('mutate,expected', MUTATIONS)
def test_every_altered_link_is_rejected(world, tmp_path, capsys, mutate, expected):
    mutate(world)
    code, out = run(world, tmp_path, capsys)
    assert code == 2 and out['decision'] == 'rejected' and out['ok'] is False
    assert expected in codes(out), (expected, sorted(codes(out)))
    assert out['accredits'] == [] and out['local_layer']['accredits'] == []


def test_the_control_world_is_accepted_so_the_alterations_are_not_vacuous(world, tmp_path, capsys):
    code, out = run(world, tmp_path, capsys)
    assert code == 0 and out['decision'] == 'accepted'


# ---- failed results are conserved, never eliminated -----------------------------------------------------------------------

def test_failed_result_is_rejected_and_preserved_in_the_decision(world, tmp_path, capsys):
    world.docs[P]['code'] = 'product_counterexample'
    world.docs[P]['fixture_retained'] = True
    crit(world, P, 'reconcile:no_replay_after_cut')['ok'] = False
    code, out = run(world, tmp_path, capsys)
    assert code == 2 and out['decision'] == 'rejected' and 'receipt_code_not_ok' in codes(out) and out['accredits'] == []
    record = out['scenarios'][P]
    assert record['code'] == 'product_counterexample' and record['verdict'] == 'rejected' and record['fixture_retained'] is True
    assert record['failed_criteria'] == ['reconcile:no_replay_after_cut']
    assert out['scenarios'][C]['verdict'] == 'accepted'          # the other scenarios are still evaluated and shown


@pytest.mark.parametrize('result_code', ['harness_error', 'precondition_missing'])
def test_other_failure_codes_are_also_conserved(world, tmp_path, capsys, result_code):
    world.docs[L].update(code=result_code, criteria=[], fixture_retained=True, error='harness stopped')
    code, out = run(world, tmp_path, capsys)
    assert code == 2 and out['scenarios'][L]['code'] == result_code and 'receipt_code_not_ok' in codes(out)


def test_missing_scenario_is_incomplete_and_duplicate_or_unknown_is_rejected(world, tmp_path, capsys):
    world.order.remove(X)
    code, out = run(world, tmp_path, capsys)
    assert code == 2 and out['decision'] == 'incomplete' and out['rejections'] == [] and 'scenario_missing' in codes(out, 'incomplete')
    world.order = list(sc4.SCENARIOS) + [C]
    code, out = run(world, tmp_path, capsys)
    assert code == 2 and out['decision'] == 'rejected' and 'scenario_duplicate' in codes(out)


# ---- bytes and bounds -------------------------------------------------------------------------------------------------------

def test_duplicate_json_keys_and_non_finite_numbers_are_refused(world, tmp_path, capsys):
    text = json.dumps(world.docs[C], sort_keys=True)
    world.raw['scenario-0.json'] = (text[:-1] + ', "code": "ok"}').encode()
    code, out = run(world, tmp_path, capsys)
    assert code == 2 and 'json_duplicate_key' in codes(out) and 'scenario_missing' in codes(out, 'incomplete')
    world.raw['scenario-0.json'] = b'{"code": NaN}'
    code, out = run(world, tmp_path, capsys)
    assert code == 2 and 'json_invalid' in codes(out)


@pytest.mark.parametrize('constant,value,expected', [('MAX_RECEIPT_BYTES', 200, 'file_too_large'), ('MAX_CRITERIA', 5, 'criteria_too_many'),
                                                     ('MAX_EVENTS', 5, 'type_mismatch'), ('MAX_CONTAINERS', 1, 'inventory_invalid')])
def test_bounds_are_enforced(world, tmp_path, capsys, monkeypatch, constant, value, expected):
    monkeypatch.setattr(sc4, constant, value)
    code, out = run(world, tmp_path, capsys)
    assert code == 2 and expected in codes(out), (expected, sorted(codes(out)))


# ---- scope: local never accredits private, independent or global ------------------------------------------------------------

@pytest.mark.parametrize('scope', ['private', 'independent', 'global'])
def test_local_receipts_never_accredit_a_wider_scope(world, tmp_path, capsys, scope):
    world.scope = scope
    code, out = run(world, tmp_path, capsys)
    assert code == 2 and out['decision'] == 'incomplete' and out['ok'] is False and out['accredits'] == [] and out['rejections'] == []
    assert out['local_layer']['decision'] == 'accepted' and out['local_layer']['accredits']
    fields = {item['field'] for item in out['pending_fields']}
    assert {'private.positive_report', 'private.f_veto_receipt', 'private.f_guard_receipt', 'private.vm_identities', 'private.crash_recovery_receipt',
            'private.restitution_receipt', 'private.preflight_receipt'} <= fields
    assert ('independent.reproduction_report' in fields) == (scope != 'private')
    assert {'global.sc2_3_controller_separation', 'global.sc2_4_branch_compatibility', 'global.sc3_integrated_recovery_concurrency_cancellation'} <= fields if scope == 'global' else True
    assert any('SC2.3' in item for item in out['does_not_accredit'])


# ---- guard (F-guard) and actor (positive, F-veto) are separate controls --------------------------------------------------------

def test_guard_receipt_of_another_photo_is_not_the_current_candidate(world, tmp_path, capsys):
    world.guard = build_guard(world.env, bound=False)
    code, out = run(world, tmp_path, capsys)
    assert code == 0 and out['decision'] == 'accepted', out['rejections']       # M1 local with F-veto is unaffected by the historical guard receipt
    control = out['controls']['f_guard']
    assert control['status'] == 'historical_other_photo' and control['counts_for_current_candidate'] is False
    assert {'changed:daemon_guard.py', 'changed:guard_client.py'} <= set(control['differing_sources'])
    assert not any('F-guard' in item for item in out['accredits'])
    world.scope = 'private'
    code, out = run(world, tmp_path, capsys)
    assert code == 2 and out['decision'] == 'incomplete' and out['controls']['f_guard']['status'] == 'historical_other_photo'
    assert 'private.f_guard_receipt' in {item['field'] for item in out['pending_fields']}


def test_bound_guard_receipt_without_artifact_bytes_does_not_establish_f_guard(world, tmp_path, capsys):
    world.guard = build_guard(world.env)
    code, out = run(world, tmp_path, capsys)
    assert code == 0 and out['controls']['f_guard']['status'] == 'incomplete_artifact_bytes_missing' and 'false total' in out['controls']['f_guard']['note']
    assert not any('F-guard' in item for item in out['accredits']) and out['pending_fields'] == []
    world.scope = 'private'
    code, out = run(world, tmp_path, capsys)
    assert code == 2 and 'f_guard.artifact_bytes' in {item['field'] for item in out['pending_fields']}


def test_f_guard_is_established_only_with_the_false_total_artifact(world, tmp_path, capsys):
    world.guard = build_guard(world.env, rejected=FALSE_ARTIFACT)
    world.attachments.append((D1_ARTIFACT, FALSE_ARTIFACT))        # found by its digest, whatever name it carries
    code, out = run(world, tmp_path, capsys)
    assert code == 0 and out['controls']['f_guard']['status'] == 'established_local', out['rejections']
    assert any('F-guard' in item for item in out['accredits'])
    world.guard = build_guard(world.env, rejected=GOOD_ARTIFACT)   # a rejection of the CORRECT total would not test the oracle
    world.attachments[-1] = (D1_ARTIFACT, GOOD_ARTIFACT)
    code, out = run(world, tmp_path, capsys)
    assert code == 2 and 'f_guard_total_not_false' in codes(out) and out['controls']['f_guard']['status'] == 'rejected'
    world.guard = build_guard(world.env, rejected=b'not json')
    world.attachments[-1] = (D1_ARTIFACT, b'not json')
    code, out = run(world, tmp_path, capsys)
    assert code == 2 and 'json_invalid' in codes(out) and out['controls']['f_guard']['status'] == 'rejected'


def test_guard_and_actor_controls_do_not_stand_in_for_each_other(world, tmp_path, capsys):
    world.service, world.guard = None, build_guard(world.env)
    world.attachments.append((D1_ARTIFACT, FALSE_ARTIFACT))
    code, out = run(world, tmp_path, capsys)
    assert code == 2 and out['decision'] == 'incomplete' and 'service_receipt_missing' in codes(out, 'incomplete')
    controls = out['controls']
    assert controls['positive']['status'] == controls['f_veto']['status'] == 'not_supplied' and controls['f_guard']['status'] == 'established_local'
    world.service, world.guard = build_service(world.env), None
    code, out = run(world, tmp_path, capsys)
    assert code == 0 and out['controls']['f_guard']['status'] == 'not_supplied' and out['controls']['positive']['status'] == 'established_local_provider_double'


GUARD_MUTATIONS = [
    ('verdicts_unexpected', lambda g: g['receipts'][1].__setitem__('status', 'passed')),
    ('restitution_not_observed', lambda g: g.__setitem__('containers_absent_after', False)),
    ('verifier_cleanup_unconfirmed', lambda g: g['receipts'][0].__setitem__('cleanup_confirmed', False)),
    ('lifecycle_invalid', lambda g: g['lifecycle'][next(iter(g['lifecycle']))].pop()),
    ('wrong_client_accepted', lambda g: g.__setitem__('wrong_client', {'reason': 'ok', 'status': 'ok'})),
    ('wrong_server_accepted', lambda g: g.__setitem__('wrong_server', {'reason': 'ok', 'status': 'ok'})),
    ('artifact_reused', lambda g: g['receipts'][1].__setitem__('artifact_sha256', g['receipts'][0]['artifact_sha256'])),
    ('identity_reused', lambda g: g['receipts'][1].__setitem__('container_id', g['receipts'][0]['container_id'])),
    ('verifier_digest_mismatch', lambda g: g['source_sha256'].__setitem__('invoice_verifier.py', hx('other'))),
    ('direct_control_invalid', lambda g: g['direct_control'].__setitem__('uid', 1000)),
    ('malformed_request_accepted', lambda g: g['direct_control'].__setitem__('malformed_request', {'reason': 'ok', 'status': 'ok'})),
    ('docker_denial_unproven', lambda g: g['direct_control']['docker'].update({key: 'ENOENT' for key in g['direct_control']['docker']})),
    ('type_mismatch', lambda g: g.__setitem__('receipts', [g['receipts'][0]])),
]


@pytest.mark.parametrize('expected,mutate', GUARD_MUTATIONS, ids=[item[0] for item in GUARD_MUTATIONS])
def test_inconsistent_guard_receipt_is_rejected(world, tmp_path, capsys, mutate, expected):
    world.guard = build_guard(world.env)
    mutate(world.guard)
    code, out = run(world, tmp_path, capsys)
    assert code == 2 and out['decision'] == 'rejected' and expected in codes(out), (expected, sorted(codes(out)))
    assert out['controls']['f_guard']['status'] == 'rejected'


def test_offline_receipt_is_authoring_evidence_and_adds_no_control(world, tmp_path, capsys):
    (tmp_path / 'base').mkdir()
    baseline = run(world, tmp_path / 'base', capsys)
    world.offline = build_offline(world.env, world.inheritance_sha)
    code, out = run(world, tmp_path, capsys)
    assert baseline[0] == 0 and code == 0 and out['receipts']['offline']['bound'] is True and out['controls'] == baseline[1]['controls']
    world.offline['dependencies'][sc4.OPERATOR_HARNESS]['sha256'] = hx('older-harness')
    code, out = run(world, tmp_path, capsys)
    assert code == 0 and out['receipts']['offline']['valid'] is True and out['receipts']['offline']['bound'] is False
    assert out['receipts']['offline']['diffs'] == ['changed:' + sc4.OPERATOR_HARNESS]


@pytest.mark.parametrize('mutate,expected', [
    (lambda o: o.__setitem__('docker_used', True), 'offline_not_offline'), (lambda o: o.__setitem__('returncode', 1), 'offline_tests_failed'),
    (lambda o: o.__setitem__('output_tail', '3 failed, 46 passed'), 'offline_tests_not_passed'), (lambda o: o.__setitem__('code', 'harness_error'), 'receipt_code_not_ok'),
    (lambda o: o['dependencies'].pop(sc4.INHERITANCE_PATH), 'field_missing'), (lambda o: o['dependencies'][sc4.OPERATOR_HARNESS].__setitem__('exists', False), 'dependency_absent')])
def test_inconsistent_offline_receipt_is_rejected(world, tmp_path, capsys, mutate, expected):
    world.offline = build_offline(world.env, world.inheritance_sha)
    mutate(world.offline)
    code, out = run(world, tmp_path, capsys)
    assert code == 2 and expected in codes(out), (expected, sorted(codes(out)))


# ---- A2 inherited by hash and diff, with explicit attachments (docs/evidencia is outside P5) -----------------------------------

def with_inheritance(world, mutate):
    doc = copy.deepcopy(world.inheritance_doc)
    mutate(doc)
    data = json.dumps(doc, sort_keys=True).encode()
    world.attachments = [(sc4.INHERITANCE_PATH, data)] + list(world.a2_receipts.items())
    for scenario in world.docs.values():
        scenario['a2_inheritance']['sha256'] = sha(data)


def test_inheritance_and_a2_receipts_must_be_attached_explicitly(world, tmp_path, capsys):
    world.attachments = [item for item in world.attachments if item[0] != sc4.INHERITANCE_PATH]
    code, out = run(world, tmp_path, capsys)
    assert code == 2 and out['decision'] == 'incomplete' and 'attachment_missing' in codes(out, 'incomplete') and out['a2_inheritance']['status'] == 'attachment_missing'
    world.attachments = [(sc4.INHERITANCE_PATH, world.inheritance_bytes)] + list(world.a2_receipts.items())[:-1]
    code, out = run(world, tmp_path, capsys)
    assert code == 2 and out['decision'] == 'incomplete' and 'a2_receipt_attachment_missing' in codes(out, 'incomplete')


def test_attachment_that_is_not_the_referenced_inheritance_manifest_is_refused(world, tmp_path, capsys):
    for scenario in world.docs.values():
        scenario['a2_inheritance']['sha256'] = hx('another-manifest')
    code, out = run(world, tmp_path, capsys)
    assert code == 2 and 'a2_inheritance_hash_mismatch' in codes(out)


def _guard_module_changed(doc):
    doc['dependencies'][0].update(a2_sha256=hx('old-guard'), changed=True)


INHERITANCE_MUTATIONS = [
    ('a2_inheritance_invalidated', _guard_module_changed),
    ('a2_scope_widened', lambda d: d['receipts'][1].__setitem__('inherited_scope', 'service cancellation')),
    ('diff_flag_inconsistent', lambda d: d['dependencies'][-1].__setitem__('changed', False)),
    ('dependency_changed_after_review', lambda d: d['dependencies'][1].__setitem__('current_sha256', hx('moved'))),
    ('a2_receipt_hash_changed', lambda d: d['receipts'][0].__setitem__('sha256', hx('other'))),
    ('diff_review_missing', lambda d: d.__setitem__('diff_review', [])),
    ('a2_dependency_missing', lambda d: d['dependencies'].pop(0)),
    ('inheritance_schema', lambda d: d.__setitem__('schema', 'sc3-a2-inheritance/v0')),
    ('a2_receipt_path', lambda d: d['receipts'][2].__setitem__('path', 'docs/evidencia/other.json')),
]


@pytest.mark.parametrize('expected,mutate', INHERITANCE_MUTATIONS, ids=[item[0] for item in INHERITANCE_MUTATIONS])
def test_tampered_inheritance_manifest_is_rejected(world, tmp_path, capsys, expected, mutate):
    with_inheritance(world, mutate)
    code, out = run(world, tmp_path, capsys)
    assert code == 2 and expected in codes(out) and out['accredits'] == [], (expected, sorted(codes(out)))


def test_a4_integration_diff_is_checked_when_attached(world, tmp_path, capsys):
    diff = build_diff(world.env)
    world.attachments.append((sc4.DIFF_PATH, json.dumps(diff).encode()))
    code, out = run(world, tmp_path, capsys)
    assert code == 0 and out['a4_diff']['status'] == 'consistent', out['rejections']
    for field, value, expected in (('candidate', hx('not-the-manifest'), 'a4_diff_candidate_mismatch'), ('interface_change', True, 'diff_not_neutral')):
        broken = copy.deepcopy(diff)
        if field == 'candidate':
            broken['runtime_changes'][0]['candidate_sha256'] = value
        else:
            broken[field] = value
        world.attachments[-1] = (sc4.DIFF_PATH, json.dumps(broken).encode())
        code, out = run(world, tmp_path, capsys)
        assert code == 2 and expected in codes(out)


def test_harness_comes_from_the_manifest_or_an_explicit_attachment(tmp_path, p5, capsys):
    environment = Env(tmp_path / 'notests', p5, with_tests=False)
    (tmp_path / 'a').mkdir()
    (tmp_path / 'b').mkdir()
    code, out = run(World(environment), tmp_path / 'a', capsys)
    assert code == 2 and out['decision'] == 'incomplete' and 'harness_source_unbound' in codes(out, 'incomplete')
    attached = World(environment)
    attached.attachments += [(rel, environment.file_bytes(rel)) for rel in sc4.HARNESS_FILES]
    code, out = run(attached, tmp_path / 'b', capsys)
    assert code == 0 and out['decision'] == 'accepted', out['rejections'] + out['incomplete']


# ---- conformance with the REAL producers' output (read by path and hash, never copied; skipped when absent) --------------------

HISTORICAL_ROOT = Path(os.environ.get('SC4_HISTORICAL_ROOT', str(REPO)))
HISTORICAL_SHA = {
    'docs/evidencia/a4-local/cancel-api-01/cancel-api.json': '7faec47e921d58fb97ce166ea9c8fe9d764428ce3753fefc2e4c274ff68811ac',
    'docs/evidencia/a4-local/offline-01/offline.json': 'b22c5d11e2fa979abc74acc9a79ac8bab68a88671b837d0ac5ed70e54b2de334',
    'docs/evidencia/actor-servicio-durable-local.json': '457a53ff970da3ecf468f0e7a9987cfd4ed7987a82d0f62c66ec4e9a3d6668e9',
    'docs/evidencia/guard-verificador-local.json': 'fb70ba576ff32616f197a64d9ddadd396fc780abbbc635fb586cc37462041606',
}


def historical(rel):
    path = HISTORICAL_ROOT / rel
    if not path.is_file():
        pytest.skip(rel + ' is not present in this checkout')
    data = path.read_bytes()
    if sha(data) != HISTORICAL_SHA[rel]:
        pytest.skip(rel + ' has other bytes than the receipt this conformance test was written against')
    return sc4.strict_loads(data)


def bound_candidate(environment, p5):
    rep = sc4.Report()
    args = argparse.Namespace(manifest=str(environment.manifest), manifest_sha256=environment.manifest_sha, package=str(environment.package), candidate_id=None, files_sha256=None)
    cand = sc4.bind_candidate(rep, p5, args)
    assert cand is not None and not rep.rejections
    return cand


def test_conformance_real_cancel_api_receipt_has_the_shape_the_checker_expects(env, p5):
    doc = historical('docs/evidencia/a4-local/cancel-api-01/cancel-api.json')
    assert sorted(doc) == sorted(sc4.TOP_KEYS) and {item['id'] for item in doc['criteria']} == set(sc4.REQUIRED_CRITERIA['cancel-api'])
    rep = sc4.Report()
    record = sc4.check_scenario(rep, doc, bound_candidate(env, p5), {}, 0)
    found = {item['code'] for item in rep.rejections}
    assert record is not None and record['code'] == 'ok'
    assert found <= {'product_source_mismatch', 'harness_source_mismatch'}, rep.rejections[:6]     # only the photo differs from the synthetic candidate
    assert 'product_source_mismatch' in found                                                        # positive control: the binding does bite
    assert rep.incomplete == []


def test_conformance_real_service_and_guard_receipts(env, p5):
    cand = bound_candidate(env, p5)
    service = historical('docs/evidencia/actor-servicio-durable-local.json')
    rep = sc4.Report()
    result = sc4.check_service_receipt(rep, service, cand, {})
    allowed = {'product_source_mismatch', 'harness_source_mismatch', 'verifier_digest_mismatch', 'verifier_input_mismatch'}
    assert {item['code'] for item in rep.rejections} <= allowed, rep.rejections[:6]
    assert result['bound'] is False and result['positive'] is False and result['f_veto'] is False
    guard = historical('docs/evidencia/guard-verificador-local.json')
    rep = sc4.Report()
    result = sc4.check_guard_receipt(rep, guard, cand, {})
    assert rep.rejections == [] and result['valid'] is True and result['bound'] is False
    assert any(item.startswith('changed:daemon_guard') or item.startswith('changed:guard_client') for item in result['diffs'])


def test_conformance_real_offline_receipt(env, p5):
    offline = historical('docs/evidencia/a4-local/offline-01/offline.json')
    rep = sc4.Report()
    result = sc4.check_offline_receipt(rep, offline, bound_candidate(env, p5), {})
    assert rep.rejections == [] and result['valid'] is True and result['bound'] is False


# A4b's two exact received cuts; schema/binding validation only, no execution of a fixture or candidate.
A4B_RECEIVED = {
    'controller-kill-running': ('docs/evidencia/a4b-local/controller-kill-02/controller-kill-running.json', '375cdf616661223bcd77f93c173713d2a3a3f47ba49b63ea29c8b7d2848040df'),
    'cancel-api-verifier-running': ('docs/evidencia/a4b-local/cancel-verifier-01/cancel-api-verifier-running.json', '28065610774cf059c28aabf887397549a564b15bb0c4b7ee65e55babbd5d7139'),
}


def a4b_received(name):
    rel, digest = A4B_RECEIVED[name]
    path = HISTORICAL_ROOT / rel
    if not path.is_file():
        pytest.skip('A4b conformance receipt is not attached: ' + rel)
    data = path.read_bytes()
    assert sha(data) == digest, 'A4b received evidence changed'
    return sc4.strict_loads(data)


class A4bSourcePhoto:
    # Test double for an already verified manifest. Package integrity is covered by the P5/CLI tests above.
    def __init__(self, doc):
        self.entries = {p: {'sha256': h} for p, h in {
            **doc['service_sources'], **doc['harness_sources'], **doc['evidence']['a4b']['sources']}.items()}

    def sha_of(self, path):
        return self.entries.get(path, {}).get('sha256')


def a4b_checked(doc, photo):
    report = sc4.Report()
    result = sc4.check_scenario(report, doc, photo, {}, 0)
    return result, report


@pytest.mark.parametrize('name', sc4.A4B_SCENARIOS)
def test_a4b_received_cut_is_accepted_only_as_local_scenario_data(name):
    doc = a4b_received(name)
    result, report = a4b_checked(doc, A4bSourcePhoto(doc))
    assert result['verdict'] == 'accepted' and report.decision == 'accepted', report.rejections
    assert len(result['_ids']['containers']) == (3 if name == sc4.A4B_SCENARIOS[0] else 1)


A4B_NEGATIVES = [
    ('controller-kill-running', lambda d: d['evidence']['controller_kill']['target'].__setitem__('uids', [1000] * 4)),
    ('controller-kill-running', lambda d: d['evidence']['controller']['cut'].__setitem__('returncode', 0)),
    ('controller-kill-running', lambda d: d['evidence']['controller']['cut']['proofs'][0].__setitem__('run_status', 'completed')),
    ('controller-kill-running', lambda d: d['evidence']['controller']['blocked']['proofs'][0].__setitem__('post_http', 202)),
    ('controller-kill-running', lambda d: d['evidence']['owner_reconciliation'].__setitem__('finish_observed', False)),
    ('controller-kill-running', lambda d: d['evidence']['create_event_observation']['events'].pop()),
    ('controller-kill-running', lambda d: d['evidence']['create_event_observation']['events'][0]['Actor']['Attributes'].__setitem__('org.agent-escape-room.actor-installation', 'a' * 32)),
    ('controller-kill-running', lambda d: d['evidence']['create_event_observation']['events'].append(copy.deepcopy(d['evidence']['create_event_observation']['events'][0]))),
    ('controller-kill-running', lambda d: d['evidence']['controller']['recover']['proofs'][0]['original_receipt'].__setitem__('cleanup_confirmed', False)),
    ('cancel-api-verifier-running', lambda d: d['evidence']['verifier_running'].__setitem__('docker', ABSENT)),
    ('cancel-api-verifier-running', lambda d: d['evidence']['controller']['cut']['proofs'][0]['verifier_finished'].__setitem__('artifact_sha256', 'a' * 64)),
    ('cancel-api-verifier-running', lambda d: d['evidence']['controller']['cut']['proofs'][0]['verifier_finished'].__setitem__('cleanup_confirmed', False)),
    ('cancel-api-verifier-running', lambda d: d['evidence']['controller']['cut']['proofs'][0].__setitem__('reopened_reports_identical', False)),
    ('cancel-api-verifier-running', lambda d: d['evidence']['timeline_operator_clock_ns'].__setitem__('release_sent_ns', 1)),
    ('cancel-api-verifier-running', lambda d: d['evidence']['guard_replacement']['wrapper'].__setitem__('uids', [1000] * 4)),
    ('cancel-api-verifier-running', lambda d: d['evidence']['instrumentation'].__setitem__('sha256', 'a' * 64)),
]


@pytest.mark.parametrize('name,mutate', A4B_NEGATIVES)
def test_a4b_contradictory_observation_rejected_even_with_all_criteria_true(name, mutate):
    doc = a4b_received(name)
    photo = A4bSourcePhoto(doc)
    mutate(doc)
    assert all(c['ok'] is True for c in doc['criteria'])
    result, report = a4b_checked(doc, photo)
    assert result['verdict'] == 'rejected' and report.rejections


@pytest.mark.parametrize('name,key', [
    ('controller-kill-running', 'controller_kill'), ('controller-kill-running', 'create_event_observation'),
    ('controller-kill-running', 'owner_reconciliation'), ('controller-kill-running', 'ledgers'),
    ('cancel-api-verifier-running', 'verifier_running'), ('cancel-api-verifier-running', 'instrumentation'),
    ('cancel-api-verifier-running', 'timeline_operator_clock_ns'), ('cancel-api-verifier-running', 'controller'),
])
def test_a4b_missing_required_observation_is_rejected(name, key):
    doc = a4b_received(name)
    photo = A4bSourcePhoto(doc)
    del doc['evidence'][key]
    result, report = a4b_checked(doc, photo)
    assert result['verdict'] == 'rejected' and any(c['code'] == 'field_missing' for c in report.rejections)


def test_a4b_harness_extension_and_contract_are_bound():
    doc = a4b_received('controller-kill-running')
    photo = A4bSourcePhoto(doc)
    del doc['harness_sources'][sc4.A4B_HARNESS]
    result, report = a4b_checked(doc, photo)
    assert result['verdict'] == 'rejected'
    doc = a4b_received('controller-kill-running')
    photo.entries.pop(next(iter(doc['evidence']['a4b']['sources'])))
    result, report = a4b_checked(doc, photo)
    assert result['verdict'] == 'incomplete' and any(c['code'] == 'a4b_contract_unbound' for c in report.incomplete)
